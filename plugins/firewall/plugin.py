"""
Firewall Plugin
───────────────
Manages firewall rules as a persistent JSON store and compiles them to
nftables scripts applied via a sudo wrapper (nft_apply).  Routes mount at /v1/firewall/.

Events emitted:
  firewall.rule.added    – payload: {rule_id, name}
  firewall.rule.updated  – payload: {rule_id, changes}
  firewall.rule.deleted  – payload: {rule_id, name}
  firewall.compiled      – payload: {rule_count}
  firewall.applied       – payload: {rule_count, success}

Events consumed:
  firewall.compile       – payload: {filter_name?}
    Triggers an out-of-band compile and prints a preview to stdout.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# make the plugin-local _nft subpackage importable regardless of how this
# module was loaded (PluginLoader uses spec_from_file_location, not packages)
_plugin_dir = str(Path(__file__).parent)
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from _nft.compiler import (  # noqa: E402
    _addr_family,
    _compile_to_script,
    _port_set,
    _rule_to_nft_expr,
)

from fastapi import HTTPException

from models import (  # noqa: E402
    ChainConfig,
    ChainUpdate,
    CompileRequest,
    CompileResult,
    CustomChain,
    FirewallQuota,
    FirewallRule,
    FirewallSet,
    Flowtable,
    IngressRule,
    IngressRuleCreate,
    IngressRuleUpdate,
    NatRule,
    NatRuleCreate,
    NatRuleUpdate,
    RuleCreate,
    RuleUpdate,
    SetCreate,
    SetElementsBody,
    VerdictMap,
    VerdictMapEntryBody,
    VerdictMapKeyBody,
)

from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service
from plugin_system.core.decorators import on
from plugin_system.core.events import Event, bus
from plugin_system.core.macros import extract_macros, macro_registry


def _rule_hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


_DEFAULT_CHAINS: dict[str, dict] = {
    "input":   {"policy": "drop",   "priority": 0, "preamble": ["iif lo accept", "ct state established,related accept", "ct state invalid drop"]},
    "forward": {"policy": "drop",   "priority": 0, "preamble": ["ct state established,related accept"]},
    "output":  {"policy": "accept", "priority": 0, "preamble": []},
}




# ── plugin class ───────────────────────────────────────────────────────────────

class FirewallPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.FIREWALL]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "firewall_state.json", self.logger,
            mutation_model="deferred", data_dir=self.data_dir,
        )
        self._default_filter = self.config.get("default_filter_name", "fastfirewall")
        self._nft_wrapper = self.config.get("nft_wrapper") or str(self.plugin_dir / "nft_cmd")
        self._rules: dict[str, FirewallRule] = {}
        self._chains: dict[str, ChainConfig] = {
            name: ChainConfig(**cfg) for name, cfg in _DEFAULT_CHAINS.items()
        }
        self._sets: dict[str, FirewallSet] = {}
        self._nat_rules: dict[str, NatRule] = {}
        self._flowtables: dict[str, Flowtable] = {}
        self._custom_chains: dict[str, CustomChain] = {}
        self._ingress_rules: dict[str, IngressRule] = {}
        self._ingress_table = self.config.get("ingress_table", "ff_ingress")
        self._verdict_maps: dict[str, VerdictMap] = {}
        self._quotas: dict[str, FirewallQuota] = {}
        self._load_state()
        if not self.config.get("ignore_state_on_boot", False):
            self._apply_state()
        self.logger.info("Loaded %d rules from %r", len(self._rules), self._state_file.path)
        self._register_routes()

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("Shut down — state saved")

    @on("plugins.all_loaded")
    def _on_plugins_loaded(self, event: Event) -> None:
        if self.config.get("ignore_state_on_boot", False):
            return
        current = self._collect_macro_snapshot()
        if not current:
            return
        stored = self._state_file.get_macro_snapshot()
        if stored == current:
            return
        changed = {k for k in current if current.get(k) != (stored or {}).get(k)}
        self.logger.info("Macro values changed since last apply (%s) — re-applying", ", ".join(sorted(changed)))
        self._apply_state()

    # ── persistence ────────────────────────────────────────────────────

    def _desired_snapshot(self) -> dict:
        return {
            "rules": [r.model_dump() for r in self._rules.values()],
            "chains": {name: cfg.model_dump() for name, cfg in self._chains.items()},
            "sets": {name: s.model_dump() for name, s in self._sets.items()},
            "nat_rules": [r.model_dump() for r in self._nat_rules.values()],
            "flowtables": {name: ft.model_dump() for name, ft in self._flowtables.items()},
            "custom_chains": {name: cc.model_dump() for name, cc in self._custom_chains.items()},
            "ingress_rules": [r.model_dump() for r in self._ingress_rules.values()],
            "verdict_maps": {name: vm.model_dump() for name, vm in self._verdict_maps.items()},
            "quotas": {name: q.model_dump() for name, q in self._quotas.items()},
        }

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _collect_macro_snapshot(self) -> dict:
        macros = extract_macros(self._desired_snapshot())
        return {m: macro_registry.resolve(m) for m in sorted(macros)}

    def _load_state(self) -> None:
        fresh_install = not self._state_file.path.exists()
        default: dict = {"rules": [], "chains": _DEFAULT_CHAINS, "sets": {}, "nat_rules": [], "flowtables": {}, "custom_chains": {}, "ingress_rules": [], "verdict_maps": {}, "quotas": {}}
        raw = self._state_file.load_desired(default=default)
        try:
            self._rules = {r["id"]: FirewallRule(**r) for r in raw.get("rules", [])}
        except Exception:
            self.logger.error("Failed to parse rules from %r, starting empty", self._state_file.path, exc_info=True)
            self._rules = {}
        try:
            self._chains = {name: ChainConfig(**cfg) for name, cfg in raw.get("chains", _DEFAULT_CHAINS).items()}
        except Exception:
            self.logger.error("Failed to parse chain config, using defaults", exc_info=True)
            self._chains = {name: ChainConfig(**cfg) for name, cfg in _DEFAULT_CHAINS.items()}
        try:
            self._sets = {name: FirewallSet(**s) for name, s in raw.get("sets", {}).items()}
        except Exception:
            self.logger.error("Failed to parse sets, starting empty", exc_info=True)
            self._sets = {}
        try:
            self._nat_rules = {r["id"]: NatRule(**r) for r in raw.get("nat_rules", [])}
        except Exception:
            self.logger.error("Failed to parse NAT rules, starting empty", exc_info=True)
            self._nat_rules = {}
        try:
            self._flowtables = {name: Flowtable(**ft) for name, ft in raw.get("flowtables", {}).items()}
        except Exception:
            self.logger.error("Failed to parse flowtables, starting empty", exc_info=True)
            self._flowtables = {}
        try:
            self._custom_chains = {name: CustomChain(**cc) for name, cc in raw.get("custom_chains", {}).items()}
        except Exception:
            self.logger.error("Failed to parse custom chains, starting empty", exc_info=True)
            self._custom_chains = {}
        try:
            self._ingress_rules = {r["id"]: IngressRule(**r) for r in raw.get("ingress_rules", [])}
        except Exception:
            self.logger.error("Failed to parse ingress rules, starting empty", exc_info=True)
            self._ingress_rules = {}
        try:
            self._verdict_maps = {name: VerdictMap(**vm) for name, vm in raw.get("verdict_maps", {}).items()}
        except Exception:
            self.logger.error("Failed to parse verdict maps, starting empty", exc_info=True)
            self._verdict_maps = {}
        try:
            self._quotas = {name: FirewallQuota(**q) for name, q in raw.get("quotas", {}).items()}
        except Exception:
            self.logger.error("Failed to parse quotas, starting empty", exc_info=True)
            self._quotas = {}
        if fresh_install:
            _DEFAULT_RULES: list[RuleCreate] = [
                RuleCreate(
                    name="allow-ssh",
                    chain="input",
                    action="accept",
                    protocol="tcp",
                    dst_port="$service_port.ssh.tcp",
                    comment="Allow SSH from any source",
                    priority=10,
                ),
                RuleCreate(
                    name="allow-fastfirewall-api",
                    chain="input",
                    action="accept",
                    protocol="tcp",
                    dst_port="$service_port.fastfirewall-api.tcp",
                    comment="Allow FastFirewall API from any source",
                    priority=11,
                ),
            ]
            for rule_create in _DEFAULT_RULES:
                rule_data = rule_create.model_dump()
                rule_id = _rule_hash(rule_data)
                if rule_id not in self._rules:
                    self._rules[rule_id] = FirewallRule(id=rule_id, **rule_data)
            self._save_state()
            self.logger.info("Fresh install — seeded %d default rules", len(_DEFAULT_RULES))

    def _apply_state(self) -> None:
        enabled = [r for r in self._rules.values() if r.enabled]
        if not enabled and not self._nat_rules and not self._flowtables and not self._ingress_rules and not self._verdict_maps and not self._quotas:
            return
        try:
            script = _compile_to_script(
                enabled, self._default_filter, self._chains, self.logger,
                sets=self._sets, nat_rules=list(self._nat_rules.values()),
                flowtables=list(self._flowtables.values()),
                custom_chains=self._custom_chains,
                ingress_rules=list(self._ingress_rules.values()),
                ingress_table=self._ingress_table,
                verdict_maps=self._verdict_maps,
                quotas=self._quotas,
            )
            self._apply_nft_script(script)
            self._state_file.set_macro_snapshot(self._collect_macro_snapshot())
            self._state_file.commit(self._desired_snapshot())
            self.logger.info("Re-applied %d rules on boot", len(enabled))
        except Exception as exc:
            self.logger.warning("Could not re-apply rules on boot: %s", exc)

    # ── nftables integration ───────────────────────────────────────────

    def _apply_nft_script(self, script: str) -> None:
        result = subprocess.run(
            ["sudo", self._nft_wrapper],
            input=script,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.logger.error("nft apply failed (rc=%d): %s", result.returncode, result.stderr.strip())
            raise RuntimeError("nft command failed")

    def _validate_nft_script(self, script: str) -> tuple[bool, str]:
        result = subprocess.run(
            ["sudo", self._nft_wrapper, "--check"],
            input=script,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0, result.stderr.strip()

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        _w = "https://wiki.nftables.org/wiki-nftables/index.php"
        # filter rules
        _d = f"[nftables rule management]({_w}/Simple_rule_management)"
        add("/rules",                       self._list_rules,          methods=["GET"],    summary="List firewall rules",            description=_d)
        add("/rules",                       self._create_rule,         methods=["POST"],   summary="Create a firewall rule",         description=_d, status_code=201)
        add("/rules/{rule_id}",             self._get_rule,            methods=["GET"],    summary="Get a firewall rule",            description=_d)
        add("/rules/{rule_id}",             self._update_rule,         methods=["PUT"],    summary="Update a firewall rule",         description=_d)
        add("/rules/{rule_id}",             self._delete_rule,         methods=["DELETE"], summary="Delete a firewall rule",         description=_d)
        # chains
        _d = f"[nftables chain configuration]({_w}/Configuring_chains)"
        add("/chains",                      self._list_chains,         methods=["GET"],    summary="List chains and their policies", description=_d)
        add("/chains/{chain_name}",         self._get_chain,           methods=["GET"],    summary="Get a chain",                    description=_d)
        add("/chains/{chain_name}",         self._update_chain,        methods=["PUT"],    summary="Update chain policy or priority",description=_d)
        # named sets (§3)
        _d = f"[nftables sets]({_w}/Sets)"
        add("/sets",                        self._list_sets,           methods=["GET"],    summary="List named sets",                description=_d)
        add("/sets",                        self._create_set,          methods=["POST"],   summary="Create a named set",             description=_d, status_code=201)
        add("/sets/{set_name}",             self._get_set,             methods=["GET"],    summary="Get a named set",                description=_d)
        add("/sets/{set_name}",             self._delete_set,          methods=["DELETE"], summary="Delete a named set",             description=_d)
        add("/sets/{set_name}/elements",    self._add_set_elements,    methods=["POST"],   summary="Add elements to a set",          description=_d)
        add("/sets/{set_name}/elements",    self._remove_set_elements, methods=["DELETE"], summary="Remove elements from a set",     description=_d)
        # custom chains (§10)
        _d = f"[nftables chain configuration]({_w}/Configuring_chains)"
        add("/custom-chains",               self._list_custom_chains,  methods=["GET"],    summary="List custom chains",             description=_d)
        add("/custom-chains",               self._create_custom_chain, methods=["POST"],   summary="Create a custom chain",          description=_d, status_code=201)
        add("/custom-chains/{cc_name}",     self._get_custom_chain,    methods=["GET"],    summary="Get a custom chain",             description=_d)
        add("/custom-chains/{cc_name}",     self._delete_custom_chain, methods=["DELETE"], summary="Delete a custom chain",          description=_d)
        # flowtables (§7)
        _d = f"[nftables flowtables]({_w}/Flowtables)"
        add("/flowtables",                  self._list_flowtables,     methods=["GET"],    summary="List flowtables",                description=_d)
        add("/flowtables",                  self._create_flowtable,    methods=["POST"],   summary="Create a flowtable",             description=_d, status_code=201)
        add("/flowtables/{ft_name}",        self._get_flowtable,       methods=["GET"],    summary="Get a flowtable",                description=_d)
        add("/flowtables/{ft_name}",        self._delete_flowtable,    methods=["DELETE"], summary="Delete a flowtable",             description=_d)
        # NAT rules (§4)
        _d = f"[nftables NAT]({_w}/Performing_Network_Address_Translation_(NAT))"
        add("/nat/rules",                   self._list_nat_rules,      methods=["GET"],    summary="List NAT rules",                 description=_d)
        add("/nat/rules",                   self._create_nat_rule,     methods=["POST"],   summary="Create a NAT rule",              description=_d, status_code=201)
        add("/nat/rules/{rule_id}",         self._get_nat_rule,        methods=["GET"],    summary="Get a NAT rule",                 description=_d)
        add("/nat/rules/{rule_id}",         self._update_nat_rule,     methods=["PUT"],    summary="Update a NAT rule",              description=_d)
        add("/nat/rules/{rule_id}",         self._delete_nat_rule,     methods=["DELETE"], summary="Delete a NAT rule",              description=_d)
        # ingress rules (§11) — netdev family, per-device early drop
        _d = f"[nftables netdev / ingress]({_w}/Nftables_families#netdev)"
        add("/ingress/rules",               self._list_ingress_rules,  methods=["GET"],    summary="List ingress rules",             description=_d)
        add("/ingress/rules",               self._create_ingress_rule, methods=["POST"],   summary="Create an ingress rule",         description=_d, status_code=201)
        add("/ingress/rules/{rule_id}",     self._get_ingress_rule,    methods=["GET"],    summary="Get an ingress rule",            description=_d)
        add("/ingress/rules/{rule_id}",     self._update_ingress_rule, methods=["PUT"],    summary="Update an ingress rule",         description=_d)
        add("/ingress/rules/{rule_id}",     self._delete_ingress_rule, methods=["DELETE"], summary="Delete an ingress rule",         description=_d)
        # quotas (§8)
        _d = f"[nftables quotas]({_w}/Matching_packet_rate_limiting#Quotas)"
        add("/quotas",                      self._list_quotas,         methods=["GET"],    summary="List named quotas",              description=_d)
        add("/quotas",                      self._create_quota,        methods=["POST"],   summary="Create a named quota",           description=_d, status_code=201)
        add("/quotas/{quota_name}",         self._get_quota,           methods=["GET"],    summary="Get a named quota",              description=_d)
        add("/quotas/{quota_name}",         self._delete_quota,        methods=["DELETE"], summary="Delete a named quota",           description=_d)
        # verdict maps (§12)
        _d = f"[nftables verdict maps]({_w}/Verdict_Maps_(vmaps))"
        add("/maps",                        self._list_verdict_maps,          methods=["GET"],    summary="List verdict maps",                    description=_d)
        add("/maps",                        self._create_verdict_map,         methods=["POST"],   summary="Create a verdict map",                 description=_d, status_code=201)
        add("/maps/{map_name}",             self._get_verdict_map,            methods=["GET"],    summary="Get a verdict map",                    description=_d)
        add("/maps/{map_name}",             self._delete_verdict_map,         methods=["DELETE"], summary="Delete a verdict map",                 description=_d)
        add("/maps/{map_name}/entries",     self._add_verdict_map_entries,    methods=["POST"],   summary="Add entries to a verdict map",         description=_d)
        add("/maps/{map_name}/entries",     self._remove_verdict_map_entries, methods=["DELETE"], summary="Remove entries from a verdict map by key", description=_d)
        # counters (§8) — read-only live-state views
        _d = f"[nftables counters]({_w}/Counters)"
        add("/counters",                      self._list_counters, methods=["GET"],  summary="Live counter values from kernel",  description=_d)
        add("/counters/{counter_name}/reset", self._reset_counter, methods=["POST"], summary="Atomically reset a named counter", description=_d)
        # table / apply / compile / status
        _d = f"[nftables operations at ruleset level]({_w}/Operations_at_ruleset_level)"
        add("/table",      self._get_table, methods=["GET"],  summary="Show current table configuration",          description=_d)
        add("/check",      self._check,     methods=["POST"], summary="Dry-run validate (no apply)",               description=_d)
        add("/apply",      self._apply,     methods=["POST"], summary="Compile and apply rules to nftables",       description=_d)
        add("/compile",    self._compile,   methods=["POST"], summary="Compile rules to nft script (preview only)",description=_d)
        add("/discard",    self._discard,   methods=["POST"], summary="Revert pending changes to last applied state")
        add("/live-state", self._live_state,methods=["GET"],  summary="Live kernel ruleset (nft -j list table)",   description=_d)
        add("/status",     self._status,    methods=["GET"],  summary="Plugin status")

    # ── rule CRUD ──────────────────────────────────────────────────────

    def _snapshot_rule_map(self) -> dict[str, dict]:
        """Return {rule_id: rule_dict} from the last committed snapshot, or {} if never applied."""
        snapshot = self._state_file.current_snapshot
        return {r["id"]: r for r in snapshot["rules"]} if snapshot else {}

    def _list_rules(self, enabled_only: bool = False) -> dict:
        rules = sorted(self._rules.values(), key=lambda r: r.priority)
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        snap = self._snapshot_rule_map()
        return {
            "rules": [{**r.model_dump(), "applied": snap.get(r.id) == r.model_dump()} for r in rules],
            "count": len(rules),
        }

    def _create_rule(self, body: RuleCreate) -> dict:
        rule_id = _rule_hash(body.model_dump())
        if rule_id in self._rules:
            raise HTTPException(409, f"An identical rule already exists (id={rule_id!r})")
        rule = FirewallRule(id=rule_id, **body.model_dump())
        self._rules[rule.id] = rule
        self._save_state()
        bus.emit(Event(
            name="firewall.rule.added",
            payload={"rule_id": rule.id, "name": rule.name},
        ))
        snap = self._snapshot_rule_map()
        return {**rule.model_dump(), "applied": snap.get(rule.id) == rule.model_dump()}

    def _get_rule(self, rule_id: str) -> dict:
        rule = self._rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {rule_id!r} not found")
        snap = self._snapshot_rule_map()
        return {**rule.model_dump(), "applied": snap.get(rule.id) == rule.model_dump()}

    def _update_rule(self, rule_id: str, body: RuleUpdate) -> dict:
        rule = self._rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {rule_id!r} not found")
        updates = body.model_dump(exclude_unset=True)
        updated = rule.model_copy(update=updates)
        self._rules[rule_id] = updated
        self._save_state()
        bus.emit(Event(
            name="firewall.rule.updated",
            payload={"rule_id": rule_id, "changes": list(updates.keys())},
        ))
        snap = self._snapshot_rule_map()
        return {**updated.model_dump(), "applied": snap.get(updated.id) == updated.model_dump()}

    def _delete_rule(self, rule_id: str) -> dict:
        if rule_id not in self._rules:
            raise HTTPException(404, f"Rule {rule_id!r} not found")
        deleted = self._rules.pop(rule_id)
        self._save_state()
        bus.emit(Event(
            name="firewall.rule.deleted",
            payload={"rule_id": rule_id, "name": deleted.name},
        ))
        return {"deleted": True, "rule_id": rule_id}

    # ── named set CRUD (§3) ────────────────────────────────────────────

    def _list_sets(self) -> dict:
        return {"sets": [s.model_dump() for s in self._sets.values()], "count": len(self._sets)}

    def _create_set(self, body: SetCreate) -> dict:
        if body.name in self._sets:
            raise HTTPException(409, f"Set {body.name!r} already exists")
        fw_set = FirewallSet(**body.model_dump())
        self._sets[fw_set.name] = fw_set
        self._save_state()
        return fw_set.model_dump()

    def _get_set(self, set_name: str) -> dict:
        fw_set = self._sets.get(set_name)
        if not fw_set:
            raise HTTPException(404, f"Set {set_name!r} not found")
        return fw_set.model_dump()

    def _delete_set(self, set_name: str) -> dict:
        if set_name not in self._sets:
            raise HTTPException(404, f"Set {set_name!r} not found")
        self._sets.pop(set_name)
        self._save_state()
        return {"deleted": True, "name": set_name}

    def _add_set_elements(self, set_name: str, body: SetElementsBody) -> dict:
        fw_set = self._sets.get(set_name)
        if not fw_set:
            raise HTTPException(404, f"Set {set_name!r} not found")
        existing = set(fw_set.elements)
        merged = fw_set.elements + [e for e in body.elements if e not in existing]
        self._sets[set_name] = fw_set.model_copy(update={"elements": merged})
        self._save_state()
        return self._sets[set_name].model_dump()

    def _remove_set_elements(self, set_name: str, body: SetElementsBody) -> dict:
        fw_set = self._sets.get(set_name)
        if not fw_set:
            raise HTTPException(404, f"Set {set_name!r} not found")
        remove = set(body.elements)
        kept = [e for e in fw_set.elements if e not in remove]
        self._sets[set_name] = fw_set.model_copy(update={"elements": kept})
        self._save_state()
        return self._sets[set_name].model_dump()

    # ── custom chain CRUD (§10) ───────────────────────────────────────

    def _list_custom_chains(self) -> dict:
        return {"custom_chains": [cc.model_dump() for cc in self._custom_chains.values()], "count": len(self._custom_chains)}

    def _create_custom_chain(self, body: CustomChain) -> dict:
        if body.name in self._custom_chains:
            raise HTTPException(409, f"Custom chain {body.name!r} already exists")
        if body.name in self._chains:
            raise HTTPException(409, f"A hook chain named {body.name!r} already exists")
        self._custom_chains[body.name] = body
        self._save_state()
        return body.model_dump()

    def _get_custom_chain(self, cc_name: str) -> dict:
        cc = self._custom_chains.get(cc_name)
        if not cc:
            raise HTTPException(404, f"Custom chain {cc_name!r} not found")
        return cc.model_dump()

    def _delete_custom_chain(self, cc_name: str) -> dict:
        if cc_name not in self._custom_chains:
            raise HTTPException(404, f"Custom chain {cc_name!r} not found")
        self._custom_chains.pop(cc_name)
        self._save_state()
        return {"deleted": True, "name": cc_name}

    # ── flowtable CRUD (§7) ───────────────────────────────────────────

    def _list_flowtables(self) -> dict:
        return {"flowtables": [ft.model_dump() for ft in self._flowtables.values()], "count": len(self._flowtables)}

    def _create_flowtable(self, body: Flowtable) -> dict:
        if body.name in self._flowtables:
            raise HTTPException(409, f"Flowtable {body.name!r} already exists")
        self._flowtables[body.name] = body
        self._save_state()
        return body.model_dump()

    def _get_flowtable(self, ft_name: str) -> dict:
        ft = self._flowtables.get(ft_name)
        if not ft:
            raise HTTPException(404, f"Flowtable {ft_name!r} not found")
        return ft.model_dump()

    def _delete_flowtable(self, ft_name: str) -> dict:
        if ft_name not in self._flowtables:
            raise HTTPException(404, f"Flowtable {ft_name!r} not found")
        self._flowtables.pop(ft_name)
        self._save_state()
        return {"deleted": True, "name": ft_name}

    # ── NAT rule CRUD (§4) ─────────────────────────────────────────────

    def _snapshot_nat_map(self) -> dict[str, dict]:
        snapshot = self._state_file.current_snapshot
        if snapshot is None:
            return {}
        return {r["id"]: r for r in snapshot.get("nat_rules", [])}

    def _list_nat_rules(self) -> dict:
        rules = sorted(self._nat_rules.values(), key=lambda r: r.priority)
        snap = self._snapshot_nat_map()
        return {
            "nat_rules": [{**r.model_dump(), "applied": snap.get(r.id) == r.model_dump()} for r in rules],
            "count": len(rules),
        }

    def _create_nat_rule(self, body: NatRuleCreate) -> dict:
        rule_id = _rule_hash(body.model_dump())
        if rule_id in self._nat_rules:
            raise HTTPException(409, f"An identical NAT rule already exists (id={rule_id!r})")
        rule = NatRule(id=rule_id, **body.model_dump())
        self._nat_rules[rule.id] = rule
        self._save_state()
        snap = self._snapshot_nat_map()
        return {**rule.model_dump(), "applied": snap.get(rule.id) == rule.model_dump()}

    def _get_nat_rule(self, rule_id: str) -> dict:
        rule = self._nat_rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"NAT rule {rule_id!r} not found")
        snap = self._snapshot_nat_map()
        return {**rule.model_dump(), "applied": snap.get(rule.id) == rule.model_dump()}

    def _update_nat_rule(self, rule_id: str, body: NatRuleUpdate) -> dict:
        rule = self._nat_rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"NAT rule {rule_id!r} not found")
        updates = body.model_dump(exclude_unset=True)
        updated = rule.model_copy(update=updates)
        self._nat_rules[rule_id] = updated
        self._save_state()
        snap = self._snapshot_nat_map()
        return {**updated.model_dump(), "applied": snap.get(updated.id) == updated.model_dump()}

    def _delete_nat_rule(self, rule_id: str) -> dict:
        if rule_id not in self._nat_rules:
            raise HTTPException(404, f"NAT rule {rule_id!r} not found")
        self._nat_rules.pop(rule_id)
        self._save_state()
        return {"deleted": True, "rule_id": rule_id}

    # ── ingress rule CRUD (§11) ───────────────────────────────────────

    def _snapshot_ingress_map(self) -> dict[str, dict]:
        snapshot = self._state_file.current_snapshot
        if snapshot is None:
            return {}
        return {r["id"]: r for r in snapshot.get("ingress_rules", [])}

    def _list_ingress_rules(self, enabled_only: bool = False) -> dict:
        rules = sorted(self._ingress_rules.values(), key=lambda r: r.priority)
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        snap = self._snapshot_ingress_map()
        return {
            "ingress_rules": [{**r.model_dump(), "applied": snap.get(r.id) == r.model_dump()} for r in rules],
            "count": len(rules),
        }

    def _create_ingress_rule(self, body: IngressRuleCreate) -> dict:
        rule_id = _rule_hash(body.model_dump())
        if rule_id in self._ingress_rules:
            raise HTTPException(409, f"An identical ingress rule already exists (id={rule_id!r})")
        rule = IngressRule(id=rule_id, **body.model_dump())
        self._ingress_rules[rule.id] = rule
        self._save_state()
        snap = self._snapshot_ingress_map()
        return {**rule.model_dump(), "applied": snap.get(rule.id) == rule.model_dump()}

    def _get_ingress_rule(self, rule_id: str) -> dict:
        rule = self._ingress_rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"Ingress rule {rule_id!r} not found")
        snap = self._snapshot_ingress_map()
        return {**rule.model_dump(), "applied": snap.get(rule.id) == rule.model_dump()}

    def _update_ingress_rule(self, rule_id: str, body: IngressRuleUpdate) -> dict:
        rule = self._ingress_rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"Ingress rule {rule_id!r} not found")
        updates = body.model_dump(exclude_unset=True)
        updated = rule.model_copy(update=updates)
        self._ingress_rules[rule_id] = updated
        self._save_state()
        snap = self._snapshot_ingress_map()
        return {**updated.model_dump(), "applied": snap.get(updated.id) == updated.model_dump()}

    def _delete_ingress_rule(self, rule_id: str) -> dict:
        if rule_id not in self._ingress_rules:
            raise HTTPException(404, f"Ingress rule {rule_id!r} not found")
        self._ingress_rules.pop(rule_id)
        self._save_state()
        return {"deleted": True, "rule_id": rule_id}

    # ── quota CRUD (§8) ──────────────────────────────────────────────

    def _list_quotas(self) -> dict:
        return {"quotas": [q.model_dump() for q in self._quotas.values()], "count": len(self._quotas)}

    def _create_quota(self, body: FirewallQuota) -> dict:
        if body.name in self._quotas:
            raise HTTPException(409, f"Quota {body.name!r} already exists")
        self._quotas[body.name] = body
        self._save_state()
        return body.model_dump()

    def _get_quota(self, quota_name: str) -> dict:
        quota = self._quotas.get(quota_name)
        if not quota:
            raise HTTPException(404, f"Quota {quota_name!r} not found")
        return quota.model_dump()

    def _delete_quota(self, quota_name: str) -> dict:
        if quota_name not in self._quotas:
            raise HTTPException(404, f"Quota {quota_name!r} not found")
        self._quotas.pop(quota_name)
        self._save_state()
        return {"deleted": True, "name": quota_name}

    # ── verdict map CRUD (§12) ────────────────────────────────────────

    def _list_verdict_maps(self) -> dict:
        return {"verdict_maps": [vm.model_dump() for vm in self._verdict_maps.values()], "count": len(self._verdict_maps)}

    def _create_verdict_map(self, body: VerdictMap) -> dict:
        if body.name in self._verdict_maps:
            raise HTTPException(409, f"Verdict map {body.name!r} already exists")
        self._verdict_maps[body.name] = body
        self._save_state()
        return body.model_dump()

    def _get_verdict_map(self, map_name: str) -> dict:
        vm = self._verdict_maps.get(map_name)
        if not vm:
            raise HTTPException(404, f"Verdict map {map_name!r} not found")
        return vm.model_dump()

    def _delete_verdict_map(self, map_name: str) -> dict:
        if map_name not in self._verdict_maps:
            raise HTTPException(404, f"Verdict map {map_name!r} not found")
        self._verdict_maps.pop(map_name)
        self._save_state()
        return {"deleted": True, "name": map_name}

    def _add_verdict_map_entries(self, map_name: str, body: VerdictMapEntryBody) -> dict:
        vm = self._verdict_maps.get(map_name)
        if not vm:
            raise HTTPException(404, f"Verdict map {map_name!r} not found")
        existing_keys = {e.key for e in vm.entries}
        merged = list(vm.entries) + [e for e in body.entries if e.key not in existing_keys]
        self._verdict_maps[map_name] = vm.model_copy(update={"entries": merged})
        self._save_state()
        return self._verdict_maps[map_name].model_dump()

    def _remove_verdict_map_entries(self, map_name: str, body: VerdictMapKeyBody) -> dict:
        vm = self._verdict_maps.get(map_name)
        if not vm:
            raise HTTPException(404, f"Verdict map {map_name!r} not found")
        remove_keys = set(body.keys)
        kept = [e for e in vm.entries if e.key not in remove_keys]
        self._verdict_maps[map_name] = vm.model_copy(update={"entries": kept})
        self._save_state()
        return self._verdict_maps[map_name].model_dump()

    # ── counter endpoints (§8) ────────────────────────────────────────

    def _list_counters(self) -> dict:
        result = subprocess.run(
            ["sudo", self._nft_wrapper, "--list-counters", "inet", self._default_filter],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self.logger.error("nft list counters failed (rc=%d): %s", result.returncode, result.stderr.strip())
            raise HTTPException(500, "Failed to query counters; check server logs")
        try:
            data = json.loads(result.stdout)
        except Exception as exc:
            self.logger.error("Failed to parse nft counter output", exc_info=True)
            raise HTTPException(500, "Failed to parse counter output; check server logs") from exc
        return {"table": f"inet {self._default_filter}", "counters": data}

    def _reset_counter(self, counter_name: str) -> dict:
        result = subprocess.run(
            ["sudo", self._nft_wrapper, "--reset-counter", "inet", self._default_filter, counter_name],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self.logger.error("nft reset counter failed (rc=%d): %s", result.returncode, result.stderr.strip())
            raise HTTPException(500, "Failed to reset counter; check server logs")
        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
        except Exception as exc:
            self.logger.error("Failed to parse counter reset output", exc_info=True)
            raise HTTPException(500, "Failed to parse counter reset output; check server logs") from exc
        return {"reset": True, "name": counter_name, "previous": data}

    # ── pending-changes detail (§13) ──────────────────────────────────

    _SNAP_EMPTY: dict = {
        "rules": [], "chains": {}, "sets": {}, "nat_rules": [],
        "flowtables": {}, "custom_chains": {}, "ingress_rules": [],
        "verdict_maps": {}, "quotas": {},
    }

    def _pending_changes_detail(self) -> dict:
        snap = self._state_file.current_snapshot
        keys = list(self._SNAP_EMPTY.keys())
        if snap is None:
            return {"any": False, **{k: False for k in keys}}
        desired = self._desired_snapshot()
        # use empty baseline for keys absent in older snapshots
        result = {k: desired.get(k) != snap.get(k, self._SNAP_EMPTY[k]) for k in keys}
        result["any"] = any(result[k] for k in keys)
        return result

    # ── apply / compile endpoints ──────────────────────────────────────

    @property
    def _compiled_output_path(self) -> str:
        return os.path.join(str(self.plugin_dir), "data", f"{self._default_filter}.nft")

    def _applied_chains(self) -> dict:
        snapshot = self._state_file.current_snapshot
        return snapshot["chains"] if snapshot else {}

    def _list_chains(self) -> dict:
        committed = self._applied_chains()
        return {
            "table": f"inet {self._default_filter}",
            "chains": {
                name: {**cfg.model_dump(), "applied": committed.get(name) == cfg.model_dump()}
                for name, cfg in self._chains.items()
            },
        }

    def _get_chain(self, chain_name: str) -> dict:
        cfg = self._chains.get(chain_name)
        if cfg is None:
            raise HTTPException(404, f"Chain {chain_name!r} not found")
        committed = self._applied_chains()
        return {"name": chain_name, **cfg.model_dump(), "applied": committed.get(chain_name) == cfg.model_dump()}

    def _update_chain(self, chain_name: str, body: ChainUpdate) -> dict:
        cfg = self._chains.get(chain_name)
        if cfg is None:
            raise HTTPException(404, f"Chain {chain_name!r} not found")
        self._chains[chain_name] = cfg.model_copy(update=body.model_dump(exclude_unset=True))
        self._save_state()
        updated = self._chains[chain_name]
        committed = self._applied_chains()
        return {"name": chain_name, **updated.model_dump(), "applied": committed.get(chain_name) == updated.model_dump()}

    def _get_table(self) -> dict:
        return {
            "name": self._default_filter,
            "family": "inet",
            "chains": list(self._chains.keys()),
        }

    def _check(self) -> dict:
        enabled = [r for r in self._rules.values() if r.enabled]
        script = _compile_to_script(
            enabled, self._default_filter, self._chains, self.logger,
            sets=self._sets, nat_rules=list(self._nat_rules.values()),
            flowtables=list(self._flowtables.values()),
            custom_chains=self._custom_chains,
            ingress_rules=list(self._ingress_rules.values()),
            ingress_table=self._ingress_table,
            verdict_maps=self._verdict_maps,
            quotas=self._quotas,
        )
        success, error = self._validate_nft_script(script)
        return {
            "success": success,
            "rule_count": len(enabled),
            "chain_count": len(self._chains),
            "output": error if not success else "",
        }

    def _apply(self) -> dict:
        enabled = [r for r in self._rules.values() if r.enabled]
        script = _compile_to_script(
            enabled, self._default_filter, self._chains, self.logger,
            sets=self._sets, nat_rules=list(self._nat_rules.values()),
            flowtables=list(self._flowtables.values()),
            custom_chains=self._custom_chains,
            ingress_rules=list(self._ingress_rules.values()),
            ingress_table=self._ingress_table,
            verdict_maps=self._verdict_maps,
            quotas=self._quotas,
        )
        output_path = self._compiled_output_path
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as fh:
            fh.write(script)
        try:
            self._apply_nft_script(script)
        except RuntimeError:
            self.logger.error("Failed to apply compiled firewall rules", exc_info=True)
            raise HTTPException(500, "Failed to apply firewall rules; check server logs")
        self._state_file.set_macro_snapshot(self._collect_macro_snapshot())
        self._state_file.commit()
        bus.emit(Event(
            name="firewall.applied",
            payload={"rule_count": len(enabled), "success": True},
        ))
        return {
            "success": True,
            "rule_count": len(enabled),
            "chain_count": len(self._chains),
            "pending_changes": self._pending_changes_detail(),
        }

    def _compile(self, body: CompileRequest) -> CompileResult:
        enabled = [r for r in self._rules.values() if r.enabled]
        script = _compile_to_script(
            enabled, body.filter_name, self._chains, self.logger,
            sets=self._sets, nat_rules=list(self._nat_rules.values()),
            flowtables=list(self._flowtables.values()),
            custom_chains=self._custom_chains,
            ingress_rules=list(self._ingress_rules.values()),
            ingress_table=self._ingress_table,
            verdict_maps=self._verdict_maps,
            quotas=self._quotas,
        )
        output_path = os.path.join(str(self.plugin_dir), "data", f"{body.filter_name}.nft")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as fh:
            fh.write(script)
        bus.emit(Event(
            name="firewall.compiled",
            payload={"rule_count": len(enabled)},
        ))
        return CompileResult(
            filter_name=body.filter_name,
            output=script.splitlines(),
            rule_count=len(enabled),
            output_path=output_path,
        )

    def _discard(self) -> dict:
        snapshot = self._state_file.current_snapshot
        if snapshot is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        try:
            self._rules = {r["id"]: FirewallRule(**r) for r in snapshot.get("rules", [])}
            self._chains = {name: ChainConfig(**cfg) for name, cfg in snapshot.get("chains", _DEFAULT_CHAINS).items()}
            self._sets = {name: FirewallSet(**s) for name, s in snapshot.get("sets", {}).items()}
            self._nat_rules = {r["id"]: NatRule(**r) for r in snapshot.get("nat_rules", [])}
            self._flowtables = {name: Flowtable(**ft) for name, ft in snapshot.get("flowtables", {}).items()}
            self._custom_chains = {name: CustomChain(**cc) for name, cc in snapshot.get("custom_chains", {}).items()}
            self._ingress_rules = {r["id"]: IngressRule(**r) for r in snapshot.get("ingress_rules", [])}
            self._verdict_maps = {name: VerdictMap(**vm) for name, vm in snapshot.get("verdict_maps", {}).items()}
            self._quotas = {name: FirewallQuota(**q) for name, q in snapshot.get("quotas", {}).items()}
        except Exception as exc:
            self.logger.error("Failed to restore from snapshot", exc_info=True)
            raise HTTPException(500, "Failed to restore from snapshot; check server logs") from exc
        self._save_state()
        return {"discarded": True, "rule_count": len(self._rules)}

    def _live_state(self) -> dict:
        result = subprocess.run(
            ["sudo", self._nft_wrapper, "--list", "inet", self._default_filter],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.logger.error("nft list failed (rc=%d): %s", result.returncode, result.stderr.strip())
            raise HTTPException(500, "Failed to query live kernel state; check server logs")
        try:
            live = json.loads(result.stdout)
        except Exception as exc:
            self.logger.error("Failed to parse nft JSON output", exc_info=True)
            raise HTTPException(500, "Failed to parse live kernel state; check server logs") from exc
        return {"table": f"inet {self._default_filter}", "live": live}

    def _status(self) -> dict:
        total = len(self._rules)
        enabled = sum(1 for r in self._rules.values() if r.enabled)
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "rules": {"total": total, "enabled": enabled, "disabled": total - enabled},
            "nat_rules": len(self._nat_rules),
            "sets": len(self._sets),
            "flowtables": len(self._flowtables),
            "custom_chains": len(self._custom_chains),
            "ingress_rules": len(self._ingress_rules),
            "verdict_maps": len(self._verdict_maps),
            "quotas": len(self._quotas),
            "state_file": self._state_file.path,
            "default_filter": self._default_filter,
            "pending_changes": self._pending_changes_detail(),
            "macros": macro_registry.namespaces,
            "compiled_output": self._compiled_output_path,
        }

