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
import ipaddress
import json
import os
import subprocess
from typing import Any, Literal, Optional, Union

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator

from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service, on
from plugin_system.core.events import Event, bus
from plugin_system.core.macros import is_macro, macro_registry, validate_macro_syntax


# ── Pydantic models ────────────────────────────────────────────────────────────

def _validate_port_field(v: object) -> object:
    if isinstance(v, str):
        validate_macro_syntax(v)
    return v


class FirewallRule(BaseModel):
    id: str = Field(default_factory=lambda: hashlib.sha256(os.urandom(16)).hexdigest()[:16])
    name: str = Field(max_length=100)
    chain: Literal["input", "forward", "output"] = "input"
    action: Literal["accept", "deny", "reject"] = "deny"
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: str = Field(default="any", max_length=43)
    dst_address: str = Field(default="any", max_length=43)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class RuleCreate(BaseModel):
    name: str = Field(max_length=100)
    chain: Literal["input", "forward", "output"] = "input"
    action: Literal["accept", "deny", "reject"] = "deny"
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: str = Field(default="any", max_length=43)
    dst_address: str = Field(default="any", max_length=43)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)
    chain: Optional[Literal["input", "forward", "output"]] = None
    action: Optional[Literal["accept", "deny", "reject"]] = None
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: Optional[str] = Field(default=None, max_length=43)
    dst_address: Optional[str] = Field(default=None, max_length=43)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = None
    enabled: Optional[bool] = None

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class ChainConfig(BaseModel):
    policy: Literal["accept", "drop"] = "drop"
    priority: int = 0


class ChainUpdate(BaseModel):
    policy: Optional[Literal["accept", "drop"]] = None
    priority: Optional[int] = None


class CompileRequest(BaseModel):
    filter_name: str = Field(default="fastfirewall", max_length=64)


class CompileResult(BaseModel):
    filter_name: str
    output: list[str]
    rule_count: int


# ── nftables script helpers ────────────────────────────────────────────────────

def _addr_family(addr: str) -> str:
    """Return 'ip' for IPv4 addresses/CIDRs, 'ip6' for IPv6."""
    try:
        return "ip" if ipaddress.ip_network(addr, strict=False).version == 4 else "ip6"
    except ValueError:
        return "ip"


def _resolve_port_value(value: int | str, rule_name: str, logger: Any) -> list[int] | None:
    """Return resolved port list, or None if an unresolvable macro should cause the rule to be skipped."""
    if isinstance(value, int):
        return [value]
    ports = macro_registry.resolve_ports(value)
    if not ports and is_macro(value):
        logger.warning(
            "Skipping rule %r: macro %r resolved to no ports (plugin not loaded?)",
            rule_name, value,
        )
        return None
    return ports or []


def _port_set(ports: list[int]) -> str:
    if len(ports) == 1:
        return str(ports[0])
    return "{ " + ", ".join(str(p) for p in sorted(ports)) + " }"


def _rule_to_nft_expr(rule: FirewallRule, logger: Any) -> str | None:
    """Convert a FirewallRule to an nft match-action expression, or None to skip the rule."""
    parts: list[str] = []
    if rule.src_address and rule.src_address != "any":
        fam = _addr_family(rule.src_address)
        parts.append(f"{fam} saddr {rule.src_address}")
    if rule.dst_address and rule.dst_address != "any":
        fam = _addr_family(rule.dst_address)
        parts.append(f"{fam} daddr {rule.dst_address}")
    proto = rule.protocol
    if proto and proto != "any":
        if proto in ("tcp", "udp"):
            if rule.src_port is not None:
                ports = _resolve_port_value(rule.src_port, rule.name, logger)
                if ports is None:
                    return None
                parts.append(f"{proto} sport {_port_set(ports)}")
            if rule.dst_port is not None:
                ports = _resolve_port_value(rule.dst_port, rule.name, logger)
                if ports is None:
                    return None
                parts.append(f"{proto} dport {_port_set(ports)}")
        elif proto in ("icmp", "icmpv6", "esp", "ah"):
            nft_name = "ipv6-icmp" if proto == "icmpv6" else proto
            parts.append(f"meta l4proto {nft_name}")
    if rule.action == "accept":
        parts.append("accept")
    elif rule.action == "reject":
        parts.append("reject")
    else:
        parts.append("drop")
    return " ".join(parts)


def _compile_to_script(
    rules: list[FirewallRule],
    filter_name: str,
    chains: dict[str, ChainConfig],
    logger: Any,
) -> str:
    """Generate a complete nftables script from enabled rules and chain configs."""
    lines = [
        "# FastFirewall managed ruleset — do not edit manually",
        f"add table inet {filter_name}",
        f"flush table inet {filter_name}",
    ]
    for chain_name, cfg in chains.items():
        lines.append(
            f"add chain inet {filter_name} {chain_name} "
            f"{{ type filter hook {chain_name} priority {cfg.priority}; policy {cfg.policy}; }}"
        )
    # stateful tracking — inject on drop-policy input/forward chains before user rules
    for chain_name in ("input", "forward"):
        if chain_name in chains and chains[chain_name].policy == "drop":
            lines.append(f"add rule inet {filter_name} {chain_name} ct state established,related accept")
    seen_exprs: set[str] = set()
    for rule in sorted(rules, key=lambda r: r.priority):
        if rule.chain not in chains:
            logger.warning("Skipping rule %r: chain %r not defined", rule.name, rule.chain)
            continue
        expr = _rule_to_nft_expr(rule, logger)
        if expr is None:
            continue
        dedup_key = f"{rule.chain}:{expr}"
        if dedup_key in seen_exprs:
            logger.warning("Skipping duplicate rule %r: identical nft expression already emitted", rule.name)
            continue
        seen_exprs.add(dedup_key)
        label = json.dumps(rule.comment or rule.name)
        lines.append(f"add rule inet {filter_name} {rule.chain} {expr} comment {label}")
    return "\n".join(lines)


def _rule_hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


_DEFAULT_CHAINS: dict[str, dict] = {
    "input":   {"policy": "drop",   "priority": 0},
    "forward": {"policy": "drop",   "priority": 0},
    "output":  {"policy": "accept", "priority": 0},
}

_DEFAULT_RULES: list[RuleCreate] = [
    RuleCreate(
        name="allow-ssh",
        chain="input",
        action="accept",
        protocol="tcp",
        dst_port=22,
        comment="Allow SSH from any source",
        priority=10,
    ),
    RuleCreate(
        name="allow-fastfirewall-api",
        chain="input",
        action="accept",
        protocol="tcp",
        dst_port=8000,
        comment="Allow FastFirewall API from any source",
        priority=11,
    ),
]


# ── plugin class ───────────────────────────────────────────────────────────────

class FirewallPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.FIREWALL]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "firewall_state.json", self.logger,
            mutation_model="deferred",
        )
        self._default_filter = self.config.get("default_filter_name", "fastfirewall")
        self._nft_wrapper = self.config.get("nft_wrapper") or str(self.plugin_dir / "nft_cmd")
        self._rules: dict[str, FirewallRule] = {}
        self._chains: dict[str, ChainConfig] = {
            name: ChainConfig(**cfg) for name, cfg in _DEFAULT_CHAINS.items()
        }
        if not self.config.get("ignore_state_on_boot", False):
            self._load_state()
            self._apply_state()
        self.logger.info("Loaded %d rules from %r", len(self._rules), self._state_file.path)
        self._register_routes()

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("Shut down — state saved")

    # ── persistence ────────────────────────────────────────────────────

    def _desired_snapshot(self) -> dict:
        return {
            "rules": [r.model_dump() for r in self._rules.values()],
            "chains": {name: cfg.model_dump() for name, cfg in self._chains.items()},
        }

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _load_state(self) -> None:
        fresh_install = not self._state_file.path.exists()
        default: dict = {"rules": [], "chains": _DEFAULT_CHAINS}
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
        if fresh_install:
            for rule_create in _DEFAULT_RULES:
                rule_data = rule_create.model_dump()
                rule_id = _rule_hash(rule_data)
                if rule_id not in self._rules:
                    self._rules[rule_id] = FirewallRule(id=rule_id, **rule_data)
            self._save_state()
            self.logger.info("Fresh install — seeded %d default rules", len(_DEFAULT_RULES))

    def _apply_state(self) -> None:
        enabled = [r for r in self._rules.values() if r.enabled]
        if not enabled:
            return
        try:
            script = _compile_to_script(enabled, self._default_filter, self._chains, self.logger)
            self._apply_nft_script(script)
            self._state_file.commit()
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
        add("/rules",                self._list_rules,    methods=["GET"],    summary="List firewall rules")
        add("/rules",                self._create_rule,   methods=["POST"],   summary="Create a firewall rule", status_code=201)
        add("/rules/{rule_id}",      self._get_rule,      methods=["GET"],    summary="Get a firewall rule")
        add("/rules/{rule_id}",      self._update_rule,   methods=["PUT"],    summary="Update a firewall rule")
        add("/rules/{rule_id}",      self._delete_rule,   methods=["DELETE"], summary="Delete a firewall rule")
        add("/chains",               self._list_chains,   methods=["GET"],    summary="List chains and their policies")
        add("/chains/{chain_name}",  self._get_chain,     methods=["GET"],    summary="Get a chain")
        add("/chains/{chain_name}",  self._update_chain,  methods=["PUT"],    summary="Update chain policy or priority")
        add("/table",                self._get_table,     methods=["GET"],    summary="Show current table configuration")
        add("/check",                self._check,         methods=["POST"],   summary="Dry-run validate (no apply)")
        add("/apply",                self._apply,         methods=["POST"],   summary="Compile and apply rules to nftables")
        add("/compile",              self._compile,       methods=["POST"],   summary="Compile rules to nft script (preview only)")
        add("/discard",              self._discard,       methods=["POST"],   summary="Revert pending changes to last applied state")
        add("/status",               self._status,        methods=["GET"],    summary="Plugin status")

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
            source=self.plugin_id,
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
            source=self.plugin_id,
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
            source=self.plugin_id,
            payload={"rule_id": rule_id, "name": deleted.name},
        ))
        return {"deleted": True, "rule_id": rule_id}

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
        script = _compile_to_script(enabled, self._default_filter, self._chains, self.logger)
        success, error = self._validate_nft_script(script)
        return {
            "success": success,
            "rule_count": len(enabled),
            "chain_count": len(self._chains),
            "output": error if not success else "",
        }

    def _apply(self) -> dict:
        enabled = [r for r in self._rules.values() if r.enabled]
        script = _compile_to_script(enabled, self._default_filter, self._chains, self.logger)
        output_path = self._compiled_output_path
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as fh:
            fh.write(script)
        try:
            self._apply_nft_script(script)
        except RuntimeError:
            self.logger.error("Failed to apply compiled firewall rules", exc_info=True)
            raise HTTPException(500, "Failed to apply firewall rules; check server logs")
        self._state_file.commit()
        bus.emit(Event(
            name="firewall.applied",
            source=self.plugin_id,
            payload={"rule_count": len(enabled), "success": True},
        ))
        return {
            "success": True,
            "rule_count": len(enabled),
            "chain_count": len(self._chains),
            "pending_changes": self._state_file.pending_changes,
        }

    def _compile(self, body: CompileRequest) -> CompileResult:
        enabled = [r for r in self._rules.values() if r.enabled]
        script = _compile_to_script(enabled, body.filter_name, self._chains, self.logger)
        bus.emit(Event(
            name="firewall.compiled",
            source=self.plugin_id,
            payload={"rule_count": len(enabled)},
        ))
        return CompileResult(
            filter_name=body.filter_name,
            output=script.splitlines(),
            rule_count=len(enabled),
        )

    def _discard(self) -> dict:
        snapshot = self._state_file.current_snapshot
        if snapshot is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        try:
            self._rules = {r["id"]: FirewallRule(**r) for r in snapshot.get("rules", [])}
            self._chains = {name: ChainConfig(**cfg) for name, cfg in snapshot.get("chains", _DEFAULT_CHAINS).items()}
        except Exception as exc:
            self.logger.error("Failed to restore from snapshot", exc_info=True)
            raise HTTPException(500, "Failed to restore from snapshot; check server logs") from exc
        self._save_state()
        return {"discarded": True, "rule_count": len(self._rules)}

    def _status(self) -> dict:
        total = len(self._rules)
        enabled = sum(1 for r in self._rules.values() if r.enabled)
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "rules": {"total": total, "enabled": enabled, "disabled": total - enabled},
            "state_file": self._state_file.path,
            "default_filter": self._default_filter,
            "pending_changes": self._state_file.pending_changes,
            "macros": macro_registry.namespaces,
            "compiled_output": self._compiled_output_path,
        }

    # ── event handlers ─────────────────────────────────────────────────

    @on("firewall.compile")
    def on_compile_event(self, event: Event) -> None:
        filter_name = event.payload.get("filter_name", self._default_filter)
        enabled = [r for r in self._rules.values() if r.enabled]
        script = _compile_to_script(enabled, filter_name, self._chains, self.logger)
        self.logger.info("Compiled %d rules for filter %r", len(enabled), filter_name)
        self.logger.debug("Script:\n%s", script)
