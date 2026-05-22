"""
Firewall Plugin
───────────────
Manages firewall rules as a persistent JSON store and compiles them to
platform-specific ACL configs via aerleon.  Routes mount at /v1/firewall/.

Events emitted:
  firewall.rule.added    – payload: {rule_id, name}
  firewall.rule.updated  – payload: {rule_id, changes}
  firewall.rule.deleted  – payload: {rule_id, name}
  firewall.compiled      – payload: {platform, rule_count}
  firewall.applied       – payload: {platform, rule_count, success}

Events consumed:
  firewall.compile       – payload: {platform?, filter_name?}
    Triggers an out-of-band compile and prints a preview to stdout.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from typing import Any, Literal, Optional, Union

import yaml
from fastapi import HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, Service, on
from plugin_system.core.events import Event, bus
from plugin_system.core.macros import is_macro, macro_registry, validate_macro_syntax


# ── aerleon constants ──────────────────────────────────────────────────────────

SUPPORTED_PLATFORMS = [
    "cisco",
    "juniper",
    "paloalto",
    "arista",
    "nftables",
    "nsxv",
    "srx",
    "gce",
]


# ── Pydantic models ────────────────────────────────────────────────────────────

def _validate_port_field(v: object) -> object:
    if isinstance(v, str):
        validate_macro_syntax(v)
    return v


class FirewallRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(max_length=100)
    action: Literal["accept", "deny"] = "deny"
    protocol: Optional[Literal["tcp", "udp", "icmp", "esp", "ah", "any"]] = None
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
    action: Literal["accept", "deny"] = "deny"
    protocol: Optional[Literal["tcp", "udp", "icmp", "esp", "ah", "any"]] = None
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
    action: Optional[Literal["accept", "deny"]] = None
    protocol: Optional[Literal["tcp", "udp", "icmp", "esp", "ah", "any"]] = None
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


class CompileRequest(BaseModel):
    platform: str = Field(default="nftables", max_length=32)
    filter_name: str = Field(default="fastfirewall", max_length=64)


class CompileResult(BaseModel):
    platform: str
    filter_name: str
    output: str
    rule_count: int


# ── aerleon adapter helpers ────────────────────────────────────────────────────

def _net_name(address: str) -> str:
    if address == "any":
        return "ANY_IPv4"
    return "NET_" + address.replace(".", "_").replace("/", "_").replace(":", "_")


def _port_token(port: int) -> str:
    return str(port)


def _build_networks(rules: list[FirewallRule]) -> dict[str, Any]:
    nets: dict[str, Any] = {
        "ANY_IPv4": {"values": [{"address": "0.0.0.0/0", "comment": "IPv4 wildcard"}]}
    }
    for rule in rules:
        for addr in (rule.src_address, rule.dst_address):
            if addr and addr != "any":
                name = _net_name(addr)
                if name not in nets:
                    nets[name] = {"values": [{"address": addr}]}
    return {"networks": nets}


def _build_policy(
    rules: list[FirewallRule],
    filter_name: str,
    platform: str,
    logger: Any,
) -> dict[str, Any]:
    terms = []
    for rule in sorted(rules, key=lambda r: r.priority):
        if not rule.enabled:
            continue
        slug = rule.name.lower().replace(" ", "-")
        term: dict[str, Any] = {"name": slug, "action": rule.action}
        if rule.comment:
            term["comment"] = rule.comment
        if rule.protocol and rule.protocol != "any":
            term["protocol"] = [rule.protocol]
        if rule.src_address and rule.src_address != "any":
            term["source-address"] = [_net_name(rule.src_address)]
        if rule.dst_address and rule.dst_address != "any":
            term["destination-address"] = [_net_name(rule.dst_address)]
        if rule.src_port is not None:
            ports = macro_registry.resolve_ports(rule.src_port)
            if not ports and is_macro(rule.src_port):
                logger.warning(
                    "Skipping rule %r: macro %r resolved to no ports (plugin not loaded?)",
                    rule.name, rule.src_port,
                )
                continue
            if ports:
                term["source-port"] = [_port_token(p) for p in ports]
        if rule.dst_port is not None:
            ports = macro_registry.resolve_ports(rule.dst_port)
            if not ports and is_macro(rule.dst_port):
                logger.warning(
                    "Skipping rule %r: macro %r resolved to no ports (plugin not loaded?)",
                    rule.name, rule.dst_port,
                )
                continue
            if ports:
                term["destination-port"] = [_port_token(p) for p in ports]
        terms.append(term)
    # Implicit deny ensures no traffic slips through by default.
    terms.append({"name": "default-deny", "action": "deny", "comment": "Implicit deny all"})
    _TARGET_OPTIONS: dict[str, str] = {
        "nftables": "inet input 0",
    }
    target_opts = _TARGET_OPTIONS.get(platform, "extended")
    return {
        "filters": [{
            "header": {
                "targets": {platform: target_opts},
                "comment": f"FastFirewall managed policy: {filter_name}",
            },
            "terms": terms,
        }]
    }


def _compile_rules(
    rules: list[FirewallRule],
    filter_name: str,
    platform: str,
    logger: Any,
    debug_dir: str | None = None,
) -> str:
    """
    Invoke the aerleon CLI to produce platform-specific ACL output.
    Falls back to the raw policy YAML if aerleon is not installed or fails.
    """
    networks_data = _build_networks(rules)
    policy_data = _build_policy(rules, filter_name, platform, logger)

    with tempfile.TemporaryDirectory() as tmp:
        nets_path = os.path.join(tmp, "networks.yaml")
        policy_path = os.path.join(tmp, "policy.yaml")
        output_dir = os.path.join(tmp, "output")
        os.makedirs(output_dir)

        with open(nets_path, "w") as fh:
            yaml.dump(networks_data, fh, default_flow_style=False, sort_keys=False)
        with open(policy_path, "w") as fh:
            yaml.dump(policy_data, fh, default_flow_style=False, sort_keys=False)

        try:
            result = subprocess.run(
                [
                    "uv",
                    "run",
                    "aclgen",
                    "--policy_file", policy_path,
                    "--base_directory", tmp,
                    "--definitions_directory", tmp,
                    "--output_directory", output_dir,
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return (
                    f"# aerleon exited {result.returncode}\n"
                    f"# stderr: {result.stderr.strip()}\n\n"
                    f"# Policy YAML (fallback):\n"
                    + yaml.dump(policy_data, default_flow_style=False, sort_keys=False)
                )
            outputs: list[str] = []
            for fname in sorted(os.listdir(output_dir)):
                with open(os.path.join(output_dir, fname)) as fh:
                    outputs.append(f"# --- {fname} ---\n{fh.read()}")
            if debug_dir is not None:
                os.makedirs(debug_dir, exist_ok=True)
                shutil.copy2(nets_path, os.path.join(debug_dir, "networks.yaml"))
                shutil.copy2(policy_path, os.path.join(debug_dir, "policy.yaml"))
                logger.debug("aerleon policy inputs written to %s", debug_dir)
            return "\n".join(outputs) if outputs else "# (no output files generated)"

        except FileNotFoundError:
            return (
                "# aerleon CLI not found — returning policy YAML\n\n"
                + yaml.dump(policy_data, default_flow_style=False, sort_keys=False)
            )
        except subprocess.TimeoutExpired:
            return "# aerleon compile timed out after 30 s"


def _rule_hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


_DEFAULT_RULES: list[dict] = [
    {
        "name": "allow-ssh",
        "action": "accept",
        "protocol": "tcp",
        "src_address": "any",
        "dst_address": "any",
        "src_port": None,
        "dst_port": 22,
        "comment": "Allow SSH from any source",
        "priority": 10,
        "enabled": True,
    },
    {
        "name": "allow-fastfirewall-api",
        "action": "accept",
        "protocol": "tcp",
        "src_address": "any",
        "dst_address": "any",
        "src_port": None,
        "dst_port": 8000,
        "comment": "Allow FastFirewall API from any source",
        "priority": 11,
        "enabled": True,
    },
]


# ── plugin class ───────────────────────────────────────────────────────────────

class FirewallPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.FIREWALL]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "rules_file", "firewall_rules.json", self.logger,
            mutation_model="deferred",
        )
        self._default_platform = self.config.get("default_platform", "nftables")
        self._default_filter = self.config.get("default_filter_name", "fastfirewall")
        self._debug = bool(self.config.get("debug", False))
        self._rules: dict[str, FirewallRule] = {}
        if not self.config.get("ignore_state_on_boot", False):
            self._load_rules()
            self._apply_state()
        self.logger.info("Loaded %d rules from %r", len(self._rules), self._state_file.path)
        self._register_routes()

    def teardown(self) -> None:
        self._save_rules()
        self.logger.info("Shut down — rules saved")

    # ── persistence ────────────────────────────────────────────────────

    def _load_rules(self) -> None:
        fresh_install = not self._state_file.path.exists()
        raw = self._state_file.load_desired(default=[])
        try:
            self._rules = {r["id"]: FirewallRule(**r) for r in raw}
        except Exception:
            self.logger.error("Failed to parse rules from %r, starting empty", self._state_file.path, exc_info=True)
            self._rules = {}
        if fresh_install:
            for rule_data in _DEFAULT_RULES:
                rule_id = _rule_hash(rule_data)
                if rule_id not in self._rules:
                    self._rules[rule_id] = FirewallRule(id=rule_id, **rule_data)
            self._save_rules()
            self.logger.info("Fresh install — seeded %d default rules", len(_DEFAULT_RULES))

    def _save_rules(self) -> None:
        self._state_file.save_desired([r.model_dump() for r in self._rules.values()])

    def _apply_state(self) -> None:
        enabled = [r for r in self._rules.values() if r.enabled]
        if not enabled:
            return
        try:
            output = _compile_rules(enabled, self._default_filter, self._default_platform, self.logger, self._debug_dir)
            if output.startswith("#"):
                self.logger.warning("Skipping boot-time rule apply — aerleon did not produce clean output")
                return
            self._execute_compiled_rules(output, self._compiled_output_path)
            self._state_file.commit()
            self.logger.info("Re-applied %d rules to %s on boot", len(enabled), self._default_platform)
        except Exception as exc:
            self.logger.warning("Could not re-apply rules on boot: %s", exc)

    def _execute_compiled_rules(self, output: str, output_path: str) -> None:
        if self._default_platform != "nftables":
            raise RuntimeError(
                f"Auto-apply unsupported for platform {self._default_platform!r}; apply manually"
            )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as fh:
            fh.write(output)
        result = subprocess.run(
            ["sudo", "nft", "-f", output_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nft failed: {result.stderr.strip()}")

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        add("/rules",           self._list_rules,     methods=["GET"],    summary="List firewall rules")
        add("/rules",           self._create_rule,    methods=["POST"],   summary="Create a firewall rule",  status_code=201)
        add("/rules/{rule_id}", self._get_rule,       methods=["GET"],    summary="Get a firewall rule")
        add("/rules/{rule_id}", self._update_rule,    methods=["PUT"],    summary="Update a firewall rule")
        add("/rules/{rule_id}", self._delete_rule,    methods=["DELETE"], summary="Delete a firewall rule")
        add("/check",           self._check,          methods=["POST"],   summary="Dry-run compile (no apply)")
        add("/apply",           self._apply,          methods=["POST"],   summary="Compile and apply rules to nftables")
        add("/compile",         self._compile,        methods=["POST"],   summary="Compile rules with aerleon (preview only)")
        add("/policy",          self._get_policy,      methods=["GET"],   summary="Show raw aerleon policy")
        add("/platforms",       self._list_platforms, methods=["GET"],    summary="List supported platforms")
        add("/status",          self._status,         methods=["GET"],    summary="Plugin status")

    # ── rule CRUD ──────────────────────────────────────────────────────

    def _list_rules(self, enabled_only: bool = False) -> dict:
        rules = sorted(self._rules.values(), key=lambda r: r.priority)
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return {"rules": [r.model_dump() for r in rules], "count": len(rules)}

    def _create_rule(self, body: RuleCreate) -> dict:
        rule_id = _rule_hash(body.model_dump())
        if rule_id in self._rules:
            raise HTTPException(409, f"An identical rule already exists (id={rule_id!r})")
        rule = FirewallRule(id=rule_id, **body.model_dump())
        self._rules[rule.id] = rule
        self._save_rules()
        bus.emit(Event(
            name="firewall.rule.added",
            source=self.plugin_id,
            payload={"rule_id": rule.id, "name": rule.name},
        ))
        return rule.model_dump()

    def _get_rule(self, rule_id: str) -> dict:
        rule = self._rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {rule_id!r} not found")
        return rule.model_dump()

    def _update_rule(self, rule_id: str, body: RuleUpdate) -> dict:
        rule = self._rules.get(rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {rule_id!r} not found")
        updates = body.model_dump(exclude_unset=True)
        updated = rule.model_copy(update=updates)
        self._rules[rule_id] = updated
        self._save_rules()
        bus.emit(Event(
            name="firewall.rule.updated",
            source=self.plugin_id,
            payload={"rule_id": rule_id, "changes": list(updates.keys())},
        ))
        return updated.model_dump()

    def _delete_rule(self, rule_id: str) -> dict:
        if rule_id not in self._rules:
            raise HTTPException(404, f"Rule {rule_id!r} not found")
        deleted = self._rules.pop(rule_id)
        self._save_rules()
        bus.emit(Event(
            name="firewall.rule.deleted",
            source=self.plugin_id,
            payload={"rule_id": rule_id, "name": deleted.name},
        ))
        return {"deleted": True, "rule_id": rule_id}

    # ── apply / aerleon endpoints ──────────────────────────────────────

    @property
    def _debug_dir(self) -> str | None:
        return os.path.join(str(self.plugin_dir), "data", "aerleon_debug") if self._debug else None

    @property
    def _compiled_output_path(self) -> str:
        return os.path.join(str(self.plugin_dir), "data", f"{self._default_filter}.nft")

    def _check(self) -> dict:
        enabled = [r for r in self._rules.values() if r.enabled]
        output = _compile_rules(enabled, self._default_filter, self._default_platform, self.logger)
        success = not output.startswith("#")
        return {
            "success": success,
            "platform": self._default_platform,
            "rule_count": len(enabled),
            "output": output if not success else "",
        }

    def _apply(self) -> dict:
        enabled = [r for r in self._rules.values() if r.enabled]
        output = _compile_rules(enabled, self._default_filter, self._default_platform, self.logger, self._debug_dir)
        if output.startswith("#"):
            self.logger.error("aerleon compile failed:\n%s", output)
            raise HTTPException(503, "Compile failed — aerleon did not produce valid output; check server logs")
        try:
            self._execute_compiled_rules(output, self._compiled_output_path)
        except RuntimeError as exc:
            self.logger.error("Failed to apply compiled firewall rules", exc_info=True)
            raise HTTPException(500, "Failed to apply firewall rules; check server logs") from exc
        self._state_file.commit()
        bus.emit(Event(
            name="firewall.applied",
            source=self.plugin_id,
            payload={"platform": self._default_platform, "rule_count": len(enabled), "success": True},
        ))
        return {
            "success": True,
            "platform": self._default_platform,
            "rule_count": len(enabled),
            "pending_changes": self._state_file.pending_changes,
        }

    def _compile(self, body: CompileRequest) -> CompileResult:
        enabled = [r for r in self._rules.values() if r.enabled]
        output = _compile_rules(enabled, body.filter_name, body.platform, self.logger, self._debug_dir)
        bus.emit(Event(
            name="firewall.compiled",
            source=self.plugin_id,
            payload={"platform": body.platform, "rule_count": len(enabled)},
        ))
        return CompileResult(
            platform=body.platform,
            filter_name=body.filter_name,
            output=output,
            rule_count=len(enabled),
        )

    def _get_policy(self, platform: str = "nftables", filter_name: str = "fastfirewall", format: str = "json"):
        enabled = [r for r in self._rules.values() if r.enabled]
        policy = _build_policy(enabled, filter_name, platform, self.logger)
        if format == "yaml":
            return Response(
                content=yaml.dump(policy, default_flow_style=False, sort_keys=False),
                media_type="text/yaml",
            )
        return policy

    def _list_platforms(self) -> dict:
        return {"platforms": SUPPORTED_PLATFORMS}

    def _status(self) -> dict:
        total = len(self._rules)
        enabled = sum(1 for r in self._rules.values() if r.enabled)
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "rules": {"total": total, "enabled": enabled, "disabled": total - enabled},
            "rules_file": self._state_file.path,
            "default_platform": self._default_platform,
            "default_filter": self._default_filter,
            "pending_changes": self._state_file.pending_changes,
            "macros": macro_registry.namespaces,
            "compiled_output": self._compiled_output_path,
            **({"debug_dir": self._debug_dir} if self._debug else {}),
        }

    # ── event handlers ─────────────────────────────────────────────────

    @on("firewall.compile")
    def on_compile_event(self, event: Event) -> None:
        platform = event.payload.get("platform", self._default_platform)
        filter_name = event.payload.get("filter_name", self._default_filter)
        enabled = [r for r in self._rules.values() if r.enabled]
        output = _compile_rules(enabled, filter_name, platform, self.logger, self._debug_dir)
        if output.startswith("#"):
            self.logger.warning("Compile for %r produced no clean output: %s", platform, output.splitlines()[0])
        else:
            self.logger.info("Compiled %d rules for %r", len(enabled), platform)
