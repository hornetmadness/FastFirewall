"""
Networking Plugin
─────────────────
Manages network interfaces and routes declaratively via ifstate (ifstatecli).
Desired state is stored in a JSON file; call POST /apply to push it to the
running kernel.

Routes mount at /v1/networking/.

Events emitted:
  networking.interface.configured – payload: {name, addresses?, link?}
  networking.interface.removed    – payload: {name}
  networking.route.added          – payload: {route_id, to}
  networking.route.removed        – payload: {route_id, to}
  networking.aliases_updated      – payload: {aliases: {alias: iface, ...}}
  networking.applied              – payload: {success, returncode}

Sysctl management is delegated to the host plugin. To set a sysctl from
this plugin emit host.sysctl.set instead of calling sysctl directly.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import yaml
from fastapi import HTTPException  # TODO: add structured logging throughout this plugin (currently uses self.logger only at boot)
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, MacroProviderPlugin, Service
from plugin_system.core.events import Event, bus


# ── Pydantic models ────────────────────────────────────────────────────────────

def _validate_cidr(value: str) -> str:
    """Accept a host-address-with-prefix like '192.168.1.1/24' or '::1/128'."""
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        raise ValueError(f"{value!r} is not a valid CIDR address (e.g. '192.168.1.1/24')")
    return value


class LinkConfig(BaseModel):
    state: Optional[Literal["up", "down"]] = None
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)
    kind: Optional[str] = Field(default=None, max_length=16)  # vlan, bridge, bond, dummy, …


class InterfaceUpdate(BaseModel):
    addresses: Optional[list[str]] = None  # CIDR notation, e.g. "192.168.1.1/24"
    link: Optional[LinkConfig] = None

    @field_validator("addresses", mode="before")
    @classmethod
    def validate_addresses(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("addresses must be a list")
        return [_validate_cidr(addr) for addr in v]


class RouteCreate(BaseModel):
    to: str                         # destination: "default" or CIDR like "10.0.0.0/8"
    via: Optional[str] = None       # gateway IP
    dev: Optional[str] = None       # outgoing interface name
    preference: Optional[int] = None
    table: Optional[int] = None

    @field_validator("to")
    @classmethod
    def validate_to(cls, v: str) -> str:
        if v == "default":
            return v
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"{v!r} is not 'default' or a valid CIDR network (e.g. '10.0.0.0/8')")
        return v

    @field_validator("via")
    @classmethod
    def validate_via(cls, v: object) -> object:
        if v is None:
            return v
        try:
            ipaddress.ip_address(str(v))
        except ValueError:
            raise ValueError(f"{v!r} is not a valid IP address")
        return v


class ImportInterfacesRequest(BaseModel):
    names: Optional[list[Annotated[str, Field(max_length=15)]]] = None  # None means import all discovered interfaces
    overwrite: bool = False                                              # if True, overwrite already-managed interfaces


class ImportRoutesRequest(BaseModel):
    destinations: Optional[list[Annotated[str, Field(max_length=43)]]] = None  # None means import all discovered routes
    overwrite: bool = False                                                     # if True, overwrite already-managed routes


class AliasCreate(BaseModel):
    interface: str  # OS interface name this alias maps to (e.g. "eth0")

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("interface must not be empty")
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_:.@-]*$', v):
            raise ValueError(f"{v!r} is not a valid interface name")
        return v


_ALIAS_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')

# Loopback addresses are invariant on Linux and never managed via ifstate.
_LO_ADDRESSES = ["127.0.0.1/8", "::1/128"]


def _validate_host(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("host must not be empty")
    # Allow IPs and hostnames; reject obvious shell metacharacters
    if re.search(r"[;&|`$<>()\n\r]", value):
        raise ValueError(f"{value!r} contains invalid characters")
    return value


class PingRequest(BaseModel):
    host: str
    count: int = Field(default=4, ge=1, le=100)
    timeout: int = Field(default=30, ge=1, le=120)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host(v)


class MtrRequest(BaseModel):
    host: str
    count: int = Field(default=10, ge=1, le=100)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host(v)


# ── state diff ─────────────────────────────────────────────────────────────────

def _diff_state(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Return a structured diff between two desired-state dicts."""
    diff: dict[str, Any] = {}
    for section in ("interfaces", "routes"):
        o: dict = old.get(section) or {}
        n: dict = new.get(section) or {}
        added = {k: n[k] for k in n if k not in o}
        removed = {k: o[k] for k in o if k not in n}
        modified = {k: {"from": o[k], "to": n[k]} for k in n if k in o and o[k] != n[k]}
        if added or removed or modified:
            diff[section] = {}
            if added:
                diff[section]["added"] = added
            if removed:
                diff[section]["removed"] = removed
            if modified:
                diff[section]["modified"] = modified
    return diff


# ── plugin class ───────────────────────────────────────────────────────────────

class NetworkingPlugin(PluginBase, ApiRouterPlugin, MacroProviderPlugin):
    services = [Service.NETWORKING]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "networking_state.json", self.logger,
            mutation_model="deferred", data_dir=self.data_dir,
        )
        self._interfaces: dict[str, dict[str, Any]] = {}
        self._routes: dict[str, dict[str, Any]] = {}   # {uuid: route_dict}
        self._aliases: dict[str, str] = {}  # {alias_name: interface_name}
        if not self.config.get("ignore_state_on_boot", False):
            self._load_state()
            if not any([self._interfaces, self._routes]):
                self._import_state_from_system()
            else:
                self._apply_state()
        self.logger.info(
            "Networking plugin loaded: %d interface(s), %d route(s), %d alias(es)",
            len(self._interfaces), len(self._routes), len(self._aliases),
        )
        if self._aliases:
            bus.emit(Event(
                name="networking.aliases_updated",
                payload={"aliases": dict(self._aliases)},
            ))
        self.add_macro_namespace("interface", self._resolve_interface_macro)
        self._register_routes()
        self._sync_os_boot_service()

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("Networking plugin shut down — state saved")

    # ── state persistence ──────────────────────────────────────────────

    def _load_state(self) -> None:
        desired = self._state_file.load_desired(default={})
        self._interfaces = desired.get("interfaces", {})
        self._routes = desired.get("routes", {})
        self._aliases = desired.get("aliases", {})
        self._ensure_default_aliases()

    def _resolve_interface_macro(self, *segments: str) -> Any:
        if len(segments) < 2:
            return None
        alias, field = segments[0], segments[1]
        device = self._aliases.get(alias)
        if device is None:
            return None
        if field == "name":
            return device
        addresses = self._interfaces.get(device, {}).get("addresses") or (
            _LO_ADDRESSES if device == "lo" else []
        )
        if field == "address":
            return [str(ipaddress.ip_interface(a).ip) for a in addresses]
        if field == "net_addr":
            return [str(ipaddress.ip_interface(a).network) for a in addresses]
        return None

    def macro_snapshot(self) -> dict[str, dict[str, Any]]:
        entries: dict[str, Any] = {}
        for alias, device in self._aliases.items():
            entries[f"{alias}.name"] = device
            addresses = self._interfaces.get(device, {}).get("addresses") or (
                _LO_ADDRESSES if device == "lo" else []
            )
            addrs = [str(ipaddress.ip_interface(a).ip) for a in addresses]
            if addrs:
                entries[f"{alias}.address"] = addrs
            nets = [str(ipaddress.ip_interface(a).network) for a in addresses]
            if nets:
                entries[f"{alias}.net_addr"] = nets
        return {"interface": entries}

    def _ensure_default_aliases(self) -> None:
        """Add identity alias (name → name) for every managed interface not yet in _aliases."""
        for name in self._interfaces:
            self._aliases.setdefault(name, name)
        self._aliases.setdefault("lo", "lo")

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps({
            "interfaces": self._interfaces,
            "routes": self._routes,
            "aliases": self._aliases,
        }))

    @property
    def _ifstate_config_path(self) -> Path:
        return self.data_dir / "ifstate.yaml"

    def _apply_state(self) -> None:
        if not any([self._interfaces, self._routes]):
            return
        try:
            self.logger.info("Applying networking config on boot: %d interface(s), %d route(s)",
                             len(self._interfaces), len(self._routes))
            config_path = self._ifstate_config_path
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(self._build_ifstate_yaml())
            result = self._run_ifstate("-c", str(config_path), "apply")
            if result.returncode == 0:
                self.logger.info("Re-applied networking config on boot")
            else:
                self.logger.warning("Boot-time networking apply returned non-zero: %s", result.stderr.strip())
        except Exception as exc:
            self.logger.warning("Could not re-apply networking config on boot: %s", exc)

    def _sync_os_boot_service(self) -> None:
        service_name = "fastfirewall-networking"
        if self.config.get("enable_os_boot", False):
            bus.emit(Event("initsys.service.add", payload={
                "service_name": service_name,
                "command": f"sudo {sys.executable} -m ifstate.ifstate -c {self._ifstate_config_path} apply",
                "working_dir": str(self.plugin_dir.parent.parent),
                "description": "FastFirewall networking config",
                "service_type": "oneshot",
            }))
        else:
            bus.emit(Event("initsys.service.remove", payload={
                "service_name": service_name,
            }))

    def _import_state_from_system(self) -> None:
        """Populate interfaces and routes from the running kernel when state file is empty."""
        result = self._run_ifstate("show")
        if result.returncode != 0:
            self.logger.warning("ifstatecli show failed during boot import: %s", result.stderr.strip())
            return
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception as exc:
            self.logger.warning("Boot-time import: failed to parse ifstatecli show output: %s", exc)
            return

        for name, iface_data in (data.get("interfaces", {}) or {}).items():
            iface_data = iface_data or {}
            entry: dict[str, Any] = {}
            if iface_data.get("addresses"):
                entry["addresses"] = iface_data["addresses"]
            if iface_data.get("link"):
                entry["link"] = iface_data["link"]
            self._interfaces[name] = entry

        for r in (data.get("routing", {}) or {}).get("routes", []) or []:
            route: dict[str, Any] = {"to": r["to"]}
            for key in ("via", "dev", "preference", "table"):
                if r.get(key) is not None:
                    route[key] = r[key]
            route_id = hashlib.sha256(
                json.dumps(route, sort_keys=True).encode()
            ).hexdigest()[:16]
            self._routes[route_id] = route

        if self._interfaces or self._routes:
            self._ensure_default_aliases()
            self._state_file.save_and_commit(self._desired_snapshot())
            self.logger.info(
                "Boot-time import: %d interface(s), %d route(s), %d alias(es)",
                len(self._interfaces), len(self._routes), len(self._aliases),
            )

    # ── ifstate YAML builder ───────────────────────────────────────────

    def _build_ifstate_yaml(self) -> str:
        config: dict[str, Any] = {}

        if self._interfaces:
            config["interfaces"] = {}
            for name, iface in self._interfaces.items():
                entry: dict[str, Any] = {}
                if iface.get("addresses"):
                    entry["addresses"] = iface["addresses"]
                link = {k: v for k, v in (iface.get("link") or {}).items() if v is not None}
                # ifstate requires 'link' on every interface entry and 'kind' within it.
                # Default to "physical" when kind is not explicitly set — this covers
                # standard NICs configured by the bootstrap without a type declaration.
                if "kind" not in link:
                    link["kind"] = "physical"
                entry["link"] = link
                config["interfaces"][name] = entry

        if self._routes:
            routes_list = []
            for route in self._routes.values():
                r: dict[str, Any] = {"to": route["to"]}
                for key in ("via", "dev", "preference", "table"):
                    if route.get(key) is not None:
                        r[key] = route[key]
                routes_list.append(r)
            config["routing"] = {"routes": routes_list}

        # sysctl is NOT passed to ifstate — ifstate's schema only allows structured
        # keys (all/default/mpls/mptcp), not kernel dot-notation paths like
        # net.ipv4.ip_forward.  Sysctl is applied directly via _apply_sysctl().

        return yaml.dump(config, default_flow_style=False, sort_keys=False) if config else "{}\n"

    # ── ifstate CLI wrapper ────────────────────────────────────────────

    def _run_ifstate(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sudo", sys.executable, "-m", "ifstate.ifstate", *args],
            capture_output=True, text=True, timeout=30,
        )

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",                   self._status,                 methods=["GET"],    summary="Plugin status and counts")

        # live state from the running kernel
        add("/interfaces",               self._show_interfaces,        methods=["GET"],    summary="Current interface state (ifstatecli show)")
        add("/interfaces/{name}",        self._show_interface,         methods=["GET"],    summary="Single interface running state")
        add("/identify",                 self._identify,               methods=["GET"],    summary="Identify physical interfaces")

        # managed desired-state — interfaces
        add("/config/interfaces",        self._list_config_interfaces, methods=["GET"],    summary="List configured interfaces")
        add("/config/interfaces/import", self._import_interfaces,      methods=["POST"],   summary="Import existing interfaces from running state")
        add("/config/interfaces/{name}", self._get_config_interface,   methods=["GET"],    summary="Get one interface config")
        add("/config/interfaces/{name}", self._set_interface,          methods=["PUT"],    summary="Configure an interface")
        add("/config/interfaces/{name}", self._delete_interface,       methods=["DELETE"], summary="Remove interface from config")

        # managed desired-state — routes
        add("/config/routes",            self._list_routes,            methods=["GET"],    summary="List configured routes")
        add("/config/routes/import",     self._import_routes,          methods=["POST"],   summary="Import existing routes from running state")
        add("/config/routes",            self._add_route,              methods=["POST"],   summary="Add a route", status_code=201)
        add("/config/routes/{route_id}", self._delete_route,           methods=["DELETE"], summary="Remove a route")

        # full config + apply / check / discard / diff
        add("/config",                   self._get_config,             methods=["GET"],    summary="Full ifstate config (YAML or JSON)")
        add("/config/diff",              self._diff,                   methods=["GET"],    summary="Diff between current (applied) and desired state")
        add("/apply",                    self._apply,                  methods=["POST"],   summary="Apply config via ifstatecli apply")
        add("/check",                    self._check,                  methods=["POST"],   summary="Dry-run via ifstatecli check")
        add("/discard",                  self._discard,                methods=["POST"],   summary="Discard pending changes and restore last applied state")

        # interface aliases ($interface.NAME macros)
        add("/config/aliases",           self._list_aliases,           methods=["GET"],    summary="List interface aliases")
        add("/config/aliases/{name}",    self._set_alias,              methods=["PUT"],    summary="Set an interface alias", status_code=200)
        add("/config/aliases/{name}",    self._delete_alias,           methods=["DELETE"], summary="Delete an interface alias")

        # diagnostics
        add("/ping",                     self._ping,                   methods=["POST"],   summary="Ping a host")
        add("/mtr",                      self._mtr,                    methods=["POST"],   summary="Run mtr traceroute to a host")

    # ── status ─────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "ff_managed": {
                "interfaces": len(self._interfaces),
                "routes": len(self._routes),
                "aliases": len(self._aliases),
            },
            "pending_changes": self._state_file.pending_changes,
            "state_file": str(self._state_file.path),
            "config_file": str(self._ifstate_config_path),
        }

    # ── live state ─────────────────────────────────────────────────────

    def _show_interfaces(self) -> dict:
        result = self._run_ifstate("show")
        if result.returncode != 0:
            self.logger.error("ifstatecli show failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to read interface state; check server logs")
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception:
            raise HTTPException(500, "Failed to parse ifstatecli show output")
        interfaces = {
            name: {**(iface or {}), "ff_managed": name in self._interfaces}
            for name, iface in data.get("interfaces", {}).items()
        }
        return {"interfaces": interfaces, "source": "running"}

    def _show_interface(self, name: str) -> dict:
        result = self._run_ifstate("show")
        if result.returncode != 0:
            self.logger.error("ifstatecli show failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to read interface state; check server logs")
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception:
            raise HTTPException(500, "Failed to parse ifstatecli show output")
        interfaces = data.get("interfaces", {})
        if name not in interfaces:
            raise HTTPException(404, f"Interface {name!r} not found in running state")
        return {"name": name, **(interfaces[name] or {}), "ff_managed": name in self._interfaces}

    def _identify(self) -> dict:
        result = self._run_ifstate("identify")
        if result.returncode != 0:
            self.logger.error("ifstatecli identify failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to identify interfaces; check server logs")
        return yaml.safe_load(result.stdout) or {}

    # ── managed config — interfaces ────────────────────────────────────

    def _list_config_interfaces(self) -> dict:
        return {
            "interfaces": [{"name": n, **cfg} for n, cfg in self._interfaces.items()],
            "count": len(self._interfaces),
        }

    def _get_config_interface(self, name: str) -> dict:
        if name not in self._interfaces:
            raise HTTPException(404, f"Interface {name!r} not in managed config")
        return {"name": name, **self._interfaces[name]}

    def _set_interface(self, name: str, body: InterfaceUpdate) -> dict:
        existing = dict(self._interfaces.get(name, {}))
        updates = body.model_dump(exclude_unset=True)
        if "link" in updates and updates["link"] is not None:
            updates["link"] = {k: v for k, v in updates["link"].items() if v is not None}
        existing.update(updates)
        self._interfaces[name] = existing
        self._aliases.setdefault(name, name)
        self._save_state()
        bus.emit(Event(
            name="networking.interface.configured",
            payload={"name": name, **existing},
        ))
        return {"name": name, **existing}

    def _delete_interface(self, name: str) -> dict:
        if name not in self._interfaces:
            raise HTTPException(404, f"Interface {name!r} not in managed config")
        del self._interfaces[name]
        self._save_state()
        bus.emit(Event(
            name="networking.interface.removed",
            payload={"name": name},
        ))
        return {"deleted": name}

    def _import_interfaces(self, body: ImportInterfacesRequest) -> dict:
        result = self._run_ifstate("show")
        if result.returncode != 0:
            self.logger.error("ifstatecli show failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to read interface state; check server logs")
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception:
            raise HTTPException(500, "Failed to parse ifstatecli show output")

        running: dict[str, Any] = data.get("interfaces", {})
        names_to_import = body.names if body.names is not None else list(running.keys())

        imported: list[str] = []
        skipped: list[str] = []
        not_found: list[str] = []

        for name in names_to_import:
            if name not in running:
                not_found.append(name)
                continue
            if name in self._interfaces and not body.overwrite:
                skipped.append(name)
                continue
            iface_data: dict[str, Any] = running[name] or {}
            entry: dict[str, Any] = {}
            if iface_data.get("addresses"):
                entry["addresses"] = iface_data["addresses"]
            if iface_data.get("link"):
                entry["link"] = iface_data["link"]
            self._interfaces[name] = entry
            self._aliases.setdefault(name, name)
            imported.append(name)
            bus.emit(Event(
                name="networking.interface.configured",
                payload={"name": name, **entry},
            ))

        if imported:
            self._save_state()

        return {"imported": imported, "skipped": skipped, "not_found": not_found}

    # ── managed config — routes ────────────────────────────────────────

    def _list_routes(self) -> dict:
        routes = [{"id": rid, **r} for rid, r in self._routes.items()]
        return {"routes": routes, "count": len(routes)}

    def _add_route(self, body: RouteCreate) -> dict:
        if body.dev is not None and body.dev not in self._interfaces:
            raise HTTPException(422, f"Interface {body.dev!r} is not in managed config")
        route = body.model_dump(exclude_none=True)
        route_id = hashlib.sha256(
            json.dumps(route, sort_keys=True).encode()
        ).hexdigest()[:16]
        if route_id in self._routes:
            raise HTTPException(409, f"Route to {route['to']!r} already exists using id {route_id}")
        self._routes[route_id] = route
        self._save_state()
        bus.emit(Event(
            name="networking.route.added",
            payload={"route_id": route_id, "to": route["to"]},
        ))
        return {"id": route_id, **route}

    def _delete_route(self, route_id: str) -> dict:
        if route_id not in self._routes:
            raise HTTPException(404, f"Route {route_id!r} not found")
        route = self._routes.pop(route_id)
        self._save_state()
        bus.emit(Event(
            name="networking.route.removed",
            payload={"route_id": route_id, "to": route.get("to")},
        ))
        return {"deleted": route_id}

    def _import_routes(self, body: ImportRoutesRequest) -> dict:
        result = self._run_ifstate("show")
        if result.returncode != 0:
            self.logger.error("ifstatecli show failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to read interface state; check server logs")
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception:
            raise HTTPException(500, "Failed to parse ifstatecli show output")

        running_routes: list[dict[str, Any]] = (data.get("routing", {}) or {}).get("routes", []) or []
        if body.destinations is not None:
            running_routes = [r for r in running_routes if r.get("to") in body.destinations]

        not_found: list[str] = []
        if body.destinations is not None:
            found_destinations = {r.get("to") for r in running_routes}
            not_found = [d for d in body.destinations if d not in found_destinations]

        imported: list[str] = []
        skipped: list[str] = []

        for r in running_routes:
            route: dict[str, Any] = {"to": r["to"]}
            for key in ("via", "dev", "preference", "table"):
                if r.get(key) is not None:
                    route[key] = r[key]
            route_id = hashlib.sha256(
                json.dumps(route, sort_keys=True).encode()
            ).hexdigest()[:16]
            if route_id in self._routes and not body.overwrite:
                skipped.append(route_id)
                continue
            self._routes[route_id] = route
            imported.append(route_id)
            bus.emit(Event(
                name="networking.route.added",
                payload={"route_id": route_id, "to": route["to"]},
            ))

        if imported:
            self._save_state()

        return {"imported": imported, "skipped": skipped, "not_found": not_found}

    # ── full config ────────────────────────────────────────────────────

    def _get_config(self, format: str = "yaml") -> Any:
        config_yaml = self._build_ifstate_yaml()
        if format == "json":
            return yaml.safe_load(config_yaml) or {}
        return Response(content=config_yaml, media_type="text/yaml")

    # ── apply / check ──────────────────────────────────────────────────

    def _diff(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot or {}
        desired = self._desired_snapshot()
        changes = _diff_state(current, desired)
        return {
            "pending_changes": self._state_file.pending_changes,
            "diff": changes,
        }

    def _apply(self) -> dict[str, Any]:
        debug: bool = bool(self.config.get("debug", False))
        desired = self._desired_snapshot()
        changes = _diff_state(self._state_file.current_snapshot or {}, desired)
        config_yaml = self._build_ifstate_yaml()
        config_path = self._ifstate_config_path
        output: list[str] = []
        errors: list[str] = []
        success = True
        # Apply interfaces and routes via ifstatecli (only when there is
        # something to apply — an empty YAML would still be a valid no-op,
        # but skipping avoids a needless sudo round-trip).
        if self._interfaces or self._routes:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(config_yaml)
            if debug:
                self.logger.info("[debug] apply config: %s", config_path)
                self.logger.info("[debug] cmd: sudo ifstate_cmd -c %s apply", config_path)
            result = self._run_ifstate("-c", str(config_path), "apply")
            output = (result.stdout + result.stderr).strip().splitlines()
            errors = [ln for ln in output if "fail" in ln.lower() or "error" in ln.lower()]
            if debug:
                self.logger.info("[debug] returncode=%d", result.returncode)
                self.logger.info("[debug] output=%r", output)
            success = result.returncode == 0
        if success:
            self._state_file.commit(desired)
        bus.emit(Event(
            name="networking.applied",
            payload={"success": success, "returncode": 0 if success else 1},
        ))
        resp: dict[str, Any] = {"success": success, "returncode": 0 if success else 1, "changes": changes, "output": output}
        if errors:
            resp["errors"] = errors
        if debug:
            resp["debug"] = {"config_file": str(config_path), "output": output}
        return resp

    def _discard(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot
        if current is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        changes = _diff_state(self._desired_snapshot(), current)
        self._interfaces = dict(current.get("interfaces", {}))
        self._routes = dict(current.get("routes", {}))
        self._aliases = dict(current.get("aliases", {}))
        self._save_state()
        return {"discarded": True, "changes": changes}

    def _check(self) -> dict[str, Any]:
        config_yaml = self._build_ifstate_yaml()
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
                fh.write(config_yaml)
                tmp = fh.name
            result = self._run_ifstate("-c", tmp, "check")
            try:
                changes = yaml.safe_load(result.stdout) or {}
            except Exception:
                raise HTTPException(500, "Failed to parse ifstatecli check output")
            route_diff = _diff_state(self._state_file.current_snapshot or {}, self._desired_snapshot()).get("routes")
            if route_diff:
                changes["routes"] = route_diff
            return {"success": result.returncode == 0, "returncode": result.returncode, "changes": changes}
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # ── interface aliases ──────────────────────────────────────────────────

    def _list_aliases(self) -> dict:
        return {"aliases": dict(self._aliases), "count": len(self._aliases)}

    def _set_alias(self, name: str, body: AliasCreate) -> dict:
        if not _ALIAS_NAME_RE.match(name):
            raise HTTPException(
                422,
                f"Alias name {name!r} must start with a letter and contain only "
                "letters, digits, and underscores",
            )
        self._aliases[name] = body.interface
        self._save_state()
        self._state_file.commit(self._desired_snapshot())
        bus.emit(Event(
            name="networking.aliases_updated",
            payload={"aliases": dict(self._aliases)},
        ))
        return {"name": name, "interface": body.interface}

    def _delete_alias(self, name: str) -> dict:
        if name not in self._aliases:
            raise HTTPException(404, f"Alias {name!r} not found")
        del self._aliases[name]
        self._save_state()
        self._state_file.commit(self._desired_snapshot())
        bus.emit(Event(
            name="networking.aliases_updated",
            payload={"aliases": dict(self._aliases)},
        ))
        return {"deleted": name}

    # ── diagnostics ────────────────────────────────────────────────────────

    def _ping(self, body: PingRequest) -> dict[str, Any]:
        result = subprocess.run(
            ["ping", "-c", str(body.count), body.host],
            capture_output=True, text=True, timeout=body.timeout,
        )
        lines = (result.stdout + result.stderr).strip().splitlines()
        return {"host": body.host, "returncode": result.returncode, "output": lines}

    def _mtr(self, body: MtrRequest) -> dict[str, Any]:
        result = subprocess.run(
            ["mtr", "--report", "--json", "--report-cycles", str(body.count), body.host],
            capture_output=True, text=True, timeout=120,
        )
        try:
            data = json.loads(result.stdout)
            hubs = sorted(data.get("report", {}).get("hubs", []), key=lambda h: h["count"])
            lines = [
                f"{hub['count']:<4} {hub['host']:<40} {'timeout' if hub['host'] == '???' else 'ok':<8}"
                f" {hub['Loss%']:>6}%  {hub['Snt']:>3}  {hub['Last']:>7.2f}"
                f"  {hub['Avg']:>7.2f}  {hub['Best']:>7.2f}  {hub['Wrst']:>7.2f}  {hub['StDev']:>7.2f}"
                for hub in hubs
            ]
            header = f"{'Hop':<4} {'Ip':<45} {'Status':<8} {'Loss%':>7}  {'Snt':>3}  {'Last':>7}  {'Avg':>7}  {'Best':>7}  {'Wrst':>7}  {'StDev':>7}"
            output = [header] + lines
        except (json.JSONDecodeError, KeyError):
            output = (result.stdout + result.stderr).strip().splitlines()
        return {"host": body.host, "returncode": result.returncode, "output": output}
