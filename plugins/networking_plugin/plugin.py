"""
Networking Plugin
─────────────────
Manages network interfaces, routes, and sysctl settings declaratively via
ifstate (ifstatecli).  Desired state is stored in a JSON file; call
POST /apply to push it to the running kernel.

Routes mount at /v1/networking/.

Events emitted:
  networking.interface.configured – payload: {name, addresses?, link?}
  networking.interface.removed    – payload: {name}
  networking.route.added          – payload: {route_id, to}
  networking.route.removed        – payload: {route_id, to}
  networking.sysctl.changed       – payload: {key, value}
  networking.sysctl.removed       – payload: {key}
  networking.applied              – payload: {success, returncode}
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import subprocess
import tempfile
from typing import Any, Literal, Optional

import yaml
from fastapi import HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from plugin_system.core import PluginBase, RoutedPlugin, Service
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
    kind: Optional[str] = None  # vlan, bridge, bond, dummy, …


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
    metric: Optional[int] = None
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


class SysctlValue(BaseModel):
    value: str


class ActionResult(BaseModel):
    success: bool
    output: str
    returncode: int


# ── plugin class ───────────────────────────────────────────────────────────────

class NetworkingPlugin(PluginBase, RoutedPlugin):
    service_name = Service.NETWORKING
    services = [Service.NETWORKING]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        data_dir = self.plugin_dir / "data"
        data_dir.mkdir(exist_ok=True)
        self._state_file = data_dir / self.config.get("state_file", "networking_state.json")
        self._interfaces: dict[str, dict[str, Any]] = {}
        self._routes: dict[str, dict[str, Any]] = {}   # {uuid: route_dict}
        self._sysctl: dict[str, str] = {}
        self._load_state()
        self.logger.info(
            "Networking plugin loaded: %d interface(s), %d route(s), %d sysctl(s)",
            len(self._interfaces), len(self._routes), len(self._sysctl),
        )
        self._register_routes()

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("Networking plugin shut down — state saved")

    # ── state persistence ──────────────────────────────────────────────

    def _load_state(self) -> None:
        try:
            with open(self._state_file) as fh:
                data = json.load(fh)
            self._interfaces = data.get("interfaces", {})
            self._routes = data.get("routes", {})
            self._sysctl = data.get("sysctl", {})
        except FileNotFoundError:
            pass
        except Exception:
            self.logger.error("Failed to load state from %r", self._state_file, exc_info=True)

    def _save_state(self) -> None:
        try:
            with open(self._state_file, "w") as fh:
                json.dump(
                    {"interfaces": self._interfaces, "routes": self._routes, "sysctl": self._sysctl},
                    fh, indent=2,
                )
        except Exception:
            self.logger.error("Failed to save state to %r", self._state_file, exc_info=True)

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
                if link:
                    entry["link"] = link
                config["interfaces"][name] = entry

        if self._routes:
            routes_list = []
            for route in self._routes.values():
                r: dict[str, Any] = {"to": route["to"]}
                for key in ("via", "dev", "metric", "table"):
                    if route.get(key) is not None:
                        r[key] = route[key]
                routes_list.append(r)
            config["routing"] = {"routes": routes_list}

        if self._sysctl:
            config["sysctl"] = dict(self._sysctl)

        return yaml.dump(config, default_flow_style=False, sort_keys=False) if config else "{}\n"

    # ── ifstate CLI wrapper ────────────────────────────────────────────

    def _run_ifstate(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["ifstatecli", *args],
            capture_output=True, text=True, timeout=30,
        )

    def _run_ifstate_with_config(self, action: str) -> dict:
        config_yaml = self._build_ifstate_yaml()
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
                fh.write(config_yaml)
                tmp = fh.name
            result = self._run_ifstate("-c", tmp, action)
            output = (result.stdout + result.stderr).strip()
            return {"success": result.returncode == 0, "output": output, "returncode": result.returncode}
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

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
        add("/config/interfaces/{name}", self._get_config_interface,   methods=["GET"],    summary="Get one interface config")
        add("/config/interfaces/{name}", self._set_interface,          methods=["PUT"],    summary="Configure an interface")
        add("/config/interfaces/{name}", self._delete_interface,       methods=["DELETE"], summary="Remove interface from config")

        # managed desired-state — routes
        add("/config/routes",            self._list_routes,            methods=["GET"],    summary="List configured routes")
        add("/config/routes",            self._add_route,              methods=["POST"],   summary="Add a route", status_code=201)
        add("/config/routes/{route_id}", self._delete_route,           methods=["DELETE"], summary="Remove a route")

        # managed desired-state — sysctl
        add("/config/sysctl",            self._list_sysctl,            methods=["GET"],    summary="List sysctl settings")
        add("/config/sysctl/{key}",      self._set_sysctl,             methods=["PUT"],    summary="Set a sysctl value")
        add("/config/sysctl/{key}",      self._delete_sysctl,          methods=["DELETE"], summary="Remove a sysctl setting")

        # full config + apply / check
        add("/config",                   self._get_config,             methods=["GET"],    summary="Full ifstate config (YAML or JSON)")
        add("/apply",                    self._apply,                  methods=["POST"],   summary="Apply config via ifstatecli apply")
        add("/check",                    self._check,                  methods=["POST"],   summary="Dry-run via ifstatecli check")

    # ── status ─────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "managed": {
                "interfaces": len(self._interfaces),
                "routes": len(self._routes),
                "sysctl": len(self._sysctl),
            },
            "state_file": str(self._state_file),
        }

    # ── live state ─────────────────────────────────────────────────────

    def _show_interfaces(self) -> dict:
        result = self._run_ifstate("show")
        if result.returncode != 0:
            raise HTTPException(500, f"ifstatecli show failed: {result.stderr.strip()}")
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception:
            raise HTTPException(500, "Failed to parse ifstatecli show output")
        return {"interfaces": data.get("interfaces", {}), "source": "running"}

    def _show_interface(self, name: str) -> dict:
        result = self._run_ifstate("show")
        if result.returncode != 0:
            raise HTTPException(500, f"ifstatecli show failed: {result.stderr.strip()}")
        try:
            data = yaml.safe_load(result.stdout) or {}
        except Exception:
            raise HTTPException(500, "Failed to parse ifstatecli show output")
        interfaces = data.get("interfaces", {})
        if name not in interfaces:
            raise HTTPException(404, f"Interface {name!r} not found in running state")
        return {"name": name, **interfaces[name]}

    def _identify(self) -> dict:
        result = self._run_ifstate("identify")
        if result.returncode != 0:
            raise HTTPException(500, f"ifstatecli identify failed: {result.stderr.strip()}")
        return {"output": result.stdout}

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
        self._save_state()
        bus.emit(Event(
            name="networking.interface.configured",
            source=self.plugin_id,
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
            source=self.plugin_id,
            payload={"name": name},
        ))
        return {"deleted": name}

    # ── managed config — routes ────────────────────────────────────────

    def _list_routes(self) -> dict:
        routes = [{"id": rid, **r} for rid, r in self._routes.items()]
        return {"routes": routes, "count": len(routes)}

    def _add_route(self, body: RouteCreate) -> dict:
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
            source=self.plugin_id,
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
            source=self.plugin_id,
            payload={"route_id": route_id, "to": route.get("to")},
        ))
        return {"deleted": route_id}

    # ── managed config — sysctl ────────────────────────────────────────

    def _list_sysctl(self) -> dict:
        return {"sysctl": self._sysctl}

    def _set_sysctl(self, key: str, body: SysctlValue) -> dict:
        self._sysctl[key] = body.value
        self._save_state()
        bus.emit(Event(
            name="networking.sysctl.changed",
            source=self.plugin_id,
            payload={"key": key, "value": body.value},
        ))
        return {"key": key, "value": body.value}

    def _delete_sysctl(self, key: str) -> dict:
        if key not in self._sysctl:
            raise HTTPException(404, f"Sysctl key {key!r} not managed")
        del self._sysctl[key]
        self._save_state()
        bus.emit(Event(
            name="networking.sysctl.removed",
            source=self.plugin_id,
            payload={"key": key},
        ))
        return {"deleted": key}

    # ── full config ────────────────────────────────────────────────────

    def _get_config(self, format: str = "yaml") -> Any:
        config_yaml = self._build_ifstate_yaml()
        if format == "json":
            return yaml.safe_load(config_yaml) or {}
        return Response(content=config_yaml, media_type="text/yaml")

    # ── apply / check ──────────────────────────────────────────────────

    def _apply(self) -> ActionResult:
        result = self._run_ifstate_with_config("apply")
        bus.emit(Event(
            name="networking.applied",
            source=self.plugin_id,
            payload={"success": result["success"], "returncode": result["returncode"]},
        ))
        return ActionResult(**result)

    def _check(self) -> ActionResult:
        return ActionResult(**self._run_ifstate_with_config("check"))
