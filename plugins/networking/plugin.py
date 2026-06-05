"""
Networking Plugin
─────────────────
Manages network interfaces and routes declaratively via systemd-networkd.
Desired state is stored in a JSON file; call POST /apply to push it to the
running kernel via INI-format .network files in /etc/systemd/network/.

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
import io
import ipaddress
import json
import subprocess
from typing import Any

from fastapi import HTTPException

from infra import pyinfra_run_batch
from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, MacroProviderPlugin, Service
from plugin_system.core.events import Event, bus

from .libs.models import (
    _LO_ADDRESSES, _ALIAS_NAME_RE,
    InterfaceUpdate, RouteCreate, ImportInterfacesRequest, ImportRoutesRequest,
    AliasCreate, PingRequest, MtrRequest, _diff_state,
)
from .libs.live import LiveMixin
from .libs.builder import BuilderMixin
from .libs.bonds import BondsMixin
from .libs.bridges import BridgesMixin
from .libs.wireguard import WireguardMixin


class NetworkingPlugin(PluginBase, ApiRouterPlugin, MacroProviderPlugin,
                       LiveMixin, BuilderMixin, BondsMixin, BridgesMixin, WireguardMixin):
    services = [Service.NETWORKING]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "networking_state.json", self.logger,
            mutation_model="deferred", data_dir=self.data_dir,
        )
        self._interfaces: dict[str, dict[str, Any]] = {}
        self._routes: dict[str, dict[str, Any]] = {}
        self._aliases: dict[str, str] = {}
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

    # ── pyinfra wrapper ────────────────────────────────────────────────

    def _pyinfra_run(self, op: Any, **kwargs: Any) -> None:
        norm_kwargs = {
            k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
            for k, v in kwargs.items()
        }
        success, err = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])[0]
        if not success:
            raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")

    # ── boot-time apply / import ───────────────────────────────────────

    def _apply_state(self) -> None:
        if not any([self._interfaces, self._routes]):
            return
        try:
            self.logger.info(
                "Applying networking config on boot: %d interface(s), %d route(s)",
                len(self._interfaces), len(self._routes),
            )
            files = self._build_all_networkd_configs()
            self._write_networkd_files(files)
            subprocess.run(
                ["sudo", "networkctl", "reload"],
                capture_output=True, text=True, timeout=15,
            )
            for name in self._interfaces:
                subprocess.run(
                    ["sudo", "networkctl", "reconfigure", name],
                    capture_output=True, text=True, timeout=10,
                )
            self._save_state()
            self._state_file.commit(self._desired_snapshot())
            self.logger.info("Re-applied networking config on boot via systemd-networkd")
        except Exception as exc:
            self.logger.warning("Could not re-apply networking config on boot: %s", exc)

    def _sync_os_boot_service(self) -> None:
        if self.config.get("use_systemd_networkd", False):
            for mgr in self.config.get("disable_os_managers", []):
                results = bus.emit(Event("initsys.service.disable", payload={"service_name": mgr}))
                if not results or not (results[0] or {}).get("success"):
                    self.logger.warning("Could not disable competing network manager %r", mgr)
            bus.emit(Event(
                "initsys.service.start",
                payload={"service_name": "systemd-networkd.service"},
            ))
        else:
            bus.emit(Event(
                "initsys.service.remove",
                payload={"service_name": "fastfirewall-networking"},
            ))

    def _import_state_from_system(self) -> None:
        try:
            addr_data = self._ip_addr_show()
            route_data = self._ip_route_show()
        except Exception as exc:
            self.logger.warning("Boot-time import failed: %s", exc)
            return

        for entry in addr_data:
            name = entry.get("ifname", "")
            flags = entry.get("flags") or []
            if "LOOPBACK" in flags:
                continue
            addr_info = entry.get("addr_info") or []
            addresses = []
            for ai in addr_info:
                if ai.get("family") in ("inet", "inet6"):
                    local = ai.get("local")
                    prefixlen = ai.get("prefixlen")
                    if local and prefixlen is not None:
                        addresses.append(f"{local}/{prefixlen}")
            iface_entry: dict[str, Any] = {"dhcp4": False, "dhcp6": False}
            if addresses:
                iface_entry["addresses"] = addresses
            link_entry: dict[str, Any] = {"state": "up" if "UP" in flags else "down"}
            if entry.get("mtu") is not None:
                link_entry["mtu"] = entry["mtu"]
            iface_entry["link"] = link_entry
            self._interfaces[name] = iface_entry

        for r in route_data:
            if r.get("protocol") in ("kernel", "redirect"):
                continue
            dst = r.get("dst", "default")
            route: dict[str, Any] = {"to": dst}
            if r.get("gateway") is not None:
                route["via"] = r["gateway"]
            if r.get("dev") is not None:
                route["dev"] = r["dev"]
            if r.get("metric") is not None:
                route["preference"] = r["metric"]
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

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",                   self._status,                 methods=["GET"],    summary="Plugin status and counts")

        add("/interfaces",               self._show_interfaces,        methods=["GET"],    summary="Current interface state (ip -j addr show)")
        add("/interfaces/{name}",        self._show_interface,         methods=["GET"],    summary="Single interface running state")
        add("/identify",                 self._identify,               methods=["GET"],    summary="Identify physical interfaces via sysfs")

        add("/config/interfaces",        self._list_config_interfaces, methods=["GET"],    summary="List configured interfaces")
        add("/config/interfaces/import", self._import_interfaces,      methods=["POST"],   summary="Import existing interfaces from running state")
        add("/config/interfaces/{name}", self._get_config_interface,   methods=["GET"],    summary="Get one interface config")
        add("/config/interfaces/{name}", self._set_interface,          methods=["PUT"],    summary="Configure an interface")
        add("/config/interfaces/{name}", self._delete_interface,       methods=["DELETE"], summary="Remove interface from config")

        add("/config/interfaces/{name}/peers", self._list_wg_peers,    methods=["GET"],    summary="List WireGuard peers")
        add("/config/interfaces/{name}/peers", self._add_wg_peer,      methods=["POST"],   summary="Add WireGuard peer", status_code=201)
        add("/config/interfaces/{name}/peers/{peer_id}", self._get_wg_peer,    methods=["GET"],    summary="Get WireGuard peer")
        add("/config/interfaces/{name}/peers/{peer_id}", self._update_wg_peer, methods=["PUT"],    summary="Update WireGuard peer")
        add("/config/interfaces/{name}/peers/{peer_id}", self._delete_wg_peer, methods=["DELETE"], summary="Delete WireGuard peer")

        add("/config/routes",            self._list_routes,            methods=["GET"],    summary="List configured routes")
        add("/config/routes/import",     self._import_routes,          methods=["POST"],   summary="Import existing routes from running state")
        add("/config/routes",            self._add_route,              methods=["POST"],   summary="Add a route", status_code=201)
        add("/config/routes/{route_id}", self._delete_route,           methods=["DELETE"], summary="Remove a route")

        add("/config/bonds",             self._list_bonds,             methods=["GET"],    summary="List configured bonds")
        add("/config/bonds",             self._create_bond,            methods=["POST"],   summary="Create a bond interface", status_code=201)
        add("/config/bonds/{name}",      self._get_bond,               methods=["GET"],    summary="Get bond config")
        add("/config/bonds/{name}",      self._update_bond,            methods=["PUT"],    summary="Update bond config")
        add("/config/bonds/{name}",      self._delete_bond,            methods=["DELETE"], summary="Delete bond interface")
        add("/bonds/{name}/status",      self._get_bond_status,        methods=["GET"],    summary="Live bond status from /proc")
        add("/config/bonds/{name}/members", self._add_bond_member,     methods=["POST"],   summary="Add bond member", status_code=201)
        add("/config/bonds/{name}/members/{member}", self._delete_bond_member, methods=["DELETE"], summary="Remove bond member")

        add("/config/bridges",           self._list_bridges,           methods=["GET"],    summary="List configured bridges")
        add("/config/bridges",           self._create_bridge,          methods=["POST"],   summary="Create a bridge", status_code=201)
        add("/config/bridges/{name}",    self._get_bridge,             methods=["GET"],    summary="Get bridge config")
        add("/config/bridges/{name}",    self._update_bridge,          methods=["PUT"],    summary="Update bridge config")
        add("/config/bridges/{name}",    self._delete_bridge,          methods=["DELETE"], summary="Delete bridge interface")
        add("/config/bridges/{name}/members", self._add_bridge_member,  methods=["POST"],   summary="Add bridge member", status_code=201)
        add("/config/bridges/{name}/members/{member}", self._delete_bridge_member, methods=["DELETE"], summary="Remove bridge member")

        add("/config",                   self._get_config,             methods=["GET"],    summary="All systemd-networkd file contents")
        add("/config/diff",              self._diff,                   methods=["GET"],    summary="Diff between current (applied) and desired state")
        add("/apply",                    self._apply,                  methods=["POST"],   summary="Apply config via systemd-networkd")
        add("/check",                    self._check,                  methods=["POST"],   summary="Preview networkd files (dry-run)")
        add("/discard",                  self._discard,                methods=["POST"],   summary="Discard pending changes and restore last applied state")

        add("/config/aliases",           self._list_aliases,           methods=["GET"],    summary="List interface aliases")
        add("/config/aliases/{name}",    self._set_alias,              methods=["PUT"],    summary="Set an interface alias")
        add("/config/aliases/{name}",    self._delete_alias,           methods=["DELETE"], summary="Delete an interface alias")

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
            "networkd_dir": "/etc/systemd/network",
            "networkd_prefix": "10-ff-",
            "networkd_staging_dir": str(self._networkd_staging_dir),
        }

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
        if "wifi" in updates and updates["wifi"] is not None:
            updates["wifi"] = {k: v for k, v in updates["wifi"].items() if v is not None}
        if "wireguard" in updates and updates["wireguard"] is not None:
            updates["wireguard"] = {
                k: v for k, v in updates["wireguard"].items() if v is not None
            }
        existing.update(updates)
        existing.setdefault("dhcp4", False)
        existing.setdefault("dhcp6", False)
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
        try:
            addr_data = self._ip_addr_show()
        except RuntimeError:
            self.logger.error("ip addr show failed during import")
            raise HTTPException(500, "Failed to read interface state; check server logs")

        running: dict[str, Any] = {}
        for entry in addr_data:
            iface_name = entry.get("ifname", "")
            flags = entry.get("flags") or []
            addr_info = entry.get("addr_info") or []
            addresses = [
                f"{ai['local']}/{ai['prefixlen']}"
                for ai in addr_info
                if ai.get("family") in ("inet", "inet6")
                and ai.get("local") and ai.get("prefixlen") is not None
            ]
            iface_entry: dict[str, Any] = {}
            if addresses:
                iface_entry["addresses"] = addresses
            iface_entry["link"] = {"state": "up" if "UP" in flags else "down"}
            running[iface_name] = iface_entry

        names_to_import = body.names if body.names is not None else list(running.keys())
        imported: list[str] = []
        skipped: list[str] = []
        not_found: list[str] = []

        for iface_name in names_to_import:
            if iface_name not in running:
                not_found.append(iface_name)
                continue
            if iface_name in self._interfaces and not body.overwrite:
                skipped.append(iface_name)
                continue
            entry = dict(running[iface_name])
            entry.setdefault("dhcp4", False)
            entry.setdefault("dhcp6", False)
            self._interfaces[iface_name] = entry
            self._aliases.setdefault(iface_name, iface_name)
            imported.append(iface_name)
            bus.emit(Event(
                name="networking.interface.configured",
                payload={"name": iface_name, **entry},
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
        try:
            route_data = self._ip_route_show()
        except RuntimeError:
            self.logger.error("ip route show failed during import")
            raise HTTPException(500, "Failed to read route state; check server logs")

        running_routes: list[dict[str, Any]] = []
        for r in route_data:
            if r.get("protocol") in ("kernel", "redirect"):
                continue
            dst = r.get("dst", "default")
            route: dict[str, Any] = {"to": dst}
            if r.get("gateway") is not None:
                route["via"] = r["gateway"]
            if r.get("dev") is not None:
                route["dev"] = r["dev"]
            if r.get("metric") is not None:
                route["preference"] = r["metric"]
            running_routes.append(route)

        if body.destinations is not None:
            running_routes = [r for r in running_routes if r.get("to") in body.destinations]

        not_found: list[str] = []
        if body.destinations is not None:
            found_destinations = {r.get("to") for r in running_routes}
            not_found = [d for d in body.destinations if d not in found_destinations]

        imported: list[str] = []
        skipped: list[str] = []

        for route in running_routes:
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

    # ── full config / apply / check / discard / diff ───────────────────

    def _get_config(self) -> Any:
        try:
            return self._build_all_networkd_configs()
        except ValueError as exc:
            raise HTTPException(422, str(exc))

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
        success = True
        output: list[str] = []
        errors: list[str] = []
        files: dict[str, str] = {}

        if self._interfaces or self._routes:
            try:
                files = self._build_all_networkd_configs()
                self._prune_networkd_files(set(self._interfaces))
                self._write_networkd_files(files)
                self._write_wpa_supplicant_configs()
                r = subprocess.run(
                    ["sudo", "networkctl", "reload"],
                    capture_output=True, text=True, timeout=15,
                )
                output = (r.stdout + r.stderr).strip().splitlines()
                if r.returncode != 0:
                    success = False
                    errors = output
                else:
                    for iface_name in self._interfaces:
                        subprocess.run(
                            ["sudo", "networkctl", "reconfigure", iface_name],
                            capture_output=True, text=True, timeout=10,
                        )
            except ValueError as exc:
                success = False
                errors = [str(exc)]
            except RuntimeError as exc:
                success = False
                errors = [str(exc)]

        if success:
            self._state_file.commit(desired)

        bus.emit(Event(
            name="networking.applied",
            payload={"success": success, "returncode": 0 if success else 1},
        ))

        resp: dict[str, Any] = {
            "success": success,
            "returncode": 0 if success else 1,
            "changes": changes,
            "output": output,
        }
        if errors:
            resp["errors"] = errors
        if debug:
            resp["debug"] = {"networkd_files": list(files.keys()), "output": output}
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
        changes = _diff_state(self._state_file.current_snapshot or {}, self._desired_snapshot())
        try:
            preview = self._build_all_networkd_configs()
        except ValueError as exc:
            return {
                "success": False,
                "returncode": 1,
                "changes": changes,
                "errors": [str(exc)],
                "preview": {},
            }
        return {"success": True, "returncode": 0, "changes": changes, "preview": preview}

    # ── interface aliases ──────────────────────────────────────────────

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

    # ── diagnostics ────────────────────────────────────────────────────

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
            header = (
                f"{'Hop':<4} {'Ip':<45} {'Status':<8} {'Loss%':>7}  "
                f"{'Snt':>3}  {'Last':>7}  {'Avg':>7}  {'Best':>7}  {'Wrst':>7}  {'StDev':>7}"
            )
            lines = [header] + [
                f"{hub['count']:<4} {hub['host']:<40} "
                f"{'timeout' if hub['host'] == '???' else 'ok':<8}"
                f" {hub['Loss%']:>6}%  {hub['Snt']:>3}  {hub['Last']:>7.2f}"
                f"  {hub['Avg']:>7.2f}  {hub['Best']:>7.2f}  {hub['Wrst']:>7.2f}  {hub['StDev']:>7.2f}"
                for hub in hubs
            ]
        except (json.JSONDecodeError, KeyError):
            lines = (result.stdout + result.stderr).strip().splitlines()
        return {"host": body.host, "returncode": result.returncode, "output": lines}
