"""
PluginLoader
─────────────
Discovers plugin directories, reads their YAML config, imports their Python
module, wires up decorated event handlers, and calls setup/teardown.

Expected plugin layout
──────────────────────
plugins/
  my_plugin/
    plugin.yaml       ← required
    plugin.py         ← required (contains handlers + optional PluginBase subclass)
    (any other files)

plugin.yaml schema
──────────────────
# --- metadata (required) ---
name: My Plugin
version: "1.0.0"
description: Does something useful
author: Alice

# --- optional metadata ---
enabled: true               # default true; set false to skip loading
plugin_requirements: []    # list of other plugin ids this depends on; load order is derived from this graph

# --- port declarations (required) ---
# Use -1 (scalar) when the plugin claims no services.
# Otherwise a dict keyed by service name (must match declared services exactly).
# Port value -1 means the service has no real listening port.
service_ports:
  dns:
    tcp: [53]
    udp: [53]

# Set true for plugins that manage an already-running OS service (skips OS port check).
skip_host_os_port_check: false

# --- python package dependencies (installed via uv using pyinfra) ---
py_requirements:
  - requests>=2.28
  - boto3

# --- OS package dependencies (installed via the native package manager using pyinfra) ---
os_requirements:
  - curl
  - libpq-dev

# --- arbitrary config passed to the plugin ---
config:
  api_url: https://example.com
  retry_count: 3
"""
from __future__ import annotations

import importlib.util
import inspect
import logging
import platform
import shutil
import sys
import types
from pathlib import Path
from typing import Any

import yaml
from pyinfra.api.config import Config
from pyinfra.api.inventory import Inventory
from pyinfra.api.state import State
from pyinfra.api.connect import connect_all
from pyinfra.api.operations import run_ops
from pyinfra.context import ctx_host, ctx_state
from pyinfra.operations import apk as apk_ops
from pyinfra.operations import apt as apt_ops
from pyinfra.operations import brew as brew_ops
from pyinfra.operations import dnf as dnf_ops
from pyinfra.operations import pacman as pacman_ops
from pyinfra.operations import uv as uv_ops
from pyinfra.operations import yum as yum_ops

from .decorators import _HANDLER_EVENTS_ATTR, _WILDCARD_ATTR
from .events import Event, EventBus, bus as default_bus
from .plugin_base import PluginBase
from .api_router_plugin import ApiRouterPlugin
from .macro_provider_plugin import MacroProviderPlugin
from .macros import macro_registry
from .services import Service

YAML_FILENAME = "plugin.yaml"
MODULE_FILENAME = "plugin.py"

# Debian/Ubuntu installs apt Python packages (e.g. python3-nftables) to the system
# dist-packages, which the project venv does not search. Append these directories once
# so os_requirements that provide Python modules are importable by plugin code.
_SYSTEM_DIST_PACKAGES = (
    "/usr/lib/python3/dist-packages",
    "/usr/local/lib/python3/dist-packages",
)


def _ensure_system_dist_packages() -> None:
    for path in _SYSTEM_DIST_PACKAGES:
        if Path(path).is_dir() and path not in sys.path:
            sys.path.append(path)


class PluginError(Exception):
    pass


class LoadedPlugin:
    """Internal record for a successfully loaded plugin."""

    def __init__(
        self,
        plugin_id: str,
        meta: dict[str, Any],
        config: dict[str, Any],
        instance: PluginBase | None,
        handlers: list[tuple[str | None, Any]],  # (event_name_or_None, fn)
        services: list[Service] | None = None,
        plugin_dir: Path | None = None,
        service_ports: int | dict[str, dict[str, list[int]]] = -1,
    ) -> None:
        self.plugin_id = plugin_id
        self.meta = meta
        self.config = config
        self.instance = instance
        self.handlers = handlers  # (event_name, fn) — None means wildcard
        self.services: list[Service] = services or []
        self.plugin_dir: Path | None = plugin_dir
        self.service_ports: int | dict[str, dict[str, list[int]]] = service_ports

    def __repr__(self) -> str:
        return f"<LoadedPlugin {self.plugin_id!r} v{self.meta.get('version', '?')}>"


class PluginLoader:
    """
    Discovers and manages plugins.

    loader = PluginLoader(bus=my_bus)          # or omit for the global bus
    loader.load_directory("plugins/")
    loader.load_plugin("plugins/my_plugin")
    loader.unload_plugin("my_plugin")

    py_requirements are installed into the current environment via uv using pyinfra.
    """

    def __init__(
        self,
        bus: EventBus | None = None,
        app: Any | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._bus = bus or default_bus
        self._app = app  # FastAPI app; optional — only needed for ApiRouterPlugin support
        self.logger = logger or logging.getLogger(__name__)
        self._plugins: dict[str, LoadedPlugin] = {}
        self._service_registry: dict[Service, str] = {}  # service → plugin_id
        self._port_registry: dict[tuple[str, int], str] = {}  # (proto, port) → plugin_id
        self._loading: set[str] = set()  # plugin ids currently mid-load (cycle detection)
        self.ignore_state_on_boot: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def plugins(self) -> dict[str, LoadedPlugin]:
        return dict(self._plugins)

    @property
    def service_registry(self) -> dict[Service, str]:
        """Return a snapshot of the current service → plugin_id mapping."""
        return dict(self._service_registry)

    def list_plugins(self, directory: str | Path) -> list[dict[str, Any]]:
        """
        Scan *directory* and return plugin metadata without loading anything.

        Each entry contains: id, name, version, description, author, enabled,
        plugin_requirements, service_ports, services.  Rows are sorted in
        topological load order (dependencies before dependents; alphabetical
        tiebreaker).

        ``services`` is read by importing the plugin module and inspecting
        the PluginBase subclass — no setup() is called and no packages are
        installed.  Falls back to an empty list if the module cannot be
        imported.
        """
        root = Path(directory)
        if not root.is_dir():
            raise PluginError(f"Not a directory: {root}")
        rows: dict[str, dict[str, Any]] = {}
        for child in sorted(root.iterdir()):
            yaml_path = child / YAML_FILENAME
            module_path = child / MODULE_FILENAME
            if not child.is_dir() or not yaml_path.exists():
                continue
            try:
                raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text()) or {}
            except Exception:
                self.logger.warning("Could not read %s", yaml_path)
                continue
            pid = raw.get("id", child.name)

            services: list[str] = []
            if module_path.exists():
                try:
                    mod = self._import_module(pid, module_path)
                    for _name, obj in inspect.getmembers(mod, inspect.isclass):
                        if issubclass(obj, PluginBase) and obj is not PluginBase:
                            services = [s.value for s in getattr(obj, "services", [])]
                            break
                except Exception:
                    self.logger.debug("Could not inspect services for %s", pid)

            rows[pid] = {
                "id": pid,
                "name": raw.get("name", child.name),
                "version": str(raw.get("version", "0.0.0")),
                "description": raw.get("description", ""),
                "author": raw.get("author", ""),
                "enabled": bool(raw.get("enabled", True)),
                "plugin_requirements": list(raw.get("plugin_requirements") or []),
                "service_ports": raw.get("service_ports"),
                "services": services,
            }
        deps = {pid: row["plugin_requirements"] for pid, row in rows.items()}
        order = PluginLoader._topo_sort(deps)
        return [rows[pid] for pid in order if pid in rows]

    @staticmethod
    def _validate_service_ports(
        plugin_id: str,
        value: Any,
    ) -> int | dict[str, dict[str, list[int]]]:
        """
        Validate the ``service_ports`` field from plugin.yaml.

        Accepted forms:
          -1                              — plugin exposes no ports
          {<service>: {tcp: [int, ...], udp: [int, ...]}}  — at least one protocol key
        """
        if value == -1:
            return -1

        if not isinstance(value, dict) or not value:
            raise PluginError(
                f"Plugin {plugin_id!r}: 'service_ports' must be -1 or a non-empty dict, "
                f"got {value!r}"
            )

        validated: dict[str, dict[str, list[int]]] = {}
        for svc_name, proto_map in value.items():
            if not isinstance(svc_name, str):
                raise PluginError(
                    f"Plugin {plugin_id!r}: service_ports key {svc_name!r} must be a string"
                )
            if not isinstance(proto_map, dict):
                raise PluginError(
                    f"Plugin {plugin_id!r}: service_ports[{svc_name!r}] must be a dict "
                    f"with 'tcp' and/or 'udp' keys, got {proto_map!r}"
                )
            known_protos = {"tcp", "udp"}
            unknown = set(proto_map) - known_protos
            if unknown:
                raise PluginError(
                    f"Plugin {plugin_id!r}: service_ports[{svc_name!r}] has unknown "
                    f"protocol key(s) {unknown!r}; only 'tcp' and 'udp' are allowed"
                )
            if not proto_map:
                raise PluginError(
                    f"Plugin {plugin_id!r}: service_ports[{svc_name!r}] must have at "
                    f"least one of 'tcp' or 'udp'"
                )
            validated_proto: dict[str, list[int]] = {}
            for proto, ports in proto_map.items():
                if not isinstance(ports, list) or not ports:
                    raise PluginError(
                        f"Plugin {plugin_id!r}: service_ports[{svc_name!r}][{proto!r}] "
                        f"must be a non-empty list of integers, got {ports!r}"
                    )
                for p in ports:
                    if not isinstance(p, int):
                        raise PluginError(
                            f"Plugin {plugin_id!r}: service_ports[{svc_name!r}][{proto!r}] "
                            f"contains non-integer value {p!r}"
                        )
                validated_proto[proto] = list(ports)
            validated[svc_name] = validated_proto

        return validated

    @staticmethod
    def _validate_service_ports_vs_services(
        plugin_id: str,
        service_ports: int | dict[str, dict[str, list[int]]],
        services: list[Service],
    ) -> None:
        """
        Cross-validate that service_ports keys exactly match the services the
        plugin advertises.

        Rules:
          - service_ports == -1  →  services must be empty
          - service_ports is dict →  keys must equal {s.value for s in services}
        """
        declared = {s.value for s in services}
        if service_ports == -1:
            if declared:
                raise PluginError(
                    f"Plugin {plugin_id!r}: service_ports is -1 but the plugin "
                    f"claims services {sorted(declared)!r}; use a dict with those "
                    f"service names as keys"
                )
            return

        port_keys = set(service_ports)  # type: ignore[arg-type]
        if port_keys != declared:
            extra = port_keys - declared
            missing = declared - port_keys
            parts: list[str] = []
            if extra:
                parts.append(f"unexpected keys {sorted(extra)!r}")
            if missing:
                parts.append(f"missing keys for declared services {sorted(missing)!r}")
            raise PluginError(
                f"Plugin {plugin_id!r}: service_ports keys do not match declared "
                f"services — {'; '.join(parts)}"
            )

    @staticmethod
    def _get_os_listening_ports(proto: str) -> set[int]:
        """
        Return ports currently in use by the OS for the given protocol.

        Reads /proc/net/{tcp,tcp6,udp,udp6}.  TCP entries are filtered to
        listening state (0A); all UDP entries are included.  Returns an empty
        set on non-Linux hosts or when the proc files are unreadable.
        """
        proc_files = {
            "tcp": ["/proc/net/tcp", "/proc/net/tcp6"],
            "udp": ["/proc/net/udp", "/proc/net/udp6"],
        }
        ports: set[int] = set()
        for path_str in proc_files.get(proto, []):
            try:
                with open(path_str) as fh:
                    for line in fh:
                        parts = line.split()
                        if len(parts) < 4 or parts[0] == "sl":
                            continue  # skip header row and malformed lines
                        local_addr, state = parts[1], parts[3]
                        if proto == "tcp" and state != "0A":
                            continue  # 0A = TCP_LISTEN; ignore non-listening sockets
                        port_hex = local_addr.split(":")[1]  # format: "0100007F:0050"
                        ports.add(int(port_hex, 16))
            except (FileNotFoundError, OSError):
                pass
        return ports

    def _check_plugin_port_conflicts(
        self,
        plugin_id: str,
        service_ports: int | dict[str, dict[str, list[int]]],
    ) -> None:
        """Raise PluginError if any declared port is already claimed by a loaded plugin."""
        if not isinstance(service_ports, dict):
            return
        for svc_name, proto_map in service_ports.items():
            for proto, ports in proto_map.items():
                for port in ports:
                    if port == -1:
                        continue
                    owner = self._port_registry.get((proto, port))
                    if owner is not None:
                        raise PluginError(
                            f"Plugin {plugin_id!r}: {proto.upper()} port {port} "
                            f"(service {svc_name!r}) is already claimed by plugin {owner!r}"
                        )

    def _check_os_port_conflicts(
        self,
        plugin_id: str,
        service_ports: int | dict[str, dict[str, list[int]]],
    ) -> None:
        """Raise PluginError if any declared port is already in use by the OS."""
        if not isinstance(service_ports, dict):
            return
        for svc_name, proto_map in service_ports.items():
            for proto, ports in proto_map.items():
                os_ports = self._get_os_listening_ports(proto)
                for port in ports:
                    if port == -1:
                        continue
                    if port in os_ports:
                        raise PluginError(
                            f"Plugin {plugin_id!r}: {proto.upper()} port {port} "
                            f"(service {svc_name!r}) is already in use by the OS"
                        )

    def _register_ports(self, plugin_id: str, service_ports: int | dict[str, dict[str, list[int]]]) -> None:
        if not isinstance(service_ports, dict):
            return
        for proto_map in service_ports.values():
            for proto, ports in proto_map.items():
                for port in ports:
                    if port != -1:
                        self._port_registry[(proto, port)] = plugin_id

    def _release_ports(self, service_ports: int | dict[str, dict[str, list[int]]]) -> None:
        if not isinstance(service_ports, dict):
            return
        for proto_map in service_ports.values():
            for proto, ports in proto_map.items():
                for port in ports:
                    if port != -1:
                        self._port_registry.pop((proto, port), None)

    @staticmethod
    def _topo_sort(deps: dict[str, list[str]]) -> list[str]:
        """
        Return *deps* keys in topological order (dependencies first).
        Ties within the same depth level are broken alphabetically.
        Nodes listed only as values but not as keys are silently ignored.
        Does NOT raise on cycles — callers that care (load_directory) detect
        them by comparing len(result) to len(deps).
        """
        in_degree: dict[str, int] = {pid: 0 for pid in deps}
        dependents: dict[str, list[str]] = {pid: [] for pid in deps}
        for pid, reqs in deps.items():
            for dep in reqs:
                if dep in deps:
                    in_degree[pid] += 1
                    dependents[dep].append(pid)
        ready = sorted(pid for pid, deg in in_degree.items() if deg == 0)
        order: list[str] = []
        while ready:
            pid = ready.pop(0)
            order.append(pid)
            newly_ready = [d for d in dependents[pid] if in_degree[d] - 1 == 0]
            for d in dependents[pid]:
                in_degree[d] -= 1
            ready = sorted(ready + newly_ready)
        return order

    def set_plugin_enabled(self, directory: str | Path, plugin_id: str, enabled: bool) -> None:
        """
        Set the ``enabled`` flag for *plugin_id* in its plugin.yaml.
        Pass enabled=True to enable, enabled=False to disable.
        Raises PluginError if the plugin is not found in *directory*.
        """
        root = Path(directory)
        for child in root.iterdir():
            yaml_path = child / YAML_FILENAME
            if not child.is_dir() or not yaml_path.exists():
                continue
            raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text()) or {}
            if raw.get("id", child.name) == plugin_id:
                raw["enabled"] = enabled
                yaml_path.write_text(yaml.dump(raw, default_flow_style=False))
                return
        raise PluginError(f"Plugin {plugin_id!r} not found in {root}")

    def load_directory(self, directory: str | Path, only: list[str] | None = None, skip_requirements: bool = False) -> list[str]:
        """
        Scan *directory* for plugin sub-directories and load each one.
        Returns a list of successfully loaded plugin ids.

        Load order is derived from ``plugin_requirements`` via topological sort
        (Kahn's algorithm).  Ties within the same dependency level are broken
        alphabetically.  Raises ``PluginError`` on circular dependencies or
        missing required plugins.  If a required plugin is disabled, all plugins
        that depend on it (transitively) are also skipped with a warning.

        If *only* is supplied, only those plugins (and their transitive
        dependencies) are considered.
        """
        root = Path(directory)
        if not root.is_dir():
            raise PluginError(f"Not a directory: {root}")

        # ── 1. Discover all plugins in the directory ───────────────────────
        discovered: dict[str, dict[str, Any]] = {}
        for child in sorted(root.iterdir()):
            yaml_path = child / YAML_FILENAME
            if not child.is_dir() or not yaml_path.exists():
                continue
            try:
                raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text()) or {}
            except Exception:
                self.logger.warning("Could not read %s, skipping", yaml_path)
                continue
            pid = raw.get("id", child.name)
            discovered[pid] = {
                "path": child,
                "enabled": bool(raw.get("enabled", True)),
                "requirements": list(raw.get("plugin_requirements") or []),
            }

        # ── 2. Apply `only` filter, expanding to transitive dependencies ───
        if only is not None:
            for pid in only:
                if pid not in discovered:
                    self.logger.warning("Requested plugin %r not found in %s", pid, root)
            include: set[str] = set(only)
            queue = [p for p in only if p in discovered]
            while queue:
                pid = queue.pop()
                for dep in discovered.get(pid, {}).get("requirements", []):
                    if dep not in include:
                        include.add(dep)
                        queue.append(dep)
            candidates: dict[str, dict[str, Any]] = {
                pid: info for pid, info in discovered.items() if pid in include
            }
        else:
            candidates = dict(discovered)

        # ── 3. Guard against requirements that don't exist at all ──────────
        for pid, info in candidates.items():
            if not info["enabled"]:
                continue
            for dep in info["requirements"]:
                if dep not in discovered:
                    raise PluginError(
                        f"Plugin {pid!r} requires {dep!r} which was not found in {root}"
                    )

        # ── 4. Propagate disabled state to dependents (cascading) ──────────
        disabled: set[str] = {pid for pid, info in candidates.items() if not info["enabled"]}
        changed = True
        while changed:
            changed = False
            for pid, info in candidates.items():
                if pid in disabled:
                    continue
                for dep in info["requirements"]:
                    if dep in disabled:
                        self.logger.warning(
                            "Skipping plugin %r: required plugin %r is disabled",
                            pid, dep,
                        )
                        disabled.add(pid)
                        changed = True
                        break

        active = {pid: info for pid, info in candidates.items() if pid not in disabled}

        # ── 5 & 6. Topological sort + cycle detection ──────────────────────
        active_deps = {pid: info["requirements"] for pid, info in active.items()}
        load_order = PluginLoader._topo_sort(active_deps)
        if len(load_order) != len(active):
            cycle_members = sorted(pid for pid in active if pid not in set(load_order))
            raise PluginError(
                f"Circular dependency detected among plugins: {', '.join(cycle_members)}"
            )

        # ── 7. Load in resolved order ──────────────────────────────────────
        loaded: list[str] = []
        errored: list[tuple[str, str]] = []
        failed: set[str] = set()  # plugins that failed or were skipped due to dep failure
        for pid in load_order:
            failed_dep = next(
                (d for d in active[pid]["requirements"] if d in failed), None
            )
            if failed_dep is not None:
                msg = f"required dependency {failed_dep!r} failed to load"
                self.logger.warning("Skipping plugin %r: %s", pid, msg)
                errored.append((pid, msg))
                failed.add(pid)
                continue
            try:
                loaded_id = self.load_plugin(active[pid]["path"], skip_requirements=skip_requirements)
                loaded.append(loaded_id)
            except Exception as exc:
                self.logger.exception("Failed to load plugin from %s", active[pid]["path"])
                errored.append((pid, str(exc)))
                failed.add(pid)

        total = len(loaded) + len(errored) + len(disabled)
        res = f"Plugin loading complete: {len(loaded)}/{total} loaded, {len(errored)} errored, {len(disabled)} disabled"
        if len(errored) > 0:
            self.logger.error(res)
        else:
            self.logger.info(res)

        if loaded:
            self.logger.info("  Loaded:   %s", ", ".join(loaded))
        if errored:
            self.logger.warning(
                "  Errored:  %s",
                ", ".join(f"{pid} ({msg})" for pid, msg in errored),
            )
        if disabled:
            self.logger.info("  Disabled: %s", ", ".join(sorted(disabled)))

        # Build a full service_ports map across all successfully loaded plugins
        # so subscribers (e.g. the firewall macro resolver) get a consistent
        # snapshot of what actually loaded rather than having to reassemble it
        # from per-plugin events that may have fired in an inconvenient order.
        all_service_ports: dict[str, dict[str, list[int]]] = {}
        for pid in loaded:
            lp = self._plugins.get(pid)
            if lp is not None and isinstance(lp.service_ports, dict):
                for svc_name, proto_map in lp.service_ports.items():
                    filtered = {
                        proto: real
                        for proto, ports in proto_map.items()
                        if (real := [p for p in ports if p != -1])
                    }
                    if filtered:
                        all_service_ports[svc_name] = filtered
        macro_registry.set_service_ports(all_service_ports)
        self._bus.emit(Event(
            "plugins.all_loaded",
            source="plugin_loader",
            payload={"service_ports": all_service_ports, "loaded": loaded},
        ))
        self._log_pending_changes()

        return loaded

    def _log_pending_changes(self) -> None:
        pending = [
            pid
            for pid, lp in self._plugins.items()
            if lp.instance is not None
            and getattr(getattr(lp.instance, "_state_file", None), "pending_changes", False)
        ]
        if pending:
            self.logger.warning(
                "Plugin(s) booted with pending changes (last apply may have failed): %s",
                ", ".join(pending),
            )

    def load_plugin(self, path: str | Path, skip_requirements: bool = False) -> str:
        """
        Load a single plugin from *path* (the plugin directory).
        Returns the plugin id on success.
        """
        path = Path(path)
        yaml_path = path / YAML_FILENAME
        module_path = path / MODULE_FILENAME

        if not yaml_path.exists():
            raise PluginError(f"Missing {YAML_FILENAME} in {path}")
        if not module_path.exists():
            raise PluginError(f"Missing {MODULE_FILENAME} in {path}")

        # --- parse YAML ------------------------------------------------
        with yaml_path.open() as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}

        meta = {
            "name": raw.get("name", path.name),
            "version": str(raw.get("version", "0.0.0")),
            "description": raw.get("description", ""),
            "author": raw.get("author", ""),
            "plugin_requirements": raw.get("plugin_requirements", []),
        }
        config: dict[str, Any] = dict(raw.get("config", {}) or {})
        if self.ignore_state_on_boot:
            config["ignore_state_on_boot"] = True
        plugin_id: str = raw.get("id", path.name)
        enabled: bool = raw.get("enabled", True)
        py_requirements: list[str] = raw.get("py_requirements", []) or []
        os_requirements: list[str] = raw.get("os_requirements", []) or []
        skip_host_os_port_check: bool = bool(raw.get("skip_host_os_port_check", False))

        if "service_ports" not in raw:
            raise PluginError(
                f"Plugin {plugin_id!r}: missing required key 'service_ports' in {yaml_path}"
            )
        service_ports = PluginLoader._validate_service_ports(plugin_id, raw["service_ports"])

        if not enabled:
            self.logger.info("Plugin %r is disabled, skipping", plugin_id)
            return plugin_id

        if plugin_id in self._plugins:
            raise PluginError(f"Plugin {plugin_id!r} is already loaded")

        # --- import module early so service claims can be read --------
        module = self._import_module(plugin_id, module_path)

        # --- find PluginBase subclass (optional) -----------------------
        instance: PluginBase | None = None
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, PluginBase) and obj is not PluginBase:
                instance = obj()
                instance.plugin_id = plugin_id
                instance.meta = meta
                instance.config = config
                instance.plugin_dir = path.resolve()
                instance.logger = self.logger.getChild(plugin_id)
                break

        # --- resolve and check service claims from the class ----------
        services: list[Service] = list(getattr(instance, "services", []) if instance else [])
        for svc in services:
            if not isinstance(svc, Service):
                raise PluginError(
                    f"Plugin {plugin_id!r} declared unknown service {svc!r}; "
                    f"must be a Service enum member"
                )
            owner = self._service_registry.get(svc)
            if owner is not None:
                raise PluginError(
                    f"Plugin {plugin_id!r} cannot claim service {svc.value!r}: "
                    f"already owned by plugin {owner!r}"
                )

        if services:
            self.logger.info(
                "Plugin %r claims services: %s",
                plugin_id,
                ", ".join(s.value for s in services),
            )

        # --- cross-check service_ports keys against declared services ----
        PluginLoader._validate_service_ports_vs_services(plugin_id, service_ports, services)

        # --- check for port conflicts (other plugins + OS) ---------------
        self._check_plugin_port_conflicts(plugin_id, service_ports)
        if not skip_host_os_port_check:
            self._check_os_port_conflicts(plugin_id, service_ports)
        elif service_ports != -1:
            self.logger.info(
                "Plugin %r: skipping OS port conflict check (skip_host_os_port_check=true)",
                plugin_id,
            )

        # --- check dependencies ----------------------------------------
        if meta["plugin_requirements"]:
            self.logger.debug(
                "Plugin %r requires plugins: %s",
                plugin_id,
                ", ".join(meta["plugin_requirements"]),
            )
        self._loading.add(plugin_id)
        try:
            for dep in meta["plugin_requirements"]:
                if dep not in self._plugins:
                    if dep in self._loading:
                        raise PluginError(
                            f"Circular dependency: {plugin_id!r} requires {dep!r} "
                            f"which is already being loaded"
                        )
                    dep_path = path.parent / dep
                    if dep_path.is_dir() and (dep_path / YAML_FILENAME).exists():
                        self.logger.info(
                            "Auto-loading required dependency %r for plugin %r",
                            dep, plugin_id,
                        )
                        self.load_plugin(dep_path, skip_requirements=skip_requirements)
                    else:
                        raise PluginError(
                            f"Plugin {plugin_id!r} requires {dep!r} which is not loaded"
                        )
        finally:
            self._loading.discard(plugin_id)

        # --- install python requirements via pyinfra + pipx -----------
        if py_requirements and not skip_requirements:
            self.logger.info(
                "Plugin %r needs Python packages: %s",
                plugin_id,
                ", ".join(py_requirements),
            )
            self._install_py_requirements(plugin_id, py_requirements)

        # --- install OS requirements via pyinfra ----------------------
        if os_requirements and not skip_requirements:
            self.logger.info(
                "Plugin %r needs OS packages: %s",
                plugin_id,
                ", ".join(os_requirements),
            )
            self._install_os_requirements(plugin_id, os_requirements)

        # --- collect decorated handlers --------------------------------
        handlers: list[tuple[str | None, Any]] = []
        for _name, fn in inspect.getmembers(module, callable):
            event_names: list[str] | None = getattr(fn, _HANDLER_EVENTS_ATTR, None)
            is_wildcard: bool = getattr(fn, _WILDCARD_ATTR, False)

            if event_names:
                for event_name in event_names:
                    self._bus.subscribe(event_name, fn)
                    handlers.append((event_name, fn))
                    self.logger.debug("  registered handler %s → %s", fn.__qualname__, event_name)

            if is_wildcard:
                self._bus.subscribe_all(fn)
                handlers.append((None, fn))
                self.logger.debug("  registered wildcard handler %s", fn.__qualname__)

        # --- also scan instance methods if a class was found ----------
        if instance is not None:
            for _name, method in inspect.getmembers(instance, callable):
                event_names = getattr(method, _HANDLER_EVENTS_ATTR, None)
                is_wildcard = getattr(method, _WILDCARD_ATTR, False)

                if event_names:
                    for event_name in event_names:
                        self._bus.subscribe(event_name, method)
                        handlers.append((event_name, method))

                if is_wildcard:
                    self._bus.subscribe_all(method)
                    handlers.append((None, method))

        # --- store & setup --------------------------------------------
        loaded = LoadedPlugin(plugin_id, meta, config, instance, handlers, services, path.resolve(), service_ports)
        self._plugins[plugin_id] = loaded
        for svc in services:
            self._service_registry[svc] = plugin_id
        self._bus.plugin_services[plugin_id] = [s.value for s in services]
        self._register_ports(plugin_id, service_ports)

        if instance is not None:
            instance.setup()
            self._register_api_routes(instance, plugin_id)
            self._register_macro_provider(instance, plugin_id)

        svc_values = [s.value for s in services]
        self._bus.emit(Event(
            "plugin.loaded",
            source="plugin_loader",
            payload={
                "plugin_id": plugin_id,
                "version": meta["version"],
                "services": svc_values,
                "service_ports": service_ports if isinstance(service_ports, dict) else {},
            },
        ))

        self.logger.info("Loaded plugin %r (v%s)", plugin_id, meta["version"])
        return plugin_id

    def unload_plugin(self, plugin_id: str) -> None:
        """Teardown and unregister a loaded plugin."""
        loaded = self._plugins.get(plugin_id)
        if loaded is None:
            raise PluginError(f"Plugin {plugin_id!r} is not loaded")

        # Release service claims, port reservations, and macro namespaces
        for svc in loaded.services:
            self._service_registry.pop(svc, None)
        self._bus.plugin_services.pop(plugin_id, None)
        self._release_ports(loaded.service_ports)
        if loaded.instance is not None and isinstance(loaded.instance, MacroProviderPlugin):
            for name in loaded.instance._macro_namespaces:
                macro_registry.unregister_namespace(name)

        # Unsubscribe all handlers
        for event_name, fn in loaded.handlers:
            if event_name is None:
                # wildcard
                self._bus._wildcard = [h for h in self._bus._wildcard if h is not fn]
            else:
                self._bus.unsubscribe(event_name, fn)

        if loaded.instance is not None:
            try:
                loaded.instance.teardown()
            except Exception:
                self.logger.error("Teardown of plugin %r raised an exception", plugin_id, exc_info=True)

        del self._plugins[plugin_id]

        self._bus.emit(Event(
            "plugin.unloaded",
            source="plugin_loader",
            payload={
                "plugin_id": plugin_id,
                "services": [s.value for s in loaded.services],
            },
        ))

        self.logger.info("Unloaded plugin %r", plugin_id)

    def reload_plugin(self, plugin_id: str, path: str | Path) -> None:
        """Unload then re-load a plugin (useful during development)."""
        self.unload_plugin(plugin_id)
        self.load_plugin(path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _pyinfra_state(self):
        """Return a connected pyinfra local State."""
        inventory = Inventory(([("@local", {})], {}))
        state = State(inventory, Config())
        connect_all(state)
        return state

    def _install_py_requirements(self, plugin_id: str, packages: list[str]) -> None:
        """Install plugin Python requirements via uv using pyinfra."""
        self.logger.info(
            "Installing py_requirements for plugin %r via uv: %s",
            plugin_id,
            ", ".join(packages),
        )

        state = self._pyinfra_state()
        with ctx_state.use(state):
            for host in state.activated_hosts:
                with ctx_host.use(host):
                    uv_ops.packages(packages=packages)
        run_ops(state)

    def _install_os_requirements(self, plugin_id: str, packages: list[str]) -> None:
        """Install plugin OS requirements via the native package manager using pyinfra."""
        pkg_op, op_kwargs = self._detect_os_pkg_op(plugin_id, packages)

        self.logger.info(
            "Installing os_requirements for plugin %r: %s",
            plugin_id,
            ", ".join(packages),
        )

        state = self._pyinfra_state()
        with ctx_state.use(state):
            for host in state.activated_hosts:
                with ctx_host.use(host):
                    pkg_op(**op_kwargs)  # type: ignore[call-arg]
        run_ops(state)

    def _detect_os_pkg_op(self, plugin_id: str, packages: list[str]):
        """Return (pyinfra_op, kwargs) for the detected local OS package manager."""
        system = platform.system()

        if system == "Darwin":
            return brew_ops.packages, {"packages": packages}

        if system == "Linux":
            if shutil.which("apt-get"):
                return apt_ops.packages, {"packages": packages, "update": True, "_sudo": True}
            if shutil.which("dnf"):
                return dnf_ops.packages, {"packages": packages, "_sudo": True}
            if shutil.which("yum"):
                return yum_ops.packages, {"packages": packages, "_sudo": True}
            if shutil.which("pacman"):
                return pacman_ops.packages, {"packages": packages, "_sudo": True}
            if shutil.which("apk"):
                return apk_ops.packages, {"packages": packages, "_sudo": True}

        raise PluginError(
            f"No supported OS package manager found for plugin {plugin_id!r} "
            f"(system={system!r}). Packages required: {packages}"
        )

    def _register_macro_provider(self, instance: PluginBase, plugin_id: str) -> None:
        """Register any macro namespaces a MacroProviderPlugin declared in setup()."""
        if not isinstance(instance, MacroProviderPlugin):
            return
        for name, resolver in instance._macro_namespaces.items():
            macro_registry.register_namespace(name, resolver)
            self.logger.debug("Registered macro namespace %r from plugin %r", name, plugin_id)

    def _register_api_routes(self, instance: PluginBase, plugin_id: str) -> None:
        """Mount a ApiRouterPlugin's router on the FastAPI app at /v1/<plugin_id>/."""
        if not isinstance(instance, ApiRouterPlugin):
            return
        if self._app is None:
            self.logger.warning(
                "Plugin %r is a ApiRouterPlugin but no FastAPI app was supplied to PluginLoader "
                "— routes will not be registered",
                plugin_id,
            )
            return
        prefix = f"/v1/{plugin_id}"
        self._app.include_router(instance.router, prefix=prefix, tags=[plugin_id])
        self.logger.info(
            "Mounted %r routes at %s",
            plugin_id,
            prefix,
        )

    def _import_module(self, plugin_id: str, module_path: Path):
        _ensure_system_dist_packages()
        pkg_name = f"_plugin_{plugin_id}"
        mod_name = f"{pkg_name}.plugin"

        # Remove stale cached modules so reloads work
        for key in [k for k in sys.modules if k == pkg_name or k.startswith(pkg_name + ".")]:
            sys.modules.pop(key)

        # Register the plugin directory as a package so relative imports in
        # plugin.py (e.g. `from .libs.blocklist import BlocklistMixin`) resolve.
        pkg = types.ModuleType(pkg_name)
        pkg.__path__ = [str(module_path.parent)]  # type: ignore[attr-defined]
        pkg.__package__ = pkg_name
        sys.modules[pkg_name] = pkg

        spec = importlib.util.spec_from_file_location(mod_name, module_path)
        if spec is None or spec.loader is None:
            raise PluginError(f"Cannot create module spec for {module_path}")

        module = importlib.util.module_from_spec(spec)
        module.__package__ = pkg_name
        sys.modules[mod_name] = module
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
        return module
