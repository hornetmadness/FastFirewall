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

# --- OS package dependencies (installed via the native package manager using pyinfra) ---
os_requirements:
  - curl
  - libpq-dev

# --- third-party apt/yum repos required before os_requirements can be installed ---
# Processed by the loader at parse time, before any module is imported.
# For apt: loader fetches the GPG key, writes the source list entry, then runs
# the batch apt-get install.  Only apt is supported today.
repos:
  - name: vendor-repo               # unique identifier; duplicates across plugins are merged
    key_url: https://vendor.example.com/gpg.key
    key_dest: /usr/share/keyrings/vendor.gpg  # dearmored key destination
    repo_url: https://vendor.example.com/apt  # base URL; loader appends /<codename> <codename> main
    filename: vendor                # filename under /etc/apt/sources.list.d/ (no .list extension)
    # src: "deb [signed-by=...] ..."  # optional: override the constructed src line

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
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import yaml
from infra import pyinfra_run_batch

from .decorators import _HANDLER_EVENTS_ATTR, _WILDCARD_ATTR
from .events import Event, EventBus, bus as default_bus
from .plugin_base import PluginBase
from .plugin_aspect import PluginAspect
from .api_router_plugin import ApiRouterAspect
from .macro_provider_plugin import MacroProviderAspect
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
        aspects: list[tuple[str, PluginAspect]] | None = None,
    ) -> None:
        self.plugin_id = plugin_id
        self.meta = meta
        self.config = config
        self.instance = instance
        self.handlers = handlers  # (event_name, fn) — None means wildcard
        self.services: list[Service] = services or []
        self.plugin_dir: Path | None = plugin_dir
        self.service_ports: int | dict[str, dict[str, list[int]]] = service_ports
        self.aspects: list[tuple[str, PluginAspect]] = aspects or []

    def __repr__(self) -> str:
        return f"<LoadedPlugin {self.plugin_id!r} v{self.meta.get('version', '?')}>"


class PluginLoader:
    """
    Discovers and manages plugins.

    loader = PluginLoader(bus=my_bus)          # or omit for the global bus
    loader.load_directory("plugins/")
    loader.load_plugin("plugins/my_plugin")
    loader.unload_plugin("my_plugin")

    Python dependencies are managed by each plugin's pyproject.toml; the loader
    runs ``uv sync --no-dev --frozen`` once at boot to install them all.
    OS dependencies are batch-installed via the native package manager.
    """

    def __init__(
        self,
        bus: EventBus | None = None,
        app: Any | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._bus = bus or default_bus
        self._app = app  # FastAPI app; optional — only needed for ApiRouterAspect support
        self.logger = logger or logging.getLogger(__name__)
        self._plugins: dict[str, LoadedPlugin] = {}
        self._service_registry: dict[Service, str] = {}  # service → plugin_id
        self._port_registry: dict[tuple[str, int], str] = {}  # (proto, port) → plugin_id
        self._loading: set[str] = set()  # plugin ids currently mid-load (cycle detection)
        self._loaded: set[str] = set()  # all successfully loaded plugin ids (accumulates)
        self._all_service_ports: dict[str, dict[str, list[int]]] = {}
        self.ignore_state_on_boot: bool = False
        self._pkg_manager: str | None = None  # cached OS package manager name
        self._deferred_setups: list[tuple[str, PluginBase]] = []
        self._booted: bool = False

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
            return []
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

    def load_directory(self, directory: str | Path, only: list[str] | None = None, skip_requirements: bool = False, data_dir: Path | None = None) -> list[str]:
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
            if pid in self._loaded:
                continue  # already loaded from a higher-priority directory
            discovered[pid] = {
                "path": child,
                "enabled": bool(raw.get("enabled", True)),
                "requirements": list(raw.get("plugin_requirements") or []),
                "os_requirements": list(raw.get("os_requirements") or []),
                "repos": list(raw.get("repos") or []),
            }

        return self._load_discovered(discovered, only=only, skip_requirements=skip_requirements, source=str(root), data_dir=data_dir)

    def load_installed(self, only: list[str] | None = None, skip_requirements: bool = False, data_dir: Path | None = None) -> list[str]:
        """
        Discover plugins declared under the ``fastfirewall.plugins`` entry-point
        group and load any that have not already been loaded (e.g. from the
        filesystem via :meth:`load_directory`).

        Each entry point maps a plugin id to the importable Python package that
        ships the plugin files::

            [project.entry-points."fastfirewall.plugins"]
            firewall = "fastfirewall_plugin_firewall"

        Returns a list of newly loaded plugin ids.
        """
        import importlib.util
        from importlib.metadata import entry_points

        eps = {ep.name: ep.value for ep in entry_points(group="fastfirewall.plugins")}
        if not eps:
            return []

        discovered: dict[str, dict[str, Any]] = {}
        for pid, pkg_name in eps.items():
            if pid in self._loaded:
                continue
            spec = importlib.util.find_spec(pkg_name)
            if not spec or not spec.submodule_search_locations:
                self.logger.warning("Entry point %r: package %r not importable", pid, pkg_name)
                continue
            plugin_dir = Path(list(spec.submodule_search_locations)[0])
            yaml_path = plugin_dir / YAML_FILENAME
            if not yaml_path.exists():
                self.logger.warning("Entry point %r: no plugin.yaml in %s", pid, plugin_dir)
                continue
            try:
                raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text()) or {}
            except Exception:
                self.logger.warning("Could not read plugin.yaml for entry point %r, skipping", pid)
                continue
            discovered[pid] = {
                "path": plugin_dir,
                "enabled": bool(raw.get("enabled", True)),
                "requirements": list(raw.get("plugin_requirements") or []),
                "os_requirements": list(raw.get("os_requirements") or []),
                "repos": list(raw.get("repos") or []),
            }

        if not discovered:
            return []

        return self._load_discovered(
            discovered,
            only=only,
            skip_requirements=skip_requirements,
            skip_py_requirements=True,  # Python deps already satisfied by pip; skip uv sync
            source="installed packages",
            data_dir=data_dir,
        )

    def _load_discovered(
        self,
        discovered: dict[str, dict[str, Any]],
        only: list[str] | None = None,
        skip_requirements: bool = False,
        skip_py_requirements: bool = False,
        source: str = "<unknown>",
        data_dir: Path | None = None,
    ) -> list[str]:
        """
        Common steps for load_directory() and load_installed(): filter,
        topologically sort, load, and update accumulated service_ports state.
        *discovered* maps plugin_id → {path, enabled, requirements}.
        """
        # ── 2. Apply `only` filter, expanding to transitive dependencies ───
        if only is not None:
            for pid in only:
                if pid not in discovered and pid not in self._loaded:
                    self.logger.warning("Requested plugin %r not found in %s", pid, source)
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
                if dep not in discovered and dep not in self._loaded:
                    raise PluginError(
                        f"Plugin {pid!r} requires {dep!r} which was not found (source: {source})"
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

        # ── 7. Pre-install: repos → OS packages → Python packages ─────────────
        # All packages are installed once here before any plugin module is
        # imported, so setup() never runs against a missing system dependency.
        if not skip_requirements:
            self._register_repos(active, discovered)
            batch_os = self._collect_os_requirements(active, discovered)
            if batch_os:
                self._install_os_requirements("<batch>", batch_os)
            if not skip_py_requirements:
                self._install_py_requirements_uv_sync()

        # ── 8. Load in resolved order ──────────────────────────────────────
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
                loaded_id = self.load_plugin(
                    active[pid]["path"],
                    skip_requirements=skip_requirements,
                    skip_py_requirements=skip_py_requirements,
                    _batch_installed=not skip_requirements,
                    data_dir=data_dir,
                )
                loaded.append(loaded_id)
            except Exception as exc:
                self.logger.exception("Failed to load plugin from %s", active[pid]["path"])
                errored.append((pid, str(exc)))
                failed.add(pid)

        # Skip the summary entirely when this pass produced no actionable output
        # (e.g. load_installed found nothing new — disabled entries were already
        # reported by load_directory).
        if loaded or errored:
            total = len(loaded) + len(errored) + len(disabled)
            res = f"Plugin loading complete [{source}]: {len(loaded)}/{total} loaded, {len(errored)} errored, {len(disabled)} disabled"
            if errored:
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

        # Accumulate loaded ids and register service_port macros for all loaded plugins.
        self._loaded.update(loaded)
        all_service_ports: dict[str, dict[str, list[int]]] = {}
        for lp in self._plugins.values():
            if isinstance(lp.service_ports, dict):
                for svc_name, proto_map in lp.service_ports.items():
                    filtered = {
                        proto: real
                        for proto, ports in proto_map.items()
                        if (real := [p for p in ports if p != -1])
                    }
                    for proto, ports in filtered.items():
                        macro_registry.register(f"$service_port.{svc_name}.{proto}", ports)
                    if filtered:
                        all_service_ports[svc_name] = filtered
        self._all_service_ports = all_service_ports

        return loaded

    def finished(self) -> None:
        """
        Run every deferred plugin setup() (in dependency order), mark the
        loader as booted, then emit ``plugins.all_loaded``.

        setup() is deferred until this point for every plugin loaded during
        initial boot, so each plugin's apply-state step can assume every
        other plugin's routes/macros are already registered. Kept as an
        event for future extensibility even though no plugin subscribes to
        it after this design — plugins loaded after boot (self._booted is
        True) have their setup() run immediately in load_plugin() instead of
        being deferred here, since there's no barrier left to wait for.
        """
        for plugin_id, instance in self._deferred_setups:
            try:
                instance.setup()
            except Exception:
                self.logger.exception("setup() failed for plugin %r", plugin_id)
        self._deferred_setups.clear()
        self._booted = True
        self._log_pending_changes()

        loaded = sorted(self._loaded)
        all_service_ports = self._all_service_ports
        self._bus.emit(Event(
            "plugins.all_loaded",
            payload={"service_ports": all_service_ports, "loaded": loaded},
        ))

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

    def _find_installed_module(self, plugin_id: str) -> Path | None:
        """Return the plugin.py path from the installed package for *plugin_id*, or None."""
        import importlib.util as _ilu
        from importlib.metadata import entry_points as _eps
        ep_map = {ep.name: ep.value for ep in _eps(group="fastfirewall.plugins")}
        pkg = ep_map.get(plugin_id)
        if not pkg:
            return None
        spec = _ilu.find_spec(pkg)
        if not spec or not spec.submodule_search_locations:
            return None
        candidate = Path(list(spec.submodule_search_locations)[0]) / MODULE_FILENAME
        return candidate if candidate.exists() else None

    def load_plugin(self, path: str | Path, skip_requirements: bool = False, skip_py_requirements: bool = False, _batch_installed: bool = False, data_dir: Path | None = None) -> str:
        """
        Load a single plugin from *path* (the plugin directory).
        Returns the plugin id on success.
        """
        path = Path(path)
        yaml_path = path / YAML_FILENAME
        module_path = path / MODULE_FILENAME

        if not yaml_path.exists():
            raise PluginError(f"Missing {YAML_FILENAME} in {path}")

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
        plugin_id: str = raw.get("id", path.name)

        # If plugin.py isn't in this directory, fall back to the installed package.
        if not module_path.exists():
            module_path = self._find_installed_module(plugin_id)
            if module_path is None:
                raise PluginError(f"Missing {MODULE_FILENAME} in {path}")
            self.logger.debug("Plugin %r: code (plugin.py) from installed package at %s", plugin_id, module_path.parent)

        self.logger.debug("Plugin %r: config (plugin.yaml) from %s", plugin_id, path)

        config: dict[str, Any] = dict(raw.get("config", {}) or {})
        if self.ignore_state_on_boot:
            config["ignore_state_on_boot"] = True

        enabled: bool = raw.get("enabled", True)
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
                if data_dir is not None:
                    instance._data_dir = data_dir / plugin_id / "data"
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
                        self.load_plugin(dep_path, skip_requirements=skip_requirements, skip_py_requirements=skip_py_requirements, _batch_installed=_batch_installed, data_dir=data_dir)
                    else:
                        raise PluginError(
                            f"Plugin {plugin_id!r} requires {dep!r} which is not loaded"
                        )
        finally:
            self._loading.discard(plugin_id)

        # --- install OS requirements (fallback for direct load_plugin() calls) ---
        # When called via load_directory/load_installed, _batch_installed=True and
        # the batch apt-get install has already run; skip per-plugin install.
        if os_requirements and not skip_requirements and not _batch_installed:
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

        # --- store, configure, instantiate aspects, then setup ---------
        loaded = LoadedPlugin(plugin_id, meta, config, instance, handlers, services, path.resolve(), service_ports)
        self._plugins[plugin_id] = loaded
        for svc in services:
            self._service_registry[svc] = plugin_id
        self._bus.plugin_services[plugin_id] = [s.value for s in services]
        self._register_ports(plugin_id, service_ports)

        if instance is not None:
            instance.configure()
            aspects = self._instantiate_aspects(instance)
            self._mount_aspect_routers(aspects, plugin_id)
            loaded.aspects = aspects
            if self._booted:
                # Loaded after initial boot (e.g. via reload_plugin) — no
                # "wait for everyone" barrier left to observe, so setup()
                # runs immediately instead of being deferred forever.
                instance.setup()
            else:
                self._deferred_setups.append((plugin_id, instance))

        svc_values = [s.value for s in services]
        self._bus.emit(Event(
            "plugin.loaded",
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
        for _name, aspect in loaded.aspects:
            if isinstance(aspect, MacroProviderAspect):
                for key in aspect._macro_keys:
                    macro_registry.unregister(key)

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

    def _install_py_requirements_uv_sync(self) -> None:
        """Install all workspace Python dependencies via a single uv sync call.

        Replaces per-plugin uv pip install. OS packages must be installed first
        so any Python extension packages that need system libraries can compile.
        """
        uv = shutil.which("uv")
        if uv is None:
            self.logger.warning(
                "uv not found on PATH; skipping uv sync (Python deps must be pre-installed)"
            )
            return
        # Walk up from cwd to find a pyproject.toml — only present in dev/repo mode.
        workspace_root = next(
            (p for p in [Path.cwd(), *Path.cwd().parents] if (p / "pyproject.toml").exists()),
            None,
        )
        if workspace_root is None:
            return
        self.logger.info("Running uv sync --all-packages --no-dev --frozen in %s", workspace_root)
        proc = subprocess.run(
            [uv, "sync", "--all-packages", "--no-dev", "--frozen", "--no-install-workspace"],
            capture_output=True,
            text=True,
            cwd=str(workspace_root),
        )
        if proc.returncode != 0:
            self.logger.error("uv sync failed:\n%s", proc.stderr.strip())
            raise PluginError("uv sync failed; check server logs")
        self.logger.info("uv sync complete")

    def _detect_pkg_manager(self) -> str:
        """Return the name of the local OS package manager, cached after first detection."""
        if self._pkg_manager is not None:
            return self._pkg_manager
        system = platform.system()
        if system == "Darwin":
            self._pkg_manager = "brew"
        elif system == "Linux":
            for mgr, cmd in [
                ("apt", "apt-get"),
                ("dnf", "dnf"),
                ("yum", "yum"),
                ("pacman", "pacman"),
                ("apk", "apk"),
            ]:
                if shutil.which(cmd):
                    self._pkg_manager = mgr
                    break
        if self._pkg_manager is None:
            raise PluginError(
                f"No supported OS package manager found (system={system!r})"
            )
        return self._pkg_manager

    def _detect_os_codename(self) -> str:
        """Return the OS version codename for apt repo src line construction."""
        try:
            return platform.freedesktop_os_release().get("VERSION_CODENAME", "trixie")
        except Exception:
            return "trixie"

    def _collect_os_requirements(
        self,
        active: dict[str, dict[str, Any]],
        discovered: dict[str, dict[str, Any]],
    ) -> list[str]:
        """Return a deduplicated sorted list of all OS packages from active plugins."""
        pkgs: set[str] = set()
        for pid in active:
            pkgs.update(discovered[pid].get("os_requirements") or [])
        return sorted(pkgs)

    def _register_repos(
        self,
        active: dict[str, dict[str, Any]],
        discovered: dict[str, dict[str, Any]],
    ) -> None:
        """Register third-party apt repos declared in plugin.yaml before the batch OS install."""
        seen: set[str] = set()
        repos: list[dict[str, Any]] = []
        for pid in active:
            for repo in discovered[pid].get("repos") or []:
                name = repo.get("name", "")
                if name and name not in seen:
                    seen.add(name)
                    repos.append(repo)

        if not repos:
            return

        mgr = self._detect_pkg_manager()
        if mgr != "apt":
            self.logger.warning(
                "repos: in plugin.yaml is only supported for apt; "
                "skipping repo registration on %r", mgr,
            )
            return

        codename = self._detect_os_codename()
        ops: list[tuple[str, str, dict[str, Any]]] = []
        for repo in repos:
            name = repo["name"]
            key_url = repo.get("key_url", "")
            key_dest = repo.get("key_dest", "")
            filename = repo.get("filename", name)
            src = repo.get("src") or (
                f"deb [signed-by={key_dest}] {repo['repo_url']}/{codename} {codename} main"
                if repo.get("repo_url") else ""
            )
            if not src:
                self.logger.warning("Repo %r has no 'src' or 'repo_url'; skipping", name)
                continue
            if key_url and key_dest:
                ops.append((
                    "pyinfra.operations.apt", "key",
                    {"name": f"Import GPG key for {name}", "src": key_url, "dest": key_dest, "_sudo": True},
                ))
            ops.append((
                "pyinfra.operations.apt", "repo",
                {"name": f"Add apt repo {name}", "src": src, "present": True, "filename": filename, "_sudo": True},
            ))

        if not ops:
            return

        self.logger.info(
            "Registering %d apt repo(s): %s",
            len(repos), ", ".join(r["name"] for r in repos),
        )
        results = pyinfra_run_batch(ops)
        for op, (success, err) in zip(ops, results):
            if not success:
                self.logger.error("Failed to register repo %r: %s", op[2].get("name"), err)
                raise PluginError("Failed to register apt repos; check server logs")

    def _install_os_requirements(self, plugin_id: str, packages: list[str]) -> None:
        """Install OS packages via pyinfra_run_batch (one subprocess, one apt-get call)."""
        op_module, op_name, op_kwargs = self._detect_os_pkg_op(plugin_id, packages)
        self.logger.info(
            "Installing OS packages (%s): %s",
            plugin_id,
            ", ".join(packages),
        )
        results = pyinfra_run_batch([(op_module, op_name, op_kwargs)])
        success, err = results[0]
        if not success:
            self.logger.error("OS package install failed for %r: %s", plugin_id, err)
            raise PluginError(
                f"Failed to install OS packages for plugin {plugin_id!r}; check server logs"
            )

    def _detect_os_pkg_op(self, plugin_id: str, packages: list[str]) -> tuple[str, str, dict[str, Any]]:
        """Return (op_module, op_name, kwargs) for pyinfra_run_batch based on the local package manager."""
        mgr = self._detect_pkg_manager()
        if mgr == "brew":
            return "pyinfra.operations.brew", "packages", {"packages": packages}
        if mgr == "apt":
            return "pyinfra.operations.apt", "packages", {"packages": packages, "update": True, "_sudo": True}
        if mgr == "dnf":
            return "pyinfra.operations.dnf", "packages", {"packages": packages, "_sudo": True}
        if mgr == "yum":
            return "pyinfra.operations.yum", "packages", {"packages": packages, "_sudo": True}
        if mgr == "pacman":
            return "pyinfra.operations.pacman", "packages", {"packages": packages, "_sudo": True}
        if mgr == "apk":
            return "pyinfra.operations.apk", "packages", {"packages": packages, "_sudo": True}
        raise PluginError(
            f"No supported OS package manager found for plugin {plugin_id!r}. "
            f"Packages required: {packages}"
        )

    def _instantiate_aspects(self, instance: PluginBase) -> list[tuple[str, PluginAspect]]:
        """
        Instantiate every PluginAspect subclass declared as a class attribute
        on *instance*'s class (e.g. ``api = FooAPI``), wiring each to
        *instance*, and shadow the class attribute with the instance so
        ``instance.api`` becomes the ``FooAPI`` object.

        Called after ``instance.configure()`` so aspects (particularly macro
        aspects) can read already-loaded state.
        """
        aspects: list[tuple[str, PluginAspect]] = []
        for name, attr in inspect.getmembers(
            type(instance),
            lambda v: isinstance(v, type) and issubclass(v, PluginAspect),
        ):
            aspect = attr(instance)
            setattr(instance, name, aspect)
            aspects.append((name, aspect))
            if isinstance(aspect, MacroProviderAspect) and aspect._macro_keys:
                self.logger.debug(
                    "Plugin %r aspect %r registered %d macro key(s): %s",
                    instance.plugin_id, name, len(aspect._macro_keys), ", ".join(aspect._macro_keys),
                )
        return aspects

    def _mount_aspect_routers(self, aspects: list[tuple[str, PluginAspect]], plugin_id: str) -> None:
        """Mount every ApiRouterAspect's router on the FastAPI app at /v1/<plugin_id>/."""
        for _name, aspect in aspects:
            if not isinstance(aspect, ApiRouterAspect):
                continue
            if self._app is None:
                self.logger.warning(
                    "Plugin %r has an ApiRouterAspect but no FastAPI app was supplied to "
                    "PluginLoader — routes will not be registered",
                    plugin_id,
                )
                continue
            prefix = f"/v1/{plugin_id}"
            self._app.include_router(aspect.router, prefix=prefix, tags=[plugin_id])
            self.logger.info("Mounted %r routes at %s", plugin_id, prefix)

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
