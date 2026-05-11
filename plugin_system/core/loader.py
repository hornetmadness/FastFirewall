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
boot_priority: 100          # load order — lower = earlier; default 100; ties broken alphabetically
plugin_requirements: []    # list of other plugin ids this depends on

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
from .routed_plugin import RoutedPlugin
from .services import Service

YAML_FILENAME = "plugin.yaml"
MODULE_FILENAME = "plugin.py"


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
    ) -> None:
        self.plugin_id = plugin_id
        self.meta = meta
        self.config = config
        self.instance = instance
        self.handlers = handlers  # (event_name, fn) — None means wildcard
        self.services: list[Service] = services or []
        self.plugin_dir: Path | None = plugin_dir

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
        self._app = app  # FastAPI app; optional — only needed for RoutedPlugin support
        self.logger = logger or logging.getLogger(__name__)
        self._plugins: dict[str, LoadedPlugin] = {}
        self._service_registry: dict[Service, str] = {}  # service → plugin_id

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

        Each entry contains: id, name, version, description, author,
        enabled, boot_priority.
        """
        root = Path(directory)
        if not root.is_dir():
            raise PluginError(f"Not a directory: {root}")
        results = []
        for child in sorted(root.iterdir()):
            yaml_path = child / YAML_FILENAME
            if not child.is_dir() or not yaml_path.exists():
                continue
            try:
                raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text()) or {}
            except Exception:
                self.logger.warning("Could not read %s", yaml_path)
                continue
            results.append({
                "id": raw.get("id", child.name),
                "name": raw.get("name", child.name),
                "version": str(raw.get("version", "0.0.0")),
                "description": raw.get("description", ""),
                "author": raw.get("author", ""),
                "enabled": bool(raw.get("enabled", True)),
                "boot_priority": int(raw.get("boot_priority", 100)),
            })
        return results

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

    def load_directory(self, directory: str | Path, only: list[str] | None = None) -> list[str]:
        """
        Scan *directory* for plugin sub-directories and load each one.
        Returns a list of successfully loaded plugin ids.

        Load order is determined by the optional ``boot_priority`` field in each
        plugin.yaml (lower number = loaded first).  Plugins without the field
        default to boot_priority 100.  Ties are broken alphabetically.
        """
        root = Path(directory)
        if not root.is_dir():
            raise PluginError(f"Not a directory: {root}")

        def _priority_key(path: Path) -> tuple[int, str]:
            try:
                with (path / YAML_FILENAME).open() as fh:
                    raw = yaml.safe_load(fh) or {}
                return (int(raw.get("boot_priority", 100)), path.name)
            except Exception:
                return (100, path.name)

        candidates = [
            child for child in root.iterdir()
            if child.is_dir()
            and (child / YAML_FILENAME).exists()
            and (only is None or child.name in only)
        ]

        loaded = []
        for child in sorted(candidates, key=_priority_key):
            if child.is_dir() and (child / YAML_FILENAME).exists():
                try:
                    plugin_id = self.load_plugin(child)
                    loaded.append(plugin_id)
                except Exception:
                    self.logger.exception("Failed to load plugin from %s", child)
        return loaded

    def load_plugin(self, path: str | Path) -> str:
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
        config: dict[str, Any] = raw.get("config", {}) or {}
        plugin_id: str = raw.get("id", path.name)
        enabled: bool = raw.get("enabled", True)
        py_requirements: list[str] = raw.get("py_requirements", []) or []
        os_requirements: list[str] = raw.get("os_requirements", []) or []

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

        # --- check dependencies ----------------------------------------
        if meta["plugin_requirements"]:
            self.logger.debug(
                "Plugin %r requires plugins: %s",
                plugin_id,
                ", ".join(meta["plugin_requirements"]),
            )
        for dep in meta["plugin_requirements"]:
            if dep not in self._plugins:
                raise PluginError(
                    f"Plugin {plugin_id!r} requires {dep!r} which is not loaded"
                )

        # --- install python requirements via pyinfra + pipx -----------
        if py_requirements:
            self.logger.info(
                "Plugin %r needs Python packages: %s",
                plugin_id,
                ", ".join(py_requirements),
            )
            self._install_py_requirements(plugin_id, py_requirements)

        # --- install OS requirements via pyinfra ----------------------
        if os_requirements:
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
        loaded = LoadedPlugin(plugin_id, meta, config, instance, handlers, services, path.resolve())
        self._plugins[plugin_id] = loaded
        for svc in services:
            self._service_registry[svc] = plugin_id
        self._bus.plugin_services[plugin_id] = [s.value for s in services]

        if instance is not None:
            instance.setup()
            self._register_api_routes(instance, plugin_id)

        svc_values = [s.value for s in services]
        self._bus.emit(Event(
            "plugin.loaded",
            source="plugin_loader",
            payload={
                "plugin_id": plugin_id,
                "version": meta["version"],
                "services": svc_values,
            },
        ))

        self.logger.info("Loaded plugin %r (v%s)", plugin_id, meta["version"])
        return plugin_id

    def unload_plugin(self, plugin_id: str) -> None:
        """Teardown and unregister a loaded plugin."""
        loaded = self._plugins.get(plugin_id)
        if loaded is None:
            raise PluginError(f"Plugin {plugin_id!r} is not loaded")

        # Release service claims
        for svc in loaded.services:
            self._service_registry.pop(svc, None)
        self._bus.plugin_services.pop(plugin_id, None)

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

    def _register_api_routes(self, instance: PluginBase, plugin_id: str) -> None:
        """Mount a RoutedPlugin's router on the FastAPI app at /v1/<service_name>/."""
        if not isinstance(instance, RoutedPlugin):
            return
        if self._app is None:
            self.logger.warning(
                "Plugin %r is a RoutedPlugin but no FastAPI app was supplied to PluginLoader "
                "— routes will not be registered",
                plugin_id,
            )
            return
        if not hasattr(instance, "service_name"):
            raise PluginError(
                f"RoutedPlugin {plugin_id!r} must define a 'service_name' (Service enum member)"
            )
        prefix = f"/v1/{instance.service_name.value}"
        self._app.include_router(instance.router, prefix=prefix)
        self.logger.info(
            "Mounted %r routes at %s",
            plugin_id,
            prefix,
        )

    def _import_module(self, plugin_id: str, module_path: Path):
        module_name = f"_plugin_{plugin_id}"
        # Remove stale cached module so reloads work
        sys.modules.pop(module_name, None)

        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise PluginError(f"Cannot create module spec for {module_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
        return module
