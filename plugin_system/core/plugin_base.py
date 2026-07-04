from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .services import Service


class PluginBase:
    """
    Base class for all plugins.

    Subclass this in your plugin's module:

        class MyPlugin(PluginBase):
            services = [Service.DNS, Service.DHCP]

            def setup(self):
                ...
            def teardown(self):
                ...

    Declare ``services`` to claim exclusive ownership of one or more network
    appliance services. The loader will refuse to load a second plugin that
    claims a service already owned by another loaded plugin.

    Config values from the YAML file are available as self.config.
    Plugin metadata (name, version, author, …) is available as self.meta.
    """

    # Declare the services this plugin owns. Override in subclasses.
    services: list[Service] = []

    # Set by the loader before setup() is called
    config: dict[str, Any]
    meta: dict[str, Any]
    plugin_id: str
    plugin_dir: Path
    logger: logging.Logger
    _data_dir: Path | None = None  # overridden by loader when plugins.data_dir is configured

    @property
    def data_dir(self) -> Path:
        """Directory where this plugin's state files are stored.

        Defaults to plugin_dir/data.  The loader overrides this when
        plugins.data_dir is set in app_config.yaml, placing state at
        <data_dir>/<plugin_id>/ so it lives outside the installed package.
        """
        return self._data_dir if self._data_dir is not None else self.plugin_dir / "data"

    def __init__(self) -> None:
        super().__init__()
        # Derive plugin_id from the module name so events emitted during __init__
        # have a non-empty source before the loader sets the authoritative value.
        # Real loader uses "_plugin_<id>.plugin"; tests use "plugins.<id>.plugin".
        module = type(self).__module__
        head = module.split(".")[0]
        if head.startswith("_plugin_"):
            self.plugin_id = head[len("_plugin_"):]
        elif module.startswith("plugins."):
            self.plugin_id = module.split(".")[1]

    def configure(self) -> None:
        """
        Called once after the loader injects plugin_id/meta/config/plugin_dir/
        logger/data_dir, but before this plugin's aspects (declared as class
        attributes, e.g. ``api = FooAPI``) are instantiated, and before
        setup(). Load state and any config-derived attributes here — aspects
        and setup() may depend on them. Override to initialise resources.
        """

    def setup(self) -> None:
        """
        Called once every plugin has been configured (state loaded, aspects
        instantiated, routes/macros registered) — see PluginLoader.finished().
        Override to apply state to the OS (pyinfra pushes, service restarts,
        etc.). Do not register routes or macros here; do that via aspects
        during configure()/aspect __init__ instead.
        """

    def teardown(self) -> None:
        """Called when the plugin is unloaded. Override to clean up resources."""

    def __repr__(self) -> str:
        return f"<Plugin {self.plugin_id!r}>"
