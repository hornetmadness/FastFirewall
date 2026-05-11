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

    def setup(self) -> None:
        """Called once after the plugin is loaded. Override to initialise resources."""

    def teardown(self) -> None:
        """Called when the plugin is unloaded. Override to clean up resources."""

    def __repr__(self) -> str:
        return f"<Plugin {self.plugin_id!r}>"
