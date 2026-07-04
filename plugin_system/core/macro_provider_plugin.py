from __future__ import annotations

from typing import Any

from .macros import macro_registry
from .plugin_aspect import PluginAspect


class MacroProviderAspect(PluginAspect):
    """
    Aspect that lets a plugin register macro keys into the shared registry.

    Declare it as a class attribute on the plugin's ``PluginBase`` subclass,
    and register macros in its ``__init__`` (which runs after the core's
    ``configure()``, so state/config is already loaded)::

        class FooMacros(MacroProviderAspect):
            def __init__(self, core):
                super().__init__(core)
                for alias, device in core._aliases.items():
                    self.register_macro(f"$interface.{alias}.name", device)

            def macro_snapshot(self):
                return {"interface": {...}}

        class FooPlugin(PluginBase):
            macros = FooMacros

    Keys are stored in ``_macro_keys`` so the loader can clean them up on
    plugin unload. Re-instantiate/re-register whenever the underlying data
    changes.
    """

    def __init__(self, core) -> None:
        super().__init__(core)
        self._macro_keys: list[str] = []

    def register_macro(self, key: str, value: Any) -> None:
        """Register *key* → *value* in the shared macro registry."""
        macro_registry.register(key, value)
        if key not in self._macro_keys:
            self._macro_keys.append(key)

    def unregister_macro(self, key: str) -> None:
        """Remove *key* (and its subtree) from the shared macro registry."""
        macro_registry.unregister(key)
        prefix = key if key.startswith("$") else f"${key}"
        self._macro_keys = [k for k in self._macro_keys if not k.startswith(prefix)]

    def macro_snapshot(self) -> dict[str, dict[str, Any]]:
        """
        Return a display snapshot of each namespace this aspect provides.

        Override to expose the current entries; used by ``--show-macros``.
        """
        return {}
