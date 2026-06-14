from __future__ import annotations

from typing import Any

from .macros import macro_registry


class MacroProviderPlugin:
    """
    Optional mixin: plugin registers macro keys directly into the shared registry.

    Usage::

        class NetworkingPlugin(PluginBase, MacroProviderPlugin):

            def setup(self):
                for alias, device in self._aliases.items():
                    self.register_macro(f"$interface.{alias}.name", device)
                    self.register_macro(f"$interface.{alias}.address", [...])

            def teardown(self):
                self.unregister_macro("$interface")

    Call ``register_macro(key, value)`` inside ``setup()`` for each macro key
    the plugin owns. Keys are stored in ``_macro_keys`` so the loader can
    clean them up on plugin unload.

    Rules:
    - Must also inherit ``PluginBase``.
    - Register macros inside ``setup()``, not at class definition time.
    - Re-call ``register_macro`` whenever the underlying data changes.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        from .plugin_base import PluginBase  # local import avoids circular dep

        if not issubclass(cls, PluginBase):
            raise TypeError(
                f"{cls.__name__} must also inherit from PluginBase: "
                f"class {cls.__name__}(PluginBase, MacroProviderPlugin)"
            )

    def __init__(self) -> None:
        super().__init__()
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
        Return a display snapshot of each namespace this plugin provides.

        Override to expose the current entries; used by ``--show-macros``.
        """
        return {}
