from __future__ import annotations

from typing import Any, Callable


class MacroProviderPlugin:
    """
    Optional mixin: plugin registers one or more macro namespaces.

    Usage::

        class NetworkingPlugin(PluginBase, MacroProviderPlugin):

            def setup(self):
                self.add_macro_namespace("interface", self._resolve_interface)
                self.add_macro_namespace("vlan", self._resolve_vlan)

            def _resolve_interface(self, *segments: str) -> Any:
                return self._aliases.get(segments[0]) if segments else None

    Call ``add_macro_namespace(name, resolver)`` inside ``setup()`` for each
    namespace the plugin owns — analogous to adding routes via ``self.router``.
    The loader registers every declared namespace in the shared ``macro_registry``
    after ``setup()`` completes, and unregisters them on plugin unload.

    Rules:
    - Must also inherit ``PluginBase``.
    - Register namespaces inside ``setup()``, not at class definition time.
    - A resolver is ``Callable[..., Any]`` — it receives the macro segments
      after the namespace (e.g. ``$interface.LAN1`` → ``resolver("LAN1")``).
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
        self._macro_namespaces: dict[str, Callable[..., Any]] = {}

    def add_macro_namespace(self, name: str, resolver: Callable[..., Any]) -> None:
        """Register *name* as a macro namespace backed by *resolver*."""
        self._macro_namespaces[name] = resolver

    def macro_snapshot(self) -> dict[str, dict[str, Any]]:
        """
        Return a display snapshot of each namespace this plugin provides.

        Override to expose the current entries; used by ``--show-macros``.
        Default returns each namespace name mapped to an empty dict.

        Example override::

            def macro_snapshot(self) -> dict[str, dict[str, Any]]:
                return {"interface": dict(self._aliases)}
        """
        return {name: {} for name in self._macro_namespaces}
