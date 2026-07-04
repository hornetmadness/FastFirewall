from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .plugin_base import PluginBase


class PluginAspect:
    """
    Base class for a composed plugin aspect (e.g. API routes, macros).

    Declare an aspect as a class attribute on a PluginBase subclass instead of
    using multiple inheritance::

        class FooAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)
                self.router.add_api_route("/status", core._status, methods=["GET"])

        class FooPlugin(PluginBase):
            api = FooAPI

    The loader instantiates each declared aspect class as ``cls(instance)``
    after calling ``instance.configure()``, and replaces the class attribute
    with the instance (``instance.api`` becomes the ``FooAPI`` object).
    """

    def __init__(self, core: "PluginBase") -> None:
        self.core = core
