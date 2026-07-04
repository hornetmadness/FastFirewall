from __future__ import annotations

from fastapi import APIRouter

from .plugin_aspect import PluginAspect


class ApiRouterAspect(PluginAspect):
    """
    Aspect that gives a plugin a FastAPI router.

    Declare it as a class attribute on the plugin's ``PluginBase`` subclass::

        class FooAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)
                self.router.add_api_route("/status", core._status, methods=["GET"])

        class FooPlugin(PluginBase):
            api = FooAPI

    The loader instantiates ``FooAPI(instance)`` and mounts ``self.router``
    at ``/v1/<plugin_id>/``.
    """

    def __init__(self, core) -> None:
        super().__init__(core)
        self.router: APIRouter = APIRouter()
