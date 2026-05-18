from __future__ import annotations

from fastapi import APIRouter


class ApiRouterPlugin:
    """
    Optional mixin that signals a plugin contributes FastAPI routes.

    ``PluginBase`` is always required alongside this mixin::

        class MyPlugin(PluginBase, ApiRouterPlugin):
            services = [Service.DNS]

            def setup(self):
                @self.router.get("/zones")
                def list_zones():
                    return {"zones": []}

    The loader mounts the router at /v1/<plugin_id>/.  ``self.router`` is
    created automatically — add routes to it inside ``setup()``.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        from .plugin_base import PluginBase  # local import avoids circular dep

        if not issubclass(cls, PluginBase):
            raise TypeError(
                f"{cls.__name__} must also inherit from PluginBase: "
                f"class {cls.__name__}(PluginBase, ApiRouterPlugin)"
            )

    def __init__(self) -> None:
        super().__init__()
        self.router: APIRouter = APIRouter()
