from __future__ import annotations

from fastapi import APIRouter

from .services import Service


class RoutedPlugin:
    """
    Optional mixin that signals a plugin contributes FastAPI routes.

    ``PluginBase`` is always required alongside this mixin::

        class MyPlugin(PluginBase, RoutedPlugin):
            service_name = Service.DNS
            services = [Service.DNS]

            def setup(self):
                @self.router.get("/zones")
                def list_zones():
                    return {"zones": []}

    ``service_name`` must be a ``Service`` enum member; the loader mounts the
    router at /v1/<service_name.value>/.  ``self.router`` is created
    automatically — add routes to it inside ``setup()``.
    """

    service_name: Service

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        from .plugin_base import PluginBase  # local import avoids circular dep

        if not issubclass(cls, PluginBase):
            raise TypeError(
                f"{cls.__name__} must also inherit from PluginBase: "
                f"class {cls.__name__}(PluginBase, RoutedPlugin)"
            )

    def __init__(self) -> None:
        self.router: APIRouter = APIRouter()
