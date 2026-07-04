import textwrap
import pytest
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel

from plugin_system.core import EventBus, PluginLoader, Service
from plugin_system.core.loader import PluginError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_plugin(root, name, yaml_content, py_content):
    plugin_dir = root / name
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text(textwrap.dedent(yaml_content))
    (plugin_dir / "plugin.py").write_text(textwrap.dedent(py_content))
    return plugin_dir


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def greeter_app(tmp_path):
    make_plugin(tmp_path, "greeter", """
        name: Greeter
        id: greeter
        version: "1.0.0"
        service_ports:
          ntp:
            tcp: [-1]
    """, """
        from plugin_system.core import PluginBase, ApiRouterAspect, Service

        class GreeterAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)

                @self.router.get("/hello/{username}")
                def greet(username: str):
                    msg = core._tmpl.format(username=username)
                    return {"message": msg.upper() if core._shout else msg}

                @self.router.get("/status")
                def status():
                    return {"plugin": core.meta["name"], "version": core.meta["version"]}

        class GreeterPlugin(PluginBase):
            services = [Service.NTP]
            api = GreeterAPI

            def configure(self):
                self._tmpl = self.config.get("greeting_template", "Hello, {username}!")
                self._shout = self.config.get("shout", False)
    """)
    app = FastAPI()
    loader = PluginLoader(bus=EventBus(), app=app)
    loader.load_plugin(tmp_path / "greeter")
    return app


@pytest.fixture
def client(greeter_app):
    return TestClient(greeter_app)


# ---------------------------------------------------------------------------
# Route mounting
# ---------------------------------------------------------------------------

def test_hello_endpoint_returns_greeting(client):
    response = client.get("/v1/greeter/hello/world")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, world!"}


def test_hello_endpoint_uses_username_path_param(client):
    response = client.get("/v1/greeter/hello/alice")
    assert response.status_code == 200
    assert "alice" in response.json()["message"]


def test_status_endpoint_returns_metadata(client):
    response = client.get("/v1/greeter/status")
    assert response.status_code == 200
    data = response.json()
    assert data["plugin"] == "Greeter"
    assert data["version"] == "1.0.0"


def test_unknown_route_returns_404(client):
    response = client.get("/v1/greeter/nonexistent")
    assert response.status_code == 404


def test_routes_not_mounted_at_wrong_prefix(client):
    response = client.get("/v1/dns/hello/alice")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Shout mode (config-driven behaviour)
# ---------------------------------------------------------------------------

def test_shout_config_uppercases_response(tmp_path):
    make_plugin(tmp_path, "shouter", """
        name: Shouter
        id: shouter
        config:
          shout: true
        service_ports:
          ntp:
            tcp: [-1]
    """, """
        from plugin_system.core import PluginBase, ApiRouterAspect, Service

        class ShouterAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)

                @self.router.get("/hello/{username}")
                def greet(username: str):
                    msg = f"Hello, {username}!"
                    return {"message": msg.upper() if core._shout else msg}

        class ShouterPlugin(PluginBase):
            services = [Service.NTP]
            api = ShouterAPI

            def configure(self):
                self._shout = self.config.get("shout", False)
    """)
    app = FastAPI()
    loader = PluginLoader(bus=EventBus(), app=app)
    loader.load_plugin(tmp_path / "shouter")
    client = TestClient(app)
    response = client.get("/v1/shouter/hello/bob")
    assert response.json()["message"] == "HELLO, BOB!"


# ---------------------------------------------------------------------------
# add_api_route style (like audit_plugin)
# ---------------------------------------------------------------------------

def test_add_api_route_style_endpoints(tmp_path):
    make_plugin(tmp_path, "log_plugin", "name: Log\nid: log_plugin\nservice_ports:\n  syslog:\n    tcp: [-1]\n", """
        from plugin_system.core import PluginBase, ApiRouterAspect, Service

        class LogAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)
                self.router.add_api_route("/logs", core._get_logs, methods=["GET"])
                self.router.add_api_route("/logs", core._clear_logs, methods=["DELETE"])

        class LogPlugin(PluginBase):
            services = [Service.SYSLOG]
            api = LogAPI

            def configure(self):
                self._entries = ["entry1", "entry2"]

            def _get_logs(self):
                return {"entries": self._entries}

            def _clear_logs(self):
                self._entries.clear()
                return {"cleared": True}
    """)
    app = FastAPI()
    loader = PluginLoader(bus=EventBus(), app=app)
    loader.load_plugin(tmp_path / "log_plugin")
    client = TestClient(app)

    response = client.get("/v1/log_plugin/logs")
    assert response.status_code == 200
    assert response.json()["entries"] == ["entry1", "entry2"]

    response = client.delete("/v1/log_plugin/logs")
    assert response.status_code == 200
    assert response.json()["cleared"] is True

    response = client.get("/v1/log_plugin/logs")
    assert response.json()["entries"] == []


# ---------------------------------------------------------------------------
# Multiple plugins, multiple prefixes
# ---------------------------------------------------------------------------

def test_two_plugins_mounted_at_distinct_prefixes(tmp_path):
    make_plugin(tmp_path, "ntp_plugin", "name: NTP\nid: ntp_plugin\nservice_ports:\n  ntp:\n    tcp: [-1]\n", """
        from plugin_system.core import PluginBase, ApiRouterAspect, Service

        class NTPAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)

                @self.router.get("/ping")
                def ping():
                    return {"service": "ntp"}

        class NTPPlugin(PluginBase):
            services = [Service.NTP]
            api = NTPAPI
    """)
    make_plugin(tmp_path, "dns_plugin", "name: DNS\nid: dns_plugin\nservice_ports:\n  dns:\n    tcp: [-1]\n", """
        from plugin_system.core import PluginBase, ApiRouterAspect, Service

        class DNSAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)

                @self.router.get("/ping")
                def ping():
                    return {"service": "dns"}

        class DNSPlugin(PluginBase):
            services = [Service.DNS]
            api = DNSAPI
    """)
    app = FastAPI()
    bus = EventBus()
    loader = PluginLoader(bus=bus, app=app)
    loader.load_plugin(tmp_path / "ntp_plugin")
    loader.load_plugin(tmp_path / "dns_plugin")
    client = TestClient(app)

    assert client.get("/v1/ntp_plugin/ping").json() == {"service": "ntp"}
    assert client.get("/v1/dns_plugin/ping").json() == {"service": "dns"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_routed_plugin_without_fastapi_app_does_not_raise(tmp_path):
    make_plugin(tmp_path, "no_app", "name: NoApp\nid: no_app\nservice_ports:\n  dns:\n    tcp: [-1]\n", """
        from plugin_system.core import PluginBase, ApiRouterAspect, Service

        class NoAppAPI(ApiRouterAspect):
            pass

        class NoAppPlugin(PluginBase):
            services = [Service.DNS]
            api = NoAppAPI
    """)
    loader = PluginLoader(bus=EventBus(), app=None)
    loader.load_plugin(tmp_path / "no_app")  # should not raise
    assert "no_app" in loader.plugins


def test_routed_plugin_with_no_services_loads_at_plugin_id_prefix(tmp_path):
    make_plugin(tmp_path, "bare_routed", "name: Bare\nid: bare_routed\nservice_ports: -1\n", """
        from plugin_system.core import PluginBase, ApiRouterAspect

        class BareAPI(ApiRouterAspect):
            def __init__(self, core):
                super().__init__(core)

                @self.router.get("/ping")
                def ping():
                    return {"ok": True}

        class BareApiRouterPlugin(PluginBase):
            api = BareAPI
    """)
    app = FastAPI()
    loader = PluginLoader(bus=EventBus(), app=app)
    loader.load_plugin(tmp_path / "bare_routed")
    client = TestClient(app)
    assert client.get("/v1/bare_routed/ping").status_code == 200


def test_non_routed_plugin_has_no_routes(tmp_path):
    make_plugin(tmp_path, "plain", "name: Plain\nid: plain\nservice_ports: -1\n", """
        from plugin_system.core import PluginBase

        class PlainPlugin(PluginBase):
            pass
    """)
    app = FastAPI()
    loader = PluginLoader(bus=EventBus(), app=app)
    loader.load_plugin(tmp_path / "plain")
    client = TestClient(app)
    # No routes were mounted, so anything under /v1/ should 404
    assert client.get("/v1/plain/anything").status_code == 404


# ---------------------------------------------------------------------------
# Validation error handler (matches app.py exception handler)
# ---------------------------------------------------------------------------

@pytest.fixture
def validation_app():
    _app = FastAPI()

    @_app.exception_handler(RequestValidationError)
    async def handler(req: Request, exc: RequestValidationError):
        error_messages = []
        for error in exc.errors():
            field = error["loc"][-1]
            message = error["msg"]
            error_messages.append(f"{field.capitalize()}: {message}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={
                "message": ".\n".join(error_messages),
                "source_errors": exc.errors(),
            },
        )

    class Body(BaseModel):
        name: str
        count: int

    @_app.post("/items")
    def create(body: Body):
        return body.model_dump()

    return _app


def test_validation_error_returns_422(validation_app):
    r = TestClient(validation_app).post("/items", json={"name": "x", "count": "not-a-number"})
    assert r.status_code == 422


def test_validation_error_has_message_and_source_errors(validation_app):
    r = TestClient(validation_app).post("/items", json={})
    data = r.json()
    assert "message" in data
    assert "source_errors" in data


def test_validation_error_message_capitalises_field(validation_app):
    r = TestClient(validation_app).post("/items", json={"name": "x"})  # count missing
    assert r.json()["message"].startswith("Count")


def test_validation_multiple_errors_joined_with_separator(validation_app):
    r = TestClient(validation_app).post("/items", json={})  # both fields missing
    assert ".\n" in r.json()["message"]


def test_validation_source_errors_is_list(validation_app):
    r = TestClient(validation_app).post("/items", json={})
    assert isinstance(r.json()["source_errors"], list)
