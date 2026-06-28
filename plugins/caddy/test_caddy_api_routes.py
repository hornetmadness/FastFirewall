"""
Tests for the Caddy plugin routes (/v1/caddy/*).

Caddy and pyinfra are not required — _pyinfra_run is replaced with MagicMock
before setup() is called, and _caddy_admin_load is replaced for subsequent-apply
tests. No real system changes are made.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ff_auth.auth import AuthUser, get_current_user

from plugin_system.core.events import Event, bus as global_bus
from plugin_system.core.macros import macro_registry

PLUGIN_PY = Path(__file__).parent / "plugin.py"
_REPO_ROOT = str(Path(__file__).parents[2])


# ── helpers ──────────────────────────────────────────────────────────────────

_mod = None
_DEFAULT_SETTINGS: dict = {}

def _load_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    name = "_test_caddy_plugin"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_PY)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    global _mod, _DEFAULT_SETTINGS
    _mod = mod
    _DEFAULT_SETTINGS = mod._DEFAULT_SETTINGS
    return mod


def _make_plugin(tmp_path: Path, config: dict | None = None) -> Any:
    mod = _load_module()
    plugin = mod.CaddyPlugin()
    plugin.plugin_id = "caddy"
    plugin.meta = {"name": "Caddy Plugin", "version": "1.0.0", "description": "", "author": ""}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.caddy")
    plugin.config = {
        "state_file": "caddy_state.json",
        "config_file": "caddy.json",
        "ignore_state_on_boot": True,
        **(config or {}),
    }
    # Redirect the systemd override path into tmp_path so tests can read/write it
    plugin._OVERRIDE_PATH = tmp_path / "caddy_override.conf"
    plugin._pyinfra_run = MagicMock()
    plugin._caddy_admin_load = MagicMock()
    plugin.setup()
    return plugin


def _make_client(plugin: Any) -> TestClient:
    app = FastAPI()
    app.include_router(plugin.router, prefix="/v1/caddy")
    app.dependency_overrides[get_current_user] = lambda: AuthUser(username="test", roles=["admin"])
    return TestClient(app, raise_server_exceptions=False)


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def seed_macros():
    """Seed the macros the default fastfirewall upstream requires."""
    macro_registry.register("$interface.lo.address", ["127.0.0.1", "::1"])
    macro_registry.register("$service_port.fastfirewall-api.tcp", [8000])
    yield
    macro_registry.unregister("$interface")
    macro_registry.unregister("$service_port")


@pytest.fixture
def plugin(tmp_path):
    return _make_plugin(tmp_path)


@pytest.fixture
def client(plugin):
    return _make_client(plugin)


# ── status ────────────────────────────────────────────────────────────────────

def test_status_initial(client):
    r = client.get("/v1/caddy/status")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "caddy"
    assert body["apps"] == 1  # default fastfirewall app
    assert body["pending_changes"] is False


# ── app CRUD ──────────────────────────────────────────────────────────────────

def test_add_app(client):
    r = client.post("/v1/caddy/config/apps", json={
        "name": "myapp",
        "upstream": "http://127.0.0.1:9000",
        "path_prefix": "/myapp",
        "description": "test",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "myapp"
    assert body["upstream"] == "http://127.0.0.1:9000"
    assert body["source"] == "api"


def test_add_app_conflict(client):
    client.post("/v1/caddy/config/apps", json={"name": "dup", "upstream": "http://127.0.0.1:9000"})
    r = client.post("/v1/caddy/config/apps", json={"name": "dup", "upstream": "http://127.0.0.1:9001"})
    assert r.status_code == 409


def test_get_app(client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    r = client.get("/v1/caddy/config/apps/ff")
    assert r.status_code == 200
    assert r.json()["upstream"] == "http://127.0.0.1:8000"


def test_get_app_not_found(client):
    r = client.get("/v1/caddy/config/apps/nope")
    assert r.status_code == 404


def test_list_apps(client):
    client.post("/v1/caddy/config/apps", json={"name": "a", "upstream": "http://127.0.0.1:8001"})
    client.post("/v1/caddy/config/apps", json={"name": "b", "upstream": "http://127.0.0.1:8002"})
    r = client.get("/v1/caddy/config/apps")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3  # fastfirewall default + a + b
    names = {a["name"] for a in body["apps"]}
    assert {"a", "b", "fastfirewall"} == names


def test_update_app(client):
    client.post("/v1/caddy/config/apps", json={"name": "app", "upstream": "http://127.0.0.1:8000"})
    r = client.put("/v1/caddy/config/apps/app", json={
        "name": "app",
        "upstream": "http://127.0.0.1:9999",
        "path_prefix": "/new",
        "description": "updated",
    })
    assert r.status_code == 200
    assert r.json()["upstream"] == "http://127.0.0.1:9999"
    assert r.json()["path_prefix"] == "/new"


def test_update_app_not_found(client):
    r = client.put("/v1/caddy/config/apps/ghost", json={"name": "ghost", "upstream": "http://127.0.0.1:1"})
    assert r.status_code == 404


def test_delete_app(client):
    client.post("/v1/caddy/config/apps", json={"name": "todel", "upstream": "http://127.0.0.1:8000"})
    r = client.delete("/v1/caddy/config/apps/todel")
    assert r.status_code == 204
    assert client.get("/v1/caddy/config/apps/todel").status_code == 404


def test_delete_app_not_found(client):
    r = client.delete("/v1/caddy/config/apps/ghost")
    assert r.status_code == 404


# ── settings ──────────────────────────────────────────────────────────────────

def test_get_settings_defaults(client):
    r = client.get("/v1/caddy/config/settings")
    assert r.status_code == 200
    body = r.json()
    assert body["http_port"] == 80
    assert body["https_port"] == 443
    assert body["admin_port"] == 2019
    assert body["auto_https"] == "off"
    assert body["tls_ca"] == ""


def test_patch_settings(client):
    r = client.patch("/v1/caddy/config/settings", json={"http_port": 8080, "tls_email": "admin@example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["http_port"] == 8080
    assert body["tls_email"] == "admin@example.com"
    assert body["https_port"] == 443  # unchanged


# ── pending_changes lifecycle ─────────────────────────────────────────────────

def test_pending_changes_false_initially(plugin, client):
    assert client.get("/v1/caddy/status").json()["pending_changes"] is False


def test_pending_changes_true_after_add(plugin, client):
    # Deferred model: pending_changes is only True once a current snapshot exists.
    # Apply with empty state first to establish current, then mutate.
    client.post("/v1/caddy/apply")
    client.post("/v1/caddy/config/apps", json={"name": "a", "upstream": "http://127.0.0.1:8000"})
    assert client.get("/v1/caddy/status").json()["pending_changes"] is True


def test_pending_changes_false_after_apply(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "a", "upstream": "http://127.0.0.1:8000"})
    r = client.post("/v1/caddy/apply")
    assert r.status_code == 200
    assert r.json()["success"] is True
    assert client.get("/v1/caddy/status").json()["pending_changes"] is False


# ── first apply ───────────────────────────────────────────────────────────────

def test_first_apply_starts_service(plugin, client, tmp_path):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    r = client.post("/v1/caddy/apply")
    assert r.status_code == 200

    calls = plugin._pyinfra_run.call_args_list
    # call[0]: files_ops.put — copy caddy.json to system location
    assert calls[0].args[0].__name__ == "put"
    assert calls[0].kwargs["dest"] == str(plugin._system_conf)
    assert calls[0].kwargs["mode"] == "644"
    # call[1]: files_ops.put — systemd drop-in override pointing at system location
    assert calls[1].args[0].__name__ == "put"
    assert calls[1].kwargs["dest"] == str(plugin._OVERRIDE_PATH)
    override_text = calls[1].kwargs["src"].getvalue()
    assert "ExecStart=" in override_text
    assert str(plugin._system_conf) in override_text
    # call[2]: systemd_ops.daemon_reload
    assert calls[2].args[0].__name__ == "daemon_reload"
    # call[3]: systemd_ops.service — start and enable
    assert calls[3].args[0].__name__ == "service"
    assert calls[3].kwargs["service"] == "caddy"
    assert calls[3].kwargs["running"] is True
    assert calls[3].kwargs["enabled"] is True

    # Admin API should NOT be called on first apply
    plugin._caddy_admin_load.assert_not_called()


def test_first_apply_sets_current_snapshot(plugin, client):
    assert plugin._state_file.current_snapshot is None
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    assert plugin._state_file.current_snapshot is not None
    assert "ff" in plugin._state_file.current_snapshot["apps"]


def test_first_apply_writes_data_dir_file(plugin, client, tmp_path):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    data_file = tmp_path / "data" / "caddy.json"
    assert data_file.exists()
    config = json.loads(data_file.read_text())
    assert "apps" in config
    assert "http" in config["apps"]


# ── subsequent apply ──────────────────────────────────────────────────────────

def _write_matching_override(plugin: Any) -> None:
    """Simulate the systemd override file being present and matching desired content."""
    plugin._OVERRIDE_PATH.write_text(
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/caddy run --environ --config {plugin._system_conf}\n"
    )


def test_subsequent_apply_uses_admin_api(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    _write_matching_override(plugin)
    plugin._pyinfra_run.reset_mock()
    plugin._caddy_admin_load.reset_mock()

    client.post("/v1/caddy/config/apps", json={"name": "app2", "upstream": "http://127.0.0.1:9000"})
    r = client.post("/v1/caddy/apply")
    assert r.status_code == 200

    # override unchanged — only the system_conf copy, admin API used for hot-reload
    assert plugin._pyinfra_run.call_count == 1
    assert plugin._pyinfra_run.call_args.args[0].__name__ == "put"
    assert plugin._pyinfra_run.call_args.kwargs["dest"] == str(plugin._system_conf)

    plugin._caddy_admin_load.assert_called_once()
    config_json_arg = plugin._caddy_admin_load.call_args.args[0]
    loaded = json.loads(config_json_arg)
    routes = loaded["apps"]["http"]["servers"]["main"]["routes"]
    dials = [r["handle"][0]["upstreams"][0]["dial"] for r in routes]
    assert "127.0.0.1:9000" in dials


def test_subsequent_apply_passes_admin_port(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    _write_matching_override(plugin)
    client.patch("/v1/caddy/config/settings", json={"admin_port": 2020})
    client.post("/v1/caddy/apply")
    _, port_arg = plugin._caddy_admin_load.call_args.args
    assert port_arg == 2020


# ── apply failure ─────────────────────────────────────────────────────────────

def test_apply_failure_returns_500(plugin, client):
    plugin._pyinfra_run.side_effect = RuntimeError("pyinfra failed")
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    r = client.post("/v1/caddy/apply")
    assert r.status_code == 500


def test_apply_failure_does_not_update_snapshot(plugin, client):
    plugin._pyinfra_run.side_effect = RuntimeError("pyinfra failed")
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    assert plugin._state_file.current_snapshot is None


def test_apply_failure_emits_event(plugin, client):
    plugin._pyinfra_run.side_effect = RuntimeError("pyinfra failed")
    received: list[Event] = []
    global_bus.subscribe("caddy.config.applied", received.append)
    try:
        client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
        client.post("/v1/caddy/apply")
        assert len(received) == 1
        assert received[0].payload["success"] is False
    finally:
        global_bus.unsubscribe("caddy.config.applied", received.append)


# ── discard ───────────────────────────────────────────────────────────────────

def test_discard_no_snapshot_returns_409(client):
    r = client.post("/v1/caddy/discard")
    assert r.status_code == 409


def test_discard_restores_state(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "keep", "upstream": "http://127.0.0.1:9001"})
    client.post("/v1/caddy/apply")
    client.post("/v1/caddy/config/apps", json={"name": "temp", "upstream": "http://127.0.0.1:9002"})
    assert client.get("/v1/caddy/config/apps").json()["count"] == 3  # fastfirewall + keep + temp

    r = client.post("/v1/caddy/discard")
    assert r.status_code == 200
    assert r.json()["discarded"] is True
    names = {a["name"] for a in client.get("/v1/caddy/config/apps").json()["apps"]}
    assert "keep" in names
    assert "temp" not in names


def test_discard_emits_event(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")

    received: list[Event] = []
    global_bus.subscribe("caddy.config.discarded", received.append)
    try:
        client.post("/v1/caddy/discard")
        assert len(received) == 1
    finally:
        global_bus.unsubscribe("caddy.config.discarded", received.append)


# ── event registration ────────────────────────────────────────────────────────

def test_register_event_adds_app(plugin, client):
    # @on wiring is done by the loader; call handler directly in unit tests
    plugin._on_register(Event("app_proxy.register", payload={
        "name": "evented",
        "upstream": "http://127.0.0.1:7000",
        "path_prefix": "/evented",
        "description": "from event",
    }))
    r = client.get("/v1/caddy/config/apps/evented")
    assert r.status_code == 200
    assert r.json()["upstream"] == "http://127.0.0.1:7000"
    assert r.json()["path_prefix"] == "/evented"


def test_register_event_upserts(plugin, client):
    plugin._on_register(Event("app_proxy.register", payload={"name": "app", "upstream": "http://127.0.0.1:8000"}))
    plugin._on_register(Event("app_proxy.register", payload={"name": "app", "upstream": "http://127.0.0.1:8001"}))
    assert client.get("/v1/caddy/config/apps/app").json()["upstream"] == "http://127.0.0.1:8001"


def test_register_event_missing_fields_ignored(plugin, client):
    plugin._on_register(Event("app_proxy.register", payload={"name": "noups"}))
    assert client.get("/v1/caddy/config/apps/noups").status_code == 404

    plugin._on_register(Event("app_proxy.register", payload={"upstream": "http://127.0.0.1:9000"}))
    assert client.get("/v1/caddy/config/apps").json()["count"] == 1  # only the default fastfirewall app


def test_unregister_event_removes_app(plugin, client):
    plugin._on_register(Event("app_proxy.register", payload={"name": "torem", "upstream": "http://127.0.0.1:9000"}))
    assert client.get("/v1/caddy/config/apps").json()["count"] == 2  # fastfirewall + torem
    plugin._on_unregister(Event("app_proxy.unregister", payload={"name": "torem"}))
    assert client.get("/v1/caddy/config/apps").json()["count"] == 1  # only fastfirewall remains


def test_unregister_event_unknown_name_noop(plugin, client):
    plugin._on_unregister(Event("app_proxy.unregister", payload={"name": "ghost"}))
    assert client.get("/v1/caddy/config/apps").json()["count"] == 1  # default fastfirewall unchanged


def test_on_register_handler_marked_with_correct_event(plugin):
    """@on annotation targets app_proxy.register — verified via the marker attribute."""
    from plugin_system.core.decorators import _HANDLER_EVENTS_ATTR
    handler = plugin.__class__._on_register
    assert "app_proxy.register" in getattr(handler, _HANDLER_EVENTS_ATTR, [])


def test_on_unregister_handler_marked_with_correct_event(plugin):
    from plugin_system.core.decorators import _HANDLER_EVENTS_ATTR
    handler = plugin.__class__._on_unregister
    assert "app_proxy.unregister" in getattr(handler, _HANDLER_EVENTS_ATTR, [])


# ── config generation ─────────────────────────────────────────────────────────

def test_build_config_structure(plugin):
    state = {
        "apps": {
            "ff": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/"},
        },
        "settings": {
            "http_port": 80,
            "https_port": 443,
            "admin_port": 2019,
            "auto_https": "off",
            "tls_email": "",
        },
    }
    config = plugin._build_caddy_config(state)
    # No admin key in state → falls back to localhost:{admin_port}
    assert config["admin"]["listen"] == "localhost:2019"
    assert config["apps"]["http"]["http_port"] == 80
    assert config["apps"]["http"]["https_port"] == 443
    server = config["apps"]["http"]["servers"]["main"]
    assert ":80" in server["listen"]
    assert ":443" not in server["listen"]  # no HTTPS listener when auto_https is "off"
    assert server["automatic_https"]["disable"] is True
    assert "tls" not in config["apps"]



def test_build_config_root_prefix_no_match(plugin):
    state = {
        "apps": {"ff": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/"}},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    routes = config["apps"]["http"]["servers"]["main"]["routes"]
    assert len(routes) == 1
    assert "match" not in routes[0]


def test_build_config_path_prefix_match(plugin):
    state = {
        "apps": {"api": {"upstream": "http://127.0.0.1:9000", "path_prefix": "/api"}},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    routes = config["apps"]["http"]["servers"]["main"]["routes"]
    assert routes[0]["match"] == [{"path": ["/api*"]}]


def test_build_config_route_ordering(plugin):
    """Longer path prefixes must come before shorter ones; '/' always last."""
    state = {
        "apps": {
            "root": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/"},
            "api": {"upstream": "http://127.0.0.1:9000", "path_prefix": "/api"},
            "apiv2": {"upstream": "http://127.0.0.1:9001", "path_prefix": "/api/v2"},
        },
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    routes = config["apps"]["http"]["servers"]["main"]["routes"]
    assert len(routes) == 3
    # Last route is the catch-all (no match block)
    assert "match" not in routes[-1]
    # First route is the longest prefix
    first_paths = routes[0]["match"][0]["path"]
    assert first_paths == ["/api/v2*"]
    second_paths = routes[1]["match"][0]["path"]
    assert second_paths == ["/api*"]


def test_build_config_dial_strips_scheme(plugin):
    state = {
        "apps": {"ff": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/"}},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    dial = config["apps"]["http"]["servers"]["main"]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
    assert dial == "127.0.0.1:8000"


def test_build_config_tls_block_when_email_set(plugin):
    state = {
        "apps": {},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "", "tls_email": "admin@example.com"},
    }
    config = plugin._build_caddy_config(state)
    assert "tls" in config["apps"]
    assert config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["email"] == "admin@example.com"
    assert "automatic_https" not in config["apps"]["http"]["servers"]["main"]
    # auto_https active — both ports bound
    assert ":443" in config["apps"]["http"]["servers"]["main"]["listen"]


def test_build_config_forwarded_headers(plugin):
    state = {
        "apps": {"ff": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/"}},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    headers = config["apps"]["http"]["servers"]["main"]["routes"][0]["handle"][0]["headers"]
    assert "X-Forwarded-Proto" in headers["request"]["set"]
    assert "X-Forwarded-Host" in headers["request"]["set"]
    assert "X-Real-IP" in headers["request"]["set"]
    assert "X-Forwarded-For" in headers["request"]["add"]


def test_build_config_path_prefix_trailing_slash_stripped(plugin):
    """A path_prefix of '/api/' should produce the match '/api*' not '/api/*'."""
    state = {
        "apps": {"app": {"upstream": "http://127.0.0.1:9000", "path_prefix": "/app/"}},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    match_path = config["apps"]["http"]["servers"]["main"]["routes"][0]["match"][0]["path"][0]
    assert match_path == "/app*"



def test_build_config_routes_are_terminal(plugin):
    state = {
        "apps": {"ff": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/"}},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "off", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    routes = config["apps"]["http"]["servers"]["main"]["routes"]
    assert all(r.get("terminal") is True for r in routes)


def test_build_config_auto_https_disable_redirects(plugin):
    state = {
        "apps": {},
        "settings": {"http_port": 80, "https_port": 443, "admin_port": 2019, "auto_https": "disable_redirects", "tls_email": ""},
    }
    config = plugin._build_caddy_config(state)
    server = config["apps"]["http"]["servers"]["main"]
    assert server["automatic_https"] == {"disable_redirects": True}
    assert ":443" in server["listen"]  # HTTPS listener active for TLS termination


def test_build_config_tls_ca(plugin):
    state = {
        "apps": {},
        "settings": {
            "http_port": 80, "https_port": 443, "admin_port": 2019,
            "auto_https": "on", "tls_email": "admin@example.com",
            "tls_ca": "https://acme-staging-v02.api.letsencrypt.org/directory",
        },
    }
    config = plugin._build_caddy_config(state)
    issuer = config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]
    assert issuer["email"] == "admin@example.com"
    assert issuer["ca"] == "https://acme-staging-v02.api.letsencrypt.org/directory"


# ── check (dry-run preview) ───────────────────────────────────────────────────

def test_check_returns_config_preview(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    r = client.post("/v1/caddy/check")
    assert r.status_code == 200
    body = r.json()
    assert "config" in body
    assert "changes" in body
    assert "admin" in body["config"]
    assert "http" in body["config"]["apps"]


def test_check_shows_added_apps(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    r = client.post("/v1/caddy/check")
    body = r.json()
    # No current snapshot yet — all apps show as added
    assert "ff" in body["changes"]["apps"]["added"]
    assert body["changes"]["apps"]["removed"] == []


def test_check_shows_diff_after_first_apply(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    client.post("/v1/caddy/config/apps", json={"name": "new", "upstream": "http://127.0.0.1:9000"})
    r = client.post("/v1/caddy/check")
    body = r.json()
    assert "new" in body["changes"]["apps"]["added"]
    assert body["changes"]["apps"]["removed"] == []


def test_check_shows_modified_app(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/apply")
    client.put("/v1/caddy/config/apps/ff", json={"name": "ff", "upstream": "http://127.0.0.1:9999"})
    r = client.post("/v1/caddy/check")
    body = r.json()
    assert "ff" in body["changes"]["apps"]["modified"]


def test_check_does_not_modify_state(plugin, client):
    client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
    client.post("/v1/caddy/check")
    assert plugin._state_file.current_snapshot is None
    plugin._pyinfra_run.assert_not_called()


# ── boot apply ───────────────────────────────────────────────────────────────

def test_boot_applies_desired_state(tmp_path):
    # Boot apply fires via plugins.all_loaded, not setup()
    plugin = _make_plugin(tmp_path, config={"ignore_state_on_boot": False})
    plugin._on_plugins_loaded(Event("plugins.all_loaded", payload={}))
    assert plugin._state_file.current_snapshot is not None
    assert "fastfirewall" in plugin._state_file.current_snapshot["apps"]


def test_boot_ignore_state_skips_apply(tmp_path):
    plugin = _make_plugin(tmp_path, config={"ignore_state_on_boot": True})
    plugin._on_plugins_loaded(Event("plugins.all_loaded", payload={}))
    assert plugin._state_file.current_snapshot is None
    plugin._pyinfra_run.assert_not_called()


def test_boot_falls_back_to_current_on_desired_failure(tmp_path):
    plugin = _make_plugin(tmp_path)
    current = {"apps": {"old": {"upstream": "http://127.0.0.1:7000", "path_prefix": "/", "description": "", "source": "api"}}, "settings": dict(_DEFAULT_SETTINGS)}
    plugin._state_file.save_and_commit(current)
    plugin._state = {"apps": {"new": {"upstream": "http://127.0.0.1:8000", "path_prefix": "/", "description": "", "source": "api"}}, "settings": dict(_DEFAULT_SETTINGS)}

    call_count = 0
    def fail_first_succeed_rest(op, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("simulated desired apply failure")
    plugin._pyinfra_run = fail_first_succeed_rest

    plugin._apply_state()

    # State rolled back to current
    assert "old" in plugin._state["apps"]
    assert "new" not in plugin._state["apps"]
    assert plugin._state_file.current_snapshot == current


def test_boot_errors_out_when_both_states_fail(tmp_path):
    plugin = _make_plugin(tmp_path)
    current = {"apps": {}, "settings": dict(_DEFAULT_SETTINGS)}
    plugin._state_file.save_and_commit(current)
    plugin._pyinfra_run = MagicMock(side_effect=RuntimeError("always fails"))

    with pytest.raises(RuntimeError, match="failed to apply state on boot"):
        plugin._apply_state()


def test_boot_errors_out_when_no_current_and_desired_fails(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._state["apps"]["ff"] = {"upstream": "http://127.0.0.1:8000", "path_prefix": "/", "description": "", "source": "api"}
    plugin._pyinfra_run = MagicMock(side_effect=RuntimeError("always fails"))

    with pytest.raises(RuntimeError, match="failed to apply state on boot"):
        plugin._apply_state()


# ── apply emits success event ─────────────────────────────────────────────────

def test_apply_emits_success_event(plugin, client):
    received: list[Event] = []
    global_bus.subscribe("caddy.config.applied", received.append)
    try:
        client.post("/v1/caddy/config/apps", json={"name": "ff", "upstream": "http://127.0.0.1:8000"})
        client.post("/v1/caddy/apply")
        assert len(received) == 1
        assert received[0].payload["success"] is True
    finally:
        global_bus.unsubscribe("caddy.config.applied", received.append)
