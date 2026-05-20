"""
Tests for the Apt-Cacher-NG plugin routes (/v1/apt_cacher_ng/*).

The plugin is loaded via importlib with pyinfra and subprocess interactions
replaced by mocks so apt-cacher-ng does not need to be installed.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugin_system.core.events import Event, bus as global_bus
from plugin_system.core.macros import macro_registry

PLUGIN_PY = Path(__file__).parent / "plugin.py"

_SAMPLE_CONF = """\
# apt-cacher-ng sample config
CacheDir: /var/cache/apt-cacher-ng
LogDir: /var/log/apt-cacher-ng
Port: 3142
FetchTimeout: 60
"""


# ── helpers ──────────────────────────────────────────────────────────────────────

def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _load_module():
    name = "_test_apt_cacher_ng"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_PY)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_inst(tmp_path: Path, conf_content: str | None = None) -> Any:
    mod = _load_module()
    inst = mod.AptCacherNgPlugin()
    inst.plugin_id = "apt_cacher_ng"
    inst.meta = {"name": "Apt-Cacher-NG Plugin", "version": "1.0.0", "description": "", "author": ""}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.apt_cacher_ng")

    conf_file = tmp_path / "acng.conf"
    if conf_content is not None:
        conf_file.write_text(conf_content)

    inst.config = {
        "state_file": "apt_cacher_ng_state.json",
        "conf_file": str(conf_file),
        "cache_dir": str(tmp_path / "cache"),
        "log_dir": str(tmp_path / "logs"),
        "ignore_state_on_boot": True,
    }
    inst._pyinfra_run = MagicMock()
    inst._run_cmd = MagicMock(return_value=_proc(0))
    inst.setup()
    return inst


def _make_client(
    tmp_path: Path,
    conf_content: str | None = None,
) -> tuple[TestClient, Any]:
    inst = _make_inst(tmp_path, conf_content)
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/apt_cacher_ng")
    return TestClient(app, raise_server_exceptions=False), inst


# ── fixtures ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def ctx(tmp_path):
    return _make_client(tmp_path)


@pytest.fixture
def client(ctx):
    return ctx[0]


# ── status ────────────────────────────────────────────────────────────────────────

def test_status_returns_plugin_metadata(client):
    r = client.get("/v1/apt_cacher_ng/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "Apt-Cacher-NG Plugin"
    assert data["version"] == "1.0.0"


def test_status_includes_service_key(client):
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert "apt-cacher-ng" in data["service"]


def test_status_reflects_systemctl_active(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0, "active")
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert data["service"]["apt-cacher-ng"] == "active"


def test_status_reflects_systemctl_inactive(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(1, "inactive")
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert data["service"]["apt-cacher-ng"] == "inactive"


def test_status_includes_apt_proxy_conf(client):
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert data["apt_proxy_conf"].startswith('Acquire::http::proxy "http://')
    assert data["apt_proxy_conf"].endswith('";')
    assert data["apt_proxy_conf"].split('"')[1] == data["proxy_url"]


def test_status_includes_proxy_url(client):
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert "proxy_url" in data
    assert data["proxy_url"].startswith("http://")
    assert ":3142/" in data["proxy_url"]


def test_status_proxy_url_reflects_configured_port(tmp_path):
    client, inst = _make_client(tmp_path, conf_content="Port: 3150\n")
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert ":3150/" in data["proxy_url"]


def test_status_proxy_url_uses_lan_macro_when_registered(tmp_path):
    macro_registry.register_namespace("interface", lambda *s: ["10.0.0.5"] if s == ("lan", "address") else None)
    try:
        client, inst = _make_client(tmp_path)
        data = client.get("/v1/apt_cacher_ng/status").json()
        assert "10.0.0.5" in data["proxy_url"]
    finally:
        macro_registry.unregister_namespace("interface")


def test_status_proxy_url_falls_back_to_fqdn_when_macro_absent(client):
    import socket
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert socket.getfqdn() in data["proxy_url"]


def test_status_proxy_url_falls_back_when_lan_alias_missing(tmp_path):
    macro_registry.register_namespace("interface", lambda *s: None)
    try:
        client, inst = _make_client(tmp_path)
        import socket
        data = client.get("/v1/apt_cacher_ng/status").json()
        assert socket.getfqdn() in data["proxy_url"]
    finally:
        macro_registry.unregister_namespace("interface")


# ── proxy-url endpoints ───────────────────────────────────────────────────────────

def test_get_proxy_url_returns_structure(client):
    data = client.get("/v1/apt_cacher_ng/proxy-url").json()
    assert "proxy_url" in data
    assert "host" in data
    assert "port" in data
    assert "host_source" in data


def test_get_proxy_url_default_source_is_fqdn_or_macro(client):
    data = client.get("/v1/apt_cacher_ng/proxy-url").json()
    assert data["host_source"] in ("fqdn", "macro")


def test_get_proxy_url_default_port_is_3142(client):
    assert client.get("/v1/apt_cacher_ng/proxy-url").json()["port"] == 3142


def test_set_proxy_host_stores_override(ctx):
    client, inst = ctx
    r = client.put("/v1/apt_cacher_ng/proxy-url", json={"host": "192.168.1.50"})
    assert r.status_code == 200
    assert inst._state["proxy_host"] == "192.168.1.50"


def test_set_proxy_host_reflects_in_proxy_url(ctx):
    client, inst = ctx
    client.put("/v1/apt_cacher_ng/proxy-url", json={"host": "192.168.1.50"})
    data = client.get("/v1/apt_cacher_ng/proxy-url").json()
    assert data["host"] == "192.168.1.50"
    assert data["host_source"] == "override"
    assert "192.168.1.50" in data["proxy_url"]


def test_set_proxy_host_overrides_macro(tmp_path):
    macro_registry.register_namespace("interface", lambda *s: ["10.0.0.5"] if s == ("lan", "address") else None)
    try:
        client, inst = _make_client(tmp_path)
        client.put("/v1/apt_cacher_ng/proxy-url", json={"host": "myproxy.local"})
        data = client.get("/v1/apt_cacher_ng/proxy-url").json()
        assert data["host"] == "myproxy.local"
        assert data["host_source"] == "override"
    finally:
        macro_registry.unregister_namespace("interface")


def test_set_proxy_host_empty_string_rejected(ctx):
    client, inst = ctx
    r = client.put("/v1/apt_cacher_ng/proxy-url", json={"host": ""})
    assert r.status_code == 422


def test_clear_proxy_host_removes_override(ctx):
    client, inst = ctx
    client.put("/v1/apt_cacher_ng/proxy-url", json={"host": "192.168.1.50"})
    r = client.delete("/v1/apt_cacher_ng/proxy-url")
    assert r.status_code == 200
    assert inst._state["proxy_host"] is None


def test_clear_proxy_host_falls_back_to_fqdn(ctx):
    import socket
    client, inst = ctx
    client.put("/v1/apt_cacher_ng/proxy-url", json={"host": "192.168.1.50"})
    client.delete("/v1/apt_cacher_ng/proxy-url")
    data = client.get("/v1/apt_cacher_ng/proxy-url").json()
    assert data["host_source"] in ("fqdn", "macro")
    assert "192.168.1.50" not in data["proxy_url"]


def test_proxy_host_persists_across_restart(tmp_path):
    inst1 = _make_inst(tmp_path)
    app1 = FastAPI()
    app1.include_router(inst1.router, prefix="/v1/apt_cacher_ng")
    c1 = TestClient(app1, raise_server_exceptions=False)
    c1.put("/v1/apt_cacher_ng/proxy-url", json={"host": "10.1.2.3"})

    inst2 = _make_inst(tmp_path)
    inst2.config["ignore_state_on_boot"] = False
    inst2._state = inst2._state_file.load_desired(default={"acng_settings": {}, "proxy_host": None})
    assert inst2._state["proxy_host"] == "10.1.2.3"


def test_status_uses_override_when_set(ctx):
    client, inst = ctx
    client.put("/v1/apt_cacher_ng/proxy-url", json={"host": "10.9.8.7"})
    data = client.get("/v1/apt_cacher_ng/status").json()
    assert "10.9.8.7" in data["proxy_url"]


def test_status_managed_settings_starts_at_zero(client):
    assert client.get("/v1/apt_cacher_ng/status").json()["managed_settings"] == 0


def test_status_pending_changes_false_at_start(client):
    assert client.get("/v1/apt_cacher_ng/status").json()["pending_changes"] is False


def test_status_managed_settings_increments(ctx):
    client, inst = ctx
    client.patch("/v1/apt_cacher_ng/config", json={"port": 3143})
    assert client.get("/v1/apt_cacher_ng/status").json()["managed_settings"] == 1


# ── config GET ────────────────────────────────────────────────────────────────────

def test_get_config_reads_live_conf(tmp_path):
    client, inst = _make_client(tmp_path, conf_content=_SAMPLE_CONF)
    data = client.get("/v1/apt_cacher_ng/config").json()
    assert data["settings"]["Port"]["value"] == "3142"
    assert data["settings"]["FetchTimeout"]["value"] == "60"


def test_get_config_returns_empty_when_no_conf(client):
    data = client.get("/v1/apt_cacher_ng/config").json()
    assert isinstance(data["settings"], dict)


def test_get_config_marks_managed_keys(tmp_path):
    client, inst = _make_client(tmp_path, conf_content=_SAMPLE_CONF)
    inst._state["acng_settings"] = {"port": 3142}
    data = client.get("/v1/apt_cacher_ng/config").json()
    assert data["settings"]["Port"]["managed"] is True


def test_get_config_marks_unmanaged_keys(tmp_path):
    client, inst = _make_client(tmp_path, conf_content=_SAMPLE_CONF)
    data = client.get("/v1/apt_cacher_ng/config").json()
    assert data["settings"]["Port"]["managed"] is False


def test_get_config_includes_conf_file_path(tmp_path):
    client, inst = _make_client(tmp_path, conf_content=_SAMPLE_CONF)
    data = client.get("/v1/apt_cacher_ng/config").json()
    assert "conf_file" in data


def test_get_config_field_name_mapped(tmp_path):
    client, inst = _make_client(tmp_path, conf_content=_SAMPLE_CONF)
    data = client.get("/v1/apt_cacher_ng/config").json()
    assert data["settings"]["Port"]["field"] == "port"
    assert data["settings"]["FetchTimeout"]["field"] == "fetch_timeout"


# ── config PATCH ──────────────────────────────────────────────────────────────────

def test_update_config_stores_setting(ctx):
    client, inst = ctx
    r = client.patch("/v1/apt_cacher_ng/config", json={"port": 3143})
    assert r.status_code == 200
    assert inst._state["acng_settings"]["port"] == 3143


def test_update_config_writes_conf_file(ctx):
    client, inst = ctx
    client.patch("/v1/apt_cacher_ng/config", json={"port": 3143})
    assert inst._pyinfra_run.called


def test_update_config_reloads_service(ctx):
    client, inst = ctx
    client.patch("/v1/apt_cacher_ng/config", json={"port": 3143})
    reload_calls = [
        c for c in inst._run_cmd.call_args_list
        if "reload-or-restart" in str(c)
    ]
    assert reload_calls


def test_update_config_returns_updated_keys(ctx):
    client, inst = ctx
    r = client.patch("/v1/apt_cacher_ng/config", json={"port": 3143, "fetch_timeout": 90})
    data = r.json()
    assert set(data["updated"]) == {"port", "fetch_timeout"}


def test_update_config_bool_setting(ctx):
    client, inst = ctx
    r = client.patch("/v1/apt_cacher_ng/config", json={"force_managed": True})
    assert r.status_code == 200
    assert inst._state["acng_settings"]["force_managed"] is True


def test_update_config_empty_body_returns_400(ctx):
    client, inst = ctx
    r = client.patch("/v1/apt_cacher_ng/config", json={})
    assert r.status_code == 400


def test_update_config_invalid_port_returns_422(ctx):
    client, inst = ctx
    r = client.patch("/v1/apt_cacher_ng/config", json={"port": 99999})
    assert r.status_code == 422


def test_update_config_service_reload_failure_returns_500(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(1, "", "Failed to reload")
    r = client.patch("/v1/apt_cacher_ng/config", json={"port": 3143})
    assert r.status_code == 500


# ── config reload ─────────────────────────────────────────────────────────────────

def test_reload_calls_systemctl(ctx):
    client, inst = ctx
    r = client.post("/v1/apt_cacher_ng/config/reload")
    assert r.status_code == 200
    assert r.json()["reloaded"] is True
    reload_calls = [c for c in inst._run_cmd.call_args_list if "reload-or-restart" in str(c)]
    assert reload_calls


def test_reload_failure_returns_500(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(1, "", "Unit not found")
    r = client.post("/v1/apt_cacher_ng/config/reload")
    assert r.status_code == 500


def test_reload_emits_event(ctx):
    client, inst = ctx
    received: list[Event] = []
    global_bus.subscribe("apt_cacher_ng.service.reloaded", received.append)
    try:
        client.post("/v1/apt_cacher_ng/config/reload")
        assert len(received) == 1
    finally:
        global_bus.unsubscribe("apt_cacher_ng.service.reloaded", received.append)


# ── raw config ────────────────────────────────────────────────────────────────────

def test_get_raw_conf_returns_content(tmp_path):
    client, inst = _make_client(tmp_path, conf_content=_SAMPLE_CONF)
    r = client.get("/v1/apt_cacher_ng/config/raw")
    assert r.status_code == 200
    data = r.json()
    assert "Port: 3142" in data["content"]
    assert "path" in data


def test_get_raw_conf_missing_returns_404(client):
    r = client.get("/v1/apt_cacher_ng/config/raw")
    assert r.status_code == 404


# ── cache stats ───────────────────────────────────────────────────────────────────

def test_cache_stats_missing_dir(client):
    data = client.get("/v1/apt_cacher_ng/cache").json()
    assert data["exists"] is False


def test_cache_stats_returns_disk_usage(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    client, inst = _make_client(tmp_path)
    inst._run_cmd.side_effect = [
        _proc(0, f"1048576\t{cache_dir}\n"),  # du -sb
        _proc(0, f"{cache_dir}/pkg1.deb\n{cache_dir}/pkg2.deb\n"),  # find
    ]
    data = client.get("/v1/apt_cacher_ng/cache").json()
    assert data["exists"] is True
    assert data["total_bytes"] == 1048576
    assert data["total_mb"] == 1.0
    assert data["file_count"] == 2


# ── cache flush ───────────────────────────────────────────────────────────────────

def test_flush_cache_missing_dir_returns_404(client):
    r = client.delete("/v1/apt_cacher_ng/cache")
    assert r.status_code == 404


def test_flush_cache_calls_find_delete(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    client, inst = _make_client(tmp_path)
    r = client.delete("/v1/apt_cacher_ng/cache")
    assert r.status_code == 200
    assert r.json()["flushed"] is True
    find_calls = [c for c in inst._run_cmd.call_args_list if "-delete" in str(c)]
    assert find_calls


def test_flush_cache_failure_returns_500(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    client, inst = _make_client(tmp_path)
    inst._run_cmd.return_value = _proc(1, "", "Permission denied")
    r = client.delete("/v1/apt_cacher_ng/cache")
    assert r.status_code == 500


def test_flush_cache_emits_event(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    client, inst = _make_client(tmp_path)
    received: list[Event] = []
    global_bus.subscribe("apt_cacher_ng.cache.flushed", received.append)
    try:
        client.delete("/v1/apt_cacher_ng/cache")
        assert len(received) == 1
        assert "cache_dir" in received[0].payload
    finally:
        global_bus.unsubscribe("apt_cacher_ng.cache.flushed", received.append)


# ── logs ──────────────────────────────────────────────────────────────────────────

def test_get_logs_calls_journalctl(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0, "May 19 10:00:00 host apt-cacher-ng[123]: Started\n")
    r = client.get("/v1/apt_cacher_ng/logs")
    assert r.status_code == 200
    data = r.json()
    assert "content" in data
    assert data["line_count"] == 1
    journalctl_calls = [c for c in inst._run_cmd.call_args_list if "journalctl" in str(c)]
    assert journalctl_calls


def test_get_logs_respects_lines_param(ctx):
    client, inst = ctx
    client.get("/v1/apt_cacher_ng/logs?lines=50")
    journalctl_calls = [c for c in inst._run_cmd.call_args_list if "journalctl" in str(c)]
    assert journalctl_calls
    args = journalctl_calls[0][0][0]
    assert "50" in args


# ── persistence ───────────────────────────────────────────────────────────────────

def test_state_file_created_on_first_load(tmp_path):
    inst = _make_inst(tmp_path)
    inst.config["ignore_state_on_boot"] = False
    inst._state = inst._state_file.load_desired(default={"acng_settings": {}, "proxy_host": None})
    assert (tmp_path / "data" / "apt_cacher_ng_state.json").exists()


def test_settings_persist_across_restart(tmp_path):
    inst1 = _make_inst(tmp_path)
    inst1._run_cmd.return_value = _proc(0)

    app1 = FastAPI()
    app1.include_router(inst1.router, prefix="/v1/apt_cacher_ng")
    c1 = TestClient(app1, raise_server_exceptions=False)
    c1.patch("/v1/apt_cacher_ng/config", json={"port": 3150, "fetch_timeout": 120})

    inst2 = _make_inst(tmp_path)
    inst2.config["ignore_state_on_boot"] = False
    inst2._pyinfra_run = MagicMock()
    inst2._run_cmd = MagicMock(return_value=_proc(0))

    # Reload state from disk the same way the plugin does at startup
    inst2._state = inst2._state_file.load_desired(default={"acng_settings": {}})

    assert inst2._state["acng_settings"]["port"] == 3150
    assert inst2._state["acng_settings"]["fetch_timeout"] == 120


# ── config update event ───────────────────────────────────────────────────────────

def test_update_config_emits_event(ctx):
    client, inst = ctx
    received: list[Event] = []
    global_bus.subscribe("apt_cacher_ng.config.updated", received.append)
    try:
        client.patch("/v1/apt_cacher_ng/config", json={"port": 3143})
        assert len(received) == 1
        assert received[0].payload["keys"] == ["port"]
    finally:
        global_bus.unsubscribe("apt_cacher_ng.config.updated", received.append)


# ── acng.conf rendering ───────────────────────────────────────────────────────────

def test_render_updates_existing_key(tmp_path):
    mod = _load_module()
    conf = tmp_path / "acng.conf"
    conf.write_text("Port: 3142\nFetchTimeout: 60\n")
    result = mod._render_acng_conf(conf, {"Port": "3150"})
    assert "Port: 3150" in result
    assert "FetchTimeout: 60" in result
    assert "Port: 3142" not in result


def test_render_appends_new_key(tmp_path):
    mod = _load_module()
    conf = tmp_path / "acng.conf"
    conf.write_text("Port: 3142\n")
    result = mod._render_acng_conf(conf, {"MaxDlSpeed": "512"})
    assert "Port: 3142" in result
    assert "MaxDlSpeed: 512" in result


def test_render_creates_file_when_missing(tmp_path):
    mod = _load_module()
    conf = tmp_path / "nonexistent.conf"
    result = mod._render_acng_conf(conf, {"Port": "3143"})
    assert "Port: 3143" in result


def test_render_preserves_comments(tmp_path):
    mod = _load_module()
    conf = tmp_path / "acng.conf"
    conf.write_text("# my comment\nPort: 3142\n")
    result = mod._render_acng_conf(conf, {"Port": "3143"})
    assert "# my comment" in result


def test_settings_to_acng_bool_true(tmp_path):
    mod = _load_module()
    out = mod._settings_to_acng({"force_managed": True})
    assert out["ForceManaged"] == "1"


def test_settings_to_acng_bool_false(tmp_path):
    mod = _load_module()
    out = mod._settings_to_acng({"force_managed": False})
    assert out["ForceManaged"] == "0"


def test_parse_acng_conf_skips_comments(tmp_path):
    mod = _load_module()
    conf = tmp_path / "acng.conf"
    conf.write_text("# Port: 9999\nPort: 3142\n")
    out = mod._parse_acng_conf(conf)
    assert out["Port"] == "3142"
    assert "# Port" not in out


def test_parse_acng_conf_missing_returns_empty(tmp_path):
    mod = _load_module()
    out = mod._parse_acng_conf(tmp_path / "missing.conf")
    assert out == {}
