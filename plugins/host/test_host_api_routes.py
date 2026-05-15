"""
Tests for host_plugin routes.

pyinfra calls are mocked via _pyinfra_run so no actual system changes are made.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── helpers ────────────────────────────────────────────────────────────────────

_REPO_ROOT = str(Path(__file__).parents[2])  # plugins/host_plugin → plugins → /app


def _load_pkg_manager_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    pm_py = Path(__file__).parent / "_pkg_manager.py"
    sys.modules.pop("_host_pkg_manager_test", None)
    spec = importlib.util.spec_from_file_location("_host_pkg_manager_test", pm_py)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_host_pkg_manager_test"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _load_plugin_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    plugin_py = Path(__file__).parent / "plugin.py"
    sys.modules.pop("_host_test", None)
    spec = importlib.util.spec_from_file_location("_host_test", plugin_py)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_host_test"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_plugin(tmp_path, config=None, system_repos=None):
    mod = _load_plugin_module()
    plugin = mod.HostPlugin()
    plugin.plugin_id = "host"
    plugin.meta = {"name": "Host Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.host")
    plugin._pyinfra_run = MagicMock()
    plugin.setup()
    plugin._pkg_mgr.list_system_repos = MagicMock(return_value=system_repos or {})
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={})
    plugin._pkg_mgr.list_available_packages = MagicMock(return_value={})
    return plugin


def _make_client(plugin) -> TestClient:
    app = FastAPI()
    app.include_router(plugin.router, prefix="/v1/host")
    return TestClient(app)


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def plugin(tmp_path):
    return _make_plugin(tmp_path)


@pytest.fixture
def client(plugin):
    return _make_client(plugin)


# ── status ─────────────────────────────────────────────────────────────────────

def test_status_returns_plugin_metadata(client):
    r = client.get("/v1/host/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "Host Plugin"
    assert data["version"] == "1.0.0"
    assert "hostname" in data


def test_status_managed_counts_start_at_zero(client):
    r = client.get("/v1/host/status")
    managed = r.json()["managed"]
    assert managed == {"services": 0, "sysctl": 0, "users": 0, "groups": 0, "cron": 0, "packages": 0, "repos": 0}


def test_status_counts_update_after_additions(client):
    client.put("/v1/host/services/nginx", json={"running": True, "enabled": True})
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    managed = client.get("/v1/host/status").json()["managed"]
    assert managed["services"] == 1
    assert managed["sysctl"] == 1


# ── hostname ───────────────────────────────────────────────────────────────────

def test_get_hostname_returns_string(client):
    r = client.get("/v1/host/hostname")
    assert r.status_code == 200
    assert isinstance(r.json()["hostname"], str)


def test_set_hostname_calls_pyinfra(client, plugin):
    r = client.put("/v1/host/hostname", json={"hostname": "mybox.example.com"})
    assert r.status_code == 200
    assert r.json()["hostname"] == "mybox.example.com"
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["hostname"] == "mybox.example.com"


def test_set_hostname_uses_server_hostname_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.put("/v1/host/hostname", json={"hostname": "newhost"})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.hostname


# ── services ───────────────────────────────────────────────────────────────────

def test_list_services_empty(client):
    r = client.get("/v1/host/services")
    assert r.status_code == 200
    assert r.json() == {"services": {}}


def test_set_service_running_and_enabled(client, plugin):
    r = client.put("/v1/host/services/nginx", json={"running": True, "enabled": True})
    assert r.status_code == 200
    assert r.json() == {"service": "nginx", "running": True, "enabled": True}
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["service"] == "nginx"
    assert kwargs["running"] is True
    assert kwargs["enabled"] is True


def test_set_service_stopped_disabled(client, plugin):
    client.put("/v1/host/services/cron", json={"running": False, "enabled": False})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["running"] is False
    assert kwargs["enabled"] is False


def test_set_service_uses_server_service_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.put("/v1/host/services/sshd", json={"running": True, "enabled": True})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.service


def test_list_services_shows_added_entry(client):
    client.put("/v1/host/services/nginx", json={"running": True, "enabled": True})
    r = client.get("/v1/host/services")
    assert "nginx" in r.json()["services"]


def test_delete_service_removes_entry(client):
    client.put("/v1/host/services/nginx", json={"running": True, "enabled": True})
    r = client.delete("/v1/host/services/nginx")
    assert r.status_code == 200
    assert r.json() == {"deleted": "nginx"}
    assert "nginx" not in client.get("/v1/host/services").json()["services"]


def test_delete_service_not_managed_returns_404(client):
    r = client.delete("/v1/host/services/ghost")
    assert r.status_code == 404


# ── sysctl ─────────────────────────────────────────────────────────────────────

def test_list_sysctl_empty(client):
    r = client.get("/v1/host/sysctl")
    assert r.status_code == 200
    assert r.json() == {"sysctl": {}}


def test_set_sysctl_calls_pyinfra(client, plugin):
    r = client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    assert r.status_code == 200
    assert r.json()["key"] == "vm.swappiness"
    assert r.json()["value"] == "10"
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["key"] == "vm.swappiness"
    assert kwargs["value"] == "10"
    assert kwargs["persist"] is True


def test_set_sysctl_persist_false(client, plugin):
    client.put("/v1/host/sysctl/net.ipv4.ip_forward", json={"value": "1", "persist": False})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["persist"] is False


def test_set_sysctl_uses_server_sysctl_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "0"})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.sysctl


def test_set_sysctl_dotted_key(client):
    r = client.put("/v1/host/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    assert r.status_code == 200
    assert r.json()["key"] == "net.ipv4.ip_forward"


def test_list_sysctl_shows_added_key(client):
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    r = client.get("/v1/host/sysctl")
    assert "vm.swappiness" in r.json()["sysctl"]


def test_delete_sysctl_removes_key(client):
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    r = client.delete("/v1/host/sysctl/vm.swappiness")
    assert r.status_code == 200
    assert r.json() == {"deleted": "vm.swappiness"}
    assert "vm.swappiness" not in client.get("/v1/host/sysctl").json()["sysctl"]


def test_delete_sysctl_not_managed_returns_404(client):
    r = client.delete("/v1/host/sysctl/nonexistent.key")
    assert r.status_code == 404


# ── users ──────────────────────────────────────────────────────────────────────

def test_list_users_empty(client):
    assert client.get("/v1/host/users").json() == {"users": {}}


def test_set_user_creates_entry(client, plugin):
    r = client.post("/v1/host/users/deploy", json={"shell": "/bin/bash"})
    assert r.status_code == 201
    assert r.json()["user"] == "deploy"
    assert r.json()["shell"] == "/bin/bash"
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["user"] == "deploy"
    assert kwargs["shell"] == "/bin/bash"


def test_set_user_uses_server_user_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.post("/v1/host/users/ops", json={})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.user


def test_set_user_passes_home_dir_when_given(client, plugin):
    client.post("/v1/host/users/app", json={"home_dir": "/srv/app"})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["home"] == "/srv/app"


def test_set_user_passes_comment_when_given(client, plugin):
    client.post("/v1/host/users/app", json={"comment": "App service account"})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["comment"] == "App service account"


def test_set_user_system_flag(client, plugin):
    client.post("/v1/host/users/svc", json={"system": True})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["system"] is True


def test_list_users_shows_added(client):
    client.post("/v1/host/users/deploy", json={})
    assert "deploy" in client.get("/v1/host/users").json()["users"]


def test_delete_user_removes_entry(client, plugin):
    client.post("/v1/host/users/deploy", json={})
    plugin._pyinfra_run.reset_mock()
    r = client.delete("/v1/host/users/deploy")
    assert r.status_code == 200
    assert r.json() == {"deleted": "deploy"}
    assert "deploy" not in client.get("/v1/host/users").json()["users"]
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["user"] == "deploy"
    assert kwargs["present"] is False


def test_delete_user_not_managed_returns_404(client):
    assert client.delete("/v1/host/users/ghost").status_code == 404


# ── groups ─────────────────────────────────────────────────────────────────────

def test_list_groups_empty(client):
    assert client.get("/v1/host/groups").json() == {"groups": {}}


def test_set_group_creates_entry(client, plugin):
    r = client.post("/v1/host/groups/deploy", json={})
    assert r.status_code == 201
    assert r.json()["group"] == "deploy"
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["group"] == "deploy"


def test_set_group_uses_server_group_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.post("/v1/host/groups/ops", json={})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.group


def test_set_group_passes_gid_when_given(client, plugin):
    client.post("/v1/host/groups/mygroup", json={"gid": 1500})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["gid"] == 1500


def test_set_group_system_flag(client, plugin):
    client.post("/v1/host/groups/svc", json={"system": True})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["system"] is True


def test_list_groups_shows_added(client):
    client.post("/v1/host/groups/deploy", json={})
    assert "deploy" in client.get("/v1/host/groups").json()["groups"]


def test_delete_group_removes_entry(client, plugin):
    client.post("/v1/host/groups/deploy", json={})
    plugin._pyinfra_run.reset_mock()
    r = client.delete("/v1/host/groups/deploy")
    assert r.status_code == 200
    assert r.json() == {"deleted": "deploy"}
    assert "deploy" not in client.get("/v1/host/groups").json()["groups"]
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["group"] == "deploy"
    assert kwargs["present"] is False


def test_delete_group_not_managed_returns_404(client):
    assert client.delete("/v1/host/groups/ghost").status_code == 404


# ── cron ───────────────────────────────────────────────────────────────────────

def test_list_cron_empty(client):
    assert client.get("/v1/host/cron").json() == {"cron": {}}


def test_set_cron_creates_entry(client, plugin):
    r = client.post("/v1/host/cron/backup", json={"command": "/usr/bin/backup.sh", "hour": "2", "minute": "0"})
    assert r.status_code == 201
    assert r.json()["name"] == "backup"
    assert r.json()["command"] == "/usr/bin/backup.sh"
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["command"] == "/usr/bin/backup.sh"
    assert kwargs["hour"] == "2"
    assert kwargs["minute"] == "0"


def test_set_cron_uses_server_crontab_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.post("/v1/host/cron/check", json={"command": "/usr/bin/check.sh"})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.crontab


def test_set_cron_default_schedule_is_all_stars(client, plugin):
    client.post("/v1/host/cron/heartbeat", json={"command": "/bin/true"})
    _, kwargs = plugin._pyinfra_run.call_args
    for field in ("minute", "hour", "day_of_month", "month", "day_of_week"):
        assert kwargs[field] == "*"


def test_set_cron_passes_user(client, plugin):
    client.post("/v1/host/cron/cleanup", json={"command": "/bin/clean.sh", "user": "www-data"})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["user"] == "www-data"


def test_list_cron_shows_added(client):
    client.post("/v1/host/cron/backup", json={"command": "/usr/bin/backup.sh"})
    assert "backup" in client.get("/v1/host/cron").json()["cron"]


def test_delete_cron_removes_entry(client, plugin):
    client.post("/v1/host/cron/backup", json={"command": "/usr/bin/backup.sh"})
    plugin._pyinfra_run.reset_mock()
    r = client.delete("/v1/host/cron/backup")
    assert r.status_code == 200
    assert r.json() == {"deleted": "backup"}
    assert "backup" not in client.get("/v1/host/cron").json()["cron"]
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["command"] == "/usr/bin/backup.sh"
    assert kwargs["present"] is False


def test_delete_cron_not_managed_returns_404(client):
    assert client.delete("/v1/host/cron/ghost").status_code == 404


# ── state persistence ──────────────────────────────────────────────────────────

def test_state_persists_across_plugin_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/host/services/nginx", json={"running": True, "enabled": True})
    c1.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    c1.post("/v1/host/users/deploy", json={})
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert "nginx" in c2.get("/v1/host/services").json()["services"]
    assert "vm.swappiness" in c2.get("/v1/host/sysctl").json()["sysctl"]
    assert "deploy" in c2.get("/v1/host/users").json()["users"]


def test_deleted_entries_absent_after_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/host/services/nginx", json={"running": True, "enabled": True})
    c1.delete("/v1/host/services/nginx")
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert "nginx" not in c2.get("/v1/host/services").json()["services"]


def test_state_file_written_to_configured_path(tmp_path):
    p = _make_plugin(tmp_path, config={"state_file": "custom_state.json"})
    c = _make_client(p)
    c.put("/v1/host/services/sshd", json={"running": True, "enabled": True})
    p.teardown()
    assert (tmp_path / "data" / "custom_state.json").exists()


# ── init script ────────────────────────────────────────────────────────────────

def _init_plugin(tmp_path, init_cfg: dict, *, side_effect=None):
    """Build a HostPlugin with init config nested under 'init' key."""
    mod = _load_plugin_module()
    plugin = mod.HostPlugin()
    plugin.plugin_id = "host"
    plugin.meta = {"name": "Host Plugin", "version": "1.0.0"}
    plugin.config = {"init": init_cfg}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.host")
    plugin._pyinfra_run = MagicMock(side_effect=side_effect)
    return plugin, mod


# ── detection ──────────────────────────────────────────────────────────────────

def test_detect_systemd():
    mod = _load_plugin_module()
    with patch("os.path.isdir", side_effect=lambda p: p == "/run/systemd/system"):
        assert mod.HostPlugin._detect_init_system() == "systemd"


def test_detect_upstart():
    mod = _load_plugin_module()
    with patch("os.path.isdir", side_effect=lambda p: p == "/etc/init"), \
         patch("shutil.which", side_effect=lambda b: "/sbin/initctl" if b == "initctl" else None):
        assert mod.HostPlugin._detect_init_system() == "upstart"


def test_detect_sysvinit():
    mod = _load_plugin_module()
    with patch("os.path.isdir", side_effect=lambda p: p == "/etc/init.d"), \
         patch("shutil.which", return_value=None):
        assert mod.HostPlugin._detect_init_system() == "sysvinit"


def test_detect_unknown():
    mod = _load_plugin_module()
    with patch("os.path.isdir", return_value=False), \
         patch("shutil.which", return_value=None):
        assert mod.HostPlugin._detect_init_system() == "unknown"


def test_detect_systemd_takes_priority_over_sysvinit():
    mod = _load_plugin_module()
    with patch("os.path.isdir", return_value=True):  # all paths "exist"
        assert mod.HostPlugin._detect_init_system() == "systemd"


# ── service definition templates ───────────────────────────────────────────────

def test_systemd_unit_contains_execstart():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-claude", "uv run /app/app.py")
    assert "ExecStart=uv run /app/app.py" in unit
    assert "WantedBy=multi-user.target" in unit
    assert "Restart=on-failure" in unit


def test_systemd_unit_working_dir():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-claude", "uv run /app/app.py", working_dir="/app")
    assert "WorkingDirectory=/app" in unit


def test_systemd_unit_no_working_dir_omits_line():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-claude", "uv run /app/app.py")
    assert "WorkingDirectory" not in unit


def test_upstart_conf_contains_exec():
    mod = _load_plugin_module()
    conf = mod.HostPlugin._upstart_conf("ff-claude", "uv run /app/app.py")
    assert "exec uv run /app/app.py" in conf
    assert "respawn" in conf
    assert "start on runlevel" in conf


def test_upstart_conf_working_dir():
    mod = _load_plugin_module()
    conf = mod.HostPlugin._upstart_conf("ff-claude", "uv run /app/app.py", working_dir="/app")
    assert "chdir /app" in conf


def test_upstart_conf_no_working_dir_omits_line():
    mod = _load_plugin_module()
    conf = mod.HostPlugin._upstart_conf("ff-claude", "uv run /app/app.py")
    assert "chdir" not in conf


def test_sysvinit_script_contains_command():
    mod = _load_plugin_module()
    script = mod.HostPlugin._sysvinit_script("ff-claude", "uv run /app/app.py")
    assert "uv run /app/app.py" in script
    assert "BEGIN INIT INFO" in script
    assert "#!/bin/sh" in script


def test_sysvinit_script_working_dir():
    mod = _load_plugin_module()
    script = mod.HostPlugin._sysvinit_script("ff-claude", "uv run /app/app.py", working_dir="/app")
    assert "cd /app && uv run /app/app.py" in script


def test_sysvinit_script_no_working_dir_omits_cd():
    mod = _load_plugin_module()
    script = mod.HostPlugin._sysvinit_script("ff-claude", "uv run /app/app.py")
    assert "cd " not in script


# ── setup integration ──────────────────────────────────────────────────────────

def test_init_script_skipped_when_disabled(tmp_path):
    plugin, _ = _init_plugin(tmp_path, {"enable_init_script": False})
    plugin.setup()
    plugin._pyinfra_run.assert_not_called()


def test_init_script_unknown_init_system_logs_warning(tmp_path):
    plugin, mod = _init_plugin(tmp_path, {"enable_init_script": True, "service_name": "svc"})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="unknown"), \
         patch.object(plugin.logger, "warning") as mock_warn:
        plugin.setup()
        plugin._pyinfra_run.assert_not_called()
        mock_warn.assert_called_once()


# ── systemd path ───────────────────────────────────────────────────────────────

def test_init_systemd_no_command_skips_file_placement(tmp_path):
    from pyinfra.operations import systemd as systemd_ops
    plugin, mod = _init_plugin(tmp_path, {"enable_init_script": True, "service_name": "ff-claude"})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    ops_called = [call[0][0] for call in plugin._pyinfra_run.call_args_list]
    assert systemd_ops.daemon_reload in ops_called
    assert systemd_ops.service in ops_called
    from pyinfra.operations import files as files_ops
    assert files_ops.put not in ops_called


def test_init_systemd_with_command_places_unit_file(tmp_path):
    from pyinfra.operations import files as files_ops, systemd as systemd_ops
    plugin, mod = _init_plugin(
        tmp_path,
        {"enable_init_script": True, "service_name": "ff-claude", "command": "uv run /app/app.py"},
    )
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    ops_called = [call[0][0] for call in plugin._pyinfra_run.call_args_list]
    assert files_ops.put in ops_called
    assert systemd_ops.daemon_reload in ops_called
    assert systemd_ops.service in ops_called


def test_init_systemd_unit_file_dest(tmp_path):
    from pyinfra.operations import files as files_ops
    plugin, mod = _init_plugin(
        tmp_path,
        {"enable_init_script": True, "service_name": "ff-claude", "command": "uv run /app/app.py"},
    )
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    put_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.put)
    assert put_call[1]["dest"] == "/etc/systemd/system/ff-claude.service"


def test_init_systemd_enables_and_starts_service(tmp_path):
    from pyinfra.operations import systemd as systemd_ops
    plugin, mod = _init_plugin(tmp_path, {"enable_init_script": True, "service_name": "ff-claude"})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    svc_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is systemd_ops.service)
    assert svc_call[1]["running"] is True
    assert svc_call[1]["enabled"] is True


# ── upstart path ───────────────────────────────────────────────────────────────

def test_init_upstart_with_command_places_conf(tmp_path):
    from pyinfra.operations import files as files_ops
    plugin, mod = _init_plugin(
        tmp_path,
        {"enable_init_script": True, "service_name": "ff-claude", "command": "uv run /app/app.py"},
    )
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="upstart"):
        plugin.setup()
    ops_called = [call[0][0] for call in plugin._pyinfra_run.call_args_list]
    assert files_ops.put in ops_called
    put_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.put)
    assert put_call[1]["dest"] == "/etc/init/ff-claude.conf"


def test_init_upstart_starts_service(tmp_path):
    from pyinfra.operations import server as server_ops
    plugin, mod = _init_plugin(tmp_path, {"enable_init_script": True, "service_name": "ff-claude"})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="upstart"):
        plugin.setup()
    svc_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is server_ops.service)
    assert svc_call[1]["running"] is True


# ── sysvinit path ──────────────────────────────────────────────────────────────

def test_init_sysvinit_with_command_places_script(tmp_path):
    from pyinfra.operations import files as files_ops
    plugin, mod = _init_plugin(
        tmp_path,
        {"enable_init_script": True, "service_name": "ff-claude", "command": "uv run /app/app.py"},
    )
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="sysvinit"):
        plugin.setup()
    put_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.put)
    assert put_call[1]["dest"] == "/etc/init.d/ff-claude"
    assert put_call[1]["mode"] == "755"


def test_init_sysvinit_enables_and_starts_service(tmp_path):
    from pyinfra.operations import server as server_ops
    plugin, mod = _init_plugin(tmp_path, {"enable_init_script": True, "service_name": "ff-claude"})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="sysvinit"):
        plugin.setup()
    svc_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is server_ops.service)
    assert svc_call[1]["running"] is True
    assert svc_call[1]["enabled"] is True


# ── failure handling ───────────────────────────────────────────────────────────

def test_init_script_logs_warning_on_failure(tmp_path):
    plugin, mod = _init_plugin(
        tmp_path,
        {"enable_init_script": True, "service_name": "missing-svc"},
        side_effect=Exception("No hosts remaining!"),
    )
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"), \
         patch.object(plugin.logger, "warning") as mock_warn:
        plugin.setup()  # must not raise
        mock_warn.assert_called_once()
        assert "missing-svc" in mock_warn.call_args[0][1]


# ── cache TTL ──────────────────────────────────────────────────────────────────

def test_refresh_cache_runs_when_no_prior_refresh():
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt", cache_ttl=300)
    mgr.refresh_cache()
    runner.assert_called_once()


def test_refresh_cache_skipped_when_fresh():
    import time
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt", cache_ttl=300)
    mgr._cache_refreshed_at = time.monotonic()
    mgr.refresh_cache()
    runner.assert_not_called()


def test_refresh_cache_runs_when_stale():
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt", cache_ttl=300)
    mgr._cache_refreshed_at = 0.0  # epoch — always stale
    mgr.refresh_cache()
    runner.assert_called_once()


def test_refresh_cache_force_bypasses_ttl():
    import time
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt", cache_ttl=300)
    mgr._cache_refreshed_at = time.monotonic()  # fresh cache
    mgr.refresh_cache(force=True)
    runner.assert_called_once()


def test_install_skips_refresh_when_cache_fresh(tmp_path):
    import time
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr._cache_refreshed_at = time.monotonic()
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    pkg_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.packages)
    assert pkg_call is not None
    update_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.update]
    assert update_calls == []


def test_repo_add_refreshes_even_when_cache_fresh(tmp_path):
    import time
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr._cache_refreshed_at = time.monotonic()  # fresh cache
    client = _make_client(plugin)
    client.post("/v1/host/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    update_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.update]
    assert len(update_calls) == 1


def test_cache_ttl_zero_always_refreshes(tmp_path):
    import time
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, config={"os_pkgmgr_max_cache_ttl_secs": 0})
    plugin._pkg_mgr._cache_refreshed_at = time.monotonic()
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    update_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.update]
    assert len(update_calls) == 1


# ── package manager detection ──────────────────────────────────────────────────

def test_detect_apt():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        assert pm.detect_package_manager() == "apt"


def test_detect_dnf():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/dnf" if b == "dnf" else None):
        assert pm.detect_package_manager() == "dnf"


def test_detect_yum():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/yum" if b == "yum" else None):
        assert pm.detect_package_manager() == "yum"


def test_detect_apk():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", side_effect=lambda b: "/sbin/apk" if b == "apk" else None):
        assert pm.detect_package_manager() == "apk"


def test_detect_pacman():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/pacman" if b == "pacman" else None):
        assert pm.detect_package_manager() == "pacman"


def test_detect_pkg_manager_unknown():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", return_value=None):
        assert pm.detect_package_manager() == "unknown"


def test_detect_apt_takes_priority_over_dnf():
    pm = _load_pkg_manager_module()
    with patch("shutil.which", return_value="/usr/bin/tool"):
        assert pm.detect_package_manager() == "apt"


# ── packages ───────────────────────────────────────────────────────────────────


def test_list_packages_default_mode_is_installed(client):
    r = client.get("/v1/host/packages")
    assert r.status_code == 200
    assert r.json()["mode"] == "installed"


def test_list_packages_installed_shows_system_packages(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"bash": {"version": "5.1", "installed": True}})
    client = _make_client(plugin)
    entry = client.get("/v1/host/packages").json()["packages"]["bash"]
    assert entry["installed"] is True
    assert entry["managed"] is False


def test_list_packages_installed_marks_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={"present": True, "latest": False})
    entry = client.get("/v1/host/packages").json()["packages"]["curl"]
    assert entry["installed"] is True
    assert entry["managed"] is True
    assert entry["version"] == "7.88"


def test_list_packages_managed_mode_only_shows_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"bash": {"version": "5.1", "installed": True}})
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    data = client.get("/v1/host/packages?mode=managed").json()
    assert "curl" in data["packages"]
    assert "bash" not in data["packages"]
    assert data["packages"]["curl"]["managed"] is True


def test_list_packages_managed_mode_annotates_installed_status(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    entry = client.get("/v1/host/packages?mode=managed").json()["packages"]["curl"]
    assert entry["installed"] is True
    assert entry["version"] == "7.88"


def test_list_packages_managed_mode_not_installed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/packages/vim", json={})
    entry = client.get("/v1/host/packages?mode=managed").json()["packages"]["vim"]
    assert entry["installed"] is False
    assert entry["managed"] is True


def test_list_packages_available_mode_shows_repo_packages(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_available_packages = MagicMock(return_value={"curl": {}, "vim": {}, "git": {}})
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    data = client.get("/v1/host/packages?mode=available").json()
    assert "curl" in data["packages"]
    assert "vim" in data["packages"]
    assert data["packages"]["curl"]["installed"] is True
    assert data["packages"]["vim"]["installed"] is False


def test_list_packages_available_mode_marks_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_available_packages = MagicMock(return_value={"curl": {}, "vim": {}})
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    data = client.get("/v1/host/packages?mode=available").json()["packages"]
    assert data["curl"]["managed"] is True
    assert data["vim"]["managed"] is False


def test_list_packages_invalid_mode_returns_400(client):
    assert client.get("/v1/host/packages?mode=bogus").status_code == 400


def test_list_packages_includes_mode_in_response(client):
    for mode in ("installed", "managed", "available"):
        assert client.get(f"/v1/host/packages?mode={mode}").json()["mode"] == mode


def test_install_package_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/host/packages/curl", json={"present": True, "latest": False})
    assert r.status_code == 201
    assert r.json()["package"] == "curl"
    assert r.json()["platform"] == "apt"
    pkg_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.packages)
    args, kwargs = pkg_call
    assert kwargs["packages"] == ["curl"]
    assert kwargs["present"] is True
    assert kwargs["latest"] is False


def test_install_package_pacman_omits_latest(tmp_path):
    from pyinfra.operations import pacman as pacman_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/pacman" if b == "pacman" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/packages/vim", json={})
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is pacman_ops.packages
    assert "latest" not in kwargs


def test_install_package_appears_in_managed_list(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    entry = client.get("/v1/host/packages?mode=managed").json()["packages"]["curl"]
    assert entry["managed"] is True


def test_update_package_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    plugin._pyinfra_run.reset_mock()

    r = client.put("/v1/host/packages/curl")
    assert r.status_code == 200
    assert r.json()["updated"] is True
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is apt_ops.packages
    assert kwargs["latest"] is True


def test_update_package_not_managed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.put("/v1/host/packages/ghost").status_code == 404


def test_remove_package_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    plugin._pyinfra_run.reset_mock()

    r = client.delete("/v1/host/packages/curl")
    assert r.status_code == 200
    assert r.json() == {"deleted": "curl"}
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is apt_ops.packages
    assert kwargs["present"] is False
    assert "curl" not in client.get("/v1/host/packages").json()["packages"]


def test_remove_package_not_managed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.delete("/v1/host/packages/ghost").status_code == 404


def test_package_endpoints_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/host/packages/curl", json={}).status_code == 503
    assert client.put("/v1/host/packages/curl").status_code == 503
    assert client.delete("/v1/host/packages/curl").status_code == 503


def test_status_includes_package_manager_and_counts(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/packages/curl", json={})
    data = client.get("/v1/host/status").json()
    assert data["package_manager"] == "apt"
    assert data["managed"]["packages"] == 1
    assert data["managed"]["repos"] == 0


# ── repos ──────────────────────────────────────────────────────────────────────

def test_list_repos_empty(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    r = client.get("/v1/host/repos")
    assert r.status_code == 200
    assert r.json()["repos"] == {}


def test_list_repos_shows_system_repos_as_unmanaged(tmp_path):
    system = {"deb https://packages.example.com/apt focal main": {"src": "deb https://packages.example.com/apt focal main"}}
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, system_repos=system)
    client = _make_client(plugin)
    r = client.get("/v1/host/repos")
    assert r.status_code == 200
    entry = r.json()["repos"]["deb https://packages.example.com/apt focal main"]
    assert entry["managed"] is False


def test_list_repos_marks_managed_repo(tmp_path):
    src = "deb https://packages.example.com/apt focal main"
    system = {src: {"src": src}}
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, system_repos=system)
    client = _make_client(plugin)
    client.post("/v1/host/repos/myrepo", json={"src": src})
    r = client.get("/v1/host/repos")
    assert r.status_code == 200
    entry = r.json()["repos"][src]
    assert entry["managed"] is True


def test_list_repos_managed_but_not_in_system_uses_name_as_key(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/host/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    r = client.get("/v1/host/repos")
    assert r.status_code == 200
    assert "myrepo" in r.json()["repos"]
    assert r.json()["repos"]["myrepo"]["managed"] is True


def test_add_apt_repo_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/host/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    assert r.status_code == 201
    assert r.json()["repo"] == "myrepo"
    assert r.json()["platform"] == "apt"
    repo_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.repo)
    args, kwargs = repo_call
    assert kwargs["src"] == "deb https://example.com/apt focal main"
    assert kwargs["present"] is True


def test_add_apt_repo_with_key_calls_key_op(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    client.post("/v1/host/repos/myrepo", json={"src": "deb https://example.com/apt focal main", "key_url": "https://example.com/key.gpg"})
    calls = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert apt_ops.repo in calls
    assert apt_ops.key in calls
    key_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.key)
    assert key_call[1]["src"] == "https://example.com/key.gpg"


def test_add_apt_repo_missing_src_returns_422(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/host/repos/myrepo", json={}).status_code == 422


def test_add_yum_repo_calls_pyinfra(tmp_path):
    from pyinfra.operations import yum as yum_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/yum" if b == "yum" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/host/repos/epel", json={"src": "epel", "baseurl": "https://dl.fedoraproject.org/pub/epel/9/x86_64/", "gpgcheck": True})
    assert r.status_code == 201
    assert r.json()["platform"] == "yum"
    repo_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is yum_ops.repo)
    args, kwargs = repo_call
    assert kwargs["src"] == "epel"
    assert kwargs["baseurl"] == "https://dl.fedoraproject.org/pub/epel/9/x86_64/"


def test_add_dnf_repo_calls_dnf_ops(tmp_path):
    from pyinfra.operations import dnf as dnf_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/dnf" if b == "dnf" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    client.post("/v1/host/repos/myrepo", json={"src": "myrepo"})
    repo_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is dnf_ops.repo)
    args, _ = repo_call
    assert args[0] is dnf_ops.repo


def test_add_apk_repo_calls_files_line(tmp_path):
    from pyinfra.operations import files as files_ops
    with patch("shutil.which", side_effect=lambda b: "/sbin/apk" if b == "apk" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/host/repos/alpine-edge", json={"url": "https://dl-cdn.alpinelinux.org/alpine/edge/main"})
    assert r.status_code == 201
    line_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.line)
    args, kwargs = line_call
    assert kwargs["path"] == "/etc/apk/repositories"
    assert kwargs["line"] == "https://dl-cdn.alpinelinux.org/alpine/edge/main"
    assert kwargs["present"] is True


def test_add_apk_repo_missing_url_returns_422(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/sbin/apk" if b == "apk" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/host/repos/myrepo", json={}).status_code == 422


def test_add_pacman_repo_calls_shell(tmp_path):
    from pyinfra.operations import server as server_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/pacman" if b == "pacman" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/host/repos/archlinux-cn", json={"url": "https://repo.archlinuxcn.org/x86_64"})
    assert r.status_code == 201
    repo_call = next(
        c for c in plugin._pyinfra_run.call_args_list
        if c[0][0] is server_ops.shell and "[archlinux-cn]" in (c[1].get("commands") or [""])[0]
    )
    args, kwargs = repo_call
    assert "[archlinux-cn]" in kwargs["commands"][0]
    assert "https://repo.archlinuxcn.org/x86_64" in kwargs["commands"][0]


def test_remove_repo_calls_pyinfra_with_present_false(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    client.post("/v1/host/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    plugin._pyinfra_run.reset_mock()

    r = client.delete("/v1/host/repos/myrepo")
    assert r.status_code == 200
    assert r.json() == {"deleted": "myrepo"}
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is apt_ops.repo
    assert kwargs["present"] is False
    assert "myrepo" not in client.get("/v1/host/repos").json()["repos"]


def test_remove_repo_not_managed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.delete("/v1/host/repos/ghost").status_code == 404


def test_repo_endpoints_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/host/repos/myrepo", json={"src": "deb https://x.com focal main"}).status_code == 503
    assert client.delete("/v1/host/repos/myrepo").status_code == 503


def test_search_packages_returns_results(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.search_packages = MagicMock(return_value=[
        {"name": "curl", "description": "command line tool for transferring data"},
        {"name": "libcurl4", "description": "easy-to-use client-side URL transfer library"},
    ])
    client = _make_client(plugin)
    r = client.get("/v1/host/packages/search?q=curl")
    assert r.status_code == 200
    data = r.json()
    assert data["query"] == "curl"
    assert data["platform"] == "apt"
    assert len(data["results"]) == 2
    assert data["results"][0]["name"] == "curl"


def test_search_packages_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.get("/v1/host/packages/search?q=curl").status_code == 503


def test_search_apt_packages_parses_output():
    pm = _load_pkg_manager_module()
    raw = "curl - command line tool for transferring data\nlibcurl4 - easy-to-use URL library\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=raw, returncode=0)
        results = pm.PackageManager._search_apt_packages("curl")
    assert {"name": "curl", "description": "command line tool for transferring data"} in results
    assert {"name": "libcurl4", "description": "easy-to-use URL library"} in results


def test_search_pacman_packages_parses_output():
    pm = _load_pkg_manager_module()
    raw = "extra/curl 8.1.2-1\n    An URL retrieval utility\ncommunity/libcurl 8.1.2-1\n    URL library\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=raw, returncode=0)
        results = pm.PackageManager._search_pacman_packages("curl")
    assert any(r["name"] == "curl" and "URL retrieval" in r["description"] for r in results)
    assert any(r["name"] == "libcurl" for r in results)


def test_package_state_persists_across_restart(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.post("/v1/host/packages/curl", json={})
    p1.teardown()

    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    packages = c2.get("/v1/host/packages?mode=managed").json()["packages"]
    assert "curl" in packages
    assert packages["curl"]["managed"] is True


def test_repo_state_persists_across_restart(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.post("/v1/host/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    p1.teardown()

    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert "myrepo" in c2.get("/v1/host/repos").json()["repos"]


def test_old_state_file_without_packages_loads_cleanly(tmp_path):
    state_path = tmp_path / "data" / "host_state.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps({"services": {"nginx": {"running": True, "enabled": True}}, "sysctl": {}, "users": {}, "groups": {}, "cron": {}}))

    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.get("/v1/host/packages").status_code == 200
    assert client.get("/v1/host/repos").status_code == 200
    assert "nginx" in client.get("/v1/host/services").json()["services"]


# ── system upgrade ─────────────────────────────────────────────────────────────

def _make_upgrade_plugin(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.upgrade_system = MagicMock(return_value={
        "platform": "apt", "returncode": 0, "stdout": "0 upgraded.", "stderr": "",
    })
    return plugin


def test_upgrade_returns_started(tmp_path):
    plugin = _make_upgrade_plugin(tmp_path)
    client = _make_client(plugin)
    r = client.post("/v1/host/packages/upgrade-system", json={"email": "ops@example.com"})
    assert r.status_code == 200
    assert r.json()["status"] == "started"
    assert r.json()["email"] == "ops@example.com"


def test_upgrade_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/host/packages/upgrade-system", json={"email": "ops@example.com"}).status_code == 503


def test_upgrade_task_emits_smtp_send_on_success(tmp_path):
    from plugin_system.core.events import bus as global_bus
    plugin = _make_upgrade_plugin(tmp_path)
    task_id = "test-task-1"
    plugin._bg_tasks[task_id] = {"id": task_id, "type": "upgrade_system", "status": "running", "started_at": "", "finished_at": None, "error": None, "email": "ops@example.com"}
    received = []
    global_bus.subscribe("smtp.send", received.append)
    try:
        plugin._run_upgrade_task(task_id, "ops@example.com")
        assert len(received) == 1
        assert received[0].payload["to"] == "ops@example.com"
        assert "succeeded" in received[0].payload["subject"]
        assert "0 upgraded." in received[0].payload["body"]
    finally:
        global_bus.unsubscribe("smtp.send", received.append)


def test_upgrade_task_emits_smtp_send_on_failure(tmp_path):
    from plugin_system.core.events import bus as global_bus
    plugin = _make_upgrade_plugin(tmp_path)
    plugin._pkg_mgr.upgrade_system = MagicMock(return_value={
        "platform": "apt", "returncode": 1, "stdout": "", "stderr": "E: Could not lock",
    })
    task_id = "test-task-2"
    plugin._bg_tasks[task_id] = {"id": task_id, "type": "upgrade_system", "status": "running", "started_at": "", "finished_at": None, "error": None, "email": "ops@example.com"}
    received = []
    global_bus.subscribe("smtp.send", received.append)
    try:
        plugin._run_upgrade_task(task_id, "ops@example.com")
        assert "FAILED" in received[0].payload["subject"]
        assert "E: Could not lock" in received[0].payload["body"]
    finally:
        global_bus.unsubscribe("smtp.send", received.append)


def test_upgrade_task_emits_upgrade_done_event(tmp_path):
    from plugin_system.core.events import bus as global_bus
    plugin = _make_upgrade_plugin(tmp_path)
    task_id = "test-task-3"
    plugin._bg_tasks[task_id] = {"id": task_id, "type": "upgrade_system", "status": "running", "started_at": "", "finished_at": None, "error": None, "email": "ops@example.com"}
    received = []
    global_bus.subscribe("host.package.upgrade-system.done", received.append)
    try:
        plugin._run_upgrade_task(task_id, "ops@example.com")
        assert len(received) == 1
        assert received[0].payload["returncode"] == 0
        assert received[0].payload["email"] == "ops@example.com"
    finally:
        global_bus.unsubscribe("host.package.upgrade-system.done", received.append)


def test_upgrade_task_exception_still_emits_smtp_send(tmp_path):
    from plugin_system.core.events import bus as global_bus
    plugin = _make_upgrade_plugin(tmp_path)
    plugin._pkg_mgr.upgrade_system = MagicMock(side_effect=RuntimeError("disk full"))
    task_id = "test-task-4"
    plugin._bg_tasks[task_id] = {"id": task_id, "type": "upgrade_system", "status": "running", "started_at": "", "finished_at": None, "error": None, "email": "ops@example.com"}
    received = []
    global_bus.subscribe("smtp.send", received.append)
    try:
        plugin._run_upgrade_task(task_id, "ops@example.com")
        assert "FAILED" in received[0].payload["subject"]
        assert "disk full" in received[0].payload["body"]
    finally:
        global_bus.unsubscribe("smtp.send", received.append)


def test_upgrade_system_runs_apt_dist_upgrade(tmp_path):
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="0 upgraded.", stderr="")
        result = mgr.upgrade_system()
    cmd = mock_run.call_args[0][0]
    assert "apt-get" in cmd
    assert "dist-upgrade" in cmd
    assert "DEBIAN_FRONTEND=noninteractive" in cmd
    assert result["returncode"] == 0
    assert result["platform"] == "apt"


def test_upgrade_system_pacman_uses_syu(tmp_path):
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "pacman")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mgr.upgrade_system()
    cmd = mock_run.call_args[0][0]
    assert "pacman" in cmd
    assert "-Syu" in cmd
    assert "--noconfirm" in cmd


# ── boot-time state apply ──────────────────────────────────────────────────────

_BOOT_STATE = {
    "services": {"nginx": {"running": True, "enabled": True}},
    "sysctl": {"vm.swappiness": {"value": "10", "persist": True}},
    "users": {"deploy": {"shell": "/bin/bash", "home_dir": None, "system": False, "comment": None}},
    "groups": {"ops": {"system": False, "gid": None}},
    "cron": {"backup": {"command": "/usr/bin/backup.sh", "minute": "0", "hour": "2", "day_of_month": "*", "month": "*", "day_of_week": "*", "user": "root"}},
    "packages": {},
    "repos": {},
}


def _write_boot_state(tmp_path, state=None):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "host_state.json").write_text(json.dumps(state or _BOOT_STATE))


def _make_inst(tmp_path, config=None):
    mod = _load_plugin_module()
    plugin = mod.HostPlugin()
    plugin.plugin_id = "host"
    plugin.meta = {"name": "Host Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.host")
    plugin._pyinfra_run = MagicMock()
    return plugin, mod


def test_state_reapplied_on_boot_calls_pyinfra(tmp_path):
    from pyinfra.operations import server as server_ops
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path)
    plugin.setup()
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert server_ops.service in ops
    assert server_ops.sysctl in ops
    assert server_ops.user in ops
    assert server_ops.group in ops
    assert server_ops.crontab in ops


def test_ignore_state_on_boot_skips_apply(tmp_path):
    from pyinfra.operations import server as server_ops
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path, config={"ignore_state_on_boot": True})
    plugin.setup()
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert server_ops.service not in ops
    assert server_ops.sysctl not in ops
    assert plugin._state == {k: {} for k in plugin._EMPTY_STATE}


def test_apply_state_does_not_crash_on_pyinfra_failure(tmp_path):
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path)
    plugin._pyinfra_run = MagicMock(side_effect=RuntimeError("pyinfra failed"))
    plugin.setup()  # must not raise
    assert "nginx" in plugin._state["services"]


def test_empty_state_skips_apply_calls(tmp_path):
    from pyinfra.operations import server as server_ops
    plugin, _ = _make_inst(tmp_path)
    plugin.setup()  # no state file — all categories empty
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert server_ops.service not in ops
    assert server_ops.sysctl not in ops
