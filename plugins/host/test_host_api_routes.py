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

from plugin_system.core.events import Event, bus as global_bus


# ── helpers ────────────────────────────────────────────────────────────────────

_REPO_ROOT = str(Path(__file__).parents[2])  # plugins/host → plugins → /app


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


def _make_plugin(tmp_path, config=None):
    mod = _load_plugin_module()
    plugin = mod.HostPlugin()
    plugin.plugin_id = "host"
    plugin.meta = {"name": "Host Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.host")
    plugin._pyinfra_run = MagicMock()
    plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
    plugin.setup()
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
    assert managed == {"sysctl": 0, "users": 0, "groups": 0, "cron": 0, "kernmod": 0}


def test_status_counts_update_after_additions(client):
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    managed = client.get("/v1/host/status").json()["managed"]
    assert managed["sysctl"] == 1


def test_status_pending_changes_false_after_mutation(client):
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    assert client.get("/v1/host/status").json()["pending_changes"] is False


def test_status_pending_changes_false_after_import(client):
    client.post("/v1/host/users/root/import")
    assert client.get("/v1/host/status").json()["pending_changes"] is False


def test_status_pending_changes_false_when_nothing_managed(client):
    assert client.get("/v1/host/status").json()["pending_changes"] is False


def test_current_state_persists_across_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    assert c1.get("/v1/host/status").json()["pending_changes"] is False
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert c2.get("/v1/host/status").json()["pending_changes"] is False


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


# ── sysctl ─────────────────────────────────────────────────────────────────────

def test_list_sysctl_empty(client):
    r = client.get("/v1/host/sysctl")
    assert r.status_code == 200
    data = r.json()
    assert "sysctl" in data
    assert all(not e["ff_managed"] for e in data["sysctl"].values())


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
    sysctl = client.get("/v1/host/sysctl").json()["sysctl"]
    assert "vm.swappiness" in sysctl
    assert sysctl["vm.swappiness"]["ff_managed"] is True


def test_delete_sysctl_removes_key(client):
    client.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    r = client.delete("/v1/host/sysctl/vm.swappiness")
    assert r.status_code == 200
    assert r.json() == {"deleted": "vm.swappiness"}
    sysctl = client.get("/v1/host/sysctl").json()["sysctl"]
    entry = sysctl.get("vm.swappiness")
    assert entry is None or entry["ff_managed"] is False


def test_delete_sysctl_not_managed_returns_404(client):
    r = client.delete("/v1/host/sysctl/nonexistent.key")
    assert r.status_code == 404


def test_import_sysctl_reads_current_value(client):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "60\n"
    with patch("subprocess.run", return_value=mock_proc):
        r = client.post("/v1/host/sysctl/vm.swappiness/import")
    assert r.status_code == 201
    data = r.json()
    assert data["key"] == "vm.swappiness"
    assert data["value"] == "60"
    assert data["persist"] is True
    assert data["ff_managed"] is True


def test_import_sysctl_missing_key_returns_404(client):
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    with patch("subprocess.run", return_value=mock_proc):
        assert client.post("/v1/host/sysctl/no.such.key/import").status_code == 404


def test_sysctl_set_event_applies_and_persists(plugin):
    from plugin_system.core.events import Event
    event = Event("host.sysctl.set", payload={
        "key": "net.ipv4.ip_forward",
        "value": "1",
        "persist": True,
    })
    plugin._handle_sysctl_set(event)
    args, kwargs = plugin._pyinfra_run.call_args
    from pyinfra.operations import server as server_ops
    assert args[0] is server_ops.sysctl
    assert kwargs["key"] == "net.ipv4.ip_forward"
    assert kwargs["value"] == "1"
    assert kwargs["persist"] is True
    assert plugin._state["sysctl"]["net.ipv4.ip_forward"] == {"value": "1", "persist": True}


def test_sysctl_set_event_persist_default_true(plugin):
    from plugin_system.core.events import Event
    event = Event("host.sysctl.set", payload={
        "key": "vm.swappiness",
        "value": "10",
    })
    plugin._handle_sysctl_set(event)
    assert plugin._state["sysctl"]["vm.swappiness"]["persist"] is True


def test_sysctl_set_event_missing_key_is_ignored(plugin):
    from plugin_system.core.events import Event
    event = Event("host.sysctl.set", payload={"value": "1"})
    plugin._handle_sysctl_set(event)
    plugin._pyinfra_run.assert_not_called()


def test_sysctl_set_event_pyinfra_failure_does_not_raise(plugin):
    from plugin_system.core.events import Event
    plugin._pyinfra_run.side_effect = RuntimeError("sysctl failed")
    event = Event("host.sysctl.set", payload={
        "key": "vm.swappiness",
        "value": "10",
    })
    plugin._handle_sysctl_set(event)
    assert "vm.swappiness" not in plugin._state["sysctl"]


# ── users ──────────────────────────────────────────────────────────────────────

def test_list_users_empty(client):
    data = client.get("/v1/host/users").json()
    assert "users" in data
    assert all(not u["ff_managed"] for u in data["users"].values())


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
    users = client.get("/v1/host/users").json()["users"]
    assert "deploy" in users
    assert users["deploy"]["ff_managed"] is True


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


def test_import_user_reads_from_passwd(client):
    r = client.post("/v1/host/users/root/import")
    assert r.status_code == 201
    data = r.json()
    assert data["user"] == "root"
    assert data["ff_managed"] is True
    assert "shell" in data
    assert "home_dir" in data
    assert client.get("/v1/host/users").json()["users"]["root"]["ff_managed"] is True


def test_import_user_not_found_returns_404(client):
    assert client.post("/v1/host/users/no_such_user_xyz/import").status_code == 404


# ── groups ─────────────────────────────────────────────────────────────────────

def test_list_groups_empty(client):
    data = client.get("/v1/host/groups").json()
    assert "groups" in data
    assert all(not g["ff_managed"] for g in data["groups"].values())


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
    groups = client.get("/v1/host/groups").json()["groups"]
    assert "deploy" in groups
    assert groups["deploy"]["ff_managed"] is True


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


def test_import_group_reads_from_grp(client):
    r = client.post("/v1/host/groups/root/import")
    assert r.status_code == 201
    data = r.json()
    assert data["group"] == "root"
    assert data["ff_managed"] is True
    assert "gid" in data
    assert client.get("/v1/host/groups").json()["groups"]["root"]["ff_managed"] is True


def test_import_group_not_found_returns_404(client):
    assert client.post("/v1/host/groups/no_such_group_xyz/import").status_code == 404


def test_import_group_includes_members(client):
    r = client.post("/v1/host/groups/root/import")
    assert r.status_code == 201
    assert "members" in r.json()


def test_list_group_members_returns_ff_managed_flag(client):
    client.post("/v1/host/groups/root/import")
    r = client.get("/v1/host/groups/root/members")
    assert r.status_code == 200
    data = r.json()
    assert data["group"] == "root"
    assert isinstance(data["members"], list)
    for m in data["members"]:
        assert "username" in m
        assert "ff_managed" in m


def test_list_group_members_not_found_returns_404(client):
    assert client.get("/v1/host/groups/no_such_group_xyz/members").status_code == 404


def test_add_group_member_requires_managed_group(client):
    r = client.post("/v1/host/groups/unmanaged_xyz/members", json={"username": "alice"})
    assert r.status_code == 404


def test_add_group_member_success(client, plugin):
    client.post("/v1/host/groups/root/import")
    plugin._pyinfra_run.reset_mock()
    r = client.post("/v1/host/groups/root/members", json={"username": "alice"})
    assert r.status_code == 201
    assert r.json() == {"group": "root", "username": "alice", "ff_managed": True}
    args, kwargs = plugin._pyinfra_run.call_args
    from pyinfra.operations import server as server_ops
    assert args[0] is server_ops.shell
    assert "alice" in kwargs["commands"][0]


def test_add_group_member_rejects_invalid_username(client):
    client.post("/v1/host/groups/root/import")
    r = client.post("/v1/host/groups/root/members", json={"username": "bad;user"})
    assert r.status_code == 422


def test_add_group_member_idempotent(client, plugin):
    client.post("/v1/host/groups/root/import")
    client.post("/v1/host/groups/root/members", json={"username": "alice"})
    plugin._pyinfra_run.reset_mock()
    r = client.post("/v1/host/groups/root/members", json={"username": "alice"})
    assert r.status_code == 201
    members_in_state = [
        m for m in client.get("/v1/host/groups/root/members").json()["members"]
        if m["username"] == "alice" and m["ff_managed"]
    ]
    assert len(members_in_state) == 1


def test_remove_group_member_success(client, plugin):
    client.post("/v1/host/groups/root/import")
    client.post("/v1/host/groups/root/members", json={"username": "alice"})
    plugin._pyinfra_run.reset_mock()
    r = client.delete("/v1/host/groups/root/members/alice")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    from pyinfra.operations import server as server_ops
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.shell
    assert "alice" in kwargs["commands"][0]


def test_remove_group_member_not_managed_returns_404(client):
    client.post("/v1/host/groups/root/import")
    assert client.delete("/v1/host/groups/root/members/nobody").status_code == 404


def test_remove_group_member_unmanaged_group_returns_404(client):
    assert client.delete("/v1/host/groups/ghost/members/alice").status_code == 404


# ── cron ───────────────────────────────────────────────────────────────────────

def test_list_cron_empty(client):
    data = client.get("/v1/host/cron").json()
    assert "cron" in data
    assert all(not e["ff_managed"] for e in data["cron"].values())


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
    cron = client.get("/v1/host/cron").json()["cron"]
    assert "backup" in cron
    assert cron["backup"]["ff_managed"] is True


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


def test_import_cron_copies_system_entry(client, plugin):
    plugin._read_system_cron = MagicMock(return_value={
        "cron.d/anacron/0": {
            "command": "run-parts /etc/cron.daily",
            "minute": "25", "hour": "6",
            "day_of_month": "*", "month": "*", "day_of_week": "*",
            "user": "root", "source": "/etc/cron.d/anacron",
        }
    })
    r = client.post("/v1/host/cron/daily/import", json={"source_key": "cron.d/anacron/0"})
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "daily"
    assert data["command"] == "run-parts /etc/cron.daily"
    assert data["hour"] == "6"
    assert data["ff_managed"] is True
    assert client.get("/v1/host/cron").json()["cron"]["daily"]["ff_managed"] is True


def test_import_cron_missing_source_key_returns_404(client, plugin):
    plugin._read_system_cron = MagicMock(return_value={})
    assert client.post("/v1/host/cron/myjob/import", json={"source_key": "nonexistent/0"}).status_code == 404


# ── state persistence ──────────────────────────────────────────────────────────

def test_state_persists_across_plugin_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    c1.post("/v1/host/users/deploy", json={})
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert "vm.swappiness" in c2.get("/v1/host/sysctl").json()["sysctl"]
    assert "deploy" in c2.get("/v1/host/users").json()["users"]


def test_deleted_entries_absent_after_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
    c1.delete("/v1/host/sysctl/vm.swappiness")
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    sysctl = c2.get("/v1/host/sysctl").json()["sysctl"]
    entry = sysctl.get("vm.swappiness")
    assert entry is None or entry["ff_managed"] is False


def test_state_file_written_to_configured_path(tmp_path):
    p = _make_plugin(tmp_path, config={"state_file": "custom_state.json"})
    c = _make_client(p)
    c.put("/v1/host/sysctl/vm.swappiness", json={"value": "10"})
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


# ── initsys.service.add event ─────────────────────────────────────────────────

def test_systemd_unit_oneshot_type():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft", service_type="oneshot")
    assert "Type=oneshot" in unit
    assert "RemainAfterExit=yes" in unit
    assert "Restart" not in unit


def test_systemd_unit_custom_description():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft", description="FastFirewall nftables rules")
    assert "Description=FastFirewall nftables rules" in unit


def test_systemd_unit_default_description_is_service_name():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft")
    assert "Description=ff-nft" in unit


def test_systemd_unit_default_after_is_network_target():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft")
    assert "After=network.target" in unit


def test_systemd_unit_custom_after():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft", after="network-pre.target")
    assert "After=network-pre.target" in unit
    assert "After=network.target" not in unit


def test_systemd_unit_before():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft", before="network-online.target")
    assert "Before=network-online.target" in unit


def test_systemd_unit_no_before_omits_line():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft")
    assert "Before=" not in unit


def test_systemd_unit_wanted_by_default():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit("ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft")
    assert "WantedBy=multi-user.target" in unit


def test_systemd_unit_wanted_by_multi():
    mod = _load_plugin_module()
    unit = mod.HostPlugin._systemd_unit(
        "ff-nft", "/usr/sbin/nft -f /data/fastfirewall.nft",
        wanted_by=["multi-user.target", "network-online.target"],
    )
    assert "WantedBy=multi-user.target network-online.target" in unit


def test_service_add_event_places_and_enables(tmp_path):
    from pyinfra.operations import files as files_ops, systemd as systemd_ops
    plugin, mod = _init_plugin(tmp_path, {})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()

    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"), \
         patch.object(mod.HostPlugin, "_get_service_status", _mock_status(False, None, exists=False)):
        event = Event("initsys.service.add", payload={
            "service_name": "ff-nft",
            "command": "/usr/sbin/nft -f /data/fastfirewall.nft",
        })
        plugin._handle_service_add(event)

    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert files_ops.put in ops
    assert systemd_ops.daemon_reload in ops
    assert systemd_ops.service in ops


def test_service_add_event_already_installed_skips(tmp_path):
    plugin, mod = _init_plugin(tmp_path, {})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()

    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"), \
         patch.object(mod.HostPlugin, "_get_service_status", _mock_status(True, True, exists=True)):
        event = Event("initsys.service.add", payload={
            "service_name": "ff-nft",
            "command": "/usr/sbin/nft -f /data/fastfirewall.nft",
        })
        result = plugin._handle_service_add(event)

    plugin._pyinfra_run.assert_not_called()
    assert result == {"success": True}


def test_service_add_event_oneshot_unit_content(tmp_path):
    from pyinfra.operations import files as files_ops
    plugin, mod = _init_plugin(tmp_path, {})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()

    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"), \
         patch.object(mod.HostPlugin, "_get_service_status", _mock_status(False, None, exists=False)):
        event = Event("initsys.service.add", payload={
            "service_name": "ff-nft",
            "command": "/usr/sbin/nft -f /data/fastfirewall.nft",
            "service_type": "oneshot",
            "description": "FastFirewall nftables rules",
        })
        plugin._handle_service_add(event)

    put_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.put)
    unit = put_call[1]["src"].getvalue()
    assert "Type=oneshot" in unit
    assert "RemainAfterExit=yes" in unit
    assert "Description=FastFirewall nftables rules" in unit
    assert "Restart" not in unit


def test_service_add_event_forwards_ordering_fields(tmp_path):
    from pyinfra.operations import files as files_ops
    plugin, mod = _init_plugin(tmp_path, {})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()

    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"), \
         patch.object(mod.HostPlugin, "_get_service_status", _mock_status(False, None, exists=False)):
        event = Event("initsys.service.add", payload={
            "service_name": "ff-networking",
            "command": "sudo python -m ifstate.ifstate apply",
            "service_type": "oneshot",
            "after": "network-pre.target",
            "before": "network-online.target",
            "wanted_by": ["multi-user.target", "network-online.target"],
        })
        plugin._handle_service_add(event)

    put_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.put)
    unit = put_call[1]["src"].getvalue()
    assert "After=network-pre.target" in unit
    assert "Before=network-online.target" in unit
    assert "WantedBy=multi-user.target network-online.target" in unit


def test_service_add_event_no_command_enables_without_placing_unit(tmp_path):
    from pyinfra.operations import files as files_ops, systemd as systemd_ops
    plugin, mod = _init_plugin(tmp_path, {})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()

    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"), \
         patch.object(mod.HostPlugin, "_get_service_status", _mock_status(False, None, exists=False)):
        event = Event("initsys.service.add", payload={"service_name": "dnsmasq"})
        plugin._handle_service_add(event)
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert files_ops.put not in ops
    assert systemd_ops.daemon_reload in ops
    assert systemd_ops.service in ops


def test_service_add_event_unknown_init_system_is_ignored(tmp_path):
    plugin, mod = _init_plugin(tmp_path, {})
    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="systemd"):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()

    with patch.object(mod.HostPlugin, "_detect_init_system", return_value="unknown"):
        event = Event("initsys.service.add", payload={
            "service_name": "ff-nft",
            "command": "/usr/sbin/nft -f /data/fastfirewall.nft",
        })
        plugin._handle_service_add(event)
    plugin._pyinfra_run.assert_not_called()


# ── boot-time state apply ──────────────────────────────────────────────────────

_BOOT_STATE = {
    "desired_state": {
        "sysctl": {"vm.swappiness": {"value": "10", "persist": True}},
        "users": {"deploy": {"shell": "/bin/bash", "home_dir": None, "system": False, "comment": None}},
        "groups": {"ops": {"system": False, "gid": None}},
        "cron": {"backup": {"command": "/usr/bin/backup.sh", "minute": "0", "hour": "2", "day_of_month": "*", "month": "*", "day_of_week": "*", "user": "root"}},
    },
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
    plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
    return plugin, mod


def test_state_reapplied_on_boot_calls_pyinfra(tmp_path):
    from pyinfra.operations import server as server_ops
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path)
    plugin.setup()
    assert plugin._pyinfra_run_many.call_count == 1
    batch = plugin._pyinfra_run_many.call_args[0][0]
    ops_called = [op for op, _ in batch]
    assert server_ops.sysctl in ops_called
    assert server_ops.user in ops_called
    assert server_ops.group in ops_called
    assert server_ops.crontab in ops_called


def test_ignore_state_on_boot_skips_apply(tmp_path):
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path, config={"ignore_state_on_boot": True})
    plugin.setup()
    plugin._pyinfra_run_many.assert_not_called()
    assert plugin._state == {k: {} for k in plugin._EMPTY_STATE}


def test_apply_state_does_not_crash_on_pyinfra_failure(tmp_path):
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path)
    plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(False, "pyinfra failed")] * len(ops))
    plugin.setup()  # must not raise
    assert "vm.swappiness" in plugin._state["sysctl"]


def test_empty_state_skips_apply_calls(tmp_path):
    plugin, _ = _make_inst(tmp_path)
    plugin.setup()  # no state file — all categories empty
    plugin._pyinfra_run_many.assert_not_called()


# ── systemd service lifecycle events ──────────────────────────────────────────

def _make_svc_plugin(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._pyinfra_run.reset_mock()
    return plugin


def _mock_status(running: bool, enabled: bool | None = True, exists: bool = True):
    return MagicMock(return_value={"running": running, "enabled": enabled, "exists": exists})


# status

def test_service_status_returns_result(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(True, True)):
        result = plugin._handle_service_status(Event("initsys.service.status", payload={"service_name": "ff-nft"}))
    assert result is not None
    assert result["service_name"] == "ff-nft"
    assert result["running"] is True
    assert result["enabled"] is True
    assert result["init_system"] == "systemd"


def test_service_status_missing_name_is_ignored(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    plugin._handle_service_status(Event("initsys.service.status", payload={}))
    plugin._pyinfra_run.assert_not_called()


# start

def test_service_start_calls_pyinfra_when_stopped(tmp_path):
    from pyinfra.operations import systemd as systemd_ops
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(False)):
        plugin._handle_service_start(Event("initsys.service.start", payload={"service_name": "ff-nft"}))
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert systemd_ops.service in ops


def test_service_start_skips_when_already_running(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(True)):
        plugin._handle_service_start(Event("initsys.service.start", payload={"service_name": "ff-nft"}))
    plugin._pyinfra_run.assert_not_called()


def test_service_start_missing_name_is_ignored(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    plugin._handle_service_start(Event("initsys.service.start", payload={}))
    plugin._pyinfra_run.assert_not_called()


# stop

def test_service_stop_calls_pyinfra_when_running(tmp_path):
    from pyinfra.operations import systemd as systemd_ops
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(True)):
        plugin._handle_service_stop(Event("initsys.service.stop", payload={"service_name": "ff-nft"}))
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert systemd_ops.service in ops


def test_service_stop_skips_when_already_stopped(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(False)):
        plugin._handle_service_stop(Event("initsys.service.stop", payload={"service_name": "ff-nft"}))
    plugin._pyinfra_run.assert_not_called()


def test_service_stop_missing_name_is_ignored(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    plugin._handle_service_stop(Event("initsys.service.stop", payload={}))
    plugin._pyinfra_run.assert_not_called()


# restart

def test_service_restart_always_calls_pyinfra(tmp_path):
    from pyinfra.operations import systemd as systemd_ops
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"):
        plugin._handle_service_restart(Event("initsys.service.restart", payload={"service_name": "ff-nft"}))
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert systemd_ops.service in ops
    svc_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is systemd_ops.service)
    assert svc_call[1]["restarted"] is True


def test_service_restart_missing_name_is_ignored(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    plugin._handle_service_restart(Event("initsys.service.restart", payload={}))
    plugin._pyinfra_run.assert_not_called()


# disable

def test_service_disable_calls_pyinfra_when_active(tmp_path):
    from pyinfra.operations import systemd as systemd_ops
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(True, True)):
        plugin._handle_service_disable(Event("initsys.service.disable", payload={"service_name": "ff-nft"}))
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert systemd_ops.service in ops
    svc_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is systemd_ops.service)
    assert svc_call[1]["running"] is False
    assert svc_call[1]["enabled"] is False


def test_service_disable_skips_when_already_disabled(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"), \
         patch.object(type(plugin), "_get_service_status", _mock_status(False, False)):
        plugin._handle_service_disable(Event("initsys.service.disable", payload={"service_name": "ff-nft"}))
    plugin._pyinfra_run.assert_not_called()


def test_service_disable_missing_name_is_ignored(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    plugin._handle_service_disable(Event("initsys.service.disable", payload={}))
    plugin._pyinfra_run.assert_not_called()


# remove

def test_service_remove_stops_disables_and_removes_unit_file(tmp_path):
    from pyinfra.operations import files as files_ops, systemd as systemd_ops
    plugin = _make_svc_plugin(tmp_path)
    with patch.object(type(plugin), "_detect_init_system", return_value="systemd"):
        plugin._handle_service_remove(Event("initsys.service.remove", payload={"service_name": "ff-nft"}))
    ops = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert systemd_ops.service in ops
    assert files_ops.file in ops
    assert systemd_ops.daemon_reload in ops
    file_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is files_ops.file)
    assert file_call[1]["path"] == "/etc/systemd/system/ff-nft.service"
    assert file_call[1]["present"] is False


def test_service_remove_missing_name_is_ignored(tmp_path):
    plugin = _make_svc_plugin(tmp_path)
    plugin._handle_service_remove(Event("initsys.service.remove", payload={}))
    plugin._pyinfra_run.assert_not_called()
