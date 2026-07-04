"""
Tests for pkg_management plugin routes.

pyinfra calls are mocked via _pyinfra_run so no actual system changes are made.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ff_auth.auth import AuthUser, get_current_user


# ── helpers ────────────────────────────────────────────────────────────────────

_REPO_ROOT = str(Path(__file__).parents[2])


def _load_pkg_manager_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    pm_py = Path(__file__).parent / "_pkg_manager.py"
    sys.modules.pop("_pkgmgmt_pkg_manager_test", None)
    spec = importlib.util.spec_from_file_location("_pkgmgmt_pkg_manager_test", pm_py)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_pkgmgmt_pkg_manager_test"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


_PKG_NAME = "plugins.pkg_management"
_PLUGIN_DIR = Path(__file__).parent


def _load_plugin_module():
    import types
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    # Register a package stub so relative imports (from ._pkg_manager) resolve.
    if _PKG_NAME not in sys.modules:
        pkg = types.ModuleType(_PKG_NAME)
        pkg.__path__ = [str(_PLUGIN_DIR)]  # type: ignore[attr-defined]
        pkg.__package__ = _PKG_NAME
        sys.modules[_PKG_NAME] = pkg
    mod_name = f"{_PKG_NAME}.plugin"
    sys.modules.pop(mod_name, None)
    plugin_py = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location(mod_name, plugin_py)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = _PKG_NAME
    sys.modules[mod_name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_plugin(tmp_path, config=None, system_repos=None):
    mod = _load_plugin_module()
    plugin = mod.PkgManagementPlugin()
    plugin.plugin_id = "pkg_management"
    plugin.meta = {"name": "Package Management Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    # Unique logger per instance so patch.object on one plugin doesn't bleed into others
    # that are still subscribed to the bus from previous tests.
    plugin.logger = logging.getLogger(f"test.pkg_management.{id(plugin)}")
    plugin._pyinfra_run = MagicMock()
    plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
    plugin.configure()
    plugin.api = mod.PkgManagementAPI(plugin)
    plugin.setup()
    plugin._pkg_mgr.list_system_repos = MagicMock(return_value=system_repos or {})
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={})
    plugin._pkg_mgr.list_available_packages = MagicMock(return_value={})
    return plugin


def _make_client(plugin) -> TestClient:
    app = FastAPI()
    app.include_router(plugin.api.router, prefix="/v1/pkg_management")
    app.dependency_overrides[get_current_user] = lambda: AuthUser(username="test", roles=["admin"])
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
    r = client.get("/v1/pkg_management/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "Package Management Plugin"
    assert data["version"] == "1.0.0"


def test_status_managed_counts_start_at_zero(client):
    managed = client.get("/v1/pkg_management/status").json()["managed"]
    assert managed == {"services": 0, "packages": 0, "repos": 0}


def test_status_counts_update_after_additions(client):
    client.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    managed = client.get("/v1/pkg_management/status").json()["managed"]
    assert managed["services"] == 1


def test_status_pending_changes_false_after_mutation(client):
    client.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    assert client.get("/v1/pkg_management/status").json()["pending_changes"] is False


def test_status_pending_changes_false_when_nothing_managed(client):
    assert client.get("/v1/pkg_management/status").json()["pending_changes"] is False


# ── services ───────────────────────────────────────────────────────────────────

def test_list_services_empty(client):
    r = client.get("/v1/pkg_management/services")
    assert r.status_code == 200
    data = r.json()
    assert "services" in data
    assert all(not s["ff_managed"] for s in data["services"].values())


def test_set_service_running_and_enabled(client, plugin):
    r = client.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    assert r.status_code == 200
    assert r.json() == {"service": "nginx", "running": True, "enabled": True}
    plugin._pyinfra_run.assert_called_once()
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["service"] == "nginx"
    assert kwargs["running"] is True
    assert kwargs["enabled"] is True


def test_set_service_stopped_disabled(client, plugin):
    client.put("/v1/pkg_management/services/cron", json={"running": False, "enabled": False})
    _, kwargs = plugin._pyinfra_run.call_args
    assert kwargs["running"] is False
    assert kwargs["enabled"] is False


def test_set_service_uses_server_service_op(client, plugin):
    from pyinfra.operations import server as server_ops
    client.put("/v1/pkg_management/services/sshd", json={"running": True, "enabled": True})
    args, _ = plugin._pyinfra_run.call_args
    assert args[0] is server_ops.service


def test_list_services_shows_added_entry(client):
    client.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    services = client.get("/v1/pkg_management/services").json()["services"]
    assert "nginx" in services
    assert services["nginx"]["ff_managed"] is True


def test_delete_service_removes_entry(client, plugin):
    plugin._read_system_services = MagicMock(return_value={})
    client.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    r = client.delete("/v1/pkg_management/services/nginx")
    assert r.status_code == 200
    assert r.json() == {"deleted": "nginx"}
    assert "nginx" not in client.get("/v1/pkg_management/services").json()["services"]


def test_delete_service_not_managed_returns_404(client):
    r = client.delete("/v1/pkg_management/services/ghost")
    assert r.status_code == 404


def test_import_service_reads_state_from_system(client, plugin):
    plugin._read_system_services = MagicMock(return_value={
        "ssh": {"running": True, "enabled": True}
    })
    r = client.post("/v1/pkg_management/services/ssh/import")
    assert r.status_code == 201
    data = r.json()
    assert data["service"] == "ssh"
    assert data["running"] is True
    assert data["enabled"] is True
    assert data["ff_managed"] is True
    assert client.get("/v1/pkg_management/services").json()["services"]["ssh"]["ff_managed"] is True


def test_import_service_not_on_system_returns_404(client, plugin):
    plugin._read_system_services = MagicMock(return_value={})
    assert client.post("/v1/pkg_management/services/ghost/import").status_code == 404


# ── state persistence ──────────────────────────────────────────────────────────

def test_state_persists_across_plugin_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert "nginx" in c2.get("/v1/pkg_management/services").json()["services"]


def test_deleted_entries_absent_after_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    p1._read_system_services = MagicMock(return_value={})
    c1 = _make_client(p1)
    c1.put("/v1/pkg_management/services/nginx", json={"running": True, "enabled": True})
    c1.delete("/v1/pkg_management/services/nginx")
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    p2._read_system_services = MagicMock(return_value={})
    c2 = _make_client(p2)
    assert "nginx" not in c2.get("/v1/pkg_management/services").json()["services"]


def test_state_file_written_to_configured_path(tmp_path):
    p = _make_plugin(tmp_path, config={"state_file": "custom_state.json"})
    c = _make_client(p)
    c.put("/v1/pkg_management/services/sshd", json={"running": True, "enabled": True})
    p.teardown()
    assert (tmp_path / "data" / "custom_state.json").exists()


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
    import time
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt", cache_ttl=300)
    mgr._cache_refreshed_at = time.monotonic() - 301
    mgr.refresh_cache()
    runner.assert_called_once()


def test_refresh_cache_force_bypasses_ttl():
    import time
    pm = _load_pkg_manager_module()
    runner = MagicMock()
    mgr = pm.PackageManager(runner, "apt", cache_ttl=300)
    mgr._cache_refreshed_at = time.monotonic()
    mgr.refresh_cache(force=True)
    runner.assert_called_once()


def test_install_skips_refresh_when_cache_fresh(tmp_path):
    import time
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr._cache_refreshed_at = time.monotonic()
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    pkg_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.packages)
    assert pkg_call is not None
    update_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.update]
    assert update_calls == []


def test_repo_add_refreshes_even_when_cache_fresh(tmp_path):
    import time
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr._cache_refreshed_at = time.monotonic()
    client = _make_client(plugin)
    client.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    update_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.update]
    assert len(update_calls) == 1


def test_cache_ttl_zero_always_refreshes(tmp_path):
    import time
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, config={"os_pkgmgr_max_cache_ttl_secs": 0})
    plugin._pkg_mgr._cache_refreshed_at = time.monotonic()
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
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
    r = client.get("/v1/pkg_management/packages")
    assert r.status_code == 200
    assert r.json()["mode"] == "installed"


def test_list_packages_installed_shows_system_packages(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"bash": {"version": "5.1", "installed": True}})
    client = _make_client(plugin)
    entry = client.get("/v1/pkg_management/packages").json()["packages"]["bash"]
    assert entry["installed"] is True
    assert entry["ff_managed"] is False


def test_list_packages_installed_marks_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={"present": True, "latest": False})
    entry = client.get("/v1/pkg_management/packages").json()["packages"]["curl"]
    assert entry["installed"] is True
    assert entry["ff_managed"] is True
    assert entry["version"] == "7.88"


def test_list_packages_managed_mode_only_shows_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"bash": {"version": "5.1", "installed": True}})
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    data = client.get("/v1/pkg_management/packages?mode=managed").json()
    assert "curl" in data["packages"]
    assert "bash" not in data["packages"]
    assert data["packages"]["curl"]["ff_managed"] is True


def test_list_packages_managed_mode_annotates_installed_status(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    entry = client.get("/v1/pkg_management/packages?mode=managed").json()["packages"]["curl"]
    assert entry["installed"] is True
    assert entry["version"] == "7.88"


def test_list_packages_managed_mode_not_installed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/vim", json={})
    entry = client.get("/v1/pkg_management/packages?mode=managed").json()["packages"]["vim"]
    assert entry["installed"] is False
    assert entry["ff_managed"] is True


def test_list_packages_available_mode_shows_repo_packages(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_available_packages = MagicMock(return_value={"curl": {}, "vim": {}, "git": {}})
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    data = client.get("/v1/pkg_management/packages?mode=available").json()
    assert "curl" in data["packages"]
    assert "vim" in data["packages"]
    assert data["packages"]["curl"]["installed"] is True
    assert data["packages"]["vim"]["installed"] is False


def test_list_packages_available_mode_marks_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_available_packages = MagicMock(return_value={"curl": {}, "vim": {}})
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    data = client.get("/v1/pkg_management/packages?mode=available").json()["packages"]
    assert data["curl"]["ff_managed"] is True
    assert data["vim"]["ff_managed"] is False


def test_list_packages_invalid_mode_returns_400(client):
    assert client.get("/v1/pkg_management/packages?mode=bogus").status_code == 400


def test_list_packages_includes_mode_in_response(client):
    for mode in ("installed", "managed", "available"):
        assert client.get(f"/v1/pkg_management/packages?mode={mode}").json()["mode"] == mode


def test_install_package_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/pkg_management/packages/curl", json={"present": True, "latest": False})
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
    client.post("/v1/pkg_management/packages/vim", json={})
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is pacman_ops.packages
    assert "latest" not in kwargs


def test_install_package_appears_in_managed_list(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    entry = client.get("/v1/pkg_management/packages?mode=managed").json()["packages"]["curl"]
    assert entry["ff_managed"] is True


def test_update_package_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    plugin._pyinfra_run.reset_mock()

    r = client.put("/v1/pkg_management/packages/curl")
    assert r.status_code == 200
    assert r.json()["updated"] is True
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is apt_ops.packages
    assert kwargs["latest"] is True


def test_update_package_not_managed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.put("/v1/pkg_management/packages/ghost").status_code == 404


def test_remove_package_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    plugin._pyinfra_run.reset_mock()

    r = client.delete("/v1/pkg_management/packages/curl")
    assert r.status_code == 200
    assert r.json() == {"deleted": "curl"}
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is apt_ops.packages
    assert kwargs["present"] is False
    assert "curl" not in client.get("/v1/pkg_management/packages").json()["packages"]


def test_remove_package_not_managed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.delete("/v1/pkg_management/packages/ghost").status_code == 404


def test_import_package_marks_installed_package_as_managed(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={"curl": {"version": "7.88", "installed": True}})
    client = _make_client(plugin)
    r = client.post("/v1/pkg_management/packages/curl/import")
    assert r.status_code == 201
    data = r.json()
    assert data["package"] == "curl"
    assert data["present"] is True
    assert data["ff_managed"] is True
    assert client.get("/v1/pkg_management/packages?mode=managed").json()["packages"]["curl"]["ff_managed"] is True


def test_import_package_not_installed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.list_system_packages = MagicMock(return_value={})
    client = _make_client(plugin)
    assert client.post("/v1/pkg_management/packages/curl/import").status_code == 404


def test_package_endpoints_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/pkg_management/packages/curl", json={}).status_code == 503
    assert client.put("/v1/pkg_management/packages/curl").status_code == 503
    assert client.delete("/v1/pkg_management/packages/curl").status_code == 503


def test_status_includes_package_manager_and_counts(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/packages/curl", json={})
    data = client.get("/v1/pkg_management/status").json()
    assert data["package_manager"] == "apt"
    assert data["managed"]["packages"] == 1
    assert data["managed"]["repos"] == 0


# ── repos ──────────────────────────────────────────────────────────────────────

def test_list_repos_empty(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    r = client.get("/v1/pkg_management/repos")
    assert r.status_code == 200
    assert r.json()["repos"] == {}


def test_list_repos_shows_system_repos_as_unmanaged(tmp_path):
    sys_key = "deb https://packages.example.com/apt focal main"
    system = {sys_key: {"src": sys_key}}
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, system_repos=system)
    client = _make_client(plugin)
    r = client.get("/v1/pkg_management/repos")
    assert r.status_code == 200
    entry = r.json()["repos"][sys_key]
    assert entry["ff_managed"] is False
    assert entry["id"] == hashlib.sha256(sys_key.encode()).hexdigest()[:8]


def test_list_repos_marks_managed_repo(tmp_path):
    src = "deb https://packages.example.com/apt focal main"
    system = {src: {"src": src}}
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, system_repos=system)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/repos/myrepo", json={"src": src})
    r = client.get("/v1/pkg_management/repos")
    assert r.status_code == 200
    entry = r.json()["repos"][src]
    assert entry["ff_managed"] is True
    assert entry["id"] == hashlib.sha256(src.encode()).hexdigest()[:8]
    assert entry["name"] == "myrepo"


def test_list_repos_managed_but_not_in_system_uses_name_as_key(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    client.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    r = client.get("/v1/pkg_management/repos")
    assert r.status_code == 200
    entry = r.json()["repos"]["myrepo"]
    assert entry["ff_managed"] is True
    assert entry["id"] == hashlib.sha256(b"myrepo").hexdigest()[:8]
    assert entry["name"] == "myrepo"


def test_add_apt_repo_calls_pyinfra(tmp_path):
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
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

    client.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://example.com/apt focal main", "key_url": "https://example.com/key.gpg"})
    calls = [c[0][0] for c in plugin._pyinfra_run.call_args_list]
    assert apt_ops.repo in calls
    assert apt_ops.key in calls
    key_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.key)
    assert key_call[1]["src"] == "https://example.com/key.gpg"


def test_add_apt_repo_missing_src_returns_422(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/pkg_management/repos/myrepo", json={}).status_code == 422


def test_add_yum_repo_calls_pyinfra(tmp_path):
    from pyinfra.operations import yum as yum_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/yum" if b == "yum" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/pkg_management/repos/epel", json={"src": "epel", "baseurl": "https://dl.fedoraproject.org/pub/epel/9/x86_64/", "gpgcheck": True})
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

    client.post("/v1/pkg_management/repos/myrepo", json={"src": "myrepo"})
    repo_call = next(c for c in plugin._pyinfra_run.call_args_list if c[0][0] is dnf_ops.repo)
    args, _ = repo_call
    assert args[0] is dnf_ops.repo


def test_add_apk_repo_calls_files_line(tmp_path):
    from pyinfra.operations import files as files_ops
    with patch("shutil.which", side_effect=lambda b: "/sbin/apk" if b == "apk" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/pkg_management/repos/alpine-edge", json={"url": "https://dl-cdn.alpinelinux.org/alpine/edge/main"})
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
    assert client.post("/v1/pkg_management/repos/myrepo", json={}).status_code == 422


def test_add_pacman_repo_calls_shell(tmp_path):
    from pyinfra.operations import server as server_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/pacman" if b == "pacman" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)

    r = client.post("/v1/pkg_management/repos/archlinux-cn", json={"url": "https://repo.archlinuxcn.org/x86_64"})
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

    client.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    plugin._pyinfra_run.reset_mock()

    r = client.delete("/v1/pkg_management/repos/myrepo")
    assert r.status_code == 200
    assert r.json() == {"deleted": "myrepo"}
    args, kwargs = plugin._pyinfra_run.call_args
    assert args[0] is apt_ops.repo
    assert kwargs["present"] is False
    assert "myrepo" not in client.get("/v1/pkg_management/repos").json()["repos"]


def test_remove_repo_not_managed_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.delete("/v1/pkg_management/repos/ghost").status_code == 404


def test_import_repo_copies_system_repo(tmp_path):
    src = "deb https://packages.example.com/apt focal main"
    src_id = hashlib.sha256(src.encode()).hexdigest()[:8]
    system = {src: {"src": src}}
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path, system_repos=system)
    client = _make_client(plugin)
    r = client.post("/v1/pkg_management/repos/import", json={"id": src_id, "alias": "myrepo"})
    assert r.status_code == 201
    data = r.json()
    assert data["repo"] == "myrepo"
    assert data["ff_managed"] is True
    assert client.get("/v1/pkg_management/repos").json()["repos"][src]["ff_managed"] is True


def test_import_repo_missing_id_returns_404(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/pkg_management/repos/import", json={"id": "deadbeef", "alias": "myrepo"}).status_code == 404


def test_repo_endpoints_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://x.com focal main"}).status_code == 503
    assert client.delete("/v1/pkg_management/repos/myrepo").status_code == 503


def test_search_packages_returns_results(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pkg_mgr.search_packages = MagicMock(return_value=[
        {"name": "curl", "description": "command line tool for transferring data"},
        {"name": "libcurl4", "description": "easy-to-use client-side URL transfer library"},
    ])
    client = _make_client(plugin)
    r = client.get("/v1/pkg_management/packages/search?q=curl")
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
    assert client.get("/v1/pkg_management/packages/search?q=curl").status_code == 503


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
    c1.post("/v1/pkg_management/packages/curl", json={})
    p1.teardown()

    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    packages = c2.get("/v1/pkg_management/packages?mode=managed").json()["packages"]
    assert "curl" in packages
    assert packages["curl"]["ff_managed"] is True


def test_repo_state_persists_across_restart(tmp_path):
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.post("/v1/pkg_management/repos/myrepo", json={"src": "deb https://example.com/apt focal main"})
    p1.teardown()

    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    assert "myrepo" in c2.get("/v1/pkg_management/repos").json()["repos"]


def test_old_state_file_without_packages_loads_cleanly(tmp_path):
    state_path = tmp_path / "data" / "pkg_management_state.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps({"desired_state": {"services": {"nginx": {"running": True, "enabled": True}}}}))

    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.get("/v1/pkg_management/packages").status_code == 200
    assert client.get("/v1/pkg_management/repos").status_code == 200
    assert "nginx" in client.get("/v1/pkg_management/services").json()["services"]


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
    r = client.post("/v1/pkg_management/packages/upgrade-system", json={"email": "ops@example.com"})
    assert r.status_code == 200
    assert r.json()["status"] == "started"
    assert r.json()["email"] == "ops@example.com"


def test_upgrade_503_when_no_pkg_manager(tmp_path):
    with patch("shutil.which", return_value=None):
        plugin = _make_plugin(tmp_path)
    client = _make_client(plugin)
    assert client.post("/v1/pkg_management/packages/upgrade-system", json={"email": "ops@example.com"}).status_code == 503


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
    global_bus.subscribe("pkg_management.package.upgrade-system.done", received.append)
    try:
        plugin._run_upgrade_task(task_id, "ops@example.com")
        assert len(received) == 1
        assert received[0].payload["returncode"] == 0
        assert received[0].payload["email"] == "ops@example.com"
    finally:
        global_bus.unsubscribe("pkg_management.package.upgrade-system.done", received.append)


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
    "desired_state": {
        "services": {"nginx": {"running": True, "enabled": True}},
        "packages": {},
        "repos": {},
    },
}


def _write_boot_state(tmp_path, state=None):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "pkg_management_state.json").write_text(json.dumps(state or _BOOT_STATE))


def _make_inst(tmp_path, config=None):
    mod = _load_plugin_module()
    plugin = mod.PkgManagementPlugin()
    plugin.plugin_id = "pkg_management"
    plugin.meta = {"name": "Package Management Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.pkg_management")
    plugin._pyinfra_run = MagicMock()
    plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
    return plugin, mod


def test_state_reapplied_on_boot_calls_pyinfra(tmp_path):
    from pyinfra.operations import server as server_ops
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path)
    plugin.configure()
    plugin.setup()
    assert plugin._pyinfra_run_many.call_count == 1
    batch = plugin._pyinfra_run_many.call_args[0][0]
    ops_called = [op for op, _ in batch]
    assert server_ops.service in ops_called


def test_ignore_state_on_boot_skips_apply(tmp_path):
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path, config={"ignore_state_on_boot": True})
    plugin.configure()
    plugin.setup()
    plugin._pyinfra_run_many.assert_not_called()
    assert plugin._state == {k: {} for k in plugin._EMPTY_STATE}


def test_apply_state_does_not_crash_on_pyinfra_failure(tmp_path):
    _write_boot_state(tmp_path)
    plugin, _ = _make_inst(tmp_path)
    plugin.configure()
    plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(False, "pyinfra failed")] * len(ops))
    plugin.setup()  # must not raise
    assert "nginx" in plugin._state["services"]


def test_empty_state_skips_apply_calls(tmp_path):
    plugin, _ = _make_inst(tmp_path)
    plugin.configure()
    plugin.setup()  # no state file — all categories empty
    plugin._pyinfra_run_many.assert_not_called()


# ── event-driven API ───────────────────────────────────────────────────────────

def test_add_package_event_installs_package(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    try:
        global_bus.emit(Event("pkg_management.add.package", payload={"name": "htop"}))
        pkg_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.packages]
        assert len(pkg_calls) == 1
        assert pkg_calls[0][1]["packages"] == ["htop"]
        assert "htop" in plugin._state["packages"]
    finally:
        plugin.teardown()


def test_add_package_event_persists_to_state(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    try:
        global_bus.emit(Event("pkg_management.add.package", payload={"name": "curl", "latest": True}))
        assert plugin._state["packages"]["curl"] == {"present": True, "latest": True}
    finally:
        plugin.teardown()


def test_add_package_event_missing_name_logs_error(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    plugin = _make_plugin(tmp_path)
    try:
        with patch.object(plugin.logger, "error") as mock_err:
            global_bus.emit(Event("pkg_management.add.package", payload={}))
            mock_err.assert_called_once()
            assert "name" in mock_err.call_args[0][0]
    finally:
        plugin.teardown()


def test_add_package_event_pyinfra_failure_logs_and_does_not_raise(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin._pyinfra_run.side_effect = RuntimeError("apt locked")
    try:
        with patch.object(plugin.logger, "error") as mock_err:
            global_bus.emit(Event("pkg_management.add.package", payload={"name": "curl"}))
            mock_err.assert_called_once()
    finally:
        plugin._pyinfra_run.side_effect = None
        plugin.teardown()


def test_add_repo_event_adds_apt_repo(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    from pyinfra.operations import apt as apt_ops
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    try:
        global_bus.emit(Event("pkg_management.add.repo", payload={
            "name": "myrepo",
            "src": "deb https://example.com/apt focal main",
        }))
        repo_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is apt_ops.repo]
        assert len(repo_calls) == 1
        assert repo_calls[0][1]["src"] == "deb https://example.com/apt focal main"
        assert "myrepo" in plugin._state["repos"]
    finally:
        plugin.teardown()


def test_add_repo_event_missing_name_logs_error(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    plugin = _make_plugin(tmp_path)
    try:
        with patch.object(plugin.logger, "error") as mock_err:
            global_bus.emit(Event("pkg_management.add.repo", payload={"src": "deb https://x.com focal main"}))
            mock_err.assert_called_once()
            assert "name" in mock_err.call_args[0][0]
    finally:
        plugin.teardown()


def test_add_service_event_configures_service(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    from pyinfra.operations import server as server_ops
    plugin = _make_plugin(tmp_path)
    try:
        global_bus.emit(Event("pkg_management.add.service", payload={
            "service": "nginx",
            "running": True,
            "enabled": True,
        }))
        svc_calls = [c for c in plugin._pyinfra_run.call_args_list if c[0][0] is server_ops.service]
        assert len(svc_calls) == 1
        assert svc_calls[0][1]["service"] == "nginx"
        assert svc_calls[0][1]["running"] is True
        assert "nginx" in plugin._state["services"]
    finally:
        plugin.teardown()


def test_add_service_event_defaults_running_and_enabled(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    plugin = _make_plugin(tmp_path)
    try:
        global_bus.emit(Event("pkg_management.add.service", payload={"service": "sshd"}))
        assert plugin._state["services"]["sshd"] == {"running": True, "enabled": True}
    finally:
        plugin.teardown()


def test_add_service_event_missing_service_logs_error(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    plugin = _make_plugin(tmp_path)
    try:
        with patch.object(plugin.logger, "error") as mock_err:
            global_bus.emit(Event("pkg_management.add.service", payload={}))
            mock_err.assert_called_once()
            assert "service" in mock_err.call_args[0][0]
    finally:
        plugin.teardown()


def test_teardown_unsubscribes_event_handlers(tmp_path):
    from plugin_system.core.events import bus as global_bus, Event
    with patch("shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        plugin = _make_plugin(tmp_path)
    plugin.teardown()
    # After teardown, emitting pkg_management.add.package must not call the plugin's pyinfra_run
    plugin._pyinfra_run.reset_mock()
    global_bus.emit(Event("pkg_management.add.package", payload={"name": "curl"}))
    plugin._pyinfra_run.assert_not_called()
