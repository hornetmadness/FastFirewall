"""
Tests for the Syslog plugin routes (/v1/syslog/*).

pyinfra calls are mocked via _pyinfra_run and subprocess.run is patched where
needed so no actual system changes are made.
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

_REPO_ROOT = str(Path(__file__).parents[2])


def _load_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    plugin_py = Path(__file__).parent / "plugin.py"
    sys.modules.pop("_test_syslog_plugin", None)
    spec = importlib.util.spec_from_file_location("_test_syslog_plugin", plugin_py)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_test_syslog_plugin"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_plugin(tmp_path, config=None):
    mod = _load_module()
    plugin = mod.SyslogPlugin()
    plugin.plugin_id = "syslog_plugin"
    plugin.meta = {"name": "Syslog Plugin", "version": "1.0.0"}
    default_conf = {
        "log_dir": str(tmp_path / "logs"),
        "fastfirewall_conf": str(tmp_path / "fastfirewall"),
        "fluent_bit_main_conf": str(tmp_path / "fluent-bit.conf"),
    }
    plugin.config = {**default_conf, **(config or {})}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.syslog_plugin")
    plugin._pyinfra_run = MagicMock()
    with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
        plugin.setup()
    return plugin


def _make_client(plugin) -> TestClient:
    app = FastAPI()
    app.include_router(plugin.router, prefix="/v1/syslog")
    return TestClient(app)


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def log_dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    return d


@pytest.fixture
def plugin(tmp_path, log_dir):
    return _make_plugin(tmp_path, config={"log_dir": str(log_dir)})


@pytest.fixture
def client(plugin):
    return _make_client(plugin)


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_fluent_conf(plugin) -> str:
    """Return the fastfirewall.yaml config string that was passed to pyinfra put."""
    for call in plugin._pyinfra_run.call_args_list:
        args, kwargs = call
        if "fastfirewall" in kwargs.get("name", ""):
            src = kwargs["src"]
            return src.getvalue()
    raise AssertionError("fastfirewall config put call not found")


# ── setup ──────────────────────────────────────────────────────────────────────

def test_setup_calls_pyinfra(tmp_path):
    plugin = _make_plugin(tmp_path)
    assert plugin._pyinfra_run.called


def test_setup_starts_fluent_bit_service(tmp_path):
    plugin = _make_plugin(tmp_path)
    service_calls = [
        call for call in plugin._pyinfra_run.call_args_list
        if call[1].get("service") == "fluent-bit"
    ]
    assert service_calls, "expected a server_ops.service call for fluent-bit"
    kwargs = service_calls[0][1]
    assert kwargs.get("enabled") is True
    assert kwargs.get("running") is True, "fluent-bit must be started (running=True), not just enabled at boot"


# ── status ─────────────────────────────────────────────────────────────────────

def test_fluent_conf_network_input_present(tmp_path):
    plugin = _make_plugin(tmp_path, config={"log_dir": str(tmp_path / "logs"), "syslog_port": 514})
    conf = _get_fluent_conf(plugin)
    assert "Mode udp" in conf
    assert "Listen 0.0.0.0" in conf
    assert "Port 514" in conf


def test_fluent_conf_unix_socket_absent_by_default(tmp_path):
    plugin = _make_plugin(tmp_path, config={"log_dir": str(tmp_path / "logs")})
    conf = _get_fluent_conf(plugin)
    assert "unix_udp" not in conf
    assert "unix_tcp" not in conf


def test_fluent_conf_unix_socket_included_when_configured(tmp_path):
    plugin = _make_plugin(tmp_path, config={
        "log_dir": str(tmp_path / "logs"),
        "syslog_unix_path": "/run/fluent-bit.sock",
        "syslog_unix_mode": "unix_udp",
    })
    conf = _get_fluent_conf(plugin)
    assert "/run/fluent-bit.sock" in conf
    assert "Mode unix_udp" in conf
    assert "syslog.unix" in conf


def test_fluent_conf_unix_tcp_mode(tmp_path):
    plugin = _make_plugin(tmp_path, config={
        "log_dir": str(tmp_path / "logs"),
        "syslog_unix_path": "/run/fluent-bit.sock",
        "syslog_unix_mode": "unix_tcp",
    })
    conf = _get_fluent_conf(plugin)
    assert "Mode unix_tcp" in conf


def test_status_unix_path_reported(tmp_path):
    plugin = _make_plugin(tmp_path, config={
        "log_dir": str(tmp_path / "logs"),
        "syslog_unix_path": "/run/fluent-bit.sock",
    })
    client = _make_client(plugin)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        r = client.get("/v1/syslog/status")
    body = r.json()
    assert body["syslog_unix_path"] == "/run/fluent-bit.sock"
    assert body["syslog_unix_mode"] == "unix_udp"


def test_status_unix_path_null_when_not_configured(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        r = client.get("/v1/syslog/status")
    body = r.json()
    assert body["syslog_unix_path"] is None
    assert body["syslog_unix_mode"] is None


# ── config GET ────────────────────────────────────────────────────────────────

def test_get_config_returns_all_fields(client):
    r = client.get("/v1/syslog/config")
    assert r.status_code == 200
    body = r.json()
    for key in ("syslog_port", "syslog_mode", "syslog_unix_path", "syslog_unix_mode",
                "enable_systemd_input", "fastfirewall_conf", "log_dir"):
        assert key in body


def test_get_config_reflects_defaults(client):
    body = client.get("/v1/syslog/config").json()
    assert body["syslog_port"] == 514
    assert body["syslog_mode"] == "udp"
    assert body["enable_systemd_input"] is True
    assert body["syslog_unix_path"] is None


# ── config PATCH ───────────────────────────────────────────────────────────────

def test_patch_config_port(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.patch("/v1/syslog/config", json={"syslog_port": 5140})
    assert r.status_code == 200
    assert r.json()["syslog_port"] == 5140


def test_patch_config_persists_to_overrides(plugin, client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        client.patch("/v1/syslog/config", json={"syslog_port": 5140, "syslog_mode": "tcp"})
    overrides = json.loads(plugin._state_file.path.read_text())
    assert overrides["syslog_port"] == 5140
    assert overrides["syslog_mode"] == "tcp"


def test_patch_config_overrides_loaded_on_next_start(tmp_path, log_dir):
    plugin = _make_plugin(tmp_path, config={"log_dir": str(log_dir)})
    client = _make_client(plugin)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        client.patch("/v1/syslog/config", json={"syslog_port": 9999})
    plugin2 = _make_plugin(tmp_path, config={"log_dir": str(log_dir)})
    assert plugin2._syslog_port == 9999


def test_patch_config_invalid_mode(client):
    r = client.patch("/v1/syslog/config", json={"syslog_mode": "bogus"})
    assert r.status_code == 400


def test_patch_config_invalid_unix_mode(client):
    r = client.patch("/v1/syslog/config", json={"syslog_unix_mode": "bogus"})
    assert r.status_code == 400


def test_patch_config_enable_systemd_toggle(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.patch("/v1/syslog/config", json={"enable_systemd_input": False})
    assert r.status_code == 200
    assert r.json()["enable_systemd_input"] is False


def test_patch_config_unix_path_empty_string_disables(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.patch("/v1/syslog/config", json={"syslog_unix_path": ""})
    assert r.status_code == 200
    assert r.json()["syslog_unix_path"] is None


# ── config reload ──────────────────────────────────────────────────────────────

def test_reload_calls_systemctl(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.post("/v1/syslog/config/reload")
    assert r.status_code == 200
    assert r.json()["reloaded"] is True
    cmd = mock_run.call_args[0][0]
    assert "restart" in cmd
    assert "fluent-bit" in cmd


def test_reload_returns_500_on_failure(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", stderr="unit not found", returncode=1)
        r = client.post("/v1/syslog/config/reload")
    assert r.status_code == 500


# ── config raw ─────────────────────────────────────────────────────────────────

def test_get_raw_returns_content(plugin, client):
    plugin._fastfirewall_conf.parent.mkdir(parents=True, exist_ok=True)
    plugin._fastfirewall_conf.write_text("[SERVICE]\n    Flush 5\n")
    r = client.get("/v1/syslog/config/raw")
    assert r.status_code == 200
    body = r.json()
    assert "content" in body
    assert "[SERVICE]" in body["content"]
    assert "path" in body


def test_get_raw_404_when_missing(plugin, client):
    if plugin._fastfirewall_conf.exists():
        plugin._fastfirewall_conf.unlink()
    r = client.get("/v1/syslog/config/raw")
    assert r.status_code == 404


# ── diagnose ──────────────────────────────────────────────────────────────────

def _mock_diagnose_subproc(active=True, fb_user="root", journal_logs=""):
    def side_effect(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "is-active" in cmd_str:
            return MagicMock(stdout="active\n" if active else "inactive\n", returncode=0)
        if "show" in cmd_str and "User" in cmd_str:
            return MagicMock(stdout=f"User={fb_user}\n", returncode=0)
        if "journalctl" in cmd_str:
            return MagicMock(stdout=journal_logs, returncode=0)
        return MagicMock(stdout="", returncode=0)
    return side_effect


def test_diagnose_healthy(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("# config\n")
    plugin._fluent_bit_main_conf.write_text("imports:\n  - conf.d/*.yaml\n")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc(active=True, fb_user="root")), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    assert r.status_code == 200
    body = r.json()
    assert body["healthy"] is True
    checks = body["checks"]
    assert checks["log_dir_exists"] is True
    assert checks["config_file_exists"] is True
    assert checks["main_conf_has_include"] is True
    assert checks["fluent_bit_active"] is True
    assert checks["fluent_bit_in_journal_group"] is True


def test_diagnose_missing_log_dir(plugin, client):
    import shutil
    if plugin._log_dir.exists():
        shutil.rmtree(plugin._log_dir)
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc()), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    body = r.json()
    assert body["checks"]["log_dir_exists"] is False
    assert body["healthy"] is False


def test_diagnose_fluent_bit_inactive(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    plugin._fluent_bit_main_conf.write_text("imports:\n  - conf.d/*.yaml\n")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc(active=False)), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    body = r.json()
    assert body["checks"]["fluent_bit_active"] is False
    assert body["healthy"] is False


def test_diagnose_user_not_in_journal_group(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc(fb_user="fluent-bit")), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=["other-user"])):
        r = client.get("/v1/syslog/config/diagnose")
    body = r.json()
    assert body["checks"]["fluent_bit_user"] == "fluent-bit"
    assert body["checks"]["fluent_bit_in_journal_group"] is False
    assert body["healthy"] is False


def test_diagnose_user_in_journal_group(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc(fb_user="fluent-bit")), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=["fluent-bit"])):
        r = client.get("/v1/syslog/config/diagnose")
    body = r.json()
    assert body["checks"]["fluent_bit_in_journal_group"] is True


def test_diagnose_journal_group_missing(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc()), \
         patch("grp.getgrnam", side_effect=KeyError("systemd-journal")):
        r = client.get("/v1/syslog/config/diagnose")
    body = r.json()
    assert body["checks"]["fluent_bit_in_journal_group"] is None


def test_diagnose_output_file_reported(plugin, client, log_dir):
    (log_dir / "fluent-bit.log").write_text("some log content\n")
    plugin._fastfirewall_conf.write_text("")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc()), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    checks = r.json()["checks"]
    assert checks["output_file_exists"] is True
    assert checks["output_file_size"] > 0


def test_diagnose_includes_recent_logs(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    plugin._fluent_bit_main_conf.write_text("imports:\n  - conf.d/*.yaml\n")
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc(journal_logs="May 11 error: boom")), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    assert "boom" in r.json()["checks"]["fluent_bit_recent_logs"]


def test_diagnose_main_conf_missing_include(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    plugin._fluent_bit_main_conf.write_text("[SERVICE]\n    Flush 5\n")  # no conf.d
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc()), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    checks = r.json()["checks"]
    assert checks["main_conf_has_include"] is False
    assert r.json()["healthy"] is False


def test_diagnose_main_conf_not_found(plugin, client, log_dir):
    plugin._fastfirewall_conf.write_text("")
    # main conf does not exist (default in test setup)
    with patch("subprocess.run", side_effect=_mock_diagnose_subproc()), \
         patch("grp.getgrnam", return_value=MagicMock(gr_mem=[])):
        r = client.get("/v1/syslog/config/diagnose")
    checks = r.json()["checks"]
    assert checks["main_conf_exists"] is False
    assert checks["main_conf_has_include"] is False


# ── _ensure_main_conf_includes_confd ──────────────────────────────────────────

def test_include_creates_main_conf_when_missing(tmp_path):
    plugin = _make_plugin(tmp_path)
    assert not plugin._fluent_bit_main_conf.exists()
    plugin._ensure_main_conf_includes_confd()
    content = plugin._pyinfra_run.call_args_list[-1][1]["src"].getvalue()
    assert "conf.d" in content


def test_include_adds_to_classic_conf(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._fluent_bit_main_conf.write_text("[SERVICE]\n    Flush 5\n")
    plugin._pyinfra_run.reset_mock()
    plugin._ensure_main_conf_includes_confd()
    content = plugin._pyinfra_run.call_args[1]["src"].getvalue()
    assert "@INCLUDE conf.d/*.conf" in content
    assert "[SERVICE]" in content  # original content preserved


def test_include_skips_when_already_present(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._fluent_bit_main_conf.write_text("imports:\n  - conf.d/*.yaml\n")
    plugin._pyinfra_run.reset_mock()
    plugin._ensure_main_conf_includes_confd()
    assert not plugin._pyinfra_run.called


# ── status ─────────────────────────────────────────────────────────────────────

def test_status_returns_expected_keys(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        r = client.get("/v1/syslog/status")
    assert r.status_code == 200
    body = r.json()
    assert "log_dir" in body
    assert "fastfirewall_conf" in body
    assert "syslog_port" in body
    assert "syslog_mode" in body
    assert "services" in body
    assert "fluent-bit" in body["services"]
    assert "rsyslog" not in body["services"]


# ── file listing ───────────────────────────────────────────────────────────────

def test_list_files_empty(client):
    r = client.get("/v1/syslog/files")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 0
    assert body["files"] == []


def test_list_files_shows_log_files(client, log_dir):
    (log_dir / "syslog.log").write_text("line1\nline2\n")
    (log_dir / "fluent-bit.log").write_text("entry\n")
    r = client.get("/v1/syslog/files")
    assert r.status_code == 200
    body = r.json()
    names = [f["name"] for f in body["files"]]
    assert "syslog.log" in names
    assert "fluent-bit.log" in names
    assert body["count"] == 2


def test_list_files_missing_log_dir(tmp_path):
    plugin = _make_plugin(tmp_path, config={"log_dir": str(tmp_path / "nonexistent")})
    plugin._pyinfra_run = MagicMock()
    client = _make_client(plugin)
    r = client.get("/v1/syslog/files")
    assert r.status_code == 200
    assert r.json()["count"] == 0


# ── read log ───────────────────────────────────────────────────────────────────

def test_read_log_returns_content(client, log_dir):
    lines = "\n".join(f"line {i}" for i in range(200))
    (log_dir / "syslog.log").write_text(lines)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="line 150\nline 151\n", returncode=0)
        r = client.get("/v1/syslog/logs/syslog.log?lines=50")
    assert r.status_code == 200
    body = r.json()
    assert body["filename"] == "syslog.log"
    assert body["lines_requested"] == 50
    assert "content" in body


def test_read_log_not_found(client):
    r = client.get("/v1/syslog/logs/missing.log")
    assert r.status_code == 404


def test_read_log_path_traversal_rejected(client):
    r = client.get("/v1/syslog/logs/../etc/passwd")
    assert r.status_code in (400, 404, 422)


def test_read_log_dotdot_filename_rejected(client):
    r = client.get("/v1/syslog/logs/..%2Fetc%2Fpasswd")
    assert r.status_code in (400, 404, 422)


# ── tail ───────────────────────────────────────────────────────────────────────

def test_tail_uses_smaller_default(client, log_dir):
    (log_dir / "syslog.log").write_text("a\nb\nc\n")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="a\nb\nc\n", returncode=0)
        r = client.get("/v1/syslog/tail/syslog.log")
    assert r.status_code == 200
    body = r.json()
    assert body["lines_requested"] == 50


def test_tail_accepts_custom_lines(client, log_dir):
    (log_dir / "syslog.log").write_text("x\n")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="x\n", returncode=0)
        r = client.get("/v1/syslog/tail/syslog.log?lines=10")
    assert r.status_code == 200
    assert r.json()["lines_requested"] == 10


# ── journal ────────────────────────────────────────────────────────────────────

def test_journal_short_output(client):
    sample = "May 11 10:00:00 host rsyslog: started\nMay 11 10:00:01 host kernel: boot\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=sample, returncode=0)
        r = client.get("/v1/syslog/journal?lines=10")
    assert r.status_code == 200
    body = r.json()
    assert "content" in body
    assert body["filters"]["lines"] == 10


def test_journal_json_output(client):
    entry = {"MESSAGE": "hello", "PRIORITY": "6", "_HOSTNAME": "box"}
    sample = json.dumps(entry) + "\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=sample, returncode=0)
        r = client.get("/v1/syslog/journal?output=json&lines=5")
    assert r.status_code == 200
    body = r.json()
    assert "entries" in body
    assert body["count"] == 1
    assert body["entries"][0]["MESSAGE"] == "hello"


def test_journal_unit_filter(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.get("/v1/syslog/journal?unit=rsyslog.service")
    assert r.status_code == 200
    cmd = mock_run.call_args[0][0]
    assert "-u" in cmd
    assert "rsyslog.service" in cmd


def test_journal_priority_filter(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.get("/v1/syslog/journal?priority=err")
    assert r.status_code == 200
    cmd = mock_run.call_args[0][0]
    assert "-p" in cmd
    assert "err" in cmd


def test_journal_invalid_output_rejected(client):
    r = client.get("/v1/syslog/journal?output=malicious")
    assert r.status_code == 400


def test_journal_invalid_priority_rejected(client):
    r = client.get("/v1/syslog/journal?priority=bogus")
    assert r.status_code == 400


def test_journal_since_filter(client):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        r = client.get("/v1/syslog/journal?since=2024-01-01+00:00:00")
    assert r.status_code == 200
    cmd = mock_run.call_args[0][0]
    assert "--since" in cmd
