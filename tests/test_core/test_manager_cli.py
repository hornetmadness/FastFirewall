"""Tests for manager_cli install-service helpers."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from plugin_system import manager_cli


# ── _build_service_unit ────────────────────────────────────────────────────────

def test_build_service_unit_has_required_sections():
    content = manager_cli._build_service_unit(
        exec_start="/usr/bin/fastfirewall-api",
        config_path=Path("/etc/fastfirewall/app_config.yaml"),
        working_dir=Path("/etc/fastfirewall"),
    )
    assert "[Unit]" in content
    assert "[Service]" in content
    assert "[Install]" in content


def test_build_service_unit_exec_and_config():
    content = manager_cli._build_service_unit(
        exec_start="/usr/bin/fastfirewall-api",
        config_path=Path("/etc/fastfirewall/app_config.yaml"),
        working_dir=Path("/etc/fastfirewall"),
    )
    assert "ExecStart=/usr/bin/fastfirewall-api" in content
    assert "FASTFIREWALL_CONFIG=/etc/fastfirewall/app_config.yaml" in content
    assert "WorkingDirectory=/etc/fastfirewall" in content
    assert "WantedBy=multi-user.target" in content
    assert "After=network.target" in content


def test_build_service_unit_restart_policy():
    content = manager_cli._build_service_unit(
        exec_start="/usr/bin/fastfirewall-api",
        config_path=Path("/etc/fastfirewall/app_config.yaml"),
        working_dir=Path("/etc/fastfirewall"),
    )
    assert "Restart=on-failure" in content
    assert "RestartSec=5" in content


# ── _detect_exec ───────────────────────────────────────────────────────────────

def test_detect_exec_prefers_installed_entrypoint():
    with patch("plugin_system.manager_cli.shutil") as mock_shutil:
        mock_shutil.which.return_value = "/usr/local/bin/fastfirewall-api"
        result = manager_cli._detect_exec()
    assert result == "/usr/local/bin/fastfirewall-api"


def test_detect_exec_fallback_uses_absolute_python_path():
    with patch("plugin_system.manager_cli.shutil") as mock_shutil:
        mock_shutil.which.return_value = None
        result = manager_cli._detect_exec()
    assert "fastfirewall_app.py" in result
    assert result.startswith("/") or result.startswith(sys.executable[:1])


# ── install_service ────────────────────────────────────────────────────────────

def _fake_cfg(tmp_path: Path) -> MagicMock:
    cfg = MagicMock()
    cfg.config_path = tmp_path / "app_config.yaml"
    return cfg


def test_install_service_submits_three_ops(tmp_path):
    with (
        patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch,
        patch("plugin_system.manager_cli._detect_exec", return_value="/usr/bin/fastfirewall-api"),
    ):
        manager_cli.install_service(_fake_cfg(tmp_path))

    mock_batch.assert_called_once()
    assert len(mock_batch.call_args[0][0]) == 3


def test_install_service_first_op_writes_unit_file(tmp_path):
    with (
        patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch,
        patch("plugin_system.manager_cli._detect_exec", return_value="/usr/bin/fastfirewall-api"),
    ):
        manager_cli.install_service(_fake_cfg(tmp_path))

    _, name, kwargs = mock_batch.call_args[0][0][0]
    assert name == "put"
    assert kwargs["dest"] == manager_cli._SERVICE_UNIT_PATH
    assert kwargs["_sudo"] is True
    src_type, src_content = kwargs["src"]
    assert src_type == "__stringio__"
    assert "[Unit]" in src_content


def test_install_service_second_op_is_daemon_reload(tmp_path):
    with (
        patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch,
        patch("plugin_system.manager_cli._detect_exec", return_value="/usr/bin/fastfirewall-api"),
    ):
        manager_cli.install_service(_fake_cfg(tmp_path))

    _, name, kwargs = mock_batch.call_args[0][0][1]
    assert name == "daemon_reload"
    assert kwargs["_sudo"] is True


def test_install_service_third_op_enables_but_does_not_start(tmp_path):
    with (
        patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch,
        patch("plugin_system.manager_cli._detect_exec", return_value="/usr/bin/fastfirewall-api"),
    ):
        manager_cli.install_service(_fake_cfg(tmp_path))

    _, name, kwargs = mock_batch.call_args[0][0][2]
    assert name == "service"
    assert kwargs["enabled"] is True
    assert kwargs["running"] is False
    assert kwargs["_sudo"] is True


def test_install_service_exits_nonzero_on_failure(tmp_path):
    with (
        patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(False, "permission denied"), (True, None), (True, None)]),
        patch("plugin_system.manager_cli._detect_exec", return_value="/usr/bin/fastfirewall-api"),
    ):
        with pytest.raises(SystemExit) as exc_info:
            manager_cli.install_service(_fake_cfg(tmp_path))
    assert exc_info.value.code == 1


def test_install_service_unit_file_contains_exec_start(tmp_path):
    with (
        patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch,
        patch("plugin_system.manager_cli._detect_exec", return_value="/usr/local/bin/fastfirewall-api"),
    ):
        manager_cli.install_service(_fake_cfg(tmp_path))

    _, _, kwargs = mock_batch.call_args[0][0][0]
    _, src_content = kwargs["src"]
    assert "ExecStart=/usr/local/bin/fastfirewall-api" in src_content


# ── uninstall_service ──────────────────────────────────────────────────────────

def test_uninstall_service_submits_three_ops():
    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch:
        manager_cli.uninstall_service()

    mock_batch.assert_called_once()
    assert len(mock_batch.call_args[0][0]) == 3


def test_uninstall_service_first_op_stops_and_disables():
    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch:
        manager_cli.uninstall_service()

    _, name, kwargs = mock_batch.call_args[0][0][0]
    assert name == "service"
    assert kwargs["running"] is False
    assert kwargs["enabled"] is False
    assert kwargs["_sudo"] is True


def test_uninstall_service_second_op_removes_unit_file():
    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch:
        manager_cli.uninstall_service()

    _, name, kwargs = mock_batch.call_args[0][0][1]
    assert name == "file"
    assert kwargs["path"] == manager_cli._SERVICE_UNIT_PATH
    assert kwargs["present"] is False
    assert kwargs["_sudo"] is True


def test_uninstall_service_third_op_is_daemon_reload():
    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)] * 3) as mock_batch:
        manager_cli.uninstall_service()

    _, name, kwargs = mock_batch.call_args[0][0][2]
    assert name == "daemon_reload"
    assert kwargs["_sudo"] is True


def test_uninstall_service_exits_nonzero_on_failure():
    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None), (False, "no such file"), (True, None)]):
        with pytest.raises(SystemExit) as exc_info:
            manager_cli.uninstall_service()
    assert exc_info.value.code == 1


# ── make_cfg ───────────────────────────────────────────────────────────────────

def test_make_cfg_creates_config_with_generated_secret(tmp_path):
    dest = tmp_path / "cfg"
    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)]):
        manager_cli.make_cfg(dest, cfg=None)

    text = (dest / "app_config.yaml").read_text()
    assert '"CHANGE-ME"' not in text
    assert '"111"' not in text


def test_make_cfg_repairs_existing_placeholder_secret(tmp_path):
    dest = tmp_path / "cfg"
    dest.mkdir()
    (dest / "app_config.yaml").write_text('auth:\n  secret_key: "111"\n')

    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)]):
        manager_cli.make_cfg(dest, cfg=None)

    text = (dest / "app_config.yaml").read_text()
    assert '"111"' not in text
    assert len(text.splitlines()[1].split('"')[1]) >= 32


def test_make_cfg_leaves_existing_strong_secret_untouched(tmp_path):
    dest = tmp_path / "cfg"
    dest.mkdir()
    strong_key = "a" * 64
    (dest / "app_config.yaml").write_text(f'auth:\n  secret_key: "{strong_key}"\n')

    with patch("plugin_system.manager_cli.pyinfra_run_batch", return_value=[(True, None)]):
        manager_cli.make_cfg(dest, cfg=None)

    text = (dest / "app_config.yaml").read_text()
    assert f'"{strong_key}"' in text
