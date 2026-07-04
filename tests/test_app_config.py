import pytest
from pathlib import Path
from pydantic import ValidationError

from app_config import AppConfig, LoggingConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_config(tmp_path, content: str) -> Path:
    p = tmp_path / "app_config.yaml"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Defaults (empty / missing file sections)
# ---------------------------------------------------------------------------

def test_load_empty_yaml_gives_all_defaults(tmp_path):
    p = write_config(tmp_path, "")
    cfg = AppConfig.load(p)
    assert cfg.logging.level == "INFO"
    assert cfg.logging.format == LoggingConfig().format
    assert cfg.plugins.src_code_dir == "plugins"
    assert cfg.server.host == "0.0.0.0"
    assert cfg.server.port == 8000
    assert cfg.server.reload is False


def test_load_partial_yaml_fills_missing_with_defaults(tmp_path):
    p = write_config(tmp_path, "server:\n  port: 9000\n")
    cfg = AppConfig.load(p)
    assert cfg.server.port == 9000
    assert cfg.server.host == "0.0.0.0"   # default
    assert cfg.logging.level == "INFO"     # default


# ---------------------------------------------------------------------------
# Logging section
# ---------------------------------------------------------------------------

def test_load_logging_level(tmp_path):
    p = write_config(tmp_path, "logging:\n  level: DEBUG\n")
    cfg = AppConfig.load(p)
    assert cfg.logging.level == "DEBUG"


def test_load_logging_level_is_uppercased(tmp_path):
    p = write_config(tmp_path, "logging:\n  level: warning\n")
    cfg = AppConfig.load(p)
    assert cfg.logging.level == "WARNING"


def test_load_logging_format(tmp_path):
    fmt = "%(message)s"
    p = write_config(tmp_path, f"logging:\n  format: '{fmt}'\n")
    cfg = AppConfig.load(p)
    assert cfg.logging.format == fmt


def test_load_logging_overrides_default_quiets_pyroute2(tmp_path):
    p = write_config(tmp_path, "")
    cfg = AppConfig.load(p)
    assert cfg.logging.overrides == {"pyroute2": "WARNING"}


def test_load_logging_overrides_custom(tmp_path):
    p = write_config(tmp_path, "logging:\n  overrides:\n    pyroute2: error\n    foo.bar: debug\n")
    cfg = AppConfig.load(p)
    assert cfg.logging.overrides == {"pyroute2": "ERROR", "foo.bar": "DEBUG"}


def test_load_applies_logging_overrides_to_actual_loggers(tmp_path):
    import logging
    p = write_config(tmp_path, "logging:\n  overrides:\n    pyroute2: ERROR\n")
    AppConfig.load(p)
    assert logging.getLogger("pyroute2").level == logging.ERROR


# ---------------------------------------------------------------------------
# Plugins section
# ---------------------------------------------------------------------------

def test_load_plugins_src_code_dir(tmp_path):
    p = write_config(tmp_path, "plugins:\n  src_code_dir: my_plugins\n")
    cfg = AppConfig.load(p)
    assert cfg.plugins.src_code_dir == "my_plugins"


def test_plugins_src_dir_resolves_relative_to_base(tmp_path):
    p = write_config(tmp_path, "plugins:\n  src_code_dir: my_plugins\n")
    cfg = AppConfig.load(p)
    resolved = cfg.plugins_src_dir(base=tmp_path)
    assert resolved == (tmp_path / "my_plugins").resolve()
    assert resolved.is_absolute()


def test_plugins_src_dir_default_base_is_repo_root(tmp_path):
    p = write_config(tmp_path, "")
    cfg = AppConfig.load(p)
    resolved = cfg.plugins_src_dir()
    assert resolved.is_absolute()
    assert resolved.name == "plugins"


# ---------------------------------------------------------------------------
# Server section
# ---------------------------------------------------------------------------

def test_load_server_host(tmp_path):
    p = write_config(tmp_path, "server:\n  host: '127.0.0.1'\n")
    cfg = AppConfig.load(p)
    assert cfg.server.host == "127.0.0.1"


def test_load_server_port(tmp_path):
    p = write_config(tmp_path, "server:\n  port: 5000\n")
    cfg = AppConfig.load(p)
    assert cfg.server.port == 5000


def test_load_server_port_is_int(tmp_path):
    p = write_config(tmp_path, "server:\n  port: '7777'\n")
    cfg = AppConfig.load(p)
    assert isinstance(cfg.server.port, int)
    assert cfg.server.port == 7777


def test_load_server_reload_true(tmp_path):
    p = write_config(tmp_path, "server:\n  reload: true\n")
    cfg = AppConfig.load(p)
    assert cfg.server.reload is True


# ---------------------------------------------------------------------------
# Full config round-trip
# ---------------------------------------------------------------------------

def test_load_full_config(tmp_path):
    p = write_config(tmp_path, """
logging:
  level: ERROR
  format: "%(name)s %(message)s"

plugins:
  src_code_dir: ext_plugins

server:
  host: "127.0.0.1"
  port: 4000
  reload: true
""")
    cfg = AppConfig.load(p)
    assert cfg.logging.level == "ERROR"
    assert cfg.logging.format == "%(name)s %(message)s"
    assert cfg.plugins.src_code_dir == "ext_plugins"
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 4000
    assert cfg.server.reload is True


# ---------------------------------------------------------------------------
# Server — extra kwargs and uvicorn_kwargs()
# ---------------------------------------------------------------------------

def test_uvicorn_kwargs_contains_core_fields(tmp_path):
    p = write_config(tmp_path, "server:\n  host: '127.0.0.1'\n  port: 5000\n  reload: true\n")
    cfg = AppConfig.load(p)
    kwargs = cfg.uvicorn_kwargs()
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 5000
    assert kwargs["reload"] is True


def test_uvicorn_kwargs_excludes_known_keys_from_extras(tmp_path):
    p = write_config(tmp_path, "server:\n  host: '127.0.0.1'\n  port: 9000\n  reload: true\n")
    cfg = AppConfig.load(p)
    kwargs = cfg.uvicorn_kwargs()
    assert list(kwargs.keys()).count("host") == 1
    assert list(kwargs.keys()).count("port") == 1
    assert list(kwargs.keys()).count("reload") == 1


def test_uvicorn_kwargs_merges_extra(tmp_path):
    p = write_config(tmp_path, "server:\n  port: 8000\n  workers: 2\n")
    cfg = AppConfig.load(p)
    assert cfg.uvicorn_kwargs()["workers"] == 2


def test_uvicorn_kwargs_normalizes_hyphens_to_underscores(tmp_path):
    p = write_config(tmp_path, "server:\n  port: 8000\n  timeout-keep-alive: 30\n")
    cfg = AppConfig.load(p)
    kwargs = cfg.uvicorn_kwargs()
    assert "timeout_keep_alive" in kwargs
    assert kwargs["timeout_keep_alive"] == 30
    assert "timeout-keep-alive" not in kwargs


def test_uvicorn_kwargs_top_level_unknown_key(tmp_path):
    p = write_config(tmp_path, "server:\n  port: 8000\n  reload-excludes:\n    - '*.log'\n")
    cfg = AppConfig.load(p)
    kwargs = cfg.uvicorn_kwargs()
    assert "reload_excludes" in kwargs
    assert kwargs["reload_excludes"] == ["*.log"]


# ---------------------------------------------------------------------------
# Default file path (actual app_config.yaml)
# ---------------------------------------------------------------------------

def test_default_load_reads_repo_config():
    cfg = AppConfig.load()
    assert cfg.server.port == 8000
    assert cfg.plugins.src_code_dir == "plugins"
    assert cfg.logging.level == "DEBUG"


# ---------------------------------------------------------------------------
# Auth section
# ---------------------------------------------------------------------------

def test_auth_defaults_when_section_absent(tmp_path):
    p = write_config(tmp_path, "")
    cfg = AppConfig.load(p)
    assert cfg.auth.enabled is True
    assert cfg.auth.secret_key == "CHANGE-ME"
    assert cfg.auth.algorithm == "HS256"
    assert cfg.auth.token_expire_minutes == 60
    assert "/token" in cfg.auth.exempt_paths
    assert cfg.auth.users == []


def test_auth_enabled_flag(tmp_path):
    p = write_config(tmp_path, "auth:\n  enabled: true\n")
    cfg = AppConfig.load(p)
    assert cfg.auth.enabled is True


def test_auth_secret_key(tmp_path):
    p = write_config(tmp_path, "auth:\n  secret_key: my-secret\n")
    cfg = AppConfig.load(p)
    assert cfg.auth.secret_key == "my-secret"


def test_auth_algorithm(tmp_path):
    p = write_config(tmp_path, "auth:\n  algorithm: HS512\n")
    cfg = AppConfig.load(p)
    assert cfg.auth.algorithm == "HS512"


def test_auth_token_expire_minutes(tmp_path):
    p = write_config(tmp_path, "auth:\n  token_expire_minutes: 30\n")
    cfg = AppConfig.load(p)
    assert cfg.auth.token_expire_minutes == 30


def test_auth_exempt_paths(tmp_path):
    p = write_config(tmp_path, "auth:\n  exempt_paths:\n    - /token\n    - /healthz\n")
    cfg = AppConfig.load(p)
    assert "/token" in cfg.auth.exempt_paths
    assert "/healthz" in cfg.auth.exempt_paths


def test_auth_users_loaded(tmp_path):
    p = write_config(tmp_path, """
auth:
  users:
    - username: alice
      password: secret
      roles: [admin]
    - username: bob
      password: pass
      roles: []
""")
    cfg = AppConfig.load(p)
    assert len(cfg.auth.users) == 2
    assert cfg.auth.users[0]["username"] == "alice"
    assert cfg.auth.users[1]["username"] == "bob"


def test_auth_full_section(tmp_path):
    p = write_config(tmp_path, """
auth:
  enabled: true
  secret_key: "supersecret"
  algorithm: HS256
  token_expire_minutes: 120
  exempt_paths: [/token, /docs]
  users:
    - username: admin
      password: admin
      roles: [admin]
""")
    cfg = AppConfig.load(p)
    assert cfg.auth.enabled is True
    assert cfg.auth.secret_key == "supersecret"
    assert cfg.auth.token_expire_minutes == 120
    assert "/docs" in cfg.auth.exempt_paths
    assert cfg.auth.users[0]["roles"] == ["admin"]


# ---------------------------------------------------------------------------
# Validation errors (Pydantic catches bad values with clear messages)
# ---------------------------------------------------------------------------

def _raises_validation_error(tmp_path, yaml_content: str) -> ValidationError:
    p = write_config(tmp_path, yaml_content)
    with pytest.raises(SystemExit):
        AppConfig.load(p)
    # Also confirm model_validate raises directly (bypassing load's SystemExit)
    import yaml as _yaml
    raw = _yaml.safe_load(yaml_content) or {}
    with pytest.raises(ValidationError) as exc_info:
        AppConfig.model_validate(raw)
    return exc_info.value


def test_invalid_port_string(tmp_path):
    exc = _raises_validation_error(tmp_path, "server:\n  port: 'not-a-port'\n")
    assert "port" in str(exc)


def test_invalid_port_out_of_range(tmp_path):
    exc = _raises_validation_error(tmp_path, "server:\n  port: 99999\n")
    assert "port" in str(exc)


def test_invalid_token_expire_minutes(tmp_path):
    exc = _raises_validation_error(tmp_path, "auth:\n  token_expire_minutes: 'sixty'\n")
    assert "token_expire_minutes" in str(exc)


def test_invalid_max_attempts_not_int(tmp_path):
    exc = _raises_validation_error(tmp_path, "auth:\n  rate_limit:\n    max_attempts: 'many'\n")
    assert "max_attempts" in str(exc)


def test_invalid_reload_not_bool(tmp_path):
    exc = _raises_validation_error(tmp_path, "server:\n  reload: 'yes-please'\n")
    assert "reload" in str(exc)


def test_invalid_auth_enabled_not_bool(tmp_path):
    exc = _raises_validation_error(tmp_path, "auth:\n  enabled: 'maybe'\n")
    assert "enabled" in str(exc)


def test_valid_port_boundaries(tmp_path):
    p = write_config(tmp_path, "server:\n  port: 1\n")
    cfg = AppConfig.load(p)
    assert cfg.server.port == 1

    p = write_config(tmp_path, "server:\n  port: 65535\n")
    cfg = AppConfig.load(p)
    assert cfg.server.port == 65535


def test_rate_limit_partial_override_keeps_other_default(tmp_path):
    p = write_config(tmp_path, "auth:\n  rate_limit:\n    max_attempts: 3\n")
    cfg = AppConfig.load(p)
    assert cfg.auth.rate_limit.max_attempts == 3
    assert cfg.auth.rate_limit.window_seconds == 300  # default preserved
