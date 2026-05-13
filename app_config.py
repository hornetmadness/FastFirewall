"""
app_config.py — loads app_config.yaml into a typed AppConfig dataclass.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_PATH = Path(__file__).parent / "app_config.yaml"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(levelname)s %(name)s: %(message)s"


@dataclass
class PluginsConfig:
    directory: str = "plugins"


_AUTH_DEFAULTS = {
    "enabled": False,
    "secret_key": "CHANGE-ME",
    "algorithm": "HS256",
    "token_expire_minutes": 60,
    "exempt_paths": ["/token", "/docs", "/openapi.json", "/redoc"],
    "users": [],
}

_SERVER_KNOWN_KEYS = {"host", "port", "reload"}


@dataclass
class AuthConfig:
    enabled: bool = False
    secret_key: str = "CHANGE-ME"
    algorithm: str = "HS256"
    token_expire_minutes: int = 60
    exempt_paths: list = field(default_factory=lambda: ["/token", "/docs", "/openapi.json", "/redoc"])
    users: list = field(default_factory=list)


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False


@dataclass
class StateBackupConfig:
    enabled: bool = False
    directory: str = "/var/tmp/ff-backups/states"


@dataclass
class StateConfig:
    backup: StateBackupConfig = field(default_factory=StateBackupConfig)


@dataclass
class AppConfig:
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    state: StateConfig = field(default_factory=StateConfig)
    logger: logging.Logger = field(
        init=False, repr=False, compare=False,
        default_factory=lambda: logging.getLogger("app"),
    )
    _uvicorn_kwargs: dict[str, Any] = field(
        init=False, repr=False, compare=False,
        default_factory=dict,
    )

    @classmethod
    def load(cls, path: str | Path = _DEFAULT_PATH) -> "AppConfig":
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}

        log_raw = raw.get("logging", {})
        plugins_raw = raw.get("plugins", {})
        server_raw = raw.get("server", {})
        auth_raw = {**_AUTH_DEFAULTS, **raw.get("auth", {})}
        state_raw = raw.get("state", {})
        backup_raw = state_raw.get("backup", {})

        cfg = cls(
            logging=LoggingConfig(
                level=str(log_raw.get("level", "INFO")).upper(),
                format=log_raw.get("format", LoggingConfig.format),
            ),
            plugins=PluginsConfig(
                directory=plugins_raw.get("directory", "plugins"),
            ),
            server=ServerConfig(
                host=server_raw.get("host", "0.0.0.0"),
                port=int(server_raw.get("port", 8000)),
                reload=bool(server_raw.get("reload", False)),
            ),
            auth=AuthConfig(
                enabled=bool(auth_raw["enabled"]),
                secret_key=str(auth_raw["secret_key"]),
                algorithm=str(auth_raw["algorithm"]),
                token_expire_minutes=int(auth_raw["token_expire_minutes"]),
                exempt_paths=list(auth_raw["exempt_paths"]),
                users=list(auth_raw["users"]),
            ),
            state=StateConfig(
                backup=StateBackupConfig(
                    enabled=bool(backup_raw.get("enabled", False)),
                    directory=str(backup_raw.get("directory", "backup/state")),
                ),
            ),
        )
        extra = {k.replace("-", "_"): v for k, v in server_raw.items() if k not in _SERVER_KNOWN_KEYS}
        cfg._uvicorn_kwargs = {"host": cfg.server.host, "port": cfg.server.port, "reload": cfg.server.reload, **extra}
        
        logging.basicConfig(level=cfg.logging.level, format=cfg.logging.format)
        return cfg

    def uvicorn_kwargs(self) -> dict[str, Any]:
        """Return kwargs suitable for passing directly to uvicorn.run()."""
        return dict(getattr(self, "_uvicorn_kwargs", {"host": self.server.host, "port": self.server.port, "reload": self.server.reload}))

    def plugins_dir(self, base: Path | None = None) -> Path:
        """Return the resolved plugins directory path."""
        root = base or Path(__file__).parent
        return (root / self.plugins.directory).resolve()
