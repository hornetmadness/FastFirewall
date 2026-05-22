"""
app_config.py — loads app_config.yaml into validated Pydantic models.

Invalid values (e.g. token_expire_minutes: "sixty") produce a clear
ValidationError at startup rather than a cryptic TypeError.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

from request_context import install_filter

_DEFAULT_PATH = Path(__file__).parent / "app_config.yaml"
_SERVER_KNOWN_KEYS = {"host", "port", "reload"}


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(levelname)s %(name)s: %(message)s"

    @field_validator("level", mode="before")
    @classmethod
    def _uppercase_level(cls, v: Any) -> str:
        return str(v).upper()


class PluginsConfig(BaseModel):
    directory: str = "plugins"


class RateLimitConfig(BaseModel):
    max_attempts: int = Field(5, ge=1)
    window_seconds: int = Field(300, ge=1)


class AuthConfig(BaseModel):
    enabled: bool = True
    secret_key: str = "CHANGE-ME"
    algorithm: str = "HS256"
    token_expire_minutes: int = Field(60, ge=1)
    exempt_paths: list[str] = Field(
        default_factory=lambda: ["/token", "/docs", "/openapi.json", "/redoc"]
    )
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    users: list[dict[str, Any]] = Field(default_factory=list)


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str = "0.0.0.0"
    port: int = Field(8000, ge=1, le=65535)
    reload: bool = False


class StateBackupConfig(BaseModel):
    enabled: bool = False
    directory: str = "/var/tmp/ff-backups/states"


class StateConfig(BaseModel):
    backup: StateBackupConfig = Field(default_factory=StateBackupConfig)


class AppConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    state: StateConfig = Field(default_factory=StateConfig)

    # Not from YAML — set in load() after validation.
    # Typed as Any to avoid a name-collision: the field named "logging" above
    # shadows the logging module when Pydantic resolves "logging.Logger".
    logger: Any = Field(
        default_factory=lambda: logging.getLogger("app"),
        exclude=True,
        repr=False,
    )
    _uvicorn_kwargs: dict[str, Any] = PrivateAttr(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path = _DEFAULT_PATH) -> "AppConfig":
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}

        try:
            cfg = cls.model_validate(raw)
        except ValidationError as exc:
            print(f"Invalid app_config.yaml:\n{exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        server_raw = raw.get("server", {})
        extra = {
            k.replace("-", "_"): v
            for k, v in server_raw.items()
            if k not in _SERVER_KNOWN_KEYS
        }
        cfg._uvicorn_kwargs = {
            "host": cfg.server.host,
            "port": cfg.server.port,
            "reload": cfg.server.reload,
            "log_config": None,
            **extra,
        }

        logging.basicConfig(level=cfg.logging.level, format=cfg.logging.format)
        install_filter()
        return cfg

    def uvicorn_kwargs(self) -> dict[str, Any]:
        """Return kwargs suitable for passing directly to uvicorn.run()."""
        if self._uvicorn_kwargs:
            return dict(self._uvicorn_kwargs)
        return {"host": self.server.host, "port": self.server.port, "reload": self.server.reload}

    def plugins_dir(self, base: Path | None = None) -> Path:
        """Return the resolved plugins directory path."""
        root = base or Path(__file__).parent
        return (root / self.plugins.directory).resolve()
