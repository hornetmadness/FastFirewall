import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_backup_enabled: bool = False
_backup_directory: str = "/var/tmp/ff-backups/states"


def configure(*, backup_enabled: bool = False, backup_directory: str = "/var/tmp/ff-backups/states") -> None:
    """Apply app-level state backup settings (call once at startup from app.py)."""
    global _backup_enabled, _backup_directory
    _backup_enabled = backup_enabled
    _backup_directory = backup_directory


class PluginStateFile:
    """JSON-backed state file with logged load/save primitives."""

    def __init__(self, path: Path, logger: logging.Logger | None = None) -> None:
        self._path = path
        self._log = logger or _log

    @classmethod
    def from_config(
        cls,
        plugin_dir: Path,
        config: dict[str, Any],
        key: str,
        default_filename: str,
        logger: logging.Logger | None = None,
    ) -> "PluginStateFile":
        """Resolve plugin_dir/data/<config[key] or default_filename> and return a PluginStateFile."""
        return cls(plugin_dir / "data" / config.get(key, default_filename), logger)

    @property
    def path(self) -> Path:
        return self._path

    def load(self, default: Any = None) -> Any:
        """Return parsed JSON from the state file, or *default* if it doesn't exist yet."""
        if not self._path.exists():
            return default
        try:
            with self._path.open() as fh:
                return json.load(fh)
        except Exception:
            self._log.error("Failed to load state from %r, using default", self._path, exc_info=True)
            return default

    def _backup(self) -> None:
        if not self._path.exists():
            return
        try:
            backup_dir = Path(_backup_directory)
            backup_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = backup_dir / f"{self._path.stem}_{ts}{self._path.suffix}"
            shutil.copy2(self._path, dest)
        except Exception:
            self._log.error("Failed to back up state file %r", self._path, exc_info=True)

    def list_backups(self) -> list[Path]:
        """Return all backup files for this state file, newest first."""
        backup_dir = Path(_backup_directory)
        if not backup_dir.exists():
            return []
        files = sorted(
            backup_dir.glob(f"{self._path.stem}_*{self._path.suffix}"),
            reverse=True,
        )
        return files

    def restore(self, backup: Path) -> bool:
        """Overwrite the live state file with *backup*. Returns True on success, False on error."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, self._path)
            self._log.info("Restored state %r from backup %r", self._path, backup)
            return True
        except Exception:
            self._log.error("Failed to restore state %r from %r", self._path, backup, exc_info=True)
            return False

    def save(self, data: Any) -> bool:
        """Write *data* as indented JSON. Returns True on success, False on error."""
        try:
            if _backup_enabled:
                self._backup()
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("w") as fh:
                json.dump(data, fh, indent=2)
            return True
        except Exception:
            self._log.error("Failed to save state to %r", self._path, exc_info=True)
            return False
