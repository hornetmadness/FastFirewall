import json
import logging
import os
import shutil
import tempfile
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
    """JSON-backed state file with desired/current envelope and mutation-model awareness.

    Two mutation models:
      "immediate" — save_desired() auto-commits current = desired (host-style: apply on every mutation)
      "deferred"  — save_desired() only writes desired; call commit() after a successful external apply
    """

    def __init__(
        self,
        path: Path,
        logger: logging.Logger | None = None,
        *,
        mutation_model: str = "deferred",
    ) -> None:
        if mutation_model not in ("immediate", "deferred"):
            raise ValueError(f"mutation_model must be 'immediate' or 'deferred', got {mutation_model!r}")
        self._path = path
        self._log = logger or _log
        self._mutation_model = mutation_model
        self._desired: Any = None
        self._current: Any = None
        self._macro_snapshot: dict[str, Any] | None = None

    @classmethod
    def from_config(
        cls,
        plugin_dir: Path,
        config: dict[str, Any],
        key: str,
        default_filename: str,
        logger: logging.Logger | None = None,
        *,
        mutation_model: str = "deferred",
    ) -> "PluginStateFile":
        """Resolve plugin_dir/data/<config[key] or default_filename> and return a PluginStateFile."""
        return cls(plugin_dir / "data" / config.get(key, default_filename), logger, mutation_model=mutation_model)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def current_snapshot(self) -> Any:
        """The last committed current_state snapshot, or None if never committed."""
        return self._current

    @property
    def pending_changes(self) -> bool:
        """True when desired state differs from the last committed current state."""
        if self._desired is None:
            return False
        return self._desired != (self._current or self._desired)

    # ── envelope API ────────────────────────────────────────────────────────────

    def load_desired(self, default: Any = None) -> Any:
        """Load desired_state from the on-disk envelope.

        Also restores current_snapshot from current_state so pending_changes is
        immediately accurate after load. Returns the desired_state value, or
        *default* if the file is missing or has no desired_state key.

        On first load (file absent) the default is written to disk immediately
        so every plugin starts with a state file rather than creating it lazily
        on the first mutation.
        """
        if not self._path.exists():
            self._desired = default
            self._current = default if self._mutation_model == "immediate" else None
            self._flush()
            return default
        raw = self.load(default={})
        self._current = raw.get("current_state")
        self._macro_snapshot = raw.get("macro_snapshot")
        desired = raw.get("desired_state", default)
        self._desired = desired
        return desired

    def save_desired(self, snapshot: Any) -> bool:
        """Persist *snapshot* as desired_state.

        For 'immediate' model, also auto-commits current = snapshot so
        pending_changes stays False after every mutation.
        Returns True on success.
        """
        self._desired = snapshot
        if self._mutation_model == "immediate":
            self._current = snapshot
        return self._flush()

    def commit(self, snapshot: Any = None) -> bool:
        """Set current_state to *snapshot* (defaults to current desired) and write to disk.

        Call this after a successful external apply in deferred plugins.
        Returns True on success.
        """
        self._current = snapshot if snapshot is not None else self._desired
        return self._flush()

    def save_and_commit(self, snapshot: Any) -> bool:
        """Save *snapshot* as both desired_state and current_state in one disk write.

        Use when importing live system state — desired and current should be identical.
        Returns True on success.
        """
        self._desired = snapshot
        self._current = snapshot
        return self._flush()

    def _flush(self) -> bool:
        data: dict[str, Any] = {"desired_state": self._desired}
        if self._current is not None:
            data["current_state"] = self._current
        if self._macro_snapshot is not None:
            data["macro_snapshot"] = self._macro_snapshot
        return self.save(data)

    def set_macro_snapshot(self, snapshot: dict[str, Any]) -> None:
        """Store resolved macro values; written to disk on the next _flush() call."""
        self._macro_snapshot = snapshot

    def get_macro_snapshot(self) -> dict[str, Any] | None:
        """Return the last persisted macro snapshot, or None if never set."""
        return self._macro_snapshot

    # ── raw API (kept for backwards compatibility) ───────────────────────────────

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
        return sorted(
            backup_dir.glob(f"{self._path.stem}_*{self._path.suffix}"),
            reverse=True,
        )

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
        """Write *data* as indented JSON atomically. Returns True on success, False on error.

        Writes to a temp file in the same directory then renames it over the
        target so a crash mid-write never leaves a partial file on disk.
        """
        try:
            if _backup_enabled:
                self._backup()
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as fh:
                    json.dump(data, fh, indent=2)
                os.replace(tmp_name, self._path)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
            return True
        except Exception:
            self._log.error("Failed to save state to %r", self._path, exc_info=True)
            return False
