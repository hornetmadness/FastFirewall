"""
Syslog Plugin
─────────────
Installs fluent-bit as a standalone syslog server. It listens on UDP/TCP 514
for incoming syslog messages and reads the systemd journal, writing everything
to /var/log/fastfirewall/. Routes mount at /v1/syslog/.

Events emitted:
  syslog.setup.complete  – payload: {log_dir, fastfirewall_conf}
"""
from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pickle
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException, Query
from pydantic import BaseModel, Field

from pyinfra.operations import files as files_ops
from pyinfra.operations import server as server_ops

from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, Service
from plugin_system.core.events import Event, bus


# ── Pydantic models ────────────────────────────────────────────────────────────

class FluentBitConfigUpdate(BaseModel):
    syslog_port: Optional[int] = Field(None, ge=1, le=65535, description="Network syslog listener port")
    syslog_mode: Optional[str] = Field(None, description="Network mode: udp, tcp, tcp+udp")
    syslog_unix_path: Optional[str] = Field(None, description="Unix socket path, or empty string to disable")
    syslog_unix_mode: Optional[str] = Field(None, description="Unix socket mode: unix_udp or unix_tcp")
    enable_systemd_input: Optional[bool] = Field(None, description="Whether to read the systemd journal")


class LogrotateConfigUpdate(BaseModel):
    rotate: Optional[int] = Field(None, ge=1, le=365, description="Number of rotated files to keep")
    frequency: Optional[str] = Field(None, description="Rotation frequency: daily, weekly, monthly")
    compress: Optional[bool] = Field(None, description="Compress rotated logs with gzip")
    max_size: Optional[str] = Field(None, description="Rotate when file exceeds this size (e.g. 100M), empty to disable")


# ── constants ─────────────────────────────────────────────────────────────────

_VALID_SYSLOG_MODES = {"udp", "tcp", "tcp+udp"}
_VALID_UNIX_MODES = {"unix_udp", "unix_tcp"}

_MINIMAL_MAIN_CONF = """\
# Managed by FastFirewall syslog — do not edit by hand.
@INCLUDE conf.d/*.conf
"""

_VALID_FREQUENCIES = {"daily", "weekly", "monthly"}
_VALID_JOURNAL_OUTPUTS = {"short", "json", "cat", "verbose", "export"}
_VALID_PRIORITIES = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
                     "0", "1", "2", "3", "4", "5", "6", "7"}


# ── plugin ─────────────────────────────────────────────────────────────────────

class SyslogPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.SYSLOG]

    _WORKER_SCRIPT = Path(__file__).parent / "_pyinfra_worker.py"

    def setup(self) -> None:
        self._log_dir = Path(self.config.get("log_dir", "/var/log/fastfirewall"))
        self._fastfirewall_conf = Path(self.config.get("fastfirewall_conf", "/etc/fluent-bit/conf.d/fastfirewall")).with_suffix(".conf")
        self._fluent_bit_main_conf = Path(self.config.get("fluent_bit_main_conf", "/etc/fluent-bit/fluent-bit.conf"))
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "overrides_file", "syslog_overrides.json", self.logger,
            mutation_model="immediate",
        )

        if self.config.get("ignore_state_on_boot", False):
            overrides: dict = {}
        else:
            overrides = self._state_file.load_desired(default={})
        cfg = {**self.config, **overrides}
        self._syslog_port = int(cfg.get("syslog_port", 514))
        self._syslog_mode = cfg.get("syslog_mode", "udp")
        self._syslog_unix_path = cfg.get("syslog_unix_path") or None
        self._syslog_unix_mode = cfg.get("syslog_unix_mode", "unix_udp")
        self._enable_systemd = bool(cfg.get("enable_systemd_input", True))
        self._max_tail_lines = int(cfg.get("max_tail_lines", 1000))

        lr = {**self.config.get("logrotate", {}), **overrides.get("logrotate", {})}
        self._logrotate_conf = Path(lr.get("conf", "/etc/logrotate.d/fastfirewall"))
        self._log_rotate_count = int(lr.get("rotate", 7))
        self._log_rotate_frequency = lr.get("frequency", "daily")
        self._log_compress = bool(lr.get("compress", True))
        self._log_max_size = lr.get("max_size") or None

        # Create log dir eagerly — works when running as root (e.g. in Docker).
        # _configure_services also does this via pyinfra for non-root environments.
        try:
            self._log_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        except PermissionError:
            pass

        try:
            self._configure_services()
        except Exception as exc:
            self.logger.warning("Service configuration failed — continuing without it: %s", exc, exc_info=True)
        self._register_routes()
        self.logger.info("Syslog plugin ready; log_dir=%s", self._log_dir)
        bus.emit(Event(
            name="syslog.ready",
            source=self.plugin_id,
            payload={"log_dir": str(self._log_dir), "fastfirewall_conf": str(self._fastfirewall_conf)},
        ))

    def teardown(self) -> None:
        self.logger.info("Syslog plugin shutdown")

    # ── pyinfra helper ─────────────────────────────────────────────────────────

    def _pyinfra_run(self, op: Any, **kwargs: Any) -> None:
        norm_kwargs = {
            k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
            for k, v in kwargs.items()
        }
        payload = pickle.dumps((op.__module__, op.__name__, norm_kwargs))
        proc = subprocess.run(
            [sys.executable, str(self._WORKER_SCRIPT)],
            input=payload,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"pyinfra '{op.__name__}' failed (exit {proc.returncode}):\n"
                + proc.stderr.decode(errors="replace")
            )

    # ── service configuration ──────────────────────────────────────────────────

    def _configure_services(self) -> None:
        self._pyinfra_run(
            files_ops.directory,
            name=f"Create log directory {self._log_dir}",
            path=str(self._log_dir),
            present=True,
            mode="755",
            _sudo=True,
        )

        self._ensure_main_conf_includes_confd()

        self._pyinfra_run(
            server_ops.service,
            name="Enable and start fluent-bit",
            service="fluent-bit",
            enabled=True,
            running=True,
            _sudo=True,
        )

        self._apply_config()
        self._apply_logrotate_config()

        bus.emit(Event(
            name="syslog.setup.complete",
            source=self.plugin_id,
            payload={
                "log_dir": str(self._log_dir),
                "fastfirewall_conf": str(self._fastfirewall_conf),
                "fluent_bit_main_conf": str(self._fluent_bit_main_conf),
            },
        ))

    def _ensure_main_conf_includes_confd(self) -> None:
        try:
            existing = self._fluent_bit_main_conf.read_text()
        except FileNotFoundError:
            existing = None
        except PermissionError:
            self.logger.warning("Cannot read %s — skipping include check", self._fluent_bit_main_conf)
            return

        if existing is not None and "conf.d" in existing:
            self.logger.debug("Main config already references conf.d")
            return

        if existing is None:
            new_content = _MINIMAL_MAIN_CONF
            self.logger.info("Creating fluent-bit main config at %s", self._fluent_bit_main_conf)
        else:
            new_content = existing.rstrip() + "\n\n# Added by FastFirewall syslog\n@INCLUDE conf.d/*.conf\n"
            self.logger.info("Adding conf.d include to %s", self._fluent_bit_main_conf)

        self._pyinfra_run(
            files_ops.put,
            name="Update fluent-bit main config to include conf.d",
            src=io.StringIO(new_content),
            dest=str(self._fluent_bit_main_conf),
            mode="644",
            _sudo=True,
        )

    # ── overrides persistence ──────────────────────────────────────────────────

    def _save_overrides(self) -> None:
        self._state_file.save_desired({
            "syslog_port": self._syslog_port,
            "syslog_mode": self._syslog_mode,
            "syslog_unix_path": self._syslog_unix_path,
            "syslog_unix_mode": self._syslog_unix_mode,
            "enable_systemd_input": self._enable_systemd,
            "logrotate": {
                "rotate": self._log_rotate_count,
                "frequency": self._log_rotate_frequency,
                "compress": self._log_compress,
                "max_size": self._log_max_size,
            },
        })

    def _apply_logrotate_config(self) -> None:
        content = _build_logrotate_conf(
            self._log_dir,
            rotate=self._log_rotate_count,
            frequency=self._log_rotate_frequency,
            compress=self._log_compress,
            max_size=self._log_max_size,
        )
        self._pyinfra_run(
            files_ops.put,
            name="Write fastfirewall logrotate config",
            src=io.StringIO(content),
            dest=str(self._logrotate_conf),
            mode="644",
            _sudo=True,
        )

    def _apply_config(self) -> None:
        fluent_content = _build_fastfirewall_conf_classic(
            self._log_dir,
            syslog_port=self._syslog_port,
            syslog_mode=self._syslog_mode,
            syslog_unix_path=self._syslog_unix_path,
            syslog_unix_mode=self._syslog_unix_mode,
            enable_systemd=self._enable_systemd,
        )
        new_hash = hashlib.sha256(fluent_content.encode()).hexdigest()
        try:
            old_hash = hashlib.sha256(self._fastfirewall_conf.read_bytes()).hexdigest()
        except FileNotFoundError:
            old_hash = None

        self._pyinfra_run(
            files_ops.put,
            name="Write fluent-bit fastfirewall config",
            src=io.StringIO(fluent_content),
            dest=str(self._fastfirewall_conf),
            mode="644",
            _sudo=True,
        )

        if new_hash != old_hash:
            proc = subprocess.run(
                ["sudo", "systemctl", "restart", "fluent-bit"],
                capture_output=True, text=True,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"fluent-bit restart failed: {proc.stderr.strip()}")

    # ── route registration ─────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        add("/status",          self._status,        methods=["GET"],   summary="Plugin status and service health")
        add("/config",          self._get_config,    methods=["GET"],   summary="Get effective fluent-bit config settings")
        add("/config",          self._update_config, methods=["PATCH"], summary="Update fluent-bit config settings and reload")
        add("/config/reload",    self._reload,        methods=["POST"],  summary="Reload fluent-bit without changing config")
        add("/config/raw",       self._get_raw,       methods=["GET"],   summary="Read raw fluent-bit config file from disk")
        add("/config/diagnose",  self._diagnose,      methods=["GET"],   summary="Diagnose fluent-bit setup and journal access")
        add("/config/logrotate", self._get_logrotate, methods=["GET"],   summary="Get logrotate settings")
        add("/config/logrotate", self._update_logrotate, methods=["PATCH"], summary="Update logrotate settings")
        add("/config/logrotate/run", self._run_logrotate, methods=["POST"],  summary="Manually trigger log rotation")
        add("/files",           self._list_files,    methods=["GET"],   summary="List log files in log_dir")
        add("/logs/{filename}", self._read_log,      methods=["GET"],   summary="Read last N lines of a log file")
        add("/tail/{filename}", self._tail_log,      methods=["GET"],   summary="Tail a log file (alias for read with smaller default)")
        add("/journal",         self._journal,       methods=["GET"],   summary="Read systemd journal entries")

    # ── status ─────────────────────────────────────────────────────────────────

    def _status(self) -> dict:
        proc = subprocess.run(["systemctl", "is-active", "fluent-bit"], capture_output=True, text=True)
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "log_dir": str(self._log_dir),
            "fastfirewall_conf": str(self._fastfirewall_conf),
            "syslog_port": self._syslog_port,
            "syslog_mode": self._syslog_mode,
            "syslog_unix_path": self._syslog_unix_path,
            "syslog_unix_mode": self._syslog_unix_mode if self._syslog_unix_path else None,
            "services": {"fluent-bit": proc.stdout.strip() or "unknown"},
            "pending_changes": self._state_file.pending_changes,
        }

    # ── config management ──────────────────────────────────────────────────────

    def _get_config(self) -> dict:
        return {
            "syslog_port": self._syslog_port,
            "syslog_mode": self._syslog_mode,
            "syslog_unix_path": self._syslog_unix_path,
            "syslog_unix_mode": self._syslog_unix_mode if self._syslog_unix_path else None,
            "enable_systemd_input": self._enable_systemd,
            "fastfirewall_conf": str(self._fastfirewall_conf),
            "log_dir": str(self._log_dir),
        }

    def _update_config(self, body: FluentBitConfigUpdate) -> dict:
        if body.syslog_mode is not None and body.syslog_mode not in _VALID_SYSLOG_MODES:
            raise HTTPException(400, f"syslog_mode must be one of: {', '.join(sorted(_VALID_SYSLOG_MODES))}")
        if body.syslog_unix_mode is not None and body.syslog_unix_mode not in _VALID_UNIX_MODES:
            raise HTTPException(400, f"syslog_unix_mode must be one of: {', '.join(sorted(_VALID_UNIX_MODES))}")

        if body.syslog_port is not None:
            self._syslog_port = body.syslog_port
        if body.syslog_mode is not None:
            self._syslog_mode = body.syslog_mode
        if body.syslog_unix_path is not None:
            self._syslog_unix_path = body.syslog_unix_path or None
        if body.syslog_unix_mode is not None:
            self._syslog_unix_mode = body.syslog_unix_mode
        if body.enable_systemd_input is not None:
            self._enable_systemd = body.enable_systemd_input

        self._save_overrides()
        try:
            self._apply_config()
        except Exception as exc:
            raise HTTPException(500, f"Config written but reload failed: {exc}") from exc

        bus.emit(Event("syslog.config.updated", source=self.plugin_id, payload=self._get_config()))
        return self._get_config()

    def _reload(self) -> dict:
        proc = subprocess.run(
            ["sudo", "systemctl", "restart", "fluent-bit"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise HTTPException(500, f"fluent-bit restart failed: {proc.stderr.strip()}")
        return {"reloaded": True}

    def _get_raw(self) -> dict:
        if not self._fastfirewall_conf.exists():
            raise HTTPException(404, f"Config file not found: {self._fastfirewall_conf}")
        return {
            "path": str(self._fastfirewall_conf),
            "content": self._fastfirewall_conf.read_text(),
        }

    def _diagnose(self) -> dict:
        checks: dict[str, Any] = {}

        # log directory
        checks["log_dir_exists"] = self._log_dir.is_dir()
        checks["log_dir_writable"] = os.access(self._log_dir, os.W_OK) if self._log_dir.is_dir() else False

        # output log file
        out = self._log_dir / "fluent-bit.log"
        checks["output_file_exists"] = out.exists()
        checks["output_file_size"] = out.stat().st_size if out.exists() else None

        # fluent-bit config and main conf include
        checks["config_file_exists"] = self._fastfirewall_conf.exists()
        try:
            main_text = self._fluent_bit_main_conf.read_text()
            checks["main_conf_exists"] = True
            checks["main_conf_has_include"] = "conf.d" in main_text
        except FileNotFoundError:
            checks["main_conf_exists"] = False
            checks["main_conf_has_include"] = False
        except PermissionError:
            checks["main_conf_exists"] = None
            checks["main_conf_has_include"] = None

        # fluent-bit service state
        proc = subprocess.run(["systemctl", "is-active", "fluent-bit"], capture_output=True, text=True)
        checks["fluent_bit_status"] = proc.stdout.strip() or "unknown"
        checks["fluent_bit_active"] = checks["fluent_bit_status"] == "active"

        # fluent-bit service user
        proc = subprocess.run(
            ["systemctl", "show", "fluent-bit", "--property=User"],
            capture_output=True, text=True,
        )
        fb_user = proc.stdout.strip().split("=", 1)[-1].strip() or "root"
        checks["fluent_bit_user"] = fb_user

        # systemd-journal group membership (needed to read the journal)
        try:
            journal_members = grp.getgrnam("systemd-journal").gr_mem
            checks["journal_group_members"] = journal_members
            checks["fluent_bit_in_journal_group"] = fb_user == "root" or fb_user in journal_members
        except KeyError:
            checks["journal_group_members"] = []
            checks["fluent_bit_in_journal_group"] = None

        # recent fluent-bit service logs
        proc = subprocess.run(
            ["journalctl", "-u", "fluent-bit", "--no-pager", "-n", "30", "--since", "10 minutes ago"],
            capture_output=True, text=True,
        )
        checks["fluent_bit_recent_logs"] = proc.stdout.strip()

        healthy = (
            checks["log_dir_exists"]
            and checks["config_file_exists"]
            and checks["main_conf_has_include"] is True
            and checks["fluent_bit_active"]
            and checks["fluent_bit_in_journal_group"] is not False
        )
        return {"healthy": healthy, "checks": checks}

    # ── logrotate management ───────────────────────────────────────────────────

    def _get_logrotate(self) -> dict:
        return {
            "logrotate_conf": str(self._logrotate_conf),
            "rotate": self._log_rotate_count,
            "frequency": self._log_rotate_frequency,
            "compress": self._log_compress,
            "max_size": self._log_max_size,
        }

    def _update_logrotate(self, body: LogrotateConfigUpdate) -> dict:
        if body.frequency is not None and body.frequency not in _VALID_FREQUENCIES:
            raise HTTPException(400, f"frequency must be one of: {', '.join(sorted(_VALID_FREQUENCIES))}")

        if body.rotate is not None:
            self._log_rotate_count = body.rotate
        if body.frequency is not None:
            self._log_rotate_frequency = body.frequency
        if body.compress is not None:
            self._log_compress = body.compress
        if body.max_size is not None:
            self._log_max_size = body.max_size or None

        self._save_overrides()
        try:
            self._apply_logrotate_config()
        except Exception as exc:
            raise HTTPException(500, f"Config written but logrotate apply failed: {exc}") from exc
        bus.emit(Event("syslog.logrotate.updated", source=self.plugin_id, payload=self._get_logrotate()))
        return self._get_logrotate()

    def _run_logrotate(self) -> dict:
        proc = subprocess.run(
            ["sudo", "logrotate", "-f", str(self._logrotate_conf)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise HTTPException(500, f"logrotate failed: {proc.stderr.strip()}")
        bus.emit(Event("syslog.logrotate.ran", source=self.plugin_id, payload={"logrotate_conf": str(self._logrotate_conf)}))
        return {"rotated": True}

    # ── file listing ───────────────────────────────────────────────────────────

    def _list_files(self) -> dict:
        if not self._log_dir.is_dir():
            return {"files": [], "log_dir": str(self._log_dir), "count": 0}
        files = []
        for p in sorted(self._log_dir.iterdir()):
            if p.is_file():
                stat = p.stat()
                files.append({"name": p.name, "size": stat.st_size, "modified": stat.st_mtime})
        return {"files": files, "log_dir": str(self._log_dir), "count": len(files)}

    # ── log read / tail ────────────────────────────────────────────────────────

    def _resolve_log(self, filename: str) -> Path:
        safe = Path(filename).name
        if safe != filename or not safe:
            raise HTTPException(400, "Invalid filename — path components not allowed")
        path = self._log_dir / safe
        if not path.exists():
            raise HTTPException(404, f"Log file {filename!r} not found in {self._log_dir}")
        return path

    def _read_log(
        self,
        filename: str,
        lines: int = Query(100, ge=1, le=10000, description="Number of lines from the end of the file"),
    ) -> dict:
        path = self._resolve_log(filename)
        proc = subprocess.run(["tail", "-n", str(lines), str(path)], capture_output=True, text=True)
        content = proc.stdout
        return {
            "filename": filename,
            "path": str(path),
            "lines_requested": lines,
            "line_count": content.count("\n"),
            "content": content,
        }

    def _tail_log(
        self,
        filename: str,
        lines: int = Query(50, ge=1, le=10000, description="Number of lines from the end of the file"),
    ) -> dict:
        return self._read_log(filename, lines)

    # ── systemd journal ────────────────────────────────────────────────────────

    def _journal(
        self,
        lines: int = Query(100, ge=1, le=10000, description="Number of journal entries to return"),
        unit: Optional[str] = Query(None, description="Filter by unit name (e.g. rsyslog.service)"),
        priority: Optional[str] = Query(None, description="Max priority: emerg/alert/crit/err/warning/notice/info/debug or 0-7"),
        output: str = Query("short", description="Output format: short, json, cat, verbose, export"),
        since: Optional[str] = Query(None, description="Show entries since timestamp (e.g. '2024-01-01 00:00:00')"),
    ) -> dict:
        if output not in _VALID_JOURNAL_OUTPUTS:
            raise HTTPException(400, f"output must be one of: {', '.join(sorted(_VALID_JOURNAL_OUTPUTS))}")
        if priority is not None and priority not in _VALID_PRIORITIES:
            raise HTTPException(400, f"priority must be one of: {', '.join(sorted(_VALID_PRIORITIES))}")

        cmd = ["journalctl", "--no-pager", "-n", str(lines), "-o", output]
        if unit:
            cmd += ["-u", unit]
        if priority:
            cmd += ["-p", priority]
        if since:
            cmd += ["--since", since]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode not in (0, 1):
            raise HTTPException(500, f"journalctl failed: {proc.stderr.strip()}")

        if output == "json":
            entries = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        entries.append({"raw": line})
            return {"entries": entries, "count": len(entries), "filters": _journal_filters(unit, priority, since, lines)}

        return {
            "content": proc.stdout,
            "line_count": proc.stdout.count("\n"),
            "filters": _journal_filters(unit, priority, since, lines),
        }


# ── helpers ────────────────────────────────────────────────────────────────────

def _build_logrotate_conf(
    log_dir: Path,
    *,
    rotate: int = 7,
    frequency: str = "daily",
    compress: bool = True,
    max_size: Optional[str] = None,
) -> str:
    lines = [f"{log_dir}/*.log {{", f"    {frequency}", f"    rotate {rotate}"]
    if max_size:
        lines.append(f"    maxsize {max_size}")
    if compress:
        lines += ["    compress", "    delaycompress"]
    lines += ["    missingok", "    notifempty", "    create 0644 root root", "}"]
    return "\n".join(lines) + "\n"


def _build_fb_ini(sections: dict[str, dict | list]) -> str:
    line="# Managed by FastFirewall syslog — do not edit by hand.\n\n"
    for section, value in sections.items():
        if isinstance(value, dict):
            line += f"[{section.upper()}]\n"
            for k, v in value.items():
                line += f"    {k} {v}\n"
        elif isinstance(value, list):
            for item in value:
                line += f"\n[{section.upper()}]\n"
                for k, v in item.items():
                    line += f"    {k} {v}\n"
    return line

def _build_fastfirewall_conf_classic(
    log_dir: Path,
    *,
    syslog_port: int = 514,
    syslog_mode: str = "udp",
    syslog_unix_path: Optional[str] = None,
    syslog_unix_mode: str = "unix_udp",
    enable_systemd: bool = True,
) -> str:
    sections={}
    svc_cfg = sections["service"]={}
    svc_cfg["Flush"] = 5
    svc_cfg["Daemon"] = "Off"
    svc_cfg["Log_Level"] = "info"

    input_cfg = sections["input"]=[]
    dinput_cfg = {
        "Name": "syslog",
        "Listen": "0.0.0.0",
        "Port": syslog_port,
        "Mode": syslog_mode,
        "Tag": "syslog.net.*",
        "Parser": "syslog-rfc3164",
    }
    input_cfg.append(dinput_cfg)

    if syslog_unix_path:
        uinput_cfg = {
            "Name": "syslog",
            "Path": syslog_unix_path,
            "Mode": syslog_unix_mode,
            "Tag": "syslog.unix.*",
            "Unix_Perm": "0666",
            "Parser": "syslog-rfc3164",
        }
        input_cfg.append(uinput_cfg)

    if enable_systemd:
        journal_cfg = {
            "Name": "systemd",
            "Tag": "systemd.*",
            "Read_From_Tail": "On",
            "Strip_Underscores": "On",
        }
        input_cfg.append(journal_cfg)

    out_cfg = sections["output"]={}
    out_cfg["Name"] = "file"
    out_cfg["Match"] = "*"
    out_cfg["Path"] = str(log_dir)
    out_cfg["File"] = "fluent-bit.log"
    out_cfg["Format"] = "json"

    return _build_fb_ini(dict(sections))


def _journal_filters(unit: Optional[str], priority: Optional[str], since: Optional[str], lines: int) -> dict:
    return {"unit": unit, "priority": priority, "since": since, "lines": lines}
