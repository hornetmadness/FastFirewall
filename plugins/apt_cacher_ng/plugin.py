"""
Apt-Cacher-NG Plugin
────────────────────
Installs and manages apt-cacher-ng, a caching proxy for Debian/Ubuntu package
downloads. Writes /etc/apt-cacher-ng/acng.conf and controls the service via
systemctl. Routes mount at /v1/apt_cacher_ng/.

Events emitted:
  apt_cacher_ng.config.updated   – payload: {keys: [list of changed field names]}
  apt_cacher_ng.cache.flushed    – payload: {cache_dir}
  apt_cacher_ng.service.reloaded – payload: {}
"""
from __future__ import annotations

import io
import json
import socket
import subprocess
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, HTTPException, Query
from ff_auth import require_role
from pydantic import BaseModel, Field

from pyinfra.operations import files as files_ops

from infra import pyinfra_run_batch
from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service
from plugin_system.core.events import Event, bus
from plugin_system.core.macros import macro_registry


# ── Pydantic models ─────────────────────────────────────────────────────────────

class AcngConfigUpdate(BaseModel):
    port: Optional[int] = Field(None, ge=1, le=65535, description="Listening port")
    bind_address: Optional[str] = Field(None, max_length=1024, description="Space-separated bind addresses; empty to bind all")
    ex_threshold: Optional[int] = Field(None, ge=0, le=100, description="Disk space threshold percent; old files removed below this level")
    max_dl_speed_kb: Optional[int] = Field(None, ge=0, description="Max download speed in kB/s; 0 for unlimited")
    fetch_timeout: Optional[int] = Field(None, ge=1, le=3600, description="Fetch timeout in seconds")
    tunnel_timeout: Optional[int] = Field(None, ge=0, description="CONNECT tunnel timeout in seconds; 0 to disable")
    force_managed: Optional[bool] = Field(None, description="Only proxy known package repository paths")
    allow_user_ports: Optional[bool] = Field(None, description="Allow clients to connect to non-standard ports")


class ProxyHostUpdate(BaseModel):
    host: str = Field(..., min_length=1, max_length=253, description="Hostname or IP clients should use to reach this proxy")


# ── config key mapping ──────────────────────────────────────────────────────────

# Maps our field names → acng.conf key names.
# Note: apt-cacher-ng spells it "ExTreshold" (one 'h') — that is correct.
_FIELD_TO_KEY: dict[str, str] = {
    "port":            "Port",
    "bind_address":    "BindAddress",
    "ex_threshold":    "ExTreshold",
    "max_dl_speed_kb": "MaxDlSpeed",
    "fetch_timeout":   "FetchTimeout",
    "tunnel_timeout":  "TunnelTimeout",
    "force_managed":   "ForceManaged",
    "allow_user_ports":"AllowUserPorts",
}
_KEY_TO_FIELD: dict[str, str] = {v: k for k, v in _FIELD_TO_KEY.items()}
_ALL_MANAGED_KEYS: frozenset[str] = frozenset(_FIELD_TO_KEY.values())
_BOOL_KEYS: frozenset[str] = frozenset({"ForceManaged", "AllowUserPorts"})


# ── plugin ──────────────────────────────────────────────────────────────────────

class AptCacherNgPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.PKG_CACHE]

    def setup(self) -> None:
        self._conf_file = Path(self.config.get("conf_file", "/etc/apt-cacher-ng/acng.conf"))
        self._cache_dir = Path(self.config.get("cache_dir", "/var/cache/apt-cacher-ng"))
        self._log_dir   = Path(self.config.get("log_dir",   "/var/log/apt-cacher-ng"))
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "apt_cacher_ng_state.json", self.logger,
            mutation_model="immediate", data_dir=self.data_dir,
        )

        _default: dict[str, Any] = {"acng_settings": {}, "proxy_host": None}
        if self.config.get("ignore_state_on_boot", False):
            self._state: dict[str, Any] = dict(_default)
        else:
            self._state = self._state_file.load_desired(default=_default)
            self._apply_state()

        self._register_routes()
        self._sync_os_boot_service()
        self.logger.info(
            "Apt-Cacher-NG plugin loaded; conf=%s cache=%s",
            self._conf_file, self._cache_dir,
        )

    def teardown(self) -> None:
        self._save_state()

    # ── state helpers ────────────────────────────────────────────────────────────

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _apply_state(self) -> None:
        settings = self._state.get("acng_settings", {})
        if not settings:
            return
        try:
            content = _render_acng_conf(self._conf_file, _settings_to_acng(settings))
            self._write_conf_file(content)
            self.logger.info("Re-applied %d acng setting(s) from state on boot", len(settings))
        except Exception as exc:
            self.logger.warning("Could not re-apply acng settings on boot: %s", exc)

    # ── pyinfra helper ────────────────────────────────────────────────────────────

    def _pyinfra_run(self, op: Any, **kwargs: Any) -> None:
        norm_kwargs = {
            k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
            for k, v in kwargs.items()
        }
        success, err = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])[0]
        if not success:
            raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")

    # ── subprocess helper ─────────────────────────────────────────────────────────

    def _run_cmd(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

    # ── config file helpers ───────────────────────────────────────────────────────

    def _write_conf_file(self, content: str) -> None:
        self._pyinfra_run(
            files_ops.put,
            name="Write apt-cacher-ng config",
            src=io.StringIO(content),
            dest=str(self._conf_file),
            mode="644",
            _sudo=True,
        )

    def _reload_service(self) -> None:
        results = bus.emit(Event("initsys.service.restart", payload={"service_name": "apt-cacher-ng"}))
        if not (results and results[0].get("success")):
            raise RuntimeError("apt-cacher-ng reload failed; check server logs")

    def _sync_os_boot_service(self) -> None:
        if self.config.get("enable_os_boot", False):
            bus.emit(Event("initsys.service.add", payload={"service_name": "apt-cacher-ng"}))
        else:
            bus.emit(Event("initsys.service.disable", payload={"service_name": "apt-cacher-ng"}))

    # ── proxy host resolution ─────────────────────────────────────────────────────

    def _resolve_proxy_host(self) -> tuple[str, str]:
        """Return (host, source) where source is 'override', 'macro', or 'fqdn'."""
        override = self._state.get("proxy_host")
        if override:
            return override, "override"
        addresses = macro_registry.resolve("$interface.lan.address")
        if addresses:
            return addresses[-1], "macro"
        return socket.getfqdn(), "fqdn"

    # ── route registration ────────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        _admin = [require_role("admin")]
        add("/status",        self._status,        methods=["GET"],    summary="Plugin and service status", dependencies=_admin)
        add("/config",        self._get_config,    methods=["GET"],    summary="Get managed acng settings", dependencies=_admin)
        add("/config",        self._update_config, methods=["PATCH"],  summary="Update acng settings and reload", dependencies=_admin)
        add("/config/reload", self._reload,        methods=["POST"],   summary="Reload apt-cacher-ng without config change", dependencies=_admin)
        add("/config/raw",    self._get_raw_conf,  methods=["GET"],    summary="Read raw acng.conf from disk", dependencies=_admin)
        add("/proxy-url",     self._get_proxy_url, methods=["GET"],    summary="Get proxy URL and host resolution info", dependencies=_admin)
        add("/proxy-url",     self._set_proxy_host,methods=["PUT"],    summary="Set a static host override for the proxy URL", dependencies=_admin)
        add("/proxy-url",     self._clear_proxy_host, methods=["DELETE"], summary="Clear the static host override", dependencies=_admin)
        add("/cache",         self._cache_stats,   methods=["GET"],    summary="Cache disk usage and file count", dependencies=_admin)
        add("/cache",         self._flush_cache,   methods=["DELETE"], summary="Delete all cached packages", dependencies=_admin)
        add("/logs",          self._get_logs,      methods=["GET"],    summary="Recent apt-cacher-ng journal entries", dependencies=_admin)

    # ── route handlers ────────────────────────────────────────────────────────────

    def _status(self) -> dict:
        results = bus.emit(Event("initsys.service.status", payload={"service_name": "apt-cacher-ng"}))
        svc_status = "active" if (results and results[0] and results[0].get("running")) else "inactive"
        live_port = _parse_acng_conf(self._conf_file).get("Port")
        state_port = self._state.get("acng_settings", {}).get("port")
        port = int(live_port or state_port or 3142)
        host, _ = self._resolve_proxy_host()
        proxy_url = f"http://{host}:{port}/"
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "conf_file": str(self._conf_file),
            "cache_dir": str(self._cache_dir),
            "service": {"apt-cacher-ng": svc_status},
            "proxy_url": proxy_url,
            "apt_proxy_conf": f'Acquire::http::proxy "{proxy_url}";',
            "managed_settings": len(self._state.get("acng_settings", {})),
            "pending_changes": self._state_file.pending_changes,
        }

    def _get_config(self) -> dict:
        live = _parse_acng_conf(self._conf_file)
        managed_acng = _settings_to_acng(self._state.get("acng_settings", {}))
        settings: dict[str, Any] = {}
        for key in sorted(_ALL_MANAGED_KEYS | set(live.keys())):
            if key in live or key in managed_acng:
                settings[key] = {
                    "value": live.get(key, managed_acng.get(key, "")),
                    "field": _KEY_TO_FIELD.get(key, key.lower()),
                    "managed": key in managed_acng,
                }
        return {"settings": settings, "conf_file": str(self._conf_file)}

    def _update_config(self, body: AcngConfigUpdate) -> dict:
        updates = body.model_dump(exclude_none=True)
        if not updates:
            raise HTTPException(400, "No settings provided")

        self._state.setdefault("acng_settings", {}).update(updates)
        self._save_state()

        try:
            content = _render_acng_conf(self._conf_file, _settings_to_acng(self._state["acng_settings"]))
            self._write_conf_file(content)
            self._reload_service()
        except Exception as exc:
            self.logger.error("Config written but apt-cacher-ng reload failed", exc_info=True)
            raise HTTPException(500, "Config written but service reload failed; check server logs") from exc

        bus.emit(Event(
            "apt_cacher_ng.config.updated",
            payload={"keys": list(updates.keys())},
        ))
        return {"updated": list(updates.keys())}

    def _reload(self) -> dict:
        try:
            self._reload_service()
        except RuntimeError as exc:
            self.logger.error("apt-cacher-ng reload failed", exc_info=True)
            raise HTTPException(500, "Service reload failed; check server logs") from exc
        bus.emit(Event("apt_cacher_ng.service.reloaded", payload={}))
        return {"reloaded": True}

    def _get_proxy_url(self) -> dict:
        live_port = _parse_acng_conf(self._conf_file).get("Port")
        state_port = self._state.get("acng_settings", {}).get("port")
        port = int(live_port or state_port or 3142)
        host, source = self._resolve_proxy_host()
        return {
            "proxy_url": f"http://{host}:{port}/",
            "host": host,
            "port": port,
            "host_source": source,
        }

    def _set_proxy_host(self, body: ProxyHostUpdate) -> dict:
        self._state["proxy_host"] = body.host
        self._save_state()
        return self._get_proxy_url()

    def _clear_proxy_host(self) -> dict:
        self._state["proxy_host"] = None
        self._save_state()
        return self._get_proxy_url()

    def _get_raw_conf(self) -> dict:
        if not self._conf_file.exists():
            raise HTTPException(404, f"Config file not found: {self._conf_file}")
        return {
            "path": str(self._conf_file),
            "content": self._conf_file.read_text(),
        }

    def _cache_stats(self) -> dict:
        if not self._cache_dir.is_dir():
            return {"cache_dir": str(self._cache_dir), "exists": False}

        proc_du = self._run_cmd(["du", "-sb", str(self._cache_dir)])
        total_bytes = 0
        if proc_du.returncode == 0 and proc_du.stdout:
            try:
                total_bytes = int(proc_du.stdout.split()[0])
            except (ValueError, IndexError):
                pass

        proc_find = self._run_cmd(["find", str(self._cache_dir), "-type", "f"])
        file_count = proc_find.stdout.count("\n") if proc_find.returncode == 0 else 0

        return {
            "cache_dir": str(self._cache_dir),
            "exists": True,
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "file_count": file_count,
        }

    def _flush_cache(self) -> dict:
        if not self._cache_dir.is_dir():
            raise HTTPException(404, f"Cache directory not found: {self._cache_dir}")
        proc = self._run_cmd(["sudo", "find", str(self._cache_dir), "-type", "f", "-delete"])
        if proc.returncode != 0:
            self.logger.error("Cache flush failed: %s", proc.stderr.strip())
            raise HTTPException(500, "Cache flush failed; check server logs")
        bus.emit(Event(
            "apt_cacher_ng.cache.flushed",
            payload={"cache_dir": str(self._cache_dir)},
        ))
        return {"flushed": True, "cache_dir": str(self._cache_dir)}

    def _get_logs(
        self,
        lines: int = Query(100, ge=1, le=10000, description="Number of journal entries to return"),
    ) -> dict:
        proc = self._run_cmd(
            ["journalctl", "-u", "apt-cacher-ng", "--no-pager", "-n", str(lines)],
            timeout=10,
        )
        return {
            "content": proc.stdout,
            "line_count": proc.stdout.count("\n"),
            "lines_requested": lines,
        }


# ── helpers ──────────────────────────────────────────────────────────────────────


def _parse_acng_conf(path: Path) -> dict[str, str]:
    """Return active (uncommented) key→value pairs from an acng.conf file."""
    out: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and ":" in stripped:
                k, _, v = stripped.partition(":")
                out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out


def _settings_to_acng(settings: dict[str, Any]) -> dict[str, str]:
    """Convert field_name→value dict to acng.conf key→string-value dict."""
    out: dict[str, str] = {}
    for field, val in settings.items():
        key = _FIELD_TO_KEY.get(field, field)
        if isinstance(val, bool):
            out[key] = "1" if val else "0"
        else:
            out[key] = str(val)
    return out


def _render_acng_conf(path: Path, updates: dict[str, str]) -> str:
    """Apply key→value updates to an existing acng.conf, preserving comments and unmanaged keys.
    Creates a minimal file from scratch when none exists."""
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        lines = ["# Managed by FastFirewall apt-cacher-ng plugin"]

    written: set[str] = set()
    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and ":" in stripped:
            k = stripped.partition(":")[0].strip()
            if k in updates:
                new_lines.append(f"{k}: {updates[k]}")
                written.add(k)
                continue
        new_lines.append(line)

    for k, v in updates.items():
        if k not in written:
            new_lines.append(f"{k}: {v}")

    return "\n".join(new_lines) + "\n"
