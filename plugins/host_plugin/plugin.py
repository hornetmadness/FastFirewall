"""
Host Plugin
───────────
Manages basic host system configuration via pyinfra server.* operations.
Routes mount at /v1/host/.

Events emitted:
  host.hostname.changed  – payload: {hostname}
  host.service.changed   – payload: {service, running, enabled}
  host.service.deleted   – payload: {service}
  host.sysctl.changed    – payload: {key, value, persist}
  host.sysctl.deleted    – payload: {key}
  host.user.changed      – payload: {user, shell, home_dir, system, comment}
  host.user.deleted      – payload: {user}
  host.group.changed     – payload: {group, system, gid}
  host.group.deleted     – payload: {group}
  host.cron.changed      – payload: {name, command, minute, hour, ...}
  host.cron.deleted      – payload: {name}
"""
from __future__ import annotations

import io
import json
import os
import pickle
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel
from pyinfra.api.connect import connect_all
from pyinfra.api.operations import run_ops
from pyinfra.operations import files as files_ops
from pyinfra.operations import server as server_ops
from pyinfra.operations import systemd as systemd_ops

from plugin_system.core import PluginBase, RoutedPlugin, Service
from plugin_system.core.events import Event, bus


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class HostnameBody(BaseModel):
    hostname: str


class ServiceBody(BaseModel):
    running: bool = True
    enabled: bool = True


class SysctlBody(BaseModel):
    value: str
    persist: bool = True


class UserBody(BaseModel):
    shell: str = "/bin/bash"
    home_dir: Optional[str] = None
    system: bool = False
    comment: Optional[str] = None


class GroupBody(BaseModel):
    system: bool = False
    gid: Optional[int] = None


class CronBody(BaseModel):
    command: str
    minute: str = "*"
    hour: str = "*"
    day_of_month: str = "*"
    month: str = "*"
    day_of_week: str = "*"
    user: str = "root"


# ── Plugin ─────────────────────────────────────────────────────────────────────

class HostPlugin(PluginBase, RoutedPlugin):
    service_name = Service.HOST
    services = [Service.HOST]

    _EMPTY_STATE: dict[str, Any] = {
        "services": {},
        "sysctl": {},
        "users": {},
        "groups": {},
        "cron": {},
    }

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_path = self.plugin_dir / "data" / self.config.get("state_file", "host_state.json")
        self._state: dict[str, Any] = self._load_state()
        self._register_routes()
        init_cfg: dict[str, Any] = self.config.get("init") or {}
        if init_cfg.get("enable_init_script", False):
            self._run_init_script(init_cfg)

    def teardown(self) -> None:
        self._save_state()

    # ── persistence ────────────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, Any]:
        if self._state_path.exists():
            try:
                with self._state_path.open() as fh:
                    return json.load(fh)
            except Exception:
                self.logger.error("Failed to load state from %r, starting empty", self._state_path, exc_info=True)
        return {k: {} for k in self._EMPTY_STATE}

    def _save_state(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            with self._state_path.open("w") as fh:
                json.dump(self._state, fh, indent=2)
        except Exception:
            self.logger.error("Failed to save state to %r", self._state_path, exc_info=True)

    # ── pyinfra helper ─────────────────────────────────────────────────────────

    _WORKER_SCRIPT = Path(__file__).parent / "_pyinfra_worker.py"

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

    # ── init system detection & service registration ───────────────────────────

    @staticmethod
    def _detect_init_system() -> str:
        if os.path.isdir("/run/systemd/system"):
            return "systemd"
        if shutil.which("initctl") and os.path.isdir("/etc/init"):
            return "upstart"
        if os.path.isdir("/etc/init.d"):
            return "sysvinit"
        return "unknown"

    @staticmethod
    def _systemd_unit(service_name: str, command: str, working_dir: Optional[str] = None) -> str:
        wd_line = f"WorkingDirectory={working_dir}\n" if working_dir else ""
        return (
            f"[Unit]\n"
            f"Description={service_name}\n"
            f"After=network.target\n\n"
            f"[Service]\n"
            f"{wd_line}"
            f"ExecStart={command}\n"
            f"Restart=on-failure\n"
            f"RestartSec=5\n\n"
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )

    @staticmethod
    def _upstart_conf(service_name: str, command: str, working_dir: Optional[str] = None) -> str:
        wd_line = f"chdir {working_dir}\n" if working_dir else ""
        return (
            f'description "{service_name}"\n'
            f"start on runlevel [2345]\n"
            f"stop on runlevel [!2345]\n"
            f"respawn\n"
            f"{wd_line}"
            f"exec {command}\n"
        )

    @staticmethod
    def _sysvinit_script(service_name: str, command: str, working_dir: Optional[str] = None) -> str:
        cd_line = f"  cd {working_dir} && " if working_dir else "  "
        return (
            f"#!/bin/sh\n"
            f"### BEGIN INIT INFO\n"
            f"# Provides:          {service_name}\n"
            f"# Required-Start:    $network\n"
            f"# Required-Stop:     $network\n"
            f"# Default-Start:     2 3 4 5\n"
            f"# Default-Stop:      0 1 6\n"
            f"# Short-Description: {service_name}\n"
            f"### END INIT INFO\n\n"
            f"case \"$1\" in\n"
            f"  start)   {cd_line}{command} &;;\n"
            f"  stop)    pkill -f \"{command}\" || true;;\n"
            f"  restart) $0 stop; $0 start;;\n"
            f"  *) echo \"Usage: $0 {{start|stop|restart}}\"; exit 1;;\n"
            f"esac\n"
            f"exit 0\n"
        )

    def _place_service_definition(
        self, init_system: str, service_name: str, command: str, working_dir: Optional[str] = None
    ) -> None:
        if init_system == "systemd":
            self._pyinfra_run(
                files_ops.put,
                name=f"Place {service_name}.service unit",
                src=io.StringIO(self._systemd_unit(service_name, command, working_dir)),
                dest=f"/etc/systemd/system/{service_name}.service",
                mode="644",
            )
        elif init_system == "upstart":
            self._pyinfra_run(
                files_ops.put,
                name=f"Place {service_name} upstart conf",
                src=io.StringIO(self._upstart_conf(service_name, command, working_dir)),
                dest=f"/etc/init/{service_name}.conf",
                mode="644",
            )
        elif init_system == "sysvinit":
            self._pyinfra_run(
                files_ops.put,
                name=f"Place {service_name} init script",
                src=io.StringIO(self._sysvinit_script(service_name, command, working_dir)),
                dest=f"/etc/init.d/{service_name}",
                mode="755",
            )

    def _enable_service(self, init_system: str, service_name: str) -> None:
        if init_system == "systemd":
            self._pyinfra_run(systemd_ops.daemon_reload, name="Reload systemd daemon")
            self._pyinfra_run(
                systemd_ops.service,
                name=f"Enable and start {service_name}",
                service=service_name,
                running=True,
                enabled=True,
            )
        elif init_system == "upstart":
            # upstart picks up start/stop from the conf file; just ensure it's running
            self._pyinfra_run(
                server_ops.service,
                name=f"Start {service_name}",
                service=service_name,
                running=True,
            )
        else:  # sysvinit
            self._pyinfra_run(
                server_ops.service,
                name=f"Enable and start {service_name}",
                service=service_name,
                running=True,
                enabled=True,
            )

    def _run_init_script(self, init_cfg: dict[str, Any]) -> None:
        service_name: str = init_cfg.get("service_name", "ff-claude")
        command: str = init_cfg.get("command", "")
        working_dir: Optional[str] = init_cfg.get("working_dir") or None

        init_system = self._detect_init_system()
        if init_system == "unknown":
            self.logger.warning(
                "No supported init system detected; skipping init script for %r",
                service_name,
            )
            return

        self.logger.info(
            "Init script: %s %r via %s",
            "registering and enabling" if command else "enabling",
            service_name,
            init_system,
        )
        try:
            if command:
                self._place_service_definition(init_system, service_name, command, working_dir)
            self._enable_service(init_system, service_name)
        except Exception as exc:
            self.logger.warning(
                "Init script failed for service %r — continuing: %s",
                service_name,
                exc,
            )

    def _emit(self, event_name: str, payload: dict[str, Any]) -> None:
        bus.emit(Event(event_name, source=self.plugin_id, payload=payload))

    # ── route registration ─────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",              self._status,           methods=["GET"],    summary="Plugin status and managed-resource counts")

        add("/hostname",            self._get_hostname,     methods=["GET"],    summary="Get current hostname")
        add("/hostname",            self._set_hostname,     methods=["PUT"],    summary="Set system hostname")

        add("/services",            self._list_services,    methods=["GET"],    summary="List managed services")
        add("/services/{service}",  self._set_service,      methods=["PUT"],    summary="Start/stop/enable/disable a service")
        add("/services/{service}",  self._delete_service,   methods=["DELETE"], summary="Stop managing a service")

        add("/sysctl",              self._list_sysctl,      methods=["GET"],    summary="List managed sysctl parameters")
        add("/sysctl-all",              self._list_all_sysctl,      methods=["GET"],    summary="List all sysctl parameters")
        add("/sysctl/{key}",        self._set_sysctl,       methods=["PUT"],    summary="Set a sysctl kernel parameter")
        add("/sysctl/{key}",        self._delete_sysctl,    methods=["DELETE"], summary="Stop managing a sysctl parameter")

        add("/users",               self._list_users,       methods=["GET"],    summary="List managed users")
        add("/users/{name}",        self._set_user,         methods=["POST"],   summary="Create or reconfigure a system user",   status_code=201)
        add("/users/{name}",        self._delete_user,      methods=["DELETE"], summary="Remove a system user")

        add("/groups",              self._list_groups,      methods=["GET"],    summary="List managed groups")
        add("/groups/{name}",       self._set_group,        methods=["POST"],   summary="Create or reconfigure a system group",  status_code=201)
        add("/groups/{name}",       self._delete_group,     methods=["DELETE"], summary="Remove a system group")

        add("/cron",                self._list_cron,        methods=["GET"],    summary="List managed cron entries")
        add("/cron/{name}",         self._set_cron,         methods=["POST"],   summary="Create or update a cron entry",         status_code=201)
        add("/cron/{name}",         self._delete_cron,      methods=["DELETE"], summary="Remove a cron entry")

    # ── status ─────────────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "hostname": socket.gethostname(),
            "managed": {
                "services": len(self._state["services"]),
                "sysctl":   len(self._state["sysctl"]),
                "users":    len(self._state["users"]),
                "groups":   len(self._state["groups"]),
                "cron":     len(self._state["cron"]),
            },
        }

    # ── hostname ───────────────────────────────────────────────────────────────

    def _get_hostname(self) -> dict:
        return {"hostname": socket.gethostname()}

    def _set_hostname(self, body: HostnameBody) -> dict:
        self._pyinfra_run(
            server_ops.hostname,
            name=f"Set hostname to {body.hostname}",
            hostname=body.hostname,
            _sudo=True,
        )
        self._emit("host.hostname.changed", {"hostname": body.hostname})
        return {"hostname": body.hostname}

    # ── services ───────────────────────────────────────────────────────────────

    def _list_services(self) -> dict:
        return {"services": self._state["services"]}

    def _set_service(self, service: str, body: ServiceBody) -> dict:
        self._pyinfra_run(
            server_ops.service,
            name=f"Configure service {service}",
            service=service,
            running=body.running,
            enabled=body.enabled,
        )
        self._state["services"][service] = body.model_dump()
        self._save_state()
        self._emit("host.service.changed", {"service": service, **body.model_dump()})
        return {"service": service, **body.model_dump()}

    def _delete_service(self, service: str) -> dict:
        if service not in self._state["services"]:
            raise HTTPException(404, f"Service {service!r} not managed")
        del self._state["services"][service]
        self._save_state()
        self._emit("host.service.deleted", {"service": service})
        return {"deleted": service}

    # ── sysctl ─────────────────────────────────────────────────────────────────

    def _list_sysctl(self) -> dict:
        return {"sysctl": self._state["sysctl"]}

    def _list_all_sysctl(self) -> dict:
        # helper for testing/debugging to list all sysctl values, not just managed ones
        proc = subprocess.run(["sysctl", "-a"], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to list sysctl parameters: {proc.stderr}")
        result = {}
        for line in proc.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
        return {"sysctl": result}

    def _set_sysctl(self, key: str, body: SysctlBody) -> dict:
        self._pyinfra_run(
            server_ops.sysctl,
            name=f"Set sysctl {key}={body.value}",
            key=key,
            value=body.value,
            persist=body.persist,
        )
        self._state["sysctl"][key] = body.model_dump()
        self._save_state()
        self._emit("host.sysctl.changed", {"key": key, **body.model_dump()})
        return {"key": key, **body.model_dump()}

    def _delete_sysctl(self, key: str) -> dict:
        if key not in self._state["sysctl"]:
            raise HTTPException(404, f"Sysctl key {key!r} not managed")
        del self._state["sysctl"][key]
        self._save_state()
        self._emit("host.sysctl.deleted", {"key": key})
        return {"deleted": key}

    # ── users ──────────────────────────────────────────────────────────────────

    def _list_users(self) -> dict:
        return {"users": self._state["users"]}

    def _set_user(self, name: str, body: UserBody) -> dict:
        kwargs: dict[str, Any] = {
            "name": f"Manage user {name}",
            "user": name,
            "shell": body.shell,
            "system": body.system,
        }
        if body.home_dir:
            kwargs["home"] = body.home_dir
        if body.comment:
            kwargs["comment"] = body.comment
        self._pyinfra_run(server_ops.user, **kwargs)
        self._state["users"][name] = body.model_dump()
        self._save_state()
        self._emit("host.user.changed", {"user": name, **body.model_dump()})
        return {"user": name, **body.model_dump()}

    def _delete_user(self, name: str) -> dict:
        if name not in self._state["users"]:
            raise HTTPException(404, f"User {name!r} not managed")
        self._pyinfra_run(
            server_ops.user,
            name=f"Remove user {name}",
            user=name,
            present=False,
        )
        del self._state["users"][name]
        self._save_state()
        self._emit("host.user.deleted", {"user": name})
        return {"deleted": name}

    # ── groups ─────────────────────────────────────────────────────────────────

    def _list_groups(self) -> dict:
        return {"groups": self._state["groups"]}

    def _set_group(self, name: str, body: GroupBody) -> dict:
        kwargs: dict[str, Any] = {
            "name": f"Manage group {name}",
            "group": name,
            "system": body.system,
        }
        if body.gid is not None:
            kwargs["gid"] = body.gid
        self._pyinfra_run(server_ops.group, **kwargs)
        self._state["groups"][name] = body.model_dump()
        self._save_state()
        self._emit("host.group.changed", {"group": name, **body.model_dump()})
        return {"group": name, **body.model_dump()}

    def _delete_group(self, name: str) -> dict:
        if name not in self._state["groups"]:
            raise HTTPException(404, f"Group {name!r} not managed")
        self._pyinfra_run(
            server_ops.group,
            name=f"Remove group {name}",
            group=name,
            present=False,
        )
        del self._state["groups"][name]
        self._save_state()
        self._emit("host.group.deleted", {"group": name})
        return {"deleted": name}

    # ── cron ───────────────────────────────────────────────────────────────────

    def _list_cron(self) -> dict:
        return {"cron": self._state["cron"]}

    def _set_cron(self, name: str, body: CronBody) -> dict:
        self._pyinfra_run(
            server_ops.crontab,
            name=f"Manage cron {name}",
            command=body.command,
            minute=body.minute,
            hour=body.hour,
            day_of_month=body.day_of_month,
            month=body.month,
            day_of_week=body.day_of_week,
            user=body.user,
        )
        self._state["cron"][name] = body.model_dump()
        self._save_state()
        self._emit("host.cron.changed", {"name": name, **body.model_dump()})
        return {"name": name, **body.model_dump()}

    def _delete_cron(self, name: str) -> dict:
        if name not in self._state["cron"]:
            raise HTTPException(404, f"Cron entry {name!r} not managed")
        entry = self._state["cron"][name]
        self._pyinfra_run(
            server_ops.crontab,
            name=f"Remove cron {name}",
            command=entry["command"],
            present=False,
            user=entry["user"],
        )
        del self._state["cron"][name]
        self._save_state()
        self._emit("host.cron.deleted", {"name": name})
        return {"deleted": name}
