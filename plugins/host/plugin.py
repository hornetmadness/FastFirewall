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
  host.package.changed   – payload: {package, present, latest, platform}
  host.package.updated   – payload: {package, platform}
  host.package.deleted   – payload: {package, platform}
  host.repo.changed          – payload: {repo, platform, ...body fields}
  host.repo.deleted          – payload: {repo, platform}
  host.package.upgrade-system.started – payload: {task_id, email, platform}
  host.package.upgrade-system.done    – payload: {platform, returncode, email}
"""
from __future__ import annotations

import configparser
import grp
import hashlib
import io
import json
import os
import pickle
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, HTTPException
from pydantic import BaseModel, field_validator
from pyinfra.operations import files as files_ops
from pyinfra.operations import server as server_ops
from pyinfra.operations import systemd as systemd_ops

from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, Service
from plugin_system.core.events import Event, bus
from plugins.host._pkg_manager import (
    PackageBody,
    PackageManager,
    RepoBody,
    detect_package_manager,
)

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


class GroupMemberBody(BaseModel):
    username: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", v):
            raise ValueError("Invalid username format")
        return v


class CronBody(BaseModel):
    command: str
    minute: str = "*"
    hour: str = "*"
    day_of_month: str = "*"
    month: str = "*"
    day_of_week: str = "*"
    user: str = "root"


class UpgradeBody(BaseModel):
    email: str


class CronImportBody(BaseModel):
    source_key: str


class RepoImportBody(BaseModel):
    id: str
    alias: str


# ── Plugin ─────────────────────────────────────────────────────────────────────

class HostPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.HOST, Service.PKG_MANAGEMENT, Service.SYSCTL, Service.CRON, Service.USERS, Service.GROUPS]

    _EMPTY_STATE: dict[str, Any] = {
        "services": {},
        "sysctl": {},
        "users": {},
        "groups": {},
        "cron": {},
        "packages": {},
        "repos": {},
    }

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "host_state.json", self.logger,
            mutation_model="immediate",
        )
        self._bg_tasks: dict[str, dict[str, Any]] = {}
        self._pkg_mgr = PackageManager(
            self._pyinfra_run,
            detect_package_manager(),
            cache_ttl=int(self.config.get("os_pkgmgr_max_cache_ttl_secs", 300)),
        )
        if self.config.get("ignore_state_on_boot", False):
            self._state: dict[str, Any] = {k: {} for k in self._EMPTY_STATE}
        else:
            self._state = self._load_state()
            self._apply_state()
        self._register_routes()
        init_cfg: dict[str, Any] = self.config.get("init") or {}
        if init_cfg.get("enable_init_script", False):
            self._run_init_script(init_cfg)

    def teardown(self) -> None:
        self._save_state()

    # ── persistence ────────────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, Any]:
        desired = self._state_file.load_desired(default={})
        state = {k: {} for k in self._EMPTY_STATE}
        state.update({k: v for k, v in desired.items() if k in self._EMPTY_STATE})
        return state

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def _apply_state(self) -> None:
        if not any(self._state.get(k) for k in self._EMPTY_STATE):
            return

        applied: dict[str, Any] = {k: {} for k in self._EMPTY_STATE}

        for svc_name, v in self._state.get("services", {}).items():
            try:
                self._pyinfra_run(
                    server_ops.service,
                    name=f"Restore service {svc_name}",
                    service=svc_name,
                    running=v["running"],
                    enabled=v["enabled"],
                )
                applied["services"][svc_name] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for service %r: %s", svc_name, exc)

        for sysctl_key, v in self._state.get("sysctl", {}).items():
            try:
                self._pyinfra_run(
                    server_ops.sysctl,
                    name=f"Restore sysctl {sysctl_key}",
                    key=sysctl_key,
                    value=v["value"],
                    persist=v["persist"],
                )
                applied["sysctl"][sysctl_key] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for sysctl %r: %s", sysctl_key, exc)

        for user_name, v in self._state.get("users", {}).items():
            try:
                user_kw: dict[str, Any] = {
                    "name": f"Restore user {user_name}",
                    "user": user_name,
                    "shell": v["shell"],
                    "system": v["system"],
                }
                if v.get("home_dir"):
                    user_kw["home"] = v["home_dir"]
                if v.get("comment"):
                    user_kw["comment"] = v["comment"]
                self._pyinfra_run(server_ops.user, **user_kw)
                applied["users"][user_name] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for user %r: %s", user_name, exc)

        for group_name, v in self._state.get("groups", {}).items():
            try:
                group_kw: dict[str, Any] = {
                    "name": f"Restore group {group_name}",
                    "group": group_name,
                    "system": v["system"],
                }
                if v.get("gid") is not None:
                    group_kw["gid"] = v["gid"]
                self._pyinfra_run(server_ops.group, **group_kw)
                applied["groups"][group_name] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for group %r: %s", group_name, exc)

        for cron_name, v in self._state.get("cron", {}).items():
            try:
                self._pyinfra_run(
                    server_ops.crontab,
                    name=f"Restore cron {cron_name}",
                    command=v["command"],
                    minute=v["minute"],
                    hour=v["hour"],
                    day_of_month=v["day_of_month"],
                    month=v["month"],
                    day_of_week=v["day_of_week"],
                    user=v["user"],
                )
                applied["cron"][cron_name] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for cron %r: %s", cron_name, exc)

        for pkg_name, v in self._state.get("packages", {}).items():
            try:
                self._pkg_mgr.install(pkg_name, PackageBody(**v))
                applied["packages"][pkg_name] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for package %r: %s", pkg_name, exc)

        for repo_name, v in self._state.get("repos", {}).items():
            try:
                self._pkg_mgr.apply_repo(repo_name, RepoBody(**v))
                applied["repos"][repo_name] = v
            except Exception as exc:
                self.logger.warning("Boot-time restore failed for repo %r: %s", repo_name, exc)

        self._state_file.commit(applied)
        self.logger.info("Re-applied host state on boot")

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
        cfg = configparser.RawConfigParser()
        cfg.optionxform = lambda optionstr: optionstr  # preserve key case — systemd keys are CamelCase
        cfg["Unit"] = {"Description": service_name, "After": "network.target"}
        service: dict[str, str] = {}
        if working_dir:
            service["WorkingDirectory"] = working_dir
        service |= {"ExecStart": command, "Restart": "on-failure", "RestartSec": "5"}
        cfg["Service"] = service
        cfg["Install"] = {"WantedBy": "multi-user.target"}
        buf = io.StringIO()
        cfg.write(buf, space_around_delimiters=False)
        return buf.getvalue()

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
        add("/tasks",               self._list_bg_tasks,    methods=["GET"],    summary="List background tasks and their status")


        add("/hostname",            self._get_hostname,     methods=["GET"],    summary="Get current hostname")
        add("/hostname",            self._set_hostname,     methods=["PUT"],    summary="Set system hostname")

        add("/services",                   self._list_services,    methods=["GET"],    summary="List all services with ff_managed flag")
        add("/services/{service}",         self._set_service,      methods=["PUT"],    summary="Start/stop/enable/disable a service")
        add("/services/{service}",         self._delete_service,   methods=["DELETE"], summary="Stop managing a service")
        add("/services/{service}/import",  self._import_service,   methods=["POST"],   summary="Import an existing system service into FF management", status_code=201)

        add("/sysctl",                     self._list_sysctl,      methods=["GET"],    summary="List all sysctl parameters with ff_managed flag")
        add("/sysctl-all",                 self._list_all_sysctl,  methods=["GET"],    summary="List all sysctl parameters")
        add("/sysctl/{key}",               self._set_sysctl,       methods=["PUT"],    summary="Set a sysctl kernel parameter")
        add("/sysctl/{key}",               self._delete_sysctl,    methods=["DELETE"], summary="Stop managing a sysctl parameter")
        add("/sysctl/{key}/import",        self._import_sysctl,    methods=["POST"],   summary="Import an existing sysctl key into FF management", status_code=201)

        add("/users",                      self._list_users,       methods=["GET"],    summary="List all users with ff_managed flag")
        add("/users/{name}",               self._set_user,         methods=["POST"],   summary="Create or reconfigure a system user",   status_code=201)
        add("/users/{name}",               self._delete_user,      methods=["DELETE"], summary="Remove a system user")
        add("/users/{name}/import",        self._import_user,      methods=["POST"],   summary="Import an existing system user into FF management", status_code=201)

        add("/groups",                     self._list_groups,        methods=["GET"],    summary="List all groups with ff_managed flag")
        add("/groups/{name}",              self._set_group,          methods=["POST"],   summary="Create or reconfigure a system group",  status_code=201)
        add("/groups/{name}",              self._delete_group,       methods=["DELETE"], summary="Remove a system group")
        add("/groups/{name}/import",       self._import_group,       methods=["POST"],   summary="Import an existing system group into FF management", status_code=201)
        add("/groups/{name}/members",      self._list_group_members, methods=["GET"],    summary="List group members with ff_managed flag")
        add("/groups/{name}/members",      self._add_group_member,   methods=["POST"],   summary="Add a user to a group", status_code=201)
        add("/groups/{name}/members/{username}", self._remove_group_member, methods=["DELETE"], summary="Remove a user from a group")

        add("/cron",                       self._list_cron,        methods=["GET"],    summary="List all cron entries with ff_managed flag")
        add("/cron/{name}",                self._set_cron,         methods=["POST"],   summary="Create or update a cron entry",         status_code=201)
        add("/cron/{name}",                self._delete_cron,      methods=["DELETE"], summary="Remove a cron entry")
        add("/cron/{name}/import",         self._import_cron,      methods=["POST"],   summary="Import an existing system cron entry into FF management", status_code=201)

        add("/packages",                   self._list_packages,    methods=["GET"],    summary="List managed packages")
        add("/packages/search",            self._search_packages,  methods=["GET"],    summary="Search available packages")
        add("/packages/upgrade-system",    self._upgrade_system,   methods=["POST"],   summary="Run a full unattended system upgrade and email the output")
        add("/packages/{name}",            self._install_package,  methods=["POST"],   summary="Install or ensure a package",           status_code=201)
        add("/packages/{name}",            self._update_package,   methods=["PUT"],    summary="Update a package to latest")
        add("/packages/{name}",            self._remove_package,   methods=["DELETE"], summary="Remove a package")
        add("/packages/{name}/import",     self._import_package,   methods=["POST"],   summary="Import an installed package into FF management", status_code=201)

        add("/repos",                      self._list_repos,       methods=["GET"],    summary="List all repos with ff_managed flag")
        add("/repos/import",               self._import_repo,      methods=["POST"],   summary="Import an existing system repo into FF management", status_code=201)
        add("/repos/{name}",               self._add_repo,         methods=["POST"],   summary="Add or update a package repository",    status_code=201)
        add("/repos/{name}",               self._remove_repo,      methods=["DELETE"], summary="Remove a package repository")

    # ── status ─────────────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "hostname": socket.gethostname(),
            "package_manager": self._pkg_mgr.platform,
            "managed": {
                "services": len(self._state["services"]),
                "sysctl":   len(self._state["sysctl"]),
                "users":    len(self._state["users"]),
                "groups":   len(self._state["groups"]),
                "cron":     len(self._state["cron"]),
                "packages": len(self._state["packages"]),
                "repos":    len(self._state["repos"]),
            },
            "pending_changes": self._state_file.pending_changes,
        }

    def _list_bg_tasks(self, task_id: Optional[str] = None) -> dict:
        if task_id is not None:
            task = self._bg_tasks.get(task_id)
            if task is None:
                raise HTTPException(404, f"Task {task_id!r} not found")
            return {"tasks": [task]}
        return {"tasks": list(self._bg_tasks.values())}

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

    def _read_system_services(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        init_system = self._detect_init_system()

        if init_system == "systemd":
            try:
                proc = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--all",
                     "--no-pager", "--plain", "--no-legend"],
                    capture_output=True, text=True,
                )
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    name = parts[0].removesuffix(".service")
                    result[name] = {
                        "running": parts[2] == "active" and parts[3] == "running",
                        "enabled": False,
                    }
            except OSError:
                pass

            try:
                proc = subprocess.run(
                    ["systemctl", "list-unit-files", "--type=service",
                     "--no-pager", "--no-legend"],
                    capture_output=True, text=True,
                )
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    name = parts[0].removesuffix(".service")
                    enabled = parts[1] in ("enabled", "static", "generated")
                    if name in result:
                        result[name]["enabled"] = enabled
                    else:
                        result[name] = {"running": False, "enabled": enabled}
            except OSError:
                pass

        elif init_system == "upstart":
            try:
                proc = subprocess.run(["initctl", "list"], capture_output=True, text=True)
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if not parts:
                        continue
                    result[parts[0]] = {"running": "running" in line, "enabled": True}
            except OSError:
                pass

        else:  # sysvinit
            try:
                for f in sorted(Path("/etc/init.d").iterdir()):
                    if f.is_file() and not f.name.startswith(".") and f.name not in ("README", "skeleton"):
                        result[f.name] = {"running": False, "enabled": True}
            except OSError:
                pass

        return result

    def _list_services(self) -> dict:
        managed = self._state["services"]
        result: dict[str, Any] = {
            name: {**attrs, "ff_managed": False}
            for name, attrs in self._read_system_services().items()
        }
        for name, attrs in managed.items():
            if name in result:
                result[name] = {**result[name], **attrs, "ff_managed": True}
            else:
                result[name] = {**attrs, "ff_managed": True}
        return {"services": result}

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

    def _import_service(self, service: str) -> dict:
        system = self._read_system_services()
        if service not in system:
            raise HTTPException(404, f"Service {service!r} not found on system")
        state = {"running": system[service]["running"], "enabled": system[service]["enabled"]}
        self._state["services"][service] = state
        self._save_state()
        self._emit("host.service.changed", {"service": service, **state})
        return {"service": service, **state, "ff_managed": True}

    # ── sysctl ─────────────────────────────────────────────────────────────────

    def _list_sysctl(self) -> dict:
        managed = self._state["sysctl"]
        result: dict[str, Any] = {}
        sysctl_bin = shutil.which("sysctl") or "/usr/sbin/sysctl"
        try:
            proc = subprocess.run([sysctl_bin, "-a"], capture_output=True, text=True)
            for line in proc.stdout.splitlines():
                if " = " in line:
                    key, value = line.split(" = ", 1)
                    result[key.strip()] = {"value": value.strip(), "ff_managed": False}
        except OSError:
            pass
        for key, attrs in managed.items():
            if key in result:
                result[key] = {**result[key], **attrs, "ff_managed": True}
            else:
                result[key] = {**attrs, "ff_managed": True}
        return {"sysctl": result}

    def _list_all_sysctl(self) -> dict:
        sysctl_bin = shutil.which("sysctl") or "/usr/sbin/sysctl"
        proc = subprocess.run([sysctl_bin, "-a"], capture_output=True, text=True)
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

    def _import_sysctl(self, key: str) -> dict:
        sysctl_bin = shutil.which("sysctl") or "/usr/sbin/sysctl"
        try:
            proc = subprocess.run([sysctl_bin, "-n", key], capture_output=True, text=True)
        except OSError:
            raise HTTPException(503, "sysctl binary not available")
        if proc.returncode != 0:
            raise HTTPException(404, f"Sysctl key {key!r} not found on system")
        state = {"value": proc.stdout.strip(), "persist": True}
        self._state["sysctl"][key] = state
        self._save_state()
        self._emit("host.sysctl.changed", {"key": key, **state})
        return {"key": key, **state, "ff_managed": True}

    # ── users ──────────────────────────────────────────────────────────────────

    def _list_users(self) -> dict:
        managed = self._state["users"]
        result: dict[str, Any] = {
            entry.pw_name: {
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "shell": entry.pw_shell,
                "home_dir": entry.pw_dir,
                "comment": entry.pw_gecos,
                "ff_managed": False,
            }
            for entry in pwd.getpwall()
        }
        for name, attrs in managed.items():
            if name in result:
                result[name] = {**result[name], **attrs, "ff_managed": True}
            else:
                result[name] = {**attrs, "ff_managed": True}
        return {"users": result}

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

    def _import_user(self, name: str) -> dict:
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            raise HTTPException(404, f"User {name!r} not found on system")
        state: dict[str, Any] = {
            "shell": entry.pw_shell,
            "home_dir": entry.pw_dir,
            "system": entry.pw_uid < 1000,
            "comment": entry.pw_gecos or None,
        }
        self._state["users"][name] = state
        self._save_state()
        self._emit("host.user.changed", {"user": name, **state})
        return {"user": name, **state, "ff_managed": True}

    # ── groups ─────────────────────────────────────────────────────────────────

    def _list_groups(self) -> dict:
        managed = self._state["groups"]
        result: dict[str, Any] = {
            entry.gr_name: {
                "gid": entry.gr_gid,
                "members": entry.gr_mem,
                "ff_managed": False,
            }
            for entry in grp.getgrall()
        }
        for name, attrs in managed.items():
            if name in result:
                result[name] = {**result[name], **attrs, "ff_managed": True}
            else:
                result[name] = {**attrs, "ff_managed": True}
        return {"groups": result}

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

    def _import_group(self, name: str) -> dict:
        try:
            entry = grp.getgrnam(name)
        except KeyError:
            raise HTTPException(404, f"Group {name!r} not found on system")
        state: dict[str, Any] = {
            "system": entry.gr_gid < 1000,
            "gid": entry.gr_gid,
            "members": list(entry.gr_mem),
        }
        self._state["groups"][name] = state
        self._save_state()
        self._emit("host.group.changed", {"group": name, **state})
        return {"group": name, **state, "ff_managed": True}

    def _list_group_members(self, name: str) -> dict:
        try:
            entry = grp.getgrnam(name)
        except KeyError:
            raise HTTPException(404, f"Group {name!r} not found on system")
        ff_members = set(self._state.get("groups", {}).get(name, {}).get("members", []))
        all_members = set(entry.gr_mem) | ff_members
        return {
            "group": name,
            "members": [
                {"username": m, "ff_managed": m in ff_members}
                for m in sorted(all_members)
            ],
        }

    def _add_group_member(self, name: str, body: GroupMemberBody) -> dict:
        if name not in self._state["groups"]:
            raise HTTPException(404, f"Group {name!r} is not managed by FF — import it first")
        self._pyinfra_run(
            server_ops.shell,
            name=f"Add {body.username} to group {name}",
            commands=[f"gpasswd -a {shlex.quote(body.username)} {shlex.quote(name)}"],
        )
        members: list[str] = self._state["groups"][name].setdefault("members", [])
        if body.username not in members:
            members.append(body.username)
        self._save_state()
        self._emit("host.group.changed", {"group": name, "members": members})
        return {"group": name, "username": body.username, "ff_managed": True}

    def _remove_group_member(self, name: str, username: str) -> dict:
        if name not in self._state["groups"]:
            raise HTTPException(404, f"Group {name!r} is not managed by FF")
        members: list[str] = self._state["groups"][name].get("members", [])
        if username not in members:
            raise HTTPException(404, f"{username!r} is not an FF-managed member of {name!r}")
        self._pyinfra_run(
            server_ops.shell,
            name=f"Remove {username} from group {name}",
            commands=[f"gpasswd -d {shlex.quote(username)} {shlex.quote(name)}"],
        )
        members.remove(username)
        self._save_state()
        self._emit("host.group.changed", {"group": name, "members": members})
        return {"group": name, "username": username, "deleted": True}

    # ── cron ───────────────────────────────────────────────────────────────────

    def _read_system_cron(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        sources: list[tuple[Path, bool, str]] = []

        p = Path("/etc/crontab")
        if p.exists():
            sources.append((p, True, "system"))

        cron_d = Path("/etc/cron.d")
        if cron_d.is_dir():
            try:
                for f in sorted(cron_d.iterdir()):
                    if f.is_file() and not f.name.startswith("."):
                        sources.append((f, True, f"cron.d/{f.name}"))
            except OSError:
                pass

        # TODO: run as root so we can read /var/spool/cron/crontabs
        spool = Path("/var/spool/cron/crontabs")
        if spool.is_dir():
            try:
                for f in sorted(spool.iterdir()):
                    if f.is_file():
                        sources.append((f, False, f"user/{f.name}"))
            except OSError:
                pass

        for filepath, has_user, prefix in sources:
            try:
                lines = filepath.read_text().splitlines()
            except OSError:
                continue
            idx = 0
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if not parts or "=" in parts[0] or parts[0].startswith("@"):
                    continue
                if len(parts) < (6 if has_user else 5):
                    continue
                minute, hour, dom, month, dow = parts[0], parts[1], parts[2], parts[3], parts[4]
                if has_user:
                    user = parts[5]
                    command = " ".join(parts[6:])
                else:
                    user = filepath.name
                    command = " ".join(parts[5:])
                result[f"{prefix}/{idx}"] = {
                    "command": command,
                    "minute": minute,
                    "hour": hour,
                    "day_of_month": dom,
                    "month": month,
                    "day_of_week": dow,
                    "user": user,
                    "source": str(filepath),
                }
                idx += 1

        for period in ("hourly", "daily", "weekly", "monthly"):
            d = Path(f"/etc/cron.{period}")
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    if f.is_file() and not f.name.startswith("."):
                        result[f"cron.{period}/{f.name}"] = {
                            "command": str(f),
                            "minute": None,
                            "hour": None,
                            "day_of_month": None,
                            "month": None,
                            "day_of_week": None,
                            "user": "root",
                            "source": str(d),
                            "period": period,
                        }

        return result

    def _list_cron(self) -> dict:
        managed = self._state["cron"]
        result: dict[str, Any] = {
            key: {**attrs, "ff_managed": False}
            for key, attrs in self._read_system_cron().items()
        }
        for name, attrs in managed.items():
            if name in result:
                result[name] = {**result[name], **attrs, "ff_managed": True}
            else:
                result[name] = {**attrs, "ff_managed": True}
        return {"cron": result}

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

    def _import_cron(self, name: str, body: CronImportBody) -> dict:
        system = self._read_system_cron()
        if body.source_key not in system:
            raise HTTPException(404, f"Cron entry {body.source_key!r} not found")
        entry = system[body.source_key]
        state: dict[str, Any] = {
            "command": entry["command"],
            "minute":       entry.get("minute")       or "*",
            "hour":         entry.get("hour")         or "*",
            "day_of_month": entry.get("day_of_month") or "*",
            "month":        entry.get("month")        or "*",
            "day_of_week":  entry.get("day_of_week")  or "*",
            "user":         entry.get("user")         or "root",
        }
        self._state["cron"][name] = state
        self._save_state()
        self._emit("host.cron.changed", {"name": name, **state})
        return {"name": name, **state, "ff_managed": True}

    # ── packages ───────────────────────────────────────────────────────────────

    def _list_packages(self, mode: str = "installed") -> dict:
        if mode not in ("installed", "available", "managed"):
            raise HTTPException(400, "mode must be one of: installed, available, managed")
        managed = self._state["packages"]
        system = self._pkg_mgr.list_system_packages()
        if mode == "available":
            pool: dict[str, Any] = {
                name: {"version": system[name]["version"] if name in system else None, "installed": name in system}
                for name in self._pkg_mgr.list_available_packages()
            }
        elif mode == "installed":
            pool = {name: {"version": info["version"], "installed": True} for name, info in system.items()}
        elif mode == "managed":
            pool = {
                name: {"version": system[name]["version"] if name in system else None, "installed": name in system}
                for name in managed
            }
        else:
            pool = {}
        result: dict[str, Any] = {}
        for name, base in pool.items():
            result[name] = {**base, "ff_managed": name in managed}
            if name in managed:
                result[name].update(managed[name])
        return {"packages": result, "platform": self._pkg_mgr.platform, "mode": mode}

    def _search_packages(self, q: str) -> dict:
        self._pkg_mgr.assert_supported()
        return {"query": q, "results": self._pkg_mgr.search_packages(q), "platform": self._pkg_mgr.platform}

    def _install_package(self, name: str, body: PackageBody) -> dict:
        self._pkg_mgr.assert_supported()
        self._pkg_mgr.install(name, body)
        self._state["packages"][name] = body.model_dump()
        self._save_state()
        self._emit("host.package.changed", {"package": name, **body.model_dump(), "platform": self._pkg_mgr.platform})
        return {"package": name, **body.model_dump(), "platform": self._pkg_mgr.platform}

    def _update_package(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        if name not in self._state["packages"]:
            raise HTTPException(404, f"Package {name!r} not managed")
        self._pkg_mgr.update(name)
        self._state["packages"][name]["latest"] = True
        self._save_state()
        self._emit("host.package.updated", {"package": name, "platform": self._pkg_mgr.platform})
        return {"package": name, "updated": True, "platform": self._pkg_mgr.platform}

    def _remove_package(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        if name not in self._state["packages"]:
            raise HTTPException(404, f"Package {name!r} not managed")
        self._pkg_mgr.remove(name)
        del self._state["packages"][name]
        self._save_state()
        self._emit("host.package.deleted", {"package": name, "platform": self._pkg_mgr.platform})
        return {"deleted": name}

    def _import_package(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        system = self._pkg_mgr.list_system_packages()
        if name not in system:
            raise HTTPException(404, f"Package {name!r} is not installed on this system")
        state = {"present": True, "latest": False}
        self._state["packages"][name] = state
        self._save_state()
        self._emit("host.package.changed", {"package": name, **state, "platform": self._pkg_mgr.platform})
        return {"package": name, **state, "platform": self._pkg_mgr.platform, "ff_managed": True}

    def _upgrade_system(self, body: UpgradeBody, background_tasks: BackgroundTasks) -> dict:
        self._pkg_mgr.assert_supported()
        task_id = str(uuid.uuid4())
        self._bg_tasks[task_id] = {
            "id": task_id,
            "type": "upgrade_system",
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "error": None,
            "email": body.email,
        }
        background_tasks.add_task(self._run_upgrade_task, task_id, body.email)
        self._emit("host.package.upgrade-system.started", {"task_id": task_id, "email": body.email, "platform": self._pkg_mgr.platform})
        return {"status": "started", "task_id": task_id, "email": body.email}

    def _run_upgrade_task(self, task_id: str, email: str) -> None:
        try:
            result = self._pkg_mgr.upgrade_system()
        except Exception as exc:
            result = {"platform": self._pkg_mgr.platform, "returncode": -1, "stdout": "", "stderr": str(exc)}
        ok = result["returncode"] == 0
        self._bg_tasks[task_id].update({
            "status": "done" if ok else "failed",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "error": result["stderr"] if not ok else None,
        })
        hostname = socket.gethostname()
        subject = (
            f"[FastFirewall] System upgrade {'succeeded' if ok else 'FAILED'} on {hostname}"
        )
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        body_text = (
            f"Host:       {hostname}\n"
            f"Time:       {ts}\n"
            f"Platform:   {result['platform']}\n"
            f"Exit code:  {result['returncode']}\n"
            f"\n--- stdout ---\n{result['stdout'] or '(empty)'}\n"
            f"\n--- stderr ---\n{result['stderr'] or '(empty)'}\n"
        )
        self._emit("smtp.send", {"to": email, "subject": subject, "body": body_text})
        self._emit("host.package.upgrade-system.done", {
            "platform": result["platform"],
            "returncode": result["returncode"],
            "email": email,
        })

    # ── repos ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _repo_id(sys_key: str) -> str:
        return hashlib.sha256(sys_key.encode()).hexdigest()[:8]

    def _list_repos(self) -> dict:
        system = self._pkg_mgr.list_system_repos()
        managed = self._state["repos"]

        result: dict[str, Any] = {}
        for sys_key, attrs in system.items():
            result[sys_key] = {**attrs, "id": self._repo_id(sys_key), "ff_managed": False}
        for name, attrs in managed.items():
            sys_key = self._pkg_mgr.repo_system_id(name, attrs)
            if sys_key is not None and sys_key in result:
                result[sys_key] = {**result[sys_key], **attrs, "id": self._repo_id(sys_key), "name": name, "ff_managed": True}
            else:
                result[name] = {**attrs, "id": self._repo_id(name), "name": name, "ff_managed": True}

        return {"repos": result, "platform": self._pkg_mgr.platform}

    def _add_repo(self, name: str, body: RepoBody) -> dict:
        self._pkg_mgr.assert_supported()
        self._pkg_mgr.apply_repo(name, body)
        self._state["repos"][name] = body.model_dump()
        self._save_state()
        self._emit("host.repo.changed", {"repo": name, **body.model_dump(), "platform": self._pkg_mgr.platform})
        return {"repo": name, **body.model_dump(), "platform": self._pkg_mgr.platform}

    def _remove_repo(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        if name not in self._state["repos"]:
            raise HTTPException(404, f"Repo {name!r} not managed")
        stored = self._state["repos"][name]
        self._pkg_mgr.apply_repo(name, RepoBody(**{**stored, "present": False}))
        del self._state["repos"][name]
        self._save_state()
        self._emit("host.repo.deleted", {"repo": name, "platform": self._pkg_mgr.platform})
        return {"deleted": name}

    def _import_repo(self, body: RepoImportBody) -> dict:
        self._pkg_mgr.assert_supported()
        system = self._pkg_mgr.list_system_repos()
        # Resolve by hashing each system key at request time — no stored mapping needed.
        match = next((k for k in system if self._repo_id(k) == body.id), None)
        if match is None:
            raise HTTPException(404, f"Repo with id {body.id!r} not found on system")
        state = system[match]
        self._state["repos"][body.alias] = state
        self._save_state()
        self._emit("host.repo.changed", {"repo": body.alias, **state, "platform": self._pkg_mgr.platform})
        return {"repo": body.alias, **state, "platform": self._pkg_mgr.platform, "ff_managed": True}
