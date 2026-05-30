"""
Host Plugin
───────────
Manages basic host system configuration via pyinfra server.* operations.
Routes mount at /v1/host/.

Events emitted:
  host.hostname.changed  – payload: {hostname}
  host.sysctl.changed    – payload: {key, value, persist}
  host.sysctl.deleted    – payload: {key}
  host.user.changed      – payload: {user, shell, home_dir, system, comment}
  host.user.deleted      – payload: {user}
  host.group.changed     – payload: {group, system, gid}
  host.group.deleted     – payload: {group}
  host.cron.changed      – payload: {name, command, minute, hour, ...}
  host.cron.deleted      – payload: {name}
  host.kernmod.changed   – payload: {module, persist}
  host.kernmod.deleted   – payload: {module}

Events consumed:
  host.sysctl.set        – payload: {key, value, persist=True}
                           Any plugin may emit this to import, set, and persist
                           a sysctl variable under FF management.
"""
from __future__ import annotations

import configparser
import grp
import io
import json
import os
import pwd
import re
import shlex
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator
from pyinfra.operations import files as files_ops
from pyinfra.operations import server as server_ops
from pyinfra.operations import systemd as systemd_ops

from infra import pyinfra_run_batch
from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, MacroProviderPlugin, Service
from plugin_system.core.decorators import on
from plugin_system.core.events import Event, bus

# ── Pydantic schemas ───────────────────────────────────────────────────────────

class HostnameBody(BaseModel):
    hostname: str = Field(max_length=253)


class SysctlBody(BaseModel):
    value: str = Field(max_length=64)
    persist: bool = True


class UserBody(BaseModel):
    shell: str = Field(default="/bin/bash", max_length=255)
    home_dir: Optional[str] = Field(default=None, max_length=4096)
    system: bool = False
    comment: Optional[str] = Field(default=None, max_length=255)


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
    command: str = Field(max_length=4096)
    minute: str = Field(default="*", max_length=64)
    hour: str = Field(default="*", max_length=64)
    day_of_month: str = Field(default="*", max_length=64)
    month: str = Field(default="*", max_length=64)
    day_of_week: str = Field(default="*", max_length=64)
    user: str = Field(default="root", max_length=32)


class CronImportBody(BaseModel):
    source_key: str = Field(max_length=200)


class DomainnameBody(BaseModel):
    domainname: str = Field(max_length=253)


class KernmodBody(BaseModel):
    persist: bool = True


# ── Plugin ─────────────────────────────────────────────────────────────────────

class HostPlugin(PluginBase, ApiRouterPlugin, MacroProviderPlugin):
    services = [Service.HOST, Service.SYSCTL, Service.CRON, Service.USERS, Service.GROUPS]

    _EMPTY_STATE: dict[str, Any] = {
        "sysctl": {},
        "users": {},
        "groups": {},
        "cron": {},
        "kernmod": {},
    }

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "host_state.json", self.logger,
            mutation_model="immediate",
        )
        if self.config.get("ignore_state_on_boot", False):
            self._state: dict[str, Any] = {k: {} for k in self._EMPTY_STATE}
        else:
            self._state = self._load_state()
            self._apply_state()
        self._register_routes()
        self.add_macro_namespace("host", self._resolve_host_macro)
        init_cfg: dict[str, Any] = self.config.get("init") or {}
        if init_cfg.get("enable_init_script", False):
            self._run_init_script(init_cfg)

    def teardown(self) -> None:
        self._save_state()

    # ── persistence ────────────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, Any]:
        system_domain = self._get_system_domain()
        default: dict[str, Any] = {}
        if system_domain:
            default["domainname"] = system_domain
        desired = self._state_file.load_desired(default=default)
        state = {k: {} for k in self._EMPTY_STATE}
        state.update({k: v for k, v in desired.items() if k in self._EMPTY_STATE})
        state["domainname"] = desired.get("domainname")
        return state

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def _apply_state(self) -> None:
        if not any(self._state.get(k) for k in self._EMPTY_STATE):
            return

        applied: dict[str, Any] = {k: {} for k in self._EMPTY_STATE}
        applied["domainname"] = self._state.get("domainname")

        tracked: list[tuple[str, str, Any]] = []
        batch_ops: list[tuple[Any, dict[str, Any]]] = []

        for sysctl_key, v in self._state.get("sysctl", {}).items():
            tracked.append(("sysctl", sysctl_key, v))
            batch_ops.append((server_ops.sysctl, {
                "name": f"Restore sysctl {sysctl_key}",
                "key": sysctl_key,
                "value": v["value"],
                "persist": v["persist"],
                "_sudo": True,
            }))

        for user_name, v in self._state.get("users", {}).items():
            user_kw: dict[str, Any] = {
                "name": f"Restore user {user_name}",
                "user": user_name,
                "shell": v["shell"],
                "system": v["system"],
                "_sudo": True,
            }
            if v.get("home_dir"):
                user_kw["home"] = v["home_dir"]
            if v.get("comment"):
                user_kw["comment"] = v["comment"]
            tracked.append(("users", user_name, v))
            batch_ops.append((server_ops.user, user_kw))

        for group_name, v in self._state.get("groups", {}).items():
            group_kw: dict[str, Any] = {
                "name": f"Restore group {group_name}",
                "group": group_name,
                "system": v["system"],
                "_sudo": True,
            }
            if v.get("gid") is not None:
                group_kw["gid"] = v["gid"]
            tracked.append(("groups", group_name, v))
            batch_ops.append((server_ops.group, group_kw))

        for cron_name, v in self._state.get("cron", {}).items():
            tracked.append(("cron", cron_name, v))
            batch_ops.append((server_ops.crontab, {
                "name": f"Restore cron {cron_name}",
                "command": v["command"],
                "minute": v["minute"],
                "hour": v["hour"],
                "day_of_month": v["day_of_month"],
                "month": v["month"],
                "day_of_week": v["day_of_week"],
                "user": v["user"],
                "_sudo": True,
            }))

        for mod_name, v in self._state.get("kernmod", {}).items():
            tracked.append(("kernmod", mod_name, v))
            batch_ops.append((server_ops.modprobe, {
                "name": f"Restore kernel module {mod_name}",
                "module": mod_name,
                "present": True,
                "_sudo": True,
            }))

        if batch_ops:
            results = self._pyinfra_run_many(batch_ops)
            for (rtype, rkey, rval), (success, err) in zip(tracked, results):
                if success:
                    applied[rtype][rkey] = rval
                else:
                    self.logger.warning(
                        "Boot-time restore failed for %s %r: %s", rtype, rkey, err
                    )

        self._state_file.commit(applied)
        self.logger.info("Re-applied host state on boot")

    # ── pyinfra helper ─────────────────────────────────────────────────────────

    def _pyinfra_run(self, op: Any, **kwargs: Any) -> None:
        norm_kwargs = {
            k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
            for k, v in kwargs.items()
        }
        success, err = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])[0]
        if not success:
            raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")

    def _pyinfra_run_many(
        self, ops: list[tuple[Any, dict[str, Any]]]
    ) -> list[tuple[bool, str | None]]:
        """Run a batch of pyinfra operations in a single worker subprocess."""
        batch = [
            (op.__module__, op.__name__, {
                k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
                for k, v in kw.items()
            })
            for op, kw in ops
        ]
        return pyinfra_run_batch(batch)

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
        bus.emit(Event(event_name, payload=payload))

    # ── event handlers ─────────────────────────────────────────────────────────

    @on("host.sysctl.set")
    def _handle_sysctl_set(self, event: Event) -> None:
        key = event.payload.get("key", None)
        value = event.payload.get("value", None)
        persist = bool(event.payload.get("persist", True))
        if any([not v for v in [key, value]]):
            self.logger.warning(
                "host.sysctl.set event missing 'key' or 'value': %r", event.payload
            )
            return
        try:
            self._pyinfra_run(
                server_ops.sysctl,
                name=f"Set sysctl {key}={value} (via event)",
                key=key,
                value=value,
                persist=persist,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to set sysctl %r via event", key, exc_info=True)
            return
        self._state["sysctl"][key] = {"value": value, "persist": persist}
        self._save_state()
        self._emit("host.sysctl.changed", {"key": key, "value": value, "persist": persist})

    # ── route registration ─────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",              self._status,           methods=["GET"],    summary="Plugin status and managed-resource counts")

        add("/hostname",            self._get_hostname,     methods=["GET"],    summary="Get current hostname")
        add("/hostname",            self._set_hostname,     methods=["PUT"],    summary="Set system hostname")

        add("/domainname",          self._get_domainname,   methods=["GET"],    summary="Get managed domain name")
        add("/domainname",          self._set_domainname,   methods=["PUT"],    summary="Set system domain name")
        add("/domainname",          self._delete_domainname, methods=["DELETE"], summary="Remove managed domain name")

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

        add("/kernmod",                    self._list_kernmod,     methods=["GET"],    summary="List all kernel modules with ff_managed flag")
        add("/kernmod/{name}",             self._set_kernmod,      methods=["PUT"],    summary="Load and manage a kernel module")
        add("/kernmod/{name}",             self._delete_kernmod,   methods=["DELETE"], summary="Stop managing a kernel module")
        add("/kernmod/{name}/import",      self._import_kernmod,   methods=["POST"],   summary="Import an already-loaded kernel module into FF management", status_code=201)

    # ── status ─────────────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "hostname": socket.gethostname(),
            "domainname": self._state.get("domainname"),
            "fqdn": self._resolve_host_macro("fqdn"),
            "managed": {
                "sysctl":   len(self._state["sysctl"]),
                "users":    len(self._state["users"]),
                "groups":   len(self._state["groups"]),
                "cron":     len(self._state["cron"]),
                "kernmod":  len(self._state["kernmod"]),
            },
            "pending_changes": self._state_file.pending_changes,
        }

    # ── hostname ───────────────────────────────────────────────────────────────

    def _get_hostname(self) -> dict:
        return {"hostname": socket.gethostname()}

    def _set_hostname(self, body: HostnameBody) -> dict:
        try:
            self._pyinfra_run(
                server_ops.hostname,
                name=f"Set hostname to {body.hostname}",
                hostname=body.hostname,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to set hostname", exc_info=True)
            raise HTTPException(500, "Failed to set hostname; check server logs")
        self._emit("host.hostname.changed", {"hostname": body.hostname})
        return {"hostname": body.hostname}

    # ── domainname ─────────────────────────────────────────────────────────────

    @staticmethod
    def _get_system_domain() -> str | None:
        fqdn = socket.getfqdn()
        hostname = socket.gethostname()
        if fqdn != hostname and fqdn.startswith(hostname + "."):
            return fqdn[len(hostname) + 1:]
        return None

    def macro_snapshot(self) -> dict[str, dict]:
        hostname = socket.gethostname()
        domain = self._state.get("domainname") or self._get_system_domain()
        entries: dict[str, Any] = {"hostname": hostname}
        if domain:
            entries["domainname"] = domain
        entries["fqdn"] = f"{hostname}.{domain}" if domain else hostname
        return {"host": entries}

    def _resolve_host_macro(self, *segments: str):
        if not segments:
            return None
        key = segments[0]
        if key == "hostname":
            return socket.gethostname()
        if key == "domainname":
            return self._state.get("domainname") or self._get_system_domain()
        if key == "fqdn":
            hostname = socket.gethostname()
            domain = self._state.get("domainname") or self._get_system_domain()
            return f"{hostname}.{domain}" if domain else hostname
        return None

    def _get_domainname(self) -> dict:
        return {
            "domainname": self._state.get("domainname"),
            "system_domain": self._get_system_domain(),
        }

    def _set_domainname(self, body: DomainnameBody) -> dict:
        hostname = socket.gethostname()
        fqdn = f"{hostname}.{body.domainname}"
        try:
            self._pyinfra_run(
                server_ops.hostname,
                name=f"Set FQDN to {fqdn}",
                hostname=fqdn,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to set domain name", exc_info=True)
            raise HTTPException(500, "Failed to set domain name; check server logs")
        self._state["domainname"] = body.domainname
        self._save_state()
        self._emit("host.domainname.changed", {"domainname": body.domainname, "fqdn": fqdn})
        return {"domainname": body.domainname, "fqdn": fqdn}

    def _delete_domainname(self) -> dict:
        if not self._state.get("domainname"):
            raise HTTPException(404, "No managed domain name set")
        removed = self._state.pop("domainname")
        self._save_state()
        self._emit("host.domainname.deleted", {"domainname": removed})
        return {"deleted": removed}

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
        try:
            self._pyinfra_run(
                server_ops.sysctl,
                name=f"Set sysctl {key}={body.value}",
                key=key,
                value=body.value,
                persist=body.persist,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to set sysctl %s", key, exc_info=True)
            raise HTTPException(500, "Failed to set sysctl parameter; check server logs")
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
            "_sudo": True,
        }
        if body.home_dir:
            kwargs["home"] = body.home_dir
        if body.comment:
            kwargs["comment"] = body.comment
        try:
            self._pyinfra_run(server_ops.user, **kwargs)
        except RuntimeError:
            self.logger.error("Failed to manage user %s", name, exc_info=True)
            raise HTTPException(500, "Failed to manage user; check server logs")
        self._state["users"][name] = body.model_dump()
        self._save_state()
        self._emit("host.user.changed", {"user": name, **body.model_dump()})
        return {"user": name, **body.model_dump()}

    def _delete_user(self, name: str) -> dict:
        if name not in self._state["users"]:
            raise HTTPException(404, f"User {name!r} not managed")
        try:
            self._pyinfra_run(
                server_ops.user,
                name=f"Remove user {name}",
                user=name,
                present=False,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to delete user %s", name, exc_info=True)
            raise HTTPException(500, "Failed to delete user; check server logs")
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
            "_sudo": True,
        }
        if body.gid is not None:
            kwargs["gid"] = body.gid
        try:
            self._pyinfra_run(server_ops.group, **kwargs)
        except RuntimeError:
            self.logger.error("Failed to manage group %s", name, exc_info=True)
            raise HTTPException(500, "Failed to manage group; check server logs")
        self._state["groups"][name] = body.model_dump()
        self._save_state()
        self._emit("host.group.changed", {"group": name, **body.model_dump()})
        return {"group": name, **body.model_dump()}

    def _delete_group(self, name: str) -> dict:
        if name not in self._state["groups"]:
            raise HTTPException(404, f"Group {name!r} not managed")
        try:
            self._pyinfra_run(
                server_ops.group,
                name=f"Remove group {name}",
                group=name,
                present=False,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to delete group %s", name, exc_info=True)
            raise HTTPException(500, "Failed to delete group; check server logs")
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
        try:
            self._pyinfra_run(
                server_ops.shell,
                name=f"Add {body.username} to group {name}",
                commands=[f"gpasswd -a {shlex.quote(body.username)} {shlex.quote(name)}"],
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to add %s to group %s", body.username, name, exc_info=True)
            raise HTTPException(500, "Failed to add group member; check server logs")
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
        try:
            self._pyinfra_run(
                server_ops.shell,
                name=f"Remove {username} from group {name}",
                commands=[f"gpasswd -d {shlex.quote(username)} {shlex.quote(name)}"],
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to remove %s from group %s", username, name, exc_info=True)
            raise HTTPException(500, "Failed to remove group member; check server logs")
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
        try:
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
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to manage cron %s", name, exc_info=True)
            raise HTTPException(500, "Failed to manage cron entry; check server logs")
        self._state["cron"][name] = body.model_dump()
        self._save_state()
        self._emit("host.cron.changed", {"name": name, **body.model_dump()})
        return {"name": name, **body.model_dump()}

    def _delete_cron(self, name: str) -> dict:
        if name not in self._state["cron"]:
            raise HTTPException(404, f"Cron entry {name!r} not managed")
        entry = self._state["cron"][name]
        try:
            self._pyinfra_run(
                server_ops.crontab,
                name=f"Remove cron {name}",
                command=entry["command"],
                present=False,
                user=entry["user"],
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to delete cron %s", name, exc_info=True)
            raise HTTPException(500, "Failed to delete cron entry; check server logs")
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

    # ── kernmod ────────────────────────────────────────────────────────────────

    def _list_kernmod(self) -> dict:
        managed = self._state["kernmod"]
        result: dict[str, Any] = {}
        try:
            with open("/proc/modules") as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        result[parts[0]] = {"loaded": True, "ff_managed": False}
        except OSError:
            pass
        for name, attrs in managed.items():
            if name in result:
                result[name] = {**result[name], **attrs, "ff_managed": True}
            else:
                result[name] = {**attrs, "ff_managed": True}
        return {"kernmod": result}

    def _set_kernmod(self, name: str, body: KernmodBody) -> dict:
        try:
            self._pyinfra_run(
                server_ops.modprobe,
                name=f"Load kernel module {name}",
                module=name,
                present=True,
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to load kernel module %s", name, exc_info=True)
            raise HTTPException(500, "Failed to load kernel module; check server logs")
        if body.persist:
            try:
                self._pyinfra_run(
                    files_ops.put,
                    name=f"Persist kernel module {name}",
                    src=io.StringIO(f"{name}\n"),
                    dest=f"/etc/modules-load.d/ff-{name}.conf",
                    mode="644",
                    _sudo=True,
                )
            except RuntimeError:
                self.logger.warning(
                    "Kernel module %s loaded but persist file write failed", name, exc_info=True
                )
        self._state["kernmod"][name] = body.model_dump()
        self._save_state()
        self._emit("host.kernmod.changed", {"module": name, **body.model_dump()})
        return {"module": name, **body.model_dump()}

    def _delete_kernmod(self, name: str) -> dict:
        if name not in self._state["kernmod"]:
            raise HTTPException(404, f"Kernel module {name!r} not managed")
        del self._state["kernmod"][name]
        self._save_state()
        self._emit("host.kernmod.deleted", {"module": name})
        return {"deleted": name}

    def _find_module_config_files(self, name: str) -> list[str]:
        """Return paths of config files (outside our ff file) that contain the module as a standalone line."""
        ff_path = Path(f"/etc/modules-load.d/ff-{name}.conf").resolve()
        candidates: list[Path] = []
        if Path("/etc/modules").is_file():
            candidates.append(Path("/etc/modules"))
        modules_load_d = Path("/etc/modules-load.d")
        if modules_load_d.is_dir():
            try:
                candidates.extend(
                    f for f in modules_load_d.iterdir()
                    if f.suffix == ".conf" and f.is_file()
                )
            except OSError:
                pass
        found: list[str] = []
        for candidate in candidates:
            try:
                if candidate.resolve() == ff_path:
                    continue
                if any(line.strip() == name for line in candidate.read_text().splitlines()):
                    found.append(str(candidate))
            except OSError:
                pass
        return found

    def _import_kernmod(self, name: str) -> dict:
        try:
            with open("/proc/modules") as f:
                loaded = {line.split()[0] for line in f if line.split()}
        except OSError:
            raise HTTPException(503, "Unable to read /proc/modules")
        if name not in loaded:
            raise HTTPException(404, f"Kernel module {name!r} is not currently loaded")

        old_files = self._find_module_config_files(name)

        # write the ff persist file before touching anything else
        try:
            self._pyinfra_run(
                files_ops.put,
                name=f"Persist kernel module {name}",
                src=io.StringIO(f"{name}\n"),
                dest=f"/etc/modules-load.d/ff-{name}.conf",
                mode="644",
                _sudo=True,
            )
        except RuntimeError:
            self.logger.error("Failed to write persist file for kernel module %s", name, exc_info=True)
            raise HTTPException(503, "Failed to write module persist file; check server logs")

        # now remove the module from any pre-existing non-ff locations
        for filepath in old_files:
            try:
                self._pyinfra_run(
                    server_ops.shell,
                    name=f"Remove {name} from {filepath}",
                    commands=[f"sed -i '/^{shlex.quote(name)}$/d' {shlex.quote(filepath)}"],
                    _sudo=True,
                )
            except RuntimeError:
                self.logger.error(
                    "Failed to remove old config for %s from %s", name, filepath, exc_info=True
                )
                raise HTTPException(503, "Failed to remove old module config; check server logs")

        state: dict[str, Any] = {"persist": True}
        self._state["kernmod"][name] = state
        self._save_state()
        self._emit("host.kernmod.changed", {"module": name, **state})
        return {"module": name, **state, "ff_managed": True}
