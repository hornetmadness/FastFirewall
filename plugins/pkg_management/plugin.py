"""
Package Management Plugin
─────────────────────────
Manages OS packages, repositories, and system services via pyinfra.
Routes mount at /v1/pkg_management/.

Events consumed:
  pkg_management.add.package  – payload: {name, present?, latest?}   install/ensure a package
  pkg_management.add.repo     – payload: {name, ...RepoBody fields}  add/update a repository
  pkg_management.add.service  – payload: {service, running?, enabled?} configure a service

Events emitted:
  pkg_management.service.changed              – payload: {service, running, enabled}
  pkg_management.service.deleted              – payload: {service}
  pkg_management.package.changed              – payload: {package, present, latest, platform}
  pkg_management.package.updated              – payload: {package, platform}
  pkg_management.package.deleted              – payload: {package, platform}
  pkg_management.repo.changed                 – payload: {repo, platform, ...body fields}
  pkg_management.repo.deleted                 – payload: {repo, platform}
  pkg_management.package.upgrade-system.started – payload: {task_id, email, platform}
  pkg_management.package.upgrade-system.done    – payload: {platform, returncode, email}
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from pyinfra.operations import server as server_ops

from infra import pyinfra_run_batch
from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service
from plugin_system.core.events import Event, bus
from ._pkg_manager import (
    PackageBody,
    PackageManager,
    RepoBody,
    detect_package_manager,
)

# ── Pydantic schemas ───────────────────────────────────────────────────────────

class ServiceBody(BaseModel):
    running: bool = True
    enabled: bool = True


class UpgradeBody(BaseModel):
    email: str = Field(max_length=254)


class RepoImportBody(BaseModel):
    id: str = Field(max_length=100)
    alias: str = Field(max_length=100)


# ── Plugin ─────────────────────────────────────────────────────────────────────

class PkgManagementPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.PKG_MANAGEMENT]

    _EMPTY_STATE: dict[str, Any] = {
        "services": {},
        "packages": {},
        "repos": {},
    }

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "pkg_management_state.json", self.logger,
            mutation_model="immediate", data_dir=self.data_dir,
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
        self._handler_add_package = self._on_add_package
        self._handler_add_repo    = self._on_add_repo
        self._handler_add_service = self._on_add_service
        bus.subscribe("pkg_management.add.package", self._handler_add_package)
        bus.subscribe("pkg_management.add.repo",    self._handler_add_repo)
        bus.subscribe("pkg_management.add.service", self._handler_add_service)

    def teardown(self) -> None:
        bus.unsubscribe("pkg_management.add.package", self._handler_add_package)
        bus.unsubscribe("pkg_management.add.repo",    self._handler_add_repo)
        bus.unsubscribe("pkg_management.add.service", self._handler_add_service)
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

        tracked: list[tuple[str, str, Any]] = []
        batch_ops: list[tuple[Any, dict[str, Any]]] = []

        for svc_name, v in self._state.get("services", {}).items():
            tracked.append(("services", svc_name, v))
            batch_ops.append((server_ops.service, {
                "name": f"Restore service {svc_name}",
                "service": svc_name,
                "running": v["running"],
                "enabled": v["enabled"],
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
        self.logger.info("Re-applied pkg_management state on boot")

    # ── pyinfra helpers ────────────────────────────────────────────────────────

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
        batch = [
            (op.__module__, op.__name__, {
                k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
                for k, v in kw.items()
            })
            for op, kw in ops
        ]
        return pyinfra_run_batch(batch)

    def _emit(self, event_name: str, payload: dict[str, Any]) -> None:
        bus.emit(Event(event_name, payload=payload))

    # ── event-driven API ───────────────────────────────────────────────────────

    def _on_add_package(self, event: Event) -> None:
        name = event.payload.get("name")
        if not name:
            self.logger.error("pkg_management.add.package event missing 'name' (source: %s)", event.source)
            return
        try:
            body = PackageBody(
                present=event.payload.get("present", True),
                latest=event.payload.get("latest", False),
            )
            self._install_package(name, body)
        except Exception:
            self.logger.error("pkg_management.add.package failed for %r (source: %s)", name, event.source, exc_info=True)

    def _on_add_repo(self, event: Event) -> None:
        name = event.payload.get("name")
        if not name:
            self.logger.error("pkg_management.add.repo event missing 'name' (source: %s)", event.source)
            return
        try:
            body_fields = {k: v for k, v in event.payload.items() if k != "name"}
            body = RepoBody(**body_fields)
            self._add_repo(name, body)
        except Exception:
            self.logger.error("pkg_management.add.repo failed for %r (source: %s)", name, event.source, exc_info=True)

    def _on_add_service(self, event: Event) -> None:
        service = event.payload.get("service")
        if not service:
            self.logger.error("pkg_management.add.service event missing 'service' (source: %s)", event.source)
            return
        try:
            body = ServiceBody(
                running=event.payload.get("running", True),
                enabled=event.payload.get("enabled", True),
            )
            self._set_service(service, body)
        except Exception:
            self.logger.error("pkg_management.add.service failed for %r (source: %s)", service, event.source, exc_info=True)

    # ── init system detection ──────────────────────────────────────────────────

    @staticmethod
    def _detect_init_system() -> str:
        if os.path.isdir("/run/systemd/system"):
            return "systemd"
        if shutil.which("initctl") and os.path.isdir("/etc/init"):
            return "upstart"
        if os.path.isdir("/etc/init.d"):
            return "sysvinit"
        return "unknown"

    # ── route registration ─────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",                         self._status,           methods=["GET"],    summary="Plugin status and managed-resource counts")
        add("/tasks",                          self._list_bg_tasks,    methods=["GET"],    summary="List background tasks and their status")

        add("/services",                       self._list_services,    methods=["GET"],    summary="List all services with ff_managed flag")
        add("/services/{service}",             self._set_service,      methods=["PUT"],    summary="Start/stop/enable/disable a service")
        add("/services/{service}",             self._delete_service,   methods=["DELETE"], summary="Stop managing a service")
        add("/services/{service}/import",      self._import_service,   methods=["POST"],   summary="Import an existing system service into FF management", status_code=201)

        add("/packages",                       self._list_packages,    methods=["GET"],    summary="List managed packages")
        add("/packages/search",                self._search_packages,  methods=["GET"],    summary="Search available packages")
        add("/packages/upgrade-system",        self._upgrade_system,   methods=["POST"],   summary="Run a full unattended system upgrade and email the output")
        add("/packages/{name}",                self._install_package,  methods=["POST"],   summary="Install or ensure a package",           status_code=201)
        add("/packages/{name}",                self._update_package,   methods=["PUT"],    summary="Update a package to latest")
        add("/packages/{name}",                self._remove_package,   methods=["DELETE"], summary="Remove a package")
        add("/packages/{name}/import",         self._import_package,   methods=["POST"],   summary="Import an installed package into FF management", status_code=201)

        add("/repos",                          self._list_repos,       methods=["GET"],    summary="List all repos with ff_managed flag")
        add("/repos/import",                   self._import_repo,      methods=["POST"],   summary="Import an existing system repo into FF management", status_code=201)
        add("/repos/{name}",                   self._add_repo,         methods=["POST"],   summary="Add or update a package repository",    status_code=201)
        add("/repos/{name}",                   self._remove_repo,      methods=["DELETE"], summary="Remove a package repository")

    # ── status ─────────────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "package_manager": self._pkg_mgr.platform,
            "managed": {
                "services": len(self._state["services"]),
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
        self._emit("pkg_management.service.changed", {"service": service, **body.model_dump()})
        return {"service": service, **body.model_dump()}

    def _delete_service(self, service: str) -> dict:
        if service not in self._state["services"]:
            raise HTTPException(404, f"Service {service!r} not managed")
        del self._state["services"][service]
        self._save_state()
        self._emit("pkg_management.service.deleted", {"service": service})
        return {"deleted": service}

    def _import_service(self, service: str) -> dict:
        system = self._read_system_services()
        if service not in system:
            raise HTTPException(404, f"Service {service!r} not found on system")
        state = {"running": system[service]["running"], "enabled": system[service]["enabled"]}
        self._state["services"][service] = state
        self._save_state()
        self._emit("pkg_management.service.changed", {"service": service, **state})
        return {"service": service, **state, "ff_managed": True}

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
        self._emit("pkg_management.package.changed", {"package": name, **body.model_dump(), "platform": self._pkg_mgr.platform})
        return {"package": name, **body.model_dump(), "platform": self._pkg_mgr.platform}

    def _update_package(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        if name not in self._state["packages"]:
            raise HTTPException(404, f"Package {name!r} not managed")
        self._pkg_mgr.update(name)
        self._state["packages"][name]["latest"] = True
        self._save_state()
        self._emit("pkg_management.package.updated", {"package": name, "platform": self._pkg_mgr.platform})
        return {"package": name, "updated": True, "platform": self._pkg_mgr.platform}

    def _remove_package(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        if name not in self._state["packages"]:
            raise HTTPException(404, f"Package {name!r} not managed")
        self._pkg_mgr.remove(name)
        del self._state["packages"][name]
        self._save_state()
        self._emit("pkg_management.package.deleted", {"package": name, "platform": self._pkg_mgr.platform})
        return {"deleted": name}

    def _import_package(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        system = self._pkg_mgr.list_system_packages()
        if name not in system:
            raise HTTPException(404, f"Package {name!r} is not installed on this system")
        state = {"present": True, "latest": False}
        self._state["packages"][name] = state
        self._save_state()
        self._emit("pkg_management.package.changed", {"package": name, **state, "platform": self._pkg_mgr.platform})
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
        self._emit("pkg_management.package.upgrade-system.started", {"task_id": task_id, "email": body.email, "platform": self._pkg_mgr.platform})
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
        self._emit("pkg_management.package.upgrade-system.done", {
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
        self._emit("pkg_management.repo.changed", {"repo": name, **body.model_dump(), "platform": self._pkg_mgr.platform})
        return {"repo": name, **body.model_dump(), "platform": self._pkg_mgr.platform}

    def _remove_repo(self, name: str) -> dict:
        self._pkg_mgr.assert_supported()
        if name not in self._state["repos"]:
            raise HTTPException(404, f"Repo {name!r} not managed")
        stored = self._state["repos"][name]
        self._pkg_mgr.apply_repo(name, RepoBody(**{**stored, "present": False}))
        del self._state["repos"][name]
        self._save_state()
        self._emit("pkg_management.repo.deleted", {"repo": name, "platform": self._pkg_mgr.platform})
        return {"deleted": name}

    def _import_repo(self, body: RepoImportBody) -> dict:
        self._pkg_mgr.assert_supported()
        system = self._pkg_mgr.list_system_repos()
        match = next((k for k in system if self._repo_id(k) == body.id), None)
        if match is None:
            raise HTTPException(404, f"Repo with id {body.id!r} not found on system")
        state = system[match]
        self._state["repos"][body.alias] = state
        self._save_state()
        self._emit("pkg_management.repo.changed", {"repo": body.alias, **state, "platform": self._pkg_mgr.platform})
        return {"repo": body.alias, **state, "platform": self._pkg_mgr.platform, "ff_managed": True}
