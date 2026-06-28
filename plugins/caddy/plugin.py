"""
Caddy Plugin
────────────
Manages Caddy as an HTTPS reverse proxy. Desired state is stored in a JSON
file in the plugin data directory. Call POST /apply to push the config to
the running Caddy process.

First apply: writes data/caddy.json, copies to /etc/caddy/caddy.json via
pyinfra, and starts the caddy systemd service.

Subsequent applies: writes data/caddy.json, copies to the system location
for persistence, then hot-reloads the running Caddy via its admin API
(POST http://localhost:{admin_port}/load).

Other plugins register proxy upstreams by emitting events on the bus:
  app_proxy.register   – payload: {name, upstream, path_prefix?, description?}
  app_proxy.unregister – payload: {name}

Routes mount at /v1/caddy/.

Events emitted:
  caddy.config.applied   – payload: {success: bool}
  caddy.config.discarded – payload: {}
"""
from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, HTTPException
from ff_auth import require_role
from pydantic import BaseModel, Field

from pyinfra.operations import files as files_ops
from pyinfra.operations import systemd as systemd_ops

from plugin_system.core.macros import macro_registry

from infra import pyinfra_run_batch
from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service
from plugin_system.core.decorators import on
from plugin_system.core.events import Event, bus


# ── Pydantic models ──────────────────────────────────────────────────────────

class AppEntry(BaseModel):
    name: str = Field(..., max_length=100)
    upstream: str = Field(..., max_length=2048, description="e.g. http://127.0.0.1:8000")
    path_prefix: str = Field("/", max_length=255, description="URL path prefix")
    description: str = Field("", max_length=255)


class AppUpdate(BaseModel):
    upstream: Optional[str] = Field(None, max_length=2048)
    path_prefix: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=255)


class CaddySettings(BaseModel):
    http_port: Optional[int] = Field(None, ge=1, le=65535)
    https_port: Optional[int] = Field(None, ge=1, le=65535)
    admin_port: Optional[int] = Field(None, ge=1, le=65535)
    tls_email: Optional[str] = Field(None, max_length=254)
    tls_ca: Optional[str] = Field(None, max_length=2048, description="ACME CA directory URL (e.g. Let's Encrypt staging)")
    auto_https: Optional[str] = Field(None, max_length=32, description="'off' | 'disable_redirects' | 'on'")


_DEFAULT_SETTINGS: dict[str, Any] = {
    "http_port": 80,
    "https_port": 443,
    "admin_port": 2019,
    "tls_email": "",
    "tls_ca": "",
    "auto_https": "off",
}

_DEFAULT_STATE: dict[str, Any] = {
    "apps": {
        "fastfirewall": {
            "upstream": "$interface.lo.address[0]:$service_port.fastfirewall-api.tcp[0]",
            "path_prefix": "/",
            "description": "FastFirewall management UI",
            "source": "default",
        }
    },
    "settings": dict(_DEFAULT_SETTINGS),
}


# ── Plugin ───────────────────────────────────────────────────────────────────

class CaddyPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.APP_PROXY]

    def setup(self) -> None:
        self._system_conf = Path(
            self.config.get("system_conf_file", "/etc/caddy/caddy.json")
        )
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "caddy_state.json", self.logger,
            mutation_model="deferred", data_dir=self.data_dir,
        )
        self._state: dict[str, Any] = self._state_file.load_desired(default=dict(_DEFAULT_STATE))

        self._register_routes()

        self.logger.info(
            "Caddy plugin loaded: %d app(s), config=%s",
            len(self._state.get("apps", {})),
            self._data_config_path(),
        )

    def teardown(self) -> None:
        self._save_state()

    # ── state helpers ────────────────────────────────────────────────────────

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _data_config_path(self) -> Path:
        return self.data_dir / self.config.get("config_file", "caddy.json")

    # ── pyinfra wrapper ──────────────────────────────────────────────────────

    def _pyinfra_run(self, op: Any, **kwargs: Any) -> None:
        norm_kwargs = {
            k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
            for k, v in kwargs.items()
        }
        success, err = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])[0]
        if not success:
            raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")

    # ── route registration ───────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        _admin = [require_role("admin")]
        add("/status",             self._status,          methods=["GET"],    summary="Plugin status and pending-changes flag", dependencies=_admin)
        add("/config/apps",        self._list_apps,       methods=["GET"],    summary="List registered proxy apps", dependencies=_admin)
        add("/config/apps",        self._add_app,         methods=["POST"],   summary="Register a proxy app", status_code=201, dependencies=_admin)
        add("/config/apps/{name}", self._get_app,         methods=["GET"],    summary="Get one proxy app", dependencies=_admin)
        add("/config/apps/{name}", self._update_app,      methods=["PUT"],    summary="Replace a proxy app", dependencies=_admin)
        add("/config/apps/{name}", self._delete_app,      methods=["DELETE"], summary="Remove a proxy app", status_code=204, dependencies=_admin)
        add("/config/settings",    self._get_settings,    methods=["GET"],    summary="Get global proxy settings", dependencies=_admin)
        add("/config/settings",    self._update_settings, methods=["PATCH"],  summary="Update global proxy settings", dependencies=_admin)
        add("/check",              self._check,           methods=["POST"],   summary="Preview generated Caddy config (dry-run)", dependencies=_admin)
        add("/apply",              self._apply,           methods=["POST"],   summary="Apply Caddy config", dependencies=_admin)
        add("/discard",            self._discard,         methods=["POST"],   summary="Discard pending changes", dependencies=_admin)

    # ── event handlers ───────────────────────────────────────────────────────

    @on("app_proxy.register")
    def _on_register(self, event: Event) -> None:
        payload = event.payload
        name = payload.get("name")
        upstream = payload.get("upstream")
        if not name or not upstream:
            self.logger.warning("app_proxy.register ignored: missing name or upstream in payload")
            return
        self._state.setdefault("apps", {})[name] = {
            "upstream": upstream,
            "path_prefix": payload.get("path_prefix", "/"),
            "description": payload.get("description", ""),
            "source": event.source or "event",
        }
        self._save_state()
        self.logger.debug("app_proxy.register: registered '%s' -> %s", name, upstream)

    @on("app_proxy.unregister")
    def _on_unregister(self, event: Event) -> None:
        name = event.payload.get("name")
        if name and name in self._state.get("apps", {}):
            del self._state["apps"][name]
            self._save_state()
            self.logger.debug("app_proxy.unregister: removed '%s'", name)

    @on("plugins.all_loaded")
    def _on_plugins_loaded(self, event: Event) -> None:
        """Apply state once all plugins have loaded and macros are registered."""
        if self.config.get("ignore_state_on_boot", False):
            return
        self.logger.info("Applying Caddy config now that all plugins are loaded")
        try:
            self._apply_state()
        except Exception:
            self.logger.error("Caddy apply failed on plugins.all_loaded", exc_info=True)

    # ── API handlers ─────────────────────────────────────────────────────────

    def _status(self) -> dict[str, Any]:
        return {
            "service": "caddy",
            "apps": len(self._state.get("apps", {})),
            "pending_changes": self._state_file.pending_changes,
            "state_file": str(self._state_file.path),
            "config_file": str(self._data_config_path()),
        }

    def _list_apps(self) -> dict[str, Any]:
        apps = self._state.get("apps", {})
        return {
            "count": len(apps),
            "apps": [{"name": k, **v} for k, v in apps.items()],
        }

    def _get_app(self, name: str) -> dict[str, Any]:
        app = self._state.get("apps", {}).get(name)
        if app is None:
            raise HTTPException(404, f"App '{name}' not found")
        return {"name": name, **app}

    def _add_app(self, body: AppEntry) -> dict[str, Any]:
        apps = self._state.setdefault("apps", {})
        if body.name in apps:
            raise HTTPException(409, f"App '{body.name}' already exists")
        apps[body.name] = {
            "upstream": body.upstream,
            "path_prefix": body.path_prefix,
            "description": body.description,
            "source": "api",
        }
        self._save_state()
        return {"name": body.name, **apps[body.name]}

    def _update_app(self, name: str, body: AppEntry) -> dict[str, Any]:
        apps = self._state.setdefault("apps", {})
        if name not in apps:
            raise HTTPException(404, f"App '{name}' not found")
        apps[name] = {
            "upstream": body.upstream,
            "path_prefix": body.path_prefix,
            "description": body.description,
            "source": apps[name].get("source", "api"),
        }
        self._save_state()
        return {"name": name, **apps[name]}

    def _delete_app(self, name: str) -> None:
        if name not in self._state.get("apps", {}):
            raise HTTPException(404, f"App '{name}' not found")
        del self._state["apps"][name]
        self._save_state()

    def _get_settings(self) -> dict[str, Any]:
        return dict(self._state.get("settings", _DEFAULT_SETTINGS))

    def _update_settings(self, body: CaddySettings) -> dict[str, Any]:
        updates = body.model_dump(exclude_unset=True)
        self._state.setdefault("settings", dict(_DEFAULT_SETTINGS)).update(updates)
        self._save_state()
        return dict(self._state["settings"])

    # ── apply / discard ──────────────────────────────────────────────────────

    _OVERRIDE_PATH = Path("/etc/systemd/system/caddy.service.d/fastfirewall.conf")

    def _do_apply(self, state: dict[str, Any]) -> None:
        """Push *state* to Caddy. Raises on any failure; does not commit."""
        config_json = json.dumps(self._build_caddy_config(state), indent=2)

        data_path = self._data_config_path()
        data_path.parent.mkdir(parents=True, exist_ok=True)
        data_path.write_text(config_json, encoding="utf-8")

        # Copy to system location so the caddy user can read it
        self._pyinfra_run(
            files_ops.put,
            name="Copy Caddy JSON config to system location",
            src=io.StringIO(config_json),
            dest=str(self._system_conf),
            mode="644",
            _sudo=True,
        )

        override_content = (
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart=/usr/bin/caddy run --environ --config {self._system_conf}\n"
        )
        try:
            on_disk = self._OVERRIDE_PATH.read_text()
        except FileNotFoundError:
            on_disk = None

        if on_disk != override_content:
            self._pyinfra_run(
                files_ops.put,
                name="Write Caddy systemd override",
                src=io.StringIO(override_content),
                dest=str(self._OVERRIDE_PATH),
                mode="644",
                _sudo=True,
            )
            self._pyinfra_run(
                systemd_ops.daemon_reload,
                name="Reload systemd daemon",
                _sudo=True,
            )
            self._pyinfra_run(
                systemd_ops.service,
                name="Start and enable Caddy",
                service="caddy",
                running=True,
                enabled=True,
                restarted=True,
                _sudo=True,
            )
        else:
            settings = state.get("settings") or _DEFAULT_SETTINGS
            try:
                self._caddy_admin_load(config_json, settings.get("admin_port", 2019))
            except RuntimeError as exc:
                if "Connection refused" not in str(exc):
                    raise
                # Caddy isn't running — restart the service to pick up the config
                self.logger.warning("Caddy admin API unreachable; restarting service")
                self._pyinfra_run(
                    systemd_ops.service,
                    name="Start and enable Caddy",
                    service="caddy",
                    running=True,
                    enabled=True,
                    restarted=True,
                    _sudo=True,
                )

    def _apply_state(self) -> None:
        desired = self._desired_snapshot()
        try:
            self._do_apply(desired)
            self._state_file.commit(desired)
            return
        except Exception:
            self.logger.warning("Boot apply of desired state failed; trying current state", exc_info=True)

        current = self._state_file.current_snapshot
        if current is not None:
            try:
                self._do_apply(current)
                self._state = current
                self._state_file.commit(current)
                self.logger.warning("Running on previous (current) state — desired state was not applied")
                return
            except Exception:
                self.logger.error("Boot apply of current state also failed", exc_info=True)

        raise RuntimeError(f"{self.plugin_id}: failed to apply state on boot; plugin will not load")

    def _apply(self) -> dict[str, Any]:
        desired = self._desired_snapshot()
        try:
            self._do_apply(desired)
            self._state_file.commit(desired)
            bus.emit(Event("caddy.config.applied", payload={"success": True}))
            return {"success": True}
        except Exception as exc:
            self.logger.error("Caddy apply failed", exc_info=True)
            bus.emit(Event("caddy.config.applied", payload={"success": False}))
            raise HTTPException(500, "Failed to apply Caddy config; check server logs") from exc

    def _check(self) -> dict[str, Any]:
        desired = self._desired_snapshot()
        current = self._state_file.current_snapshot or {}
        try:
            config = self._build_caddy_config(desired)
        except Exception as exc:
            self.logger.error("Caddy config build failed during check", exc_info=True)
            raise HTTPException(500, "Failed to build Caddy config; check server logs") from exc
        current_apps = set(current.get("apps", {}).keys())
        desired_apps = set(desired.get("apps", {}).keys())
        return {
            "pending_changes": self._state_file.pending_changes,
            "config": config,
            "changes": {
                "apps": {
                    "added": sorted(desired_apps - current_apps),
                    "removed": sorted(current_apps - desired_apps),
                    "modified": sorted(
                        k for k in desired_apps & current_apps
                        if desired["apps"][k] != current.get("apps", {}).get(k)
                    ),
                }
            },
        }

    def _discard(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot
        if current is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        self._state = current
        self._save_state()
        bus.emit(Event("caddy.config.discarded", payload={}))
        return {"discarded": True}

    # ── Caddy admin API ──────────────────────────────────────────────────────

    def _caddy_admin_load(self, config_json: str, admin_port: int) -> None:
        raw = f"$interface.lo.address[0]"
        host = macro_registry.resolve(raw)
        listen_host = str(host) if host is not None else "127.0.0.1"
        url = f"http://{listen_host}:{admin_port}/load"
        req = urllib.request.Request(
            url,
            data=config_json.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status not in (200, 204):
                    raise RuntimeError(f"Caddy admin API returned HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Caddy admin API error {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Caddy admin API unreachable at {url}: {exc.reason}") from exc

    # ── config generation ────────────────────────────────────────────────────

    def _build_caddy_config(self, state: dict[str, Any]) -> dict[str, Any]:
        settings = state.get("settings") or _DEFAULT_SETTINGS
        http_port: int = settings.get("http_port", 80)
        https_port: int = settings.get("https_port", 443)
        admin_port: int = settings.get("admin_port", 2019)
        auto_https: str = settings.get("auto_https", "off")
        tls_email: str = settings.get("tls_email", "")
        tls_ca: str = settings.get("tls_ca", "")

        # Resolve admin listen address (may contain macros)
        admin_listen_raw = state.get("admin", {}).get("listen", f"localhost:{admin_port}")
        admin_listen = ":".join(
            str(v) if (v := macro_registry.resolve(p)) is not None else p
            for p in admin_listen_raw.split(":")
        )

        apps = state.get("apps") or {}

        # Longest path_prefix first; "/" catch-all last
        sorted_apps = sorted(
            apps.items(),
            key=lambda kv: (
                kv[1].get("path_prefix", "/") == "/",
                -len(kv[1].get("path_prefix", "/")),
            ),
        )

        routes: list[dict[str, Any]] = []
        for _name, app in sorted_apps:
            upstream = app["upstream"]
            path_prefix: str = app.get("path_prefix", "/")
            prefix = path_prefix.rstrip("/") if path_prefix != "/" else ""

            # Resolve any macro references in each colon-segment of the upstream
            resolved_parts = []
            for p in upstream.split(":"):
                v = macro_registry.resolve(p)
                if v is None and p.startswith("$"):
                    raise ValueError(f"Upstream macro {p!r} could not be resolved")
                resolved_parts.append(str(v) if v is not None else p)
            upstream = ":".join(resolved_parts)
            parsed = urllib.parse.urlparse(upstream)
            dial = parsed.netloc or upstream

            reverse_proxy: dict[str, Any] = {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "headers": {
                    "request": {
                        "set": {
                            "X-Forwarded-Proto": ["{http.request.scheme}"],
                            "X-Forwarded-Host": ["{http.request.host}"],
                            "X-Real-IP": ["{http.request.remote.host}"],
                        },
                        "add": {
                            "X-Forwarded-For": ["{http.request.remote.host}"],
                        },
                    }
                },
            }

            route: dict[str, Any] = {"handle": [reverse_proxy], "terminal": True}
            if prefix:
                route["match"] = [{"path": [f"{prefix}*"]}]
            routes.append(route)

        # Only bind the HTTPS port when TLS termination is active
        listen = [f":{http_port}"]
        if auto_https != "off":
            listen.append(f":{https_port}")

        server: dict[str, Any] = {
            "listen": listen,
            "routes": routes,
        }
        if auto_https == "off":
            server["automatic_https"] = {"disable": True}
        elif auto_https == "disable_redirects":
            server["automatic_https"] = {"disable_redirects": True}
        # else: omit — Caddy defaults to full automatic HTTPS

        config: dict[str, Any] = {
            "admin": {"listen": admin_listen},
            "apps": {
                "http": {
                    "http_port": http_port,
                    "https_port": https_port,
                    "servers": {"main": server},
                },
            },
        }

        if tls_email:
            issuer: dict[str, Any] = {"module": "acme", "email": tls_email}
            if tls_ca:
                issuer["ca"] = tls_ca
            config["apps"]["tls"] = {
                "automation": {
                    "policies": [{"issuers": [issuer]}]
                }
            }

        return config
