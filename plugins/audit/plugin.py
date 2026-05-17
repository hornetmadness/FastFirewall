"""
Audit Log Plugin
────────────────
Records every event to an audit trail.

Macro system live example
─────────────────────────
This plugin demonstrates end-to-end macro usage:

  • on_aliases_updated  — calls merge_interface_aliases() to keep the
    $interface namespace current; logs each resolved alias as proof.

  • on_plugin_loaded   — calls merge_service_ports() to keep the
    $service_port namespace current; logs resolved port lists.

  • _resolve_payload   — called from record() to expand any macro values
    found in event payloads before writing them to the audit log, so the
    log shows both the macro and its resolved value.
"""
import datetime
from typing import Any

from plugin_system.core import PluginBase, Service, on, on_any
from plugin_system.core.events import Event
from plugin_system.core.macros import (
    is_macro,
    merge_interface_aliases,
    merge_service_ports,
    resolve_macro,
    resolve_string_macro,
)


class AuditPlugin(PluginBase):
    services = [Service.SECURITY_LOG]

    def setup(self):
        self._log_path = self.plugin_dir / "data" / self.config.get("log_file", "audit.log")
        self._include_payload = self.config.get("include_payload", True)
        self._ignored = set(self.config.get("ignored_events", []))
        self._macro_registry: dict[str, Any] = {}
        self.logger.info("Writing audit log to %r", self._log_path)

    def teardown(self):
        self.logger.info("Shutting down audit log")

    # ── macro registry maintenance (live examples) ─────────────────────────────

    @on("networking.aliases_updated")
    def on_aliases_updated(self, event: Event) -> None:
        """Rebuild $interface namespace and log each resolved alias."""
        aliases: dict[str, str] = event.payload.get("aliases", {})
        merge_interface_aliases(self._macro_registry, aliases)
        for alias in aliases:
            resolved = resolve_string_macro(f"$interface.{alias}", self._macro_registry)
            self.logger.info("macro $interface.%s → %s", alias, resolved)

    @on("plugin.loaded")
    def on_plugin_loaded(self, event: Event) -> None:
        """Merge service_ports from every newly loaded plugin and log resolved port lists."""
        service_ports: dict[str, Any] = event.payload.get("service_ports") or {}
        if not service_ports:
            return
        merge_service_ports(self._macro_registry, service_ports)
        for svc, proto_map in service_ports.items():
            for proto in proto_map:
                ports = resolve_macro(f"$service_port.{svc}.{proto}", self._macro_registry)
                self.logger.info("macro $service_port.%s.%s → %s", svc, proto, ports)

    # ── audit logging ──────────────────────────────────────────────────────────

    def _resolve_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *payload* with any macro string values expanded.

        String values that match the macro syntax are resolved via the registry.
        Unresolvable macros are kept as-is so the log still shows the intent.
        The original key is preserved; a companion key "<key>_resolved" is added
        only when resolution succeeds and differs from the original.
        """
        out: dict[str, Any] = {}
        for k, v in payload.items():
            out[k] = v
            if isinstance(v, str) and is_macro(v):
                resolved_str = resolve_string_macro(v, self._macro_registry)
                if resolved_str is not None:
                    out[f"{k}_resolved"] = resolved_str
                    continue
                resolved_ports = resolve_macro(v, self._macro_registry)
                if resolved_ports:
                    out[f"{k}_resolved"] = resolved_ports
        return out

    @on_any
    def record(self, event: Event):
        if event.name in self._ignored:
            return
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        parts = [f"{ts} | {event.name}"]
        if event.source:
            parts.append(f"source={event.source}")
        if self._include_payload and event.payload:
            parts.append(f"payload={self._resolve_payload(event.payload)}")
        line = " | ".join(parts)
        self.logger.debug("Audit: %s", line)
        with open(self._log_path, "a") as fh:
            fh.write(line + "\n")

    @on("user.login", "user.logout")
    def on_auth_event(self, event: Event):
        self.logger.debug("Auth event: %r for %s", event.name, event.payload.get("username"))
