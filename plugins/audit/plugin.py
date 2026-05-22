"""
Audit Log Plugin
────────────────
Records every event to an audit trail.

Macro resolution
────────────────
String values in event payloads that match the macro syntax are resolved via
the shared ``macro_registry`` singleton before writing to the log, so each
entry shows both the original macro and its resolved value:

  payload={'src_port': '$service_port.dns.udp', 'src_port_resolved': [53]}

The registry is populated by the loader — no per-plugin event subscriptions
or local registry copies are needed.  ``on_all_loaded`` demonstrates a direct
resolution call once all namespaces are guaranteed to be registered.
"""
import datetime
from typing import Any

from plugin_system.core import PluginBase, Service, on, on_any
from plugin_system.core.events import Event
from plugin_system.core.macros import is_macro, macro_registry


class AuditPlugin(PluginBase):
    services = [Service.SECURITY_LOG]

    def setup(self):
        self._log_path = self.plugin_dir / "data" / self.config.get("log_file", "audit.log")
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._include_payload = self.config.get("include_payload", True)
        self._ignored = set(self.config.get("ignored_events", []))
        self.logger.info("Writing audit log to %r", self._log_path)
        

    def teardown(self):
        self.logger.info("Shutting down audit log")

    # ── audit logging ──────────────────────────────────────────────────────────

    def _resolve_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *payload* with any macro string values expanded.

        Unresolvable macros are kept as-is so the log still shows the intent.
        The original key is preserved; a companion key "<key>_resolved" is added
        only when resolution succeeds and differs from the original.
        """
        out: dict[str, Any] = {}
        for k, v in payload.items():
            out[k] = v
            if isinstance(v, str) and is_macro(v):
                resolved_str = macro_registry.resolve_string(v)
                if resolved_str is not None:
                    out[f"{k}_resolved"] = resolved_str
                    continue
                resolved_ports = macro_registry.resolve_ports(v)
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

    @on("plugins.all_loaded")
    def on_all_loaded(self, event: Event) -> None:
        resolved = macro_registry.resolve_string("$interface.lan1")
        self.logger.info("$interface.lan1 → %s", resolved)

    @on("user.login", "user.logout")
    def on_auth_event(self, event: Event):
        self.logger.debug("Auth event: %r for %s", event.name, event.payload.get("username"))
