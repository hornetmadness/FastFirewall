"""
Audit Log Plugin
────────────────
Demonstrates ApiRouterPlugin using add_api_route() instead of decorators.
Routes are mounted at /v1/audit/.
"""
import datetime
from plugin_system.core import PluginBase, Service, on, on_any
from plugin_system.core.events import Event


class AuditPlugin(PluginBase):
    services = [Service.SECURITY_LOG]

    def setup(self):
        self._log_path = self.plugin_dir / self.config.get("log_file", "audit.log")
        self._include_payload = self.config.get("include_payload", True)
        self._ignored = set(self.config.get("ignored_events", []))
        self.logger.info("Writing audit log to %r", self._log_path)

    def teardown(self):
        self.logger.info("Shutting down audit log")

    @on_any
    def record(self, event: Event):
        if event.name in self._ignored:
            return
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        parts = [f"{ts} | {event.name}"]
        if event.source:
            parts.append(f"source={event.source}")
        if self._include_payload and event.payload:
            parts.append(f"payload={event.payload}")
        line = " | ".join(parts)
        self.logger.debug("Audit: %s", line)
        with open(self._log_path, "a") as fh:
            fh.write(line + "\n")

    @on("user.login", "user.logout")
    def on_auth_event(self, event: Event):
        self.logger.debug("Auth event: %r for %s", event.name, event.payload.get("username"))
