from typing import Any

from plugin_system.core.events import Event, bus

from ..models import TftpUpdate


class TftpMixin:
    _tftp: dict[str, Any]
    _save_state: Any

    def _get_tftp(self) -> dict[str, Any]:
        return dict(self._tftp)

    def _update_tftp(self, body: TftpUpdate) -> dict[str, Any]:
        self._tftp.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.tftp.updated",
                       payload={"enabled": self._tftp.get("enabled")}))
        return dict(self._tftp)

    def render_config(self) -> list[str]:
        lines: list[str] = []
        if not self._tftp.get("enabled"):
            return lines
        lines.append("enable-tftp")
        lines.append(f"tftp-root={self._tftp.get('root', '/srv/tftp')}")
        if self._tftp.get("secure"):
            lines.append("tftp-secure")
        if self._tftp.get("no_fail"):
            lines.append("tftp-no-fail")
        return lines
