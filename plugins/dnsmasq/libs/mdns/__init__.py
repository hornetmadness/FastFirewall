from typing import Any

from plugin_system.core.events import Event, bus

from ..models import MdnsUpdate


class MdnsMixin:
    _mdns: dict[str, Any]
    _save_state: Any

    def _get_mdns(self) -> dict[str, Any]:
        return dict(self._mdns)

    def _update_mdns(self, body: MdnsUpdate) -> dict[str, Any]:
        self._mdns.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.mdns.updated",
                       payload={"enabled": self._mdns.get("enabled")}))
        return dict(self._mdns)

    def render_config(self) -> list[str]:
        lines: list[str] = []
        if not self._mdns.get("enabled"):
            return lines
        lines.append("enable-ra")
        for iface in self._mdns.get("interfaces") or []:
            lines.append(f"interface={iface}")
        return lines
