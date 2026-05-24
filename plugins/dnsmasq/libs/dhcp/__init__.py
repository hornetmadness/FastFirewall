import uuid
from typing import Any

from fastapi import HTTPException
from plugin_system.core.events import Event, bus

from ..models import (
    DhcpRangeCreate, DhcpRangeUpdate, DhcpUpdate,
    StaticLeaseCreate, StaticLeaseUpdate,
)


class DhcpMixin:
    def _get_dhcp(self) -> dict[str, Any]:
        return dict(self._dhcp)

    def _update_dhcp(self, body: DhcpUpdate) -> dict[str, Any]:
        self._dhcp.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.dhcp.updated", source=self.plugin_id,
                       payload={"enabled": self._dhcp.get("enabled")}))
        return dict(self._dhcp)

    def _list_ranges(self) -> dict[str, Any]:
        return {
            "ranges": [{"id": rid, **r} for rid, r in self._dhcp_ranges.items()],
            "count": len(self._dhcp_ranges),
        }

    def _add_range(self, body: DhcpRangeCreate) -> dict[str, Any]:
        r = body.model_dump(exclude_none=True)
        for rid, existing in self._dhcp_ranges.items():
            if existing == r:
                raise HTTPException(409, f"Identical DHCP range already exists as {rid!r}")
        range_id = str(uuid.uuid4())[:8]
        self._dhcp_ranges[range_id] = r
        self._save_state()
        bus.emit(Event("dnsmasq.range.added", source=self.plugin_id, payload={"range_id": range_id}))
        return {"id": range_id, **r}

    def _update_range(self, range_id: str, body: DhcpRangeUpdate) -> dict[str, Any]:
        if range_id not in self._dhcp_ranges:
            raise HTTPException(404, f"DHCP range {range_id!r} not found")
        self._dhcp_ranges[range_id].update(body.model_dump(exclude_unset=True))
        self._save_state()
        return {"id": range_id, **self._dhcp_ranges[range_id]}

    def _delete_range(self, range_id: str) -> dict[str, Any]:
        if range_id not in self._dhcp_ranges:
            raise HTTPException(404, f"DHCP range {range_id!r} not found")
        self._dhcp_ranges.pop(range_id)
        self._save_state()
        bus.emit(Event("dnsmasq.range.removed", source=self.plugin_id, payload={"range_id": range_id}))
        return {"deleted": range_id}

    def _read_live_leases(self) -> list[dict[str, Any]]:
        lease_file = self.config.get("dhcp", {}).get("lease_file", "/var/lib/dnsmasq/dnsmasq.leases")
        leases: list[dict[str, Any]] = []
        try:
            with open(lease_file) as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        leases.append({
                            "expires": int(parts[0]) if parts[0].isdigit() else None,
                            "mac": parts[1],
                            "ip": parts[2],
                            "hostname": parts[3] if parts[3] != "*" else None,
                            "client_id": parts[4] if len(parts) > 4 and parts[4] != "*" else None,
                        })
        except (FileNotFoundError, PermissionError):
            pass
        return leases

    def _live_leases(self) -> dict[str, Any]:
        leases = self._read_live_leases()
        return {"leases": leases, "count": len(leases)}

    def _list_static_leases(self) -> dict[str, Any]:
        return {
            "leases": [{"id": lid, **l} for lid, l in self._static_leases.items()],
            "count": len(self._static_leases),
        }

    def _add_static_lease(self, body: StaticLeaseCreate) -> dict[str, Any]:
        for lid, existing in self._static_leases.items():
            if existing.get("mac") == body.mac:
                raise HTTPException(409, f"Static lease for MAC {body.mac!r} already exists as {lid!r}")
        lease_id = str(uuid.uuid4())[:8]
        lease = body.model_dump(exclude_none=True)
        self._static_leases[lease_id] = lease
        self._save_state()
        bus.emit(Event("dnsmasq.lease.added", source=self.plugin_id,
                       payload={"lease_id": lease_id, "mac": body.mac, "ip": body.ip}))
        return {"id": lease_id, **lease}

    def _update_static_lease(self, lease_id: str, body: StaticLeaseUpdate) -> dict[str, Any]:
        if lease_id not in self._static_leases:
            raise HTTPException(404, f"Static lease {lease_id!r} not found")
        self._static_leases[lease_id].update(body.model_dump(exclude_unset=True))
        self._save_state()
        return {"id": lease_id, **self._static_leases[lease_id]}

    def _delete_static_lease(self, lease_id: str) -> dict[str, Any]:
        if lease_id not in self._static_leases:
            raise HTTPException(404, f"Static lease {lease_id!r} not found")
        self._static_leases.pop(lease_id)
        self._save_state()
        bus.emit(Event("dnsmasq.lease.removed", source=self.plugin_id, payload={"lease_id": lease_id}))
        return {"deleted": lease_id}

    def render_config(self) -> list[str]:
        lines: list[str] = []
        if not self._dhcp.get("enabled"):
            return lines
        if self._dhcp.get("authoritative", True):
            lines.append("dhcp-authoritative")
        lease_file = self.config.get("dhcp", {}).get("lease_file", "/var/lib/dnsmasq/dnsmasq.leases")
        lines.append(f"dhcp-leasefile={lease_file}")
        for r in self._dhcp_ranges.values():
            parts: list[str] = []
            if r.get("interface"):
                parts.append(f"interface:{r['interface']}")
            mode = r.get("mode", "dhcp")
            if mode != "dhcp":
                parts.append(mode)
            parts.append(r["start"])
            parts.append(r["end"])
            if r.get("netmask"):
                parts.append(r["netmask"])
            parts.append(r.get("lease_time", "12h"))
            lines.append(f"dhcp-range={','.join(parts)}")
        for lease in self._static_leases.values():
            lease_parts: list[str] = [lease["mac"], lease["ip"]]
            if lease.get("hostname"):
                lease_parts.append(lease["hostname"])
            if lease.get("lease_time"):
                lease_parts.append(lease["lease_time"])
            lines.append(f"dhcp-host={','.join(lease_parts)}")
        for opt_code, opt_val in (self._dhcp.get("options") or {}).items():
            lines.append(f"dhcp-option={opt_code},{opt_val}")
        return lines
