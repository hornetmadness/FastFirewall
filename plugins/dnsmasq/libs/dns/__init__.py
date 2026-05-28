import uuid
from typing import Any

from fastapi import HTTPException
from plugin_system.core.events import Event, bus
from plugin_system.core.macros import macro_registry

from ..models import DnsRecordCreate, DnsUpdate


class DnsMixin:
    def _get_dns(self) -> dict[str, Any]:
        return dict(self._dns)

    def _update_dns(self, body: DnsUpdate) -> dict[str, Any]:
        self._dns.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.dns.updated", payload={"config": self._dns}))
        return dict(self._dns)

    def _list_records(self) -> dict[str, Any]:
        return {
            "records": [{"id": rid, **r} for rid, r in self._records.items()],
            "count": len(self._records),
        }

    def _add_record(self, body: DnsRecordCreate) -> dict[str, Any]:
        record_id = str(uuid.uuid4())[:8]
        record = body.model_dump(exclude_none=True)
        self._records[record_id] = record
        self._save_state()
        bus.emit(Event("dnsmasq.record.added",
                       payload={"record_id": record_id, "type": record["type"], "name": record["name"]}))
        return {"id": record_id, **record}

    def _delete_record(self, record_id: str) -> dict[str, Any]:
        if record_id not in self._records:
            raise HTTPException(404, f"DNS record {record_id!r} not found")
        self._records.pop(record_id)
        self._save_state()
        bus.emit(Event("dnsmasq.record.removed", payload={"record_id": record_id}))
        return {"deleted": record_id}

    def render_config(self) -> list[str]:
        lines: list[str] = []
        dns = self._dns
        port_raw = macro_registry.resolve(dns.get("port", 53))
        port = port_raw[0] if isinstance(port_raw, list) else port_raw
        lines.append(f"port={port}")
        for addr in dns.get("listen_addresses") or ["0.0.0.0"]:
            resolved = macro_registry.resolve(addr)
            for a in (resolved if isinstance(resolved, list) else [resolved]):
                lines.append(f"listen-address={a}")
        iface = dns.get("interface")
        if iface:
            resolved = macro_registry.resolve(iface)
            lines.append(f"interface={resolved if isinstance(resolved, str) else iface}")
        if dns.get("no_resolv"):
            lines.append("no-resolv")
        for upstream in dns.get("upstream") or []:
            lines.append(f"server={upstream}")
        for domain, servers in (dns.get("domain_servers") or {}).items():
            for s in servers:
                lines.append(f"server=/{domain}/{s}")
        for local_domain in dns.get("local") or []:
            lines.append(f"local=/{local_domain}/")
        cache_size = dns.get("cache_size", 1000)
        if cache_size != 150:
            lines.append(f"cache-size={cache_size}")
        if dns.get("dnssec"):
            lines.append("dnssec")
            lines.append("dnssec-check-unsigned")
        if dns.get("log_queries"):
            lines.append("log-queries")
        if dns.get("domain"):
            lines.append(f"domain={dns['domain']}")
        local_ttl = dns.get("local_ttl", 0)
        if local_ttl:
            lines.append(f"local-ttl={local_ttl}")
        neg_ttl = dns.get("neg_ttl", 3600)
        if neg_ttl != 3600:
            lines.append(f"neg-ttl={neg_ttl}")
        if dns.get("strict_order"):
            lines.append("strict-order")
        if dns.get("rebind_protection", True):
            lines.append("stop-dns-rebind")
        if dns.get("rebind_localhost_ok", True):
            lines.append("rebind-localhost-ok")
        for rec in self._records.values():
            rtype = rec.get("type")
            name = rec.get("name", "")
            value = rec.get("value", "")
            if rtype == "A":
                lines.append(f"address=/{name}/{value}")
            elif rtype == "AAAA":
                lines.append(f"aaaa=/{name}/{value}")
            elif rtype == "CNAME":
                lines.append(f"cname={name},{value}")
            elif rtype == "TXT":
                lines.append(f'txt-record={name},"{value}"')
            elif rtype == "MX":
                priority = rec.get("priority", 10)
                lines.append(f"mx-host={name},{value},{priority}")
            elif rtype == "SRV":
                port = rec.get("port", 0)
                priority = rec.get("priority", 0)
                weight = rec.get("weight", 0)
                lines.append(f"srv-host={name},{value},{port},{priority},{weight}")
            elif rtype == "PTR":
                lines.append(f"ptr-record={name},{value}")
        return lines
