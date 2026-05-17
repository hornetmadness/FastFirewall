"""
DNSMasq Plugin
──────────────
DNS forwarding/caching, DHCP, TFTP, PXE boot, and mDNS via dnsmasq.
Includes blocklist support for domain filtering.

Mutation model: deferred — mutations update desired state only; call
POST /apply to write /etc/dnsmasq.d/ff-managed.conf and restart dnsmasq.

Routes mount at /v1/dnsmasq/.
"""
import datetime
import json
import os
import re
import subprocess
import tempfile
import urllib.request
import uuid
from typing import Any, Literal, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator

from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service
from plugin_system.core.events import Event, bus


# ── defaults ──────────────────────────────────────────────────────────────────

def _default_dns() -> dict[str, Any]:
    return {
        "port": 53,
        "listen_addresses": ["0.0.0.0"],
        "interface": "*",
        "upstream": ["8.8.8.8", "1.1.1.1"],
        "cache_size": 1000,
        "no_resolv": False,
        "dnssec": False,
        "log_queries": False,
        "domain": None,
        "local_ttl": 0,
        "neg_ttl": 3600,
        "strict_order": False,
        "rebind_protection": True,
        "rebind_localhost_ok": True,
        "domain_servers": {},
        "local": [],
    }


def _default_dhcp() -> dict[str, Any]:
    return {"enabled": False, "authoritative": True, "options": {}}


def _default_tftp() -> dict[str, Any]:
    return {"enabled": False, "root": "/srv/tftp", "secure": False, "no_fail": False}


def _default_pxe() -> dict[str, Any]:
    return {"enabled": False, "prompt": None}


def _default_mdns() -> dict[str, Any]:
    return {"enabled": False, "interfaces": []}


_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


# ── Pydantic models ────────────────────────────────────────────────────────────

class DnsUpdate(BaseModel):
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    listen_addresses: Optional[list[str]] = None
    interface: Optional[str] = None
    upstream: Optional[list[str]] = None
    cache_size: Optional[int] = Field(default=None, ge=0)
    no_resolv: Optional[bool] = None
    dnssec: Optional[bool] = None
    log_queries: Optional[bool] = None
    domain: Optional[str] = None
    local_ttl: Optional[int] = Field(default=None, ge=0)
    neg_ttl: Optional[int] = Field(default=None, ge=0)
    strict_order: Optional[bool] = None
    rebind_protection: Optional[bool] = None
    rebind_localhost_ok: Optional[bool] = None
    domain_servers: Optional[dict[str, list[str]]] = None
    local: Optional[list[str]] = None


class DnsRecordCreate(BaseModel):
    type: Literal["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR"]
    name: str
    value: str
    ttl: Optional[int] = Field(default=None, ge=0)
    priority: Optional[int] = Field(default=None, ge=0, le=65535)
    weight: Optional[int] = Field(default=None, ge=0, le=65535)
    port: Optional[int] = Field(default=None, ge=1, le=65535)


class DhcpUpdate(BaseModel):
    enabled: Optional[bool] = None
    authoritative: Optional[bool] = None
    options: Optional[dict[str, str]] = None


class DhcpRangeCreate(BaseModel):
    start: str
    end: str
    netmask: Optional[str] = None
    lease_time: str = "12h"
    interface: Optional[str] = None
    mode: Literal["dhcp", "proxy", "ra-only", "slaac", "ra-stateless", "ra-names"] = "dhcp"


class DhcpRangeUpdate(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None
    netmask: Optional[str] = None
    lease_time: Optional[str] = None
    interface: Optional[str] = None
    mode: Optional[Literal["dhcp", "proxy", "ra-only", "slaac", "ra-stateless", "ra-names"]] = None


class StaticLeaseCreate(BaseModel):
    mac: str
    ip: str
    hostname: Optional[str] = None
    lease_time: Optional[str] = None

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not _MAC_RE.match(v):
            raise ValueError(f"{v!r} is not a valid MAC address (expected xx:xx:xx:xx:xx:xx)")
        return v.lower()


class StaticLeaseUpdate(BaseModel):
    mac: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
    lease_time: Optional[str] = None

    @field_validator("mac", mode="before")
    @classmethod
    def validate_mac(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, str) or not _MAC_RE.match(v):
            raise ValueError(f"{v!r} is not a valid MAC address (expected xx:xx:xx:xx:xx:xx)")
        return str(v).lower()


class TftpUpdate(BaseModel):
    enabled: Optional[bool] = None
    root: Optional[str] = None
    secure: Optional[bool] = None
    no_fail: Optional[bool] = None


class PxeUpdate(BaseModel):
    enabled: Optional[bool] = None
    prompt: Optional[str] = None


class PxeServiceCreate(BaseModel):
    type: str       # "x86PC", "BC_EFI", "x86-64_EFI", "IA64_EFI", etc.
    menu_name: str
    boot_file: Optional[str] = None
    server: Optional[str] = None


class MdnsUpdate(BaseModel):
    enabled: Optional[bool] = None
    interfaces: Optional[list[str]] = None


class BlocklistCreate(BaseModel):
    url: str
    name: str
    format: Literal["hosts", "domains"] = "hosts"


# ── plugin class ───────────────────────────────────────────────────────────────

class DnsmasqPlugin(PluginBase, ApiRouterPlugin):
    services = [
        Service.DNS,
        Service.DHCP,
        Service.TFTP,
        Service.PXE,
        Service.MDNS,
    ]

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "dnsmasq_state.json", self.logger,
            mutation_model="deferred",
        )
        self._dns: dict[str, Any] = {}
        self._records: dict[str, dict[str, Any]] = {}
        self._dhcp: dict[str, Any] = {}
        self._dhcp_ranges: dict[str, dict[str, Any]] = {}
        self._static_leases: dict[str, dict[str, Any]] = {}
        self._tftp: dict[str, Any] = {}
        self._pxe: dict[str, Any] = {}
        self._pxe_services: list[dict[str, Any]] = []
        self._mdns: dict[str, Any] = {}
        self._blocklists: dict[str, dict[str, Any]] = {}
        self._load_state()
        if not self.config.get("ignore_state_on_boot", False):
            self._apply_state()
        self._register_routes()
        self.logger.info(
            "DNSMasq plugin loaded: %d DNS record(s), %d DHCP range(s), %d blocklist(s)",
            len(self._records), len(self._dhcp_ranges), len(self._blocklists),
        )

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("DNSMasq plugin shut down — state saved")

    # ── state helpers ──────────────────────────────────────────────────

    def _load_state(self) -> None:
        desired = self._state_file.load_desired(default={})
        self._dns = desired.get("dns") or _default_dns()
        self._records = desired.get("records") or {}
        self._dhcp = desired.get("dhcp") or _default_dhcp()
        self._dhcp_ranges = desired.get("dhcp_ranges") or {}
        self._static_leases = desired.get("static_leases") or {}
        self._tftp = desired.get("tftp") or _default_tftp()
        self._pxe = desired.get("pxe") or _default_pxe()
        self._pxe_services = desired.get("pxe_services") or []
        self._mdns = desired.get("mdns") or _default_mdns()
        self._blocklists = desired.get("blocklists") or {}
        # Ensure _desired tracks the actual in-memory state from the start so that
        # pending_changes is accurate even on first apply after a fresh install.
        if not desired:
            self._save_state()

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps({
            "dns": self._dns,
            "records": self._records,
            "dhcp": self._dhcp,
            "dhcp_ranges": self._dhcp_ranges,
            "static_leases": self._static_leases,
            "tftp": self._tftp,
            "pxe": self._pxe,
            "pxe_services": self._pxe_services,
            "mdns": self._mdns,
            "blocklists": self._blocklists,
        }))

    def _read_on_disk(self, path: str) -> Optional[str]:
        """Return the contents of a system config file, or None if unreadable."""
        try:
            with open(path) as fh:
                return fh.read()
        except (FileNotFoundError, PermissionError):
            return None

    def _apply_state(self) -> None:
        """On boot, write desired config and restart dnsmasq if on-disk config differs."""
        config_path = self.config.get("config_path", "/etc/dnsmasq.d/ff-managed.conf")
        blocklist_path = self.config.get("blocklist_path", "/etc/dnsmasq.d/ff-blocklist.conf")
        config_content = self._build_config()
        blocklist_content = self._build_blocklist_config()

        if (self._read_on_disk(config_path) == config_content
                and self._read_on_disk(blocklist_path) == blocklist_content):
            self.logger.info("Boot-time config check: on-disk config matches desired, skipping restart")
            return

        tmp_conf = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as fh:
                fh.write(config_content)
                tmp_conf = fh.name
            test_result = self._run_dnsmasq_test(tmp_conf)
            if test_result.returncode != 0:
                self.logger.warning(
                    "Boot-time config validation failed: %s",
                    (test_result.stdout + test_result.stderr).strip(),
                )
                return
            self._write_file_sudo(config_path, config_content)
            self._write_file_sudo(blocklist_path, blocklist_content)
            result = self._run_systemctl("restart")
            if result.returncode == 0:
                self._state_file.commit(self._desired_snapshot())
                self.logger.info("Boot-time config updated and dnsmasq restarted")
            else:
                self.logger.warning(
                    "Boot-time dnsmasq restart failed: %s",
                    (result.stdout + result.stderr).strip(),
                )
        except Exception as exc:
            self.logger.warning("Could not re-apply dnsmasq config on boot: %s", exc)
        finally:
            if tmp_conf:
                try:
                    os.unlink(tmp_conf)
                except OSError:
                    pass

    # ── config builders ────────────────────────────────────────────────

    def _build_config(self) -> str:
        lines: list[str] = []
        dns = self._dns

        lines.append(f"port={dns.get('port', self.config.get('service_ports', {}).get('dns', {}).get('udp', [53])[0])}")
        for addr in dns.get("listen_addresses") or ["0.0.0.0"]:
            lines.append(f"listen-address={addr}")
        iface = dns.get("interface")
        if iface:
            lines.append(f"interface={iface}")
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

        if self._dhcp.get("enabled"):
            if self._dhcp.get("authoritative", True):
                lines.append("dhcp-authoritative")
            lease_file = self.config.get("lease_file", "/var/lib/dnsmasq/dnsmasq.leases")
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

        if self._tftp.get("enabled"):
            lines.append("enable-tftp")
            lines.append(f"tftp-root={self._tftp.get('root', '/srv/tftp')}")
            if self._tftp.get("secure"):
                lines.append("tftp-secure")
            if self._tftp.get("no_fail"):
                lines.append("tftp-no-fail")

        if self._pxe.get("enabled"):
            for svc in self._pxe_services:
                parts = [svc["type"], f'"{svc["menu_name"]}"']
                if svc.get("boot_file"):
                    parts.append(svc["boot_file"])
                if svc.get("server"):
                    parts.append(svc["server"])
                lines.append(f"pxe-service={','.join(parts)}")
            if self._pxe.get("prompt") is not None:
                lines.append(f'pxe-prompt="{self._pxe["prompt"]}",0')

        if self._mdns.get("enabled"):
            lines.append("enable-ra")
            for iface in self._mdns.get("interfaces") or []:
                lines.append(f"interface={iface}")

        return "\n".join(lines) + "\n"

    def _build_blocklist_config(self) -> str:
        lines: list[str] = []
        for bl in self._blocklists.values():
            for domain in bl.get("domains") or []:
                lines.append(f"address=/{domain}/#")
        return "\n".join(lines) + "\n"

    # ── subprocess wrappers ────────────────────────────────────────────

    def _run_dnsmasq_test(self, config_path: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sudo", "dnsmasq", "--test", f"--conf-file={config_path}"],
            capture_output=True, text=True, timeout=15,
        )

    def _run_systemctl(self, action: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sudo", "systemctl", action, "dnsmasq"],
            capture_output=True, text=True, timeout=30,
        )

    def _write_file_sudo(self, path: str, content: str) -> None:
        result = subprocess.run(
            ["sudo", "tee", path],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to write {path}: {result.stderr.strip()}")

    # ── blocklist fetcher ──────────────────────────────────────────────

    def _fetch_blocklist_domains(self, url: str, fmt: str) -> list[str]:
        with urllib.request.urlopen(url, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        domains: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            if fmt == "hosts":
                parts = line.split()
                if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::1", "::"}:
                    domain = parts[1].lower()
                    if domain not in {"localhost", "localhost.localdomain", "0.0.0.0", "broadcasthost"}:
                        domains.append(domain)
            else:
                token = line.split()[0].lower() if line.split() else ""
                if token and "." in token:
                    domains.append(token)
        return list(dict.fromkeys(domains))

    # ── live DHCP lease reader ─────────────────────────────────────────

    def _read_live_leases(self) -> list[dict[str, Any]]:
        lease_file = self.config.get("lease_file", "/var/lib/dnsmasq/dnsmasq.leases")
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

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",                            self._status,              methods=["GET"],    summary="Plugin status and counts")

        add("/dns",                               self._get_dns,             methods=["GET"],    summary="Get DNS config")
        add("/dns",                               self._update_dns,          methods=["PUT"],    summary="Update DNS config")
        add("/dns/records",                       self._list_records,        methods=["GET"],    summary="List DNS records")
        add("/dns/records",                       self._add_record,          methods=["POST"],   summary="Add a DNS record", status_code=201)
        add("/dns/records/{record_id}",           self._delete_record,       methods=["DELETE"], summary="Remove a DNS record")

        add("/dhcp",                              self._get_dhcp,            methods=["GET"],    summary="Get DHCP config")
        add("/dhcp",                              self._update_dhcp,         methods=["PUT"],    summary="Update DHCP config")
        add("/dhcp/ranges",                       self._list_ranges,         methods=["GET"],    summary="List DHCP ranges")
        add("/dhcp/ranges",                       self._add_range,           methods=["POST"],   summary="Add a DHCP range", status_code=201)
        add("/dhcp/ranges/{range_id}",            self._update_range,        methods=["PUT"],    summary="Update a DHCP range")
        add("/dhcp/ranges/{range_id}",            self._delete_range,        methods=["DELETE"], summary="Remove a DHCP range")
        add("/dhcp/leases",                       self._live_leases,         methods=["GET"],    summary="Live DHCP leases (from lease file)")
        add("/dhcp/static-leases",                self._list_static_leases,  methods=["GET"],    summary="List static DHCP leases")
        add("/dhcp/static-leases",                self._add_static_lease,    methods=["POST"],   summary="Add a static DHCP lease", status_code=201)
        add("/dhcp/static-leases/{lease_id}",     self._update_static_lease, methods=["PUT"],    summary="Update a static DHCP lease")
        add("/dhcp/static-leases/{lease_id}",     self._delete_static_lease, methods=["DELETE"], summary="Remove a static DHCP lease")

        add("/tftp",                              self._get_tftp,            methods=["GET"],    summary="Get TFTP config")
        add("/tftp",                              self._update_tftp,         methods=["PUT"],    summary="Update TFTP config")

        add("/pxe",                               self._get_pxe,             methods=["GET"],    summary="Get PXE config")
        add("/pxe",                               self._update_pxe,          methods=["PUT"],    summary="Update PXE config")
        add("/pxe/services",                      self._list_pxe_services,   methods=["GET"],    summary="List PXE service entries")
        add("/pxe/services",                      self._add_pxe_service,     methods=["POST"],   summary="Add a PXE service entry", status_code=201)
        add("/pxe/services/{index}",              self._delete_pxe_service,  methods=["DELETE"], summary="Remove a PXE service entry by index")

        add("/mdns",                              self._get_mdns,            methods=["GET"],    summary="Get mDNS config")
        add("/mdns",                              self._update_mdns,         methods=["PUT"],    summary="Update mDNS config")

        add("/blocklists",                        self._list_blocklists,     methods=["GET"],    summary="List blocklists")
        add("/blocklists",                        self._add_blocklist,       methods=["POST"],   summary="Add a blocklist (fetches immediately)", status_code=201)
        add("/blocklists/{blocklist_id}",         self._delete_blocklist,    methods=["DELETE"], summary="Remove a blocklist")
        add("/blocklists/{blocklist_id}/refresh", self._refresh_blocklist,   methods=["POST"],   summary="Re-fetch a blocklist from its URL")

        add("/config",                            self._get_config,          methods=["GET"],    summary="Full dnsmasq config text")
        add("/apply",                             self._apply,               methods=["POST"],   summary="Write config and restart dnsmasq")
        add("/check",                             self._check,               methods=["POST"],   summary="Validate config (dnsmasq --test)")
        add("/discard",                           self._discard,             methods=["POST"],   summary="Discard pending changes")

    # ── status ─────────────────────────────────────────────────────────

    def _status(self) -> dict[str, Any]:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "pending_changes": self._state_file.pending_changes,
            "state_file": str(self._state_file.path),
            "counts": {
                "dns_records": len(self._records),
                "dhcp_ranges": len(self._dhcp_ranges),
                "static_leases": len(self._static_leases),
                "pxe_services": len(self._pxe_services),
                "blocklists": len(self._blocklists),
                "blocked_domains": sum(len(bl.get("domains", [])) for bl in self._blocklists.values()),
            },
            "services": {
                "dhcp": self._dhcp.get("enabled", False),
                "tftp": self._tftp.get("enabled", False),
                "pxe": self._pxe.get("enabled", False),
                "mdns": self._mdns.get("enabled", False),
            },
        }

    # ── DNS ────────────────────────────────────────────────────────────

    def _get_dns(self) -> dict[str, Any]:
        return dict(self._dns)

    def _update_dns(self, body: DnsUpdate) -> dict[str, Any]:
        self._dns.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.dns.updated", source=self.plugin_id, payload={"config": self._dns}))
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
        bus.emit(Event("dnsmasq.record.added", source=self.plugin_id,
                       payload={"record_id": record_id, "type": record["type"], "name": record["name"]}))
        return {"id": record_id, **record}

    def _delete_record(self, record_id: str) -> dict[str, Any]:
        if record_id not in self._records:
            raise HTTPException(404, f"DNS record {record_id!r} not found")
        self._records.pop(record_id)
        self._save_state()
        bus.emit(Event("dnsmasq.record.removed", source=self.plugin_id, payload={"record_id": record_id}))
        return {"deleted": record_id}

    # ── DHCP ───────────────────────────────────────────────────────────

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
        range_id = str(uuid.uuid4())[:8]
        r = body.model_dump(exclude_none=True)
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

    # ── TFTP ───────────────────────────────────────────────────────────

    def _get_tftp(self) -> dict[str, Any]:
        return dict(self._tftp)

    def _update_tftp(self, body: TftpUpdate) -> dict[str, Any]:
        self._tftp.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.tftp.updated", source=self.plugin_id,
                       payload={"enabled": self._tftp.get("enabled")}))
        return dict(self._tftp)

    # ── PXE ────────────────────────────────────────────────────────────

    def _get_pxe(self) -> dict[str, Any]:
        return dict(self._pxe)

    def _update_pxe(self, body: PxeUpdate) -> dict[str, Any]:
        self._pxe.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.pxe.updated", source=self.plugin_id,
                       payload={"enabled": self._pxe.get("enabled")}))
        return dict(self._pxe)

    def _list_pxe_services(self) -> dict[str, Any]:
        return {
            "services": [{"index": i, **s} for i, s in enumerate(self._pxe_services)],
            "count": len(self._pxe_services),
        }

    def _add_pxe_service(self, body: PxeServiceCreate) -> dict[str, Any]:
        svc = body.model_dump(exclude_none=True)
        self._pxe_services.append(svc)
        index = len(self._pxe_services) - 1
        self._save_state()
        return {"index": index, **svc}

    def _delete_pxe_service(self, index: int) -> dict[str, Any]:
        if index < 0 or index >= len(self._pxe_services):
            raise HTTPException(404, f"PXE service index {index} out of range (have {len(self._pxe_services)})")
        self._pxe_services.pop(index)
        self._save_state()
        return {"deleted": index}

    # ── mDNS ───────────────────────────────────────────────────────────

    def _get_mdns(self) -> dict[str, Any]:
        return dict(self._mdns)

    def _update_mdns(self, body: MdnsUpdate) -> dict[str, Any]:
        self._mdns.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.mdns.updated", source=self.plugin_id,
                       payload={"enabled": self._mdns.get("enabled")}))
        return dict(self._mdns)

    # ── blocklists ─────────────────────────────────────────────────────

    def _list_blocklists(self) -> dict[str, Any]:
        return {
            "blocklists": [
                {
                    "id": bid,
                    "name": bl["name"],
                    "url": bl["url"],
                    "format": bl.get("format", "hosts"),
                    "domain_count": len(bl.get("domains", [])),
                    "last_fetched": bl.get("last_fetched"),
                }
                for bid, bl in self._blocklists.items()
            ],
            "total_blocked_domains": sum(
                len(bl.get("domains", [])) for bl in self._blocklists.values()
            ),
        }

    def _add_blocklist(self, body: BlocklistCreate) -> dict[str, Any]:
        try:
            domains = self._fetch_blocklist_domains(body.url, body.format)
        except Exception as exc:
            raise HTTPException(502, f"Failed to fetch blocklist from {body.url!r}: {exc}")
        blocklist_id = str(uuid.uuid4())[:8]
        self._blocklists[blocklist_id] = {
            "name": body.name,
            "url": body.url,
            "format": body.format,
            "domains": domains,
            "last_fetched": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._save_state()
        bus.emit(Event("dnsmasq.blocklist.added", source=self.plugin_id,
                       payload={"blocklist_id": blocklist_id, "name": body.name, "domain_count": len(domains)}))
        return {"id": blocklist_id, "name": body.name, "domain_count": len(domains)}

    def _delete_blocklist(self, blocklist_id: str) -> dict[str, Any]:
        if blocklist_id not in self._blocklists:
            raise HTTPException(404, f"Blocklist {blocklist_id!r} not found")
        self._blocklists.pop(blocklist_id)
        self._save_state()
        bus.emit(Event("dnsmasq.blocklist.removed", source=self.plugin_id,
                       payload={"blocklist_id": blocklist_id}))
        return {"deleted": blocklist_id}

    def _refresh_blocklist(self, blocklist_id: str) -> dict[str, Any]:
        if blocklist_id not in self._blocklists:
            raise HTTPException(404, f"Blocklist {blocklist_id!r} not found")
        bl = self._blocklists[blocklist_id]
        try:
            domains = self._fetch_blocklist_domains(bl["url"], bl.get("format", "hosts"))
        except Exception as exc:
            raise HTTPException(502, f"Failed to refresh blocklist from {bl['url']!r}: {exc}")
        bl["domains"] = domains
        bl["last_fetched"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save_state()
        return {"id": blocklist_id, "name": bl["name"], "domain_count": len(domains)}

    # ── config view ────────────────────────────────────────────────────

    def _get_config(self) -> dict[str, Any]:
        return self._desired_snapshot()

    # ── apply / check / discard ────────────────────────────────────────

    def _apply(self) -> dict[str, Any]:
        debug: bool = bool(self.config.get("debug", False))
        desired = self._desired_snapshot()
        config_content = self._build_config()
        blocklist_content = self._build_blocklist_config()
        tmp_conf = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as fh:
                fh.write(config_content)
                tmp_conf = fh.name
            if debug:
                self.logger.info("[debug] apply config: %s", tmp_conf)
            test_result = self._run_dnsmasq_test(tmp_conf)
            test_output = (test_result.stdout + test_result.stderr).strip()
            if debug:
                self.logger.info("[debug] dnsmasq --test returncode=%d output=%r", test_result.returncode, test_output)
            if test_result.returncode != 0:
                return {
                    "success": False,
                    "error": "Config validation failed",
                    "details": test_output,
                }
            config_path = self.config.get("config_path", "/etc/dnsmasq.d/ff-managed.conf")
            blocklist_path = self.config.get("blocklist_path", "/etc/dnsmasq.d/ff-blocklist.conf")
            try:
                self._write_file_sudo(config_path, config_content)
                self._write_file_sudo(blocklist_path, blocklist_content)
            except RuntimeError as exc:
                return {"success": False, "error": str(exc)}
            restart_result = self._run_systemctl("restart")
            output = (restart_result.stdout + restart_result.stderr).strip()
            if debug:
                self.logger.info("[debug] systemctl restart returncode=%d output=%r", restart_result.returncode, output)
            success = restart_result.returncode == 0
            if success:
                self._state_file.commit(desired)
            bus.emit(Event("dnsmasq.applied", source=self.plugin_id,
                           payload={"success": success, "returncode": restart_result.returncode}))
            resp: dict[str, Any] = {
                "success": success,
                "returncode": restart_result.returncode,
                "config_path": config_path,
                "blocklist_path": blocklist_path,
                "output": output or None,
            }
            if debug:
                resp["debug"] = {"config_file": tmp_conf, "test_output": test_output}
            return resp
        finally:
            if tmp_conf:
                if debug:
                    self.logger.info("[debug] temp config retained at: %s", tmp_conf)
                else:
                    try:
                        os.unlink(tmp_conf)
                    except OSError:
                        pass

    def _check(self) -> dict[str, Any]:
        tmp_conf = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as fh:
                fh.write(self._build_config())
                tmp_conf = fh.name
            result = self._run_dnsmasq_test(tmp_conf)
            return {
                "valid": result.returncode == 0,
                "returncode": result.returncode,
                "output": (result.stdout + result.stderr).strip(),
                "pending_changes": self._state_file.pending_changes,
            }
        finally:
            if tmp_conf:
                try:
                    os.unlink(tmp_conf)
                except OSError:
                    pass

    def _discard(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot
        if current is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        self._dns = current.get("dns") or _default_dns()
        self._records = current.get("records") or {}
        self._dhcp = current.get("dhcp") or _default_dhcp()
        self._dhcp_ranges = current.get("dhcp_ranges") or {}
        self._static_leases = current.get("static_leases") or {}
        self._tftp = current.get("tftp") or _default_tftp()
        self._pxe = current.get("pxe") or _default_pxe()
        self._pxe_services = current.get("pxe_services") or []
        self._mdns = current.get("mdns") or _default_mdns()
        self._blocklists = current.get("blocklists") or {}
        self._save_state()
        return {"discarded": True}
