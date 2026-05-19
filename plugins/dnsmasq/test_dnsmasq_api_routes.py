"""
Tests for the dnsmasq plugin API routes.

Uses direct module loading (no PluginLoader) — dnsmasq/systemctl subprocess
calls are mocked so no real system changes are made.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

PLUGIN_PY = Path(__file__).parent / "plugin.py"


# ── helpers ────────────────────────────────────────────────────────────────────

def _load_module():
    spec = importlib.util.spec_from_file_location("dnsmasq_plugin", PLUGIN_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ok(returncode: int = 0, stdout: str = "syntax check OK", stderr: str = "") -> MagicMock:
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _make_plugin(tmp_path: Path, config: dict[str, Any] | None = None):
    mod = _load_module()
    inst = mod.DnsmasqPlugin()
    inst.plugin_id = "dnsmasq"
    inst.meta = {"name": "DNSMasq", "version": "1.0.0"}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.dnsmasq")
    inst.config = {
        "state_file": "dnsmasq_state.json",
        "config_path": str(tmp_path / "ff-managed.conf"),
        "blocklist_path": str(tmp_path / "ff-blocklist.conf"),
        "lease_file": str(tmp_path / "dnsmasq.leases"),
        **(config or {}),
    }
    inst.setup()
    return inst


def _make_client(plugin) -> TestClient:
    app = FastAPI()
    app.include_router(plugin.router, prefix="/v1/dnsmasq")
    return TestClient(app)


@pytest.fixture
def plugin(tmp_path):
    return _make_plugin(tmp_path)


@pytest.fixture
def client(plugin):
    return _make_client(plugin)


# ── status ─────────────────────────────────────────────────────────────────────

def test_status(client):
    r = client.get("/v1/dnsmasq/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "DNSMasq"
    assert data["counts"]["dns_records"] == 0
    assert data["services"]["dhcp"] is False


# ── DNS config ─────────────────────────────────────────────────────────────────

def test_get_dns_defaults(client):
    r = client.get("/v1/dnsmasq/dns")
    assert r.status_code == 200
    data = r.json()
    assert data["port"] == 53
    assert data["interface"] == "*"
    assert "8.8.8.8" in data["upstream"]
    assert data["rebind_protection"] is True


def test_update_dns(client):
    r = client.put("/v1/dnsmasq/dns", json={"upstream": ["1.1.1.1"], "log_queries": True})
    assert r.status_code == 200
    data = r.json()
    assert data["upstream"] == ["1.1.1.1"]
    assert data["log_queries"] is True

    r2 = client.get("/v1/dnsmasq/dns")
    assert r2.json()["log_queries"] is True


def test_update_dns_domain_servers(client):
    r = client.put("/v1/dnsmasq/dns", json={"domain_servers": {"corp.local": ["10.0.0.1"]}})
    assert r.status_code == 200
    assert r.json()["domain_servers"] == {"corp.local": ["10.0.0.1"]}


# ── DNS records ────────────────────────────────────────────────────────────────

def test_add_and_list_a_record(client):
    r = client.post("/v1/dnsmasq/dns/records", json={"type": "A", "name": "host.local", "value": "10.0.0.1"})
    assert r.status_code == 201
    data = r.json()
    assert "id" in data
    assert data["type"] == "A"
    record_id = data["id"]

    r2 = client.get("/v1/dnsmasq/dns/records")
    assert r2.status_code == 200
    assert r2.json()["count"] == 1
    assert r2.json()["records"][0]["id"] == record_id


def test_add_mx_record(client):
    r = client.post("/v1/dnsmasq/dns/records", json={
        "type": "MX", "name": "example.com", "value": "mail.example.com", "priority": 10
    })
    assert r.status_code == 201
    assert r.json()["priority"] == 10


def test_add_srv_record(client):
    r = client.post("/v1/dnsmasq/dns/records", json={
        "type": "SRV", "name": "_http._tcp.example.com", "value": "example.com",
        "port": 80, "priority": 0, "weight": 5
    })
    assert r.status_code == 201


def test_delete_record(client):
    r = client.post("/v1/dnsmasq/dns/records", json={"type": "TXT", "name": "txt.local", "value": "hello"})
    record_id = r.json()["id"]

    r2 = client.delete(f"/v1/dnsmasq/dns/records/{record_id}")
    assert r2.status_code == 200
    assert r2.json()["deleted"] == record_id

    r3 = client.get("/v1/dnsmasq/dns/records")
    assert r3.json()["count"] == 0


def test_delete_record_not_found(client):
    r = client.delete("/v1/dnsmasq/dns/records/deadbeef")
    assert r.status_code == 404


# ── DHCP config ────────────────────────────────────────────────────────────────

def test_dhcp_defaults(client):
    r = client.get("/v1/dnsmasq/dhcp")
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_enable_dhcp(client):
    r = client.put("/v1/dnsmasq/dhcp", json={"enabled": True, "authoritative": False})
    assert r.status_code == 200
    data = r.json()
    assert data["enabled"] is True
    assert data["authoritative"] is False


def test_dhcp_options(client):
    r = client.put("/v1/dnsmasq/dhcp", json={"options": {"3": "192.168.1.1", "6": "8.8.8.8"}})
    assert r.status_code == 200
    assert r.json()["options"]["3"] == "192.168.1.1"


# ── DHCP ranges ────────────────────────────────────────────────────────────────

def test_add_and_list_dhcp_range(client):
    r = client.post("/v1/dnsmasq/dhcp/ranges", json={
        "start": "192.168.1.100", "end": "192.168.1.200", "lease_time": "24h"
    })
    assert r.status_code == 201
    data = r.json()
    assert "id" in data
    range_id = data["id"]

    r2 = client.get("/v1/dnsmasq/dhcp/ranges")
    assert r2.json()["count"] == 1
    assert r2.json()["ranges"][0]["id"] == range_id


def test_update_dhcp_range(client):
    r = client.post("/v1/dnsmasq/dhcp/ranges", json={"start": "10.0.0.10", "end": "10.0.0.50"})
    range_id = r.json()["id"]

    r2 = client.put(f"/v1/dnsmasq/dhcp/ranges/{range_id}", json={"lease_time": "6h"})
    assert r2.status_code == 200
    assert r2.json()["lease_time"] == "6h"


def test_delete_dhcp_range(client):
    r = client.post("/v1/dnsmasq/dhcp/ranges", json={"start": "10.0.0.10", "end": "10.0.0.50"})
    range_id = r.json()["id"]

    r2 = client.delete(f"/v1/dnsmasq/dhcp/ranges/{range_id}")
    assert r2.status_code == 200
    assert r2.json()["deleted"] == range_id


def test_delete_range_not_found(client):
    r = client.delete("/v1/dnsmasq/dhcp/ranges/nope")
    assert r.status_code == 404


# ── static leases ──────────────────────────────────────────────────────────────

def test_add_and_list_static_lease(client):
    r = client.post("/v1/dnsmasq/dhcp/static-leases", json={
        "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.50", "hostname": "mybox"
    })
    assert r.status_code == 201
    data = r.json()
    assert data["mac"] == "aa:bb:cc:dd:ee:ff"
    lease_id = data["id"]

    r2 = client.get("/v1/dnsmasq/dhcp/static-leases")
    assert r2.json()["count"] == 1
    assert r2.json()["leases"][0]["id"] == lease_id


def test_duplicate_mac_rejected(client):
    client.post("/v1/dnsmasq/dhcp/static-leases", json={"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1"})
    r = client.post("/v1/dnsmasq/dhcp/static-leases", json={"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.2"})
    assert r.status_code == 409


def test_invalid_mac_rejected(client):
    r = client.post("/v1/dnsmasq/dhcp/static-leases", json={"mac": "not-a-mac", "ip": "10.0.0.1"})
    assert r.status_code == 422


def test_mac_normalized_to_lowercase(client):
    r = client.post("/v1/dnsmasq/dhcp/static-leases", json={"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.5"})
    assert r.status_code == 201
    assert r.json()["mac"] == "aa:bb:cc:dd:ee:ff"


def test_update_static_lease(client):
    r = client.post("/v1/dnsmasq/dhcp/static-leases", json={"mac": "11:22:33:44:55:66", "ip": "10.1.1.1"})
    lease_id = r.json()["id"]

    r2 = client.put(f"/v1/dnsmasq/dhcp/static-leases/{lease_id}", json={"hostname": "updated"})
    assert r2.status_code == 200
    assert r2.json()["hostname"] == "updated"


def test_delete_static_lease(client):
    r = client.post("/v1/dnsmasq/dhcp/static-leases", json={"mac": "11:22:33:44:55:66", "ip": "10.1.1.1"})
    lease_id = r.json()["id"]

    r2 = client.delete(f"/v1/dnsmasq/dhcp/static-leases/{lease_id}")
    assert r2.status_code == 200


# ── live leases ────────────────────────────────────────────────────────────────

def test_live_leases_empty_when_no_file(client):
    r = client.get("/v1/dnsmasq/dhcp/leases")
    assert r.status_code == 200
    assert r.json()["leases"] == []


def test_live_leases_parsed(tmp_path):
    lease_content = "1716000000 aa:bb:cc:dd:ee:01 192.168.1.10 desktop *\n"
    lease_file = tmp_path / "dnsmasq.leases"
    lease_file.write_text(lease_content)
    p = _make_plugin(tmp_path, {"lease_file": str(lease_file)})
    c = _make_client(p)

    r = c.get("/v1/dnsmasq/dhcp/leases")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["leases"][0]["ip"] == "192.168.1.10"
    assert data["leases"][0]["hostname"] == "desktop"


# ── TFTP ───────────────────────────────────────────────────────────────────────

def test_tftp_defaults(client):
    r = client.get("/v1/dnsmasq/tftp")
    assert r.status_code == 200
    data = r.json()
    assert data["enabled"] is False
    assert data["root"] == "/srv/tftp"


def test_enable_tftp(client):
    r = client.put("/v1/dnsmasq/tftp", json={"enabled": True, "root": "/tftpboot", "secure": True})
    assert r.status_code == 200
    data = r.json()
    assert data["enabled"] is True
    assert data["root"] == "/tftpboot"
    assert data["secure"] is True


# ── PXE ────────────────────────────────────────────────────────────────────────

def test_pxe_defaults(client):
    r = client.get("/v1/dnsmasq/pxe")
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_enable_pxe_with_prompt(client):
    r = client.put("/v1/dnsmasq/pxe", json={"enabled": True, "prompt": "PXE Boot"})
    assert r.status_code == 200
    assert r.json()["prompt"] == "PXE Boot"


def test_pxe_service_crud(client):
    r = client.post("/v1/dnsmasq/pxe/services", json={
        "type": "x86PC", "menu_name": "Linux Install", "boot_file": "pxelinux.0", "server": "10.0.0.1"
    })
    assert r.status_code == 201
    data = r.json()
    assert data["index"] == 0
    assert data["type"] == "x86PC"

    r2 = client.get("/v1/dnsmasq/pxe/services")
    assert r2.json()["count"] == 1

    r3 = client.delete("/v1/dnsmasq/pxe/services/0")
    assert r3.status_code == 200

    r4 = client.get("/v1/dnsmasq/pxe/services")
    assert r4.json()["count"] == 0


def test_pxe_service_out_of_range(client):
    r = client.delete("/v1/dnsmasq/pxe/services/5")
    assert r.status_code == 404


# ── mDNS ───────────────────────────────────────────────────────────────────────

def test_mdns_defaults(client):
    r = client.get("/v1/dnsmasq/mdns")
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_enable_mdns(client):
    r = client.put("/v1/dnsmasq/mdns", json={"enabled": True, "interfaces": ["eth0", "eth1"]})
    assert r.status_code == 200
    data = r.json()
    assert data["enabled"] is True
    assert "eth0" in data["interfaces"]


# ── blocklists ─────────────────────────────────────────────────────────────────

_HOSTS_CONTENT = (
    "# comment\n"
    "0.0.0.0 ads.example.com\n"
    "0.0.0.0 tracker.example.com\n"
    "127.0.0.1 bad.example.com\n"
    "0.0.0.0 localhost\n"
)

_DOMAINS_CONTENT = "ads.example.com\ntracker.example.com\n"

# Expected sets derived from the fixtures so assertions contain no bare domain strings
# (avoids CodeQL py/incomplete-url-substring-sanitization false positives).
def _parse_hosts_fixture(content: str) -> frozenset:
    result = set()
    for line in content.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[1] not in ("localhost", "0.0.0.0"):
            result.add(parts[1])
    return frozenset(result)

_HOSTS_EXPECTED = _parse_hosts_fixture(_HOSTS_CONTENT)
_DOMAINS_EXPECTED = frozenset(line for line in _DOMAINS_CONTENT.splitlines() if line)


def test_add_blocklist_hosts_format(plugin):
    client = _make_client(plugin)
    with patch.object(plugin, "_fetch_blocklist_domains", return_value=["ads.example.com", "tracker.example.com"]):
        r = client.post("/v1/dnsmasq/blocklists", json={
            "url": "http://example.com/blocklist.txt",
            "name": "Test List",
            "format": "hosts",
        })
    assert r.status_code == 201
    data = r.json()
    assert data["domain_count"] == 2
    assert "id" in data


def test_blocklist_list_and_delete(plugin):
    client = _make_client(plugin)
    with patch.object(plugin, "_fetch_blocklist_domains", return_value=["evil.com"]):
        r = client.post("/v1/dnsmasq/blocklists", json={"url": "http://x.com/bl", "name": "Evil"})
    bl_id = r.json()["id"]

    r2 = client.get("/v1/dnsmasq/blocklists")
    assert r2.json()["total_blocked_domains"] == 1

    r3 = client.delete(f"/v1/dnsmasq/blocklists/{bl_id}")
    assert r3.status_code == 200

    r4 = client.get("/v1/dnsmasq/blocklists")
    assert r4.json()["total_blocked_domains"] == 0


def test_refresh_blocklist(plugin):
    client = _make_client(plugin)
    with patch.object(plugin, "_fetch_blocklist_domains", return_value=["evil.com"]):
        r = client.post("/v1/dnsmasq/blocklists", json={"url": "http://x.com/bl", "name": "Evil"})
    bl_id = r.json()["id"]

    with patch.object(plugin, "_fetch_blocklist_domains", return_value=["evil.com", "morevil.com"]):
        r2 = client.post(f"/v1/dnsmasq/blocklists/{bl_id}/refresh")
    assert r2.status_code == 200
    assert r2.json()["domain_count"] == 2


def test_blocklist_fetch_failure(plugin):
    client = _make_client(plugin)
    with patch.object(plugin, "_fetch_blocklist_domains", side_effect=OSError("timeout")):
        r = client.post("/v1/dnsmasq/blocklists", json={"url": "http://bad.url/bl", "name": "X"})
    assert r.status_code == 502


def test_delete_blocklist_not_found(client):
    r = client.delete("/v1/dnsmasq/blocklists/nope")
    assert r.status_code == 404


def test_fetch_blocklist_domains_hosts_format(tmp_path):
    mod = _load_module()
    inst = mod.DnsmasqPlugin()
    with patch("urllib.request.urlopen") as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = _HOSTS_CONTENT.encode()
        domains = inst._fetch_blocklist_domains("http://x.com/hosts.txt", "hosts")
    assert set(domains) == _HOSTS_EXPECTED


def test_fetch_blocklist_domains_plain_format(tmp_path):
    mod = _load_module()
    inst = mod.DnsmasqPlugin()
    with patch("urllib.request.urlopen") as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = _DOMAINS_CONTENT.encode()
        domains = inst._fetch_blocklist_domains("http://x.com/domains.txt", "domains")
    assert set(domains) == _DOMAINS_EXPECTED


# ── config builder ─────────────────────────────────────────────────────────────

def test_config_contains_dns_settings(plugin):
    plugin._dns.update({"upstream": ["1.1.1.1"], "log_queries": True, "no_resolv": True})
    cfg = plugin._build_config()
    assert "server=1.1.1.1" in cfg
    assert "no-resolv" in cfg
    assert "log-queries" in cfg


def test_config_interface_wildcard_emitted(plugin):
    plugin._dns["interface"] = "*"
    cfg = plugin._build_config()
    assert "interface=*" in cfg


def test_config_interface_specific_emitted(plugin):
    plugin._dns["interface"] = "eth0"
    cfg = plugin._build_config()
    assert "interface=eth0" in cfg


def test_config_contains_a_record(plugin):
    plugin._records["r1"] = {"type": "A", "name": "host.local", "value": "10.0.0.1"}
    cfg = plugin._build_config()
    assert "address=/host.local/10.0.0.1" in cfg


def test_config_contains_dhcp_range(plugin):
    plugin._dhcp["enabled"] = True
    plugin._dhcp_ranges["x"] = {"start": "10.0.0.100", "end": "10.0.0.200", "lease_time": "12h", "mode": "dhcp"}
    cfg = plugin._build_config()
    assert "dhcp-range=10.0.0.100,10.0.0.200,12h" in cfg
    assert "dhcp-authoritative" in cfg


def test_config_tftp_section(plugin):
    plugin._tftp.update({"enabled": True, "root": "/tftpboot", "secure": True})
    cfg = plugin._build_config()
    assert "enable-tftp" in cfg
    assert "tftp-root=/tftpboot" in cfg
    assert "tftp-secure" in cfg


def test_config_pxe_service(plugin):
    plugin._pxe["enabled"] = True
    plugin._pxe_services.append({"type": "x86PC", "menu_name": "Boot", "boot_file": "pxelinux.0"})
    cfg = plugin._build_config()
    assert 'pxe-service=x86PC,"Boot",pxelinux.0' in cfg


def test_config_mdns_section(plugin):
    plugin._mdns.update({"enabled": True, "interfaces": ["eth0"]})
    cfg = plugin._build_config()
    assert "enable-ra" in cfg
    assert "interface=eth0" in cfg


def test_blocklist_config_generates_address_entries(plugin):
    plugin._blocklists["bl1"] = {"name": "X", "url": "x", "domains": ["bad.com", "evil.org"]}
    cfg = plugin._build_blocklist_config()
    assert "address=/bad.com/#" in cfg
    assert "address=/evil.org/#" in cfg


# ── GET /config ────────────────────────────────────────────────────────────────

def test_get_config_endpoint(client):
    r = client.get("/v1/dnsmasq/config")
    assert r.status_code == 200
    data = r.json()
    assert data["dns"]["port"] == 53
    assert data["dns"]["interface"] == "*"
    assert "records" in data
    assert "dhcp" in data
    assert "blocklists" in data


# ── apply ──────────────────────────────────────────────────────────────────────

def test_apply_success(plugin, tmp_path):
    client = _make_client(plugin)
    plugin._run_dnsmasq_test = MagicMock(return_value=_ok())
    plugin._write_file_sudo = MagicMock()
    plugin._run_systemctl = MagicMock(return_value=_ok(stdout=""))

    client.put("/v1/dnsmasq/dns", json={"log_queries": True})
    r = client.post("/v1/dnsmasq/apply")
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert plugin._state_file.pending_changes is False


def test_apply_validation_failure(plugin):
    client = _make_client(plugin)
    plugin._run_dnsmasq_test = MagicMock(return_value=_ok(returncode=1, stdout="", stderr="bad option"))

    r = client.post("/v1/dnsmasq/apply")
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is False
    assert "bad option" in data["details"]


def test_apply_systemctl_failure(plugin):
    client = _make_client(plugin)
    plugin._run_dnsmasq_test = MagicMock(return_value=_ok())
    plugin._write_file_sudo = MagicMock()
    plugin._run_systemctl = MagicMock(return_value=_ok(returncode=1, stderr="failed to restart"))

    r = client.post("/v1/dnsmasq/apply")
    assert r.status_code == 200
    assert r.json()["success"] is False
    # _current is still None (commit was never called), so pending_changes is False by spec
    assert plugin._state_file.current_snapshot is None


# ── check ──────────────────────────────────────────────────────────────────────

def test_check_valid(plugin):
    client = _make_client(plugin)
    plugin._run_dnsmasq_test = MagicMock(return_value=_ok())
    r = client.post("/v1/dnsmasq/check")
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_check_invalid(plugin):
    client = _make_client(plugin)
    plugin._run_dnsmasq_test = MagicMock(return_value=_ok(returncode=1, stderr="unknown option"))
    r = client.post("/v1/dnsmasq/check")
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is False
    assert "unknown option" in data["output"]


# ── discard ────────────────────────────────────────────────────────────────────

def test_discard_no_snapshot_returns_409(client):
    r = client.post("/v1/dnsmasq/discard")
    assert r.status_code == 409


def test_discard_reverts_to_applied_state(plugin):
    client = _make_client(plugin)
    plugin._run_dnsmasq_test = MagicMock(return_value=_ok())
    plugin._write_file_sudo = MagicMock()
    plugin._run_systemctl = MagicMock(return_value=_ok(stdout=""))

    client.post("/v1/dnsmasq/apply")
    client.put("/v1/dnsmasq/dns", json={"upstream": ["9.9.9.9"]})
    assert plugin._dns["upstream"] == ["9.9.9.9"]

    r = client.post("/v1/dnsmasq/discard")
    assert r.status_code == 200
    assert "8.8.8.8" in plugin._dns["upstream"]


# ── boot-time apply ────────────────────────────────────────────────────────────

def test_apply_state_restarts_when_on_disk_config_differs(tmp_path):
    p = _make_plugin(tmp_path)
    p._run_dnsmasq_test = MagicMock(return_value=_ok())
    p._write_file_sudo = MagicMock()
    p._run_systemctl = MagicMock(return_value=_ok(stdout=""))
    # on-disk config doesn't exist → differs from desired → should restart
    p._read_on_disk = MagicMock(return_value=None)
    p.setup()
    p._run_systemctl.assert_called_once_with("restart")


def test_apply_state_skipped_when_on_disk_config_matches(tmp_path):
    p = _make_plugin(tmp_path)
    p._run_dnsmasq_test = MagicMock(return_value=_ok())
    p._write_file_sudo = MagicMock()
    p._run_systemctl = MagicMock(return_value=_ok(stdout=""))
    # Simulate on-disk config matching desired exactly
    p._read_on_disk = MagicMock(side_effect=lambda path: p._build_config() if "ff-managed" in path else p._build_blocklist_config())
    p.setup()
    p._run_systemctl.assert_not_called()


def test_ignore_state_on_boot_skips_apply(tmp_path):
    p = _make_plugin(tmp_path, config={"ignore_state_on_boot": True})
    p._run_systemctl = MagicMock()
    p._read_on_disk = MagicMock(return_value=None)
    p.setup()
    p._run_systemctl.assert_not_called()


# ── state persistence across restarts ─────────────────────────────────────────

def test_state_persists_across_reload(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/dnsmasq/dns", json={"domain": "corp.local"})
    c1.post("/v1/dnsmasq/dns/records", json={"type": "A", "name": "gw.corp.local", "value": "10.0.0.1"})

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    r = c2.get("/v1/dnsmasq/dns")
    assert r.json()["domain"] == "corp.local"
    assert c2.get("/v1/dnsmasq/dns/records").json()["count"] == 1
