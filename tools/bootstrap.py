#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests", "pyyaml"]
# ///
"""
FastFirewall bootstrap wizard.

Drives the FastFirewall REST API to configure common appliance scenarios.

Scenarios:
  gateway   — Networking interfaces + firewall rules + DNS/DHCP + host user
  firewall  — Firewall rules only
  dns-dhcp  — DNS and DHCP via dnsmasq only

Usage:
  uv run tools/bootstrap.py                           # interactive wizard
  uv run tools/bootstrap.py --config config.yaml      # non-interactive, from YAML/JSON
  uv run tools/bootstrap.py --save requests.json      # also save all API calls to file
  uv run tools/bootstrap.py --apply requests.json     # replay a previously saved session
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import sys
import textwrap
from typing import Any
from urllib.parse import urlparse

import requests
import yaml


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


class FFError(Exception):
    pass


class FFClient:
    """Thin HTTP client that optionally logs every API call for later replay.

    Pass simulate=True to log calls without authenticating or making any real
    HTTP requests.  Used to pre-build the export file before the apply prompt.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        export_path: str | None = None,
        simulate: bool = False,
    ) -> None:
        self.host = host.rstrip("/")
        self._export_path = export_path
        self._simulate = simulate
        self._log: list[dict[str, Any]] = []
        if not simulate:
            self._session = requests.Session()
            self._authenticate(username, password)

    def _authenticate(self, username: str, password: str) -> None:
        url = f"{self.host}/token"
        try:
            resp = requests.post(
                url,
                data={"username": username, "password": password},
                timeout=10,
            )
        except requests.ConnectionError:
            raise FFError(f"Cannot connect to {self.host}. Is the server running?")
        if not resp.ok:
            raise FFError(f"Authentication failed ({resp.status_code}): check username/password")
        token = resp.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        description: str = "",
    ) -> dict[str, Any]:
        url = f"{self.host}{path}"

        if self._export_path is not None:
            entry: dict[str, Any] = {
                "method": method,
                "url": url,
                "description": description or f"{method} {path}",
            }
            if body is not None:
                entry["body"] = body
            self._log.append(entry)

        if self._simulate:
            # Return enough for scenario code to keep running without errors.
            return {"success": True, "valid": True, "returncode": 0, "output": ""}

        try:
            resp = self._session.request(method, url, json=body, timeout=30)
        except requests.ConnectionError:
            raise FFError(f"Connection lost during {method} {path}")

        if not resp.ok:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise FFError(f"{method} {path} → {resp.status_code}: {detail}")

        try:
            return resp.json()
        except Exception:
            return {}

    def get(self, path: str, *, description: str = "") -> dict[str, Any]:
        return self.request("GET", path, description=description)

    def post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        description: str = "",
    ) -> dict[str, Any]:
        return self.request("POST", path, body, description=description)

    def put(
        self,
        path: str,
        body: dict[str, Any],
        *,
        description: str = "",
    ) -> dict[str, Any]:
        return self.request("PUT", path, body, description=description)

    def delete(self, path: str, *, description: str = "") -> dict[str, Any]:
        return self.request("DELETE", path, description=description)

    def flush_export(self) -> None:
        if self._export_path is None:
            return
        with open(self._export_path, "w") as fh:
            json.dump(self._log, fh, indent=2)
        _print_ok(f"Saved {len(self._log)} API calls to {self._export_path}")


# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------


def _print_header(title: str) -> None:
    width = 64
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def _print_step(msg: str) -> None:
    print(f"\n  >> {msg}")


def _print_ok(msg: str) -> None:
    print(f"     [OK] {msg}")


def _print_warn(msg: str) -> None:
    print(f"     [!]  {msg}", file=sys.stderr)


def _prompt(msg: str, default: str | None = None, *, secret: bool = False) -> str:
    hint = f" [{default}]" if default is not None else ""
    prompt_str = f"  {msg}{hint}: "
    while True:
        if secret:
            value = getpass.getpass(prompt_str)
        else:
            value = input(prompt_str).strip()
        if value:
            return value
        if default is not None:
            return default
        print("    (required — cannot be blank)")


def _prompt_yn(msg: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    answer = input(f"  {msg} [{hint}]: ").strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def _prompt_choice(msg: str, options: list[tuple[str, str]]) -> str:
    """Print a numbered menu and return the key of the chosen option."""
    print(f"\n  {msg}")
    for i, (_, label) in enumerate(options, 1):
        print(f"    {i}. {label}")
    while True:
        raw = input("  Choice [1]: ").strip()
        if not raw:
            return options[0][0]
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            pass
        print("    Invalid — enter a number from the list.")


# ---------------------------------------------------------------------------
# Check-then-apply helper
# ---------------------------------------------------------------------------


def _check_before_apply(client: FFClient, check_path: str, success_key: str, label: str) -> None:
    """Run a /check endpoint and abort (or prompt to continue) if it fails."""
    _print_step(f"Validating {label} config (dry run)")
    result = client.post(check_path, description=f"Validate {label} config before applying")
    passed = result.get(success_key, False)
    output = result.get("output") or result.get("changes") or ""
    if passed:
        _print_ok(f"{label} check passed")
    else:
        _print_warn(f"{label} check failed")
        if output:
            print(f"       {output}")
        if not _prompt_yn("Apply anyway?", default=False):
            print("  Aborted.")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Network utilities
# ---------------------------------------------------------------------------


def _network_of(cidr: str) -> str:
    """'192.168.0.1/24' → '192.168.0.0/24'"""
    try:
        return str(ipaddress.IPv4Interface(cidr).network)
    except ValueError:
        return cidr


def _host_of(cidr: str) -> str:
    """'192.168.0.1/24' → '192.168.0.1'"""
    return cidr.split("/")[0] if "/" in cidr else cidr


# ---------------------------------------------------------------------------
# Shared firewall rule builder
# ---------------------------------------------------------------------------


def _print_firewall_debug_hint(client: FFClient) -> None:
    """After a failed apply, print the compiled nft output path if available."""
    try:
        status = client.get("/v1/firewall/status")
    except FFError:
        return
    compiled_output = status.get("compiled_output")
    if compiled_output:
        _print_warn(f"Last compiled nft script: {compiled_output}")


def _apply_firewall_rules(client: FFClient, fw: dict[str, Any]) -> None:
    _print_step("Adding firewall rules")

    lan_subnet = fw.get("lan_subnet", "192.168.0.0/24")

    rules: list[dict[str, Any]] = [
        {
            "name": "allow-icmp",
            "chain": "input",
            "action": "accept",
            "protocol": "icmp",
            "comment": "Allow ICMP (ping)",
            "priority": 10,
        },
        {
            "name": "allow-dns-udp-from-lan",
            "chain": "input",
            "action": "accept",
            "protocol": "udp",
            "src_address": lan_subnet,
            "dst_port": 53,
            "comment": "Allow DNS/UDP from LAN",
            "priority": 20,
        },
        {
            "name": "allow-dns-tcp-from-lan",
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "src_address": lan_subnet,
            "dst_port": 53,
            "comment": "Allow DNS/TCP from LAN",
            "priority": 21,
        },
        {
            "name": "allow-dhcp-from-lan",
            "chain": "input",
            "action": "accept",
            "protocol": "udp",
            "src_address": lan_subnet,
            "dst_port": 67,
            "comment": "Allow DHCP from LAN",
            "priority": 22,
        },
    ]

    if fw.get("allow_lan_forwarding", False):
        rules.append({
            "name": "allow-lan-forward",
            "chain": "forward",
            "action": "accept",
            "src_address": lan_subnet,
            "comment": "Allow LAN clients to forward through gateway",
            "priority": 50,
        })

    if fw.get("allow_ssh_from_lan", True):
        rules.append({
            "name": "allow-ssh-from-lan",
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "src_address": lan_subnet,
            "dst_port": 22,
            "comment": "Allow SSH from LAN",
            "priority": 30,
        })

    if fw.get("allow_http_from_lan", True):
        rules.append({
            "name": "allow-http-from-lan",
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "src_address": lan_subnet,
            "dst_port": 80,
            "comment": "Allow HTTP from LAN",
            "priority": 40,
        })

    if fw.get("allow_https_from_lan", True):
        rules.append({
            "name": "allow-https-from-lan",
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "src_address": lan_subnet,
            "dst_port": 443,
            "comment": "Allow HTTPS from LAN",
            "priority": 41,
        })

    rules.append({
        "name": "deny-all",
        "chain": "input",
        "action": "deny",
        "comment": "Default deny — must be last",
        "priority": 1000,
    })

    for rule in rules:
        client.post("/v1/firewall/rules", rule, description=f"Add rule: {rule['name']}")
        _print_ok(f"Rule '{rule['name']}' added")

    _check_before_apply(client, "/v1/firewall/check", "success", "firewall")
    _print_step("Applying firewall rules")
    try:
        result = client.post("/v1/firewall/apply", description="Apply firewall rules to nftables")
        if result.get("success"):
            _print_ok(f"Firewall applied — {result.get('rule_count', '?')} rules active")
        else:
            _print_warn(f"Firewall apply result: {result}")
            _print_firewall_debug_hint(client)
    except FFError as exc:
        _print_warn(str(exc))
        _print_firewall_debug_hint(client)
        raise


# ---------------------------------------------------------------------------
# Scenario: gateway
# ---------------------------------------------------------------------------


def run_gateway(client: FFClient, cfg: dict[str, Any]) -> None:
    _print_header("Gateway Setup — Networking + Firewall + DNS/DHCP + Host User")

    net = cfg.get("network", {})
    dns_cfg = cfg.get("dns", {})
    dhcp_cfg = cfg.get("dhcp", {})
    fw_cfg = cfg.get("firewall", {})
    user_cfg = cfg.get("user", {})
    hostname = cfg.get("hostname")

    lan_iface = net.get("lan", {}).get("interface")
    lan_address = net.get("lan", {}).get("address")

    # 1. Hostname
    if hostname:
        _print_step(f"Setting hostname → '{hostname}'")
        client.put("/v1/host/hostname", {"hostname": hostname}, description="Set system hostname")
        _print_ok(f"Hostname set to '{hostname}'")

    # 2. WAN interface
    wan = net.get("wan", {})
    wan_iface = wan.get("interface")
    if wan_iface:
        _print_step(f"Configuring WAN interface '{wan_iface}'")
        wan_body: dict[str, Any] = {"link": {"state": "up"}}
        if wan.get("mode", "dhcp") == "static" and wan.get("address"):
            wan_body["addresses"] = [wan["address"]]
        client.put(
            f"/v1/networking/config/interfaces/{wan_iface}",
            wan_body,
            description=f"Configure WAN interface {wan_iface}",
        )
        _print_ok(f"{wan_iface} configured (mode: {wan.get('mode', 'dhcp')})")

        if wan.get("gateway"):
            client.post(
                "/v1/networking/config/routes",
                {"to": "default", "via": wan["gateway"], "dev": wan_iface},
                description="Add default gateway route",
            )
            _print_ok(f"Default route via {wan['gateway']}")

    # 3. LAN interface
    if lan_iface and lan_address:
        _print_step(f"Configuring LAN interface '{lan_iface}' → {lan_address}")
        client.put(
            f"/v1/networking/config/interfaces/{lan_iface}",
            {"addresses": [lan_address], "link": {"state": "up"}},
            description=f"Configure LAN interface {lan_iface}",
        )
        _print_ok(f"{lan_iface} configured with {lan_address}")

    # 4. Interface aliases
    aliases: dict[str, str] = {}
    if wan_iface:
        aliases[wan.get("alias", "wan")] = wan_iface
    if lan_iface:
        aliases[net.get("lan", {}).get("alias", "lan")] = lan_iface
    aliases.update(net.get("aliases", {}))
    if aliases:
        _print_step("Setting interface aliases")
        for alias_name, iface_name in aliases.items():
            client.put(
                f"/v1/networking/config/aliases/{alias_name}",
                {"interface": iface_name},
                description=f"Set alias {alias_name} → {iface_name}",
            )
            _print_ok(f"Alias '{alias_name}' → '{iface_name}'")
            _print_ok(f"  Macros: $interface.{alias_name}.name  $interface.{alias_name}.address")

    # 5. IP forwarding
    _print_step("Enabling IPv4 forwarding")
    client.put(
        "/v1/networking/config/sysctl/net.ipv4.ip_forward",
        {"value": "1"},
        description="Enable IPv4 forwarding for routing",
    )
    _print_ok("net.ipv4.ip_forward = 1")

    # 6. Check then apply networking
    _check_before_apply(client, "/v1/networking/check", "success", "networking")
    _print_step("Applying networking configuration")
    result = client.post("/v1/networking/apply", description="Apply networking config via ifstatecli")
    if result.get("success"):
        _print_ok("Networking applied")
    else:
        _print_warn(f"Networking apply result: {result}")

    # 7. DNS
    if dns_cfg:
        _print_step("Configuring DNS (dnsmasq)")
        dns_body: dict[str, Any] = {"rebind_protection": True}
        if dns_cfg.get("domain"):
            dns_body["domain"] = dns_cfg["domain"]
        if dns_cfg.get("upstream"):
            dns_body["upstream"] = dns_cfg["upstream"]
        listen_ip = dns_cfg.get("listen_address") or (lan_address and _host_of(lan_address))
        if listen_ip:
            dns_body["listen_addresses"] = [listen_ip]
        client.put("/v1/dnsmasq/dns", dns_body, description="Configure DNS settings")
        _print_ok("DNS settings applied")

        for record in dns_cfg.get("records", []):
            client.post(
                "/v1/dnsmasq/dns/records",
                record,
                description=f"Add DNS record {record.get('name')}",
            )
            _print_ok(f"DNS record: {record.get('type')} {record.get('name')} → {record.get('value')}")

    # 8. DHCP
    if dhcp_cfg:
        _print_step("Configuring DHCP")
        client.put(
            "/v1/dnsmasq/dhcp",
            {"enabled": True, "authoritative": True},
            description="Enable authoritative DHCP",
        )

        scope: dict[str, Any] = {
            "start": dhcp_cfg["start"],
            "end": dhcp_cfg["end"],
            "lease_time": dhcp_cfg.get("lease_time", "24h"),
        }
        if dhcp_cfg.get("netmask"):
            scope["netmask"] = dhcp_cfg["netmask"]
        if lan_iface:
            scope["interface"] = lan_iface
        client.post("/v1/dnsmasq/dhcp/ranges", scope, description="Add DHCP scope")
        _print_ok(f"DHCP scope {dhcp_cfg['start']}–{dhcp_cfg['end']} ({scope['lease_time']} leases)")

        # Standard DHCP options
        options: dict[str, str] = {}
        gateway_ip = dhcp_cfg.get("gateway") or (lan_address and _host_of(lan_address))
        if gateway_ip:
            options["3"] = gateway_ip          # router
        dns_ip = dhcp_cfg.get("dns") or (lan_address and _host_of(lan_address))
        if dns_ip:
            options["6"] = dns_ip             # DNS server
        if dns_cfg.get("domain"):
            options["15"] = dns_cfg["domain"] # domain name
        if options:
            client.put(
                "/v1/dnsmasq/dhcp",
                {"options": options},
                description="Set DHCP options (router, DNS, domain)",
            )
            _print_ok(f"DHCP options: router={options.get('3')}, dns={options.get('6')}")

    # 8. Check then apply dnsmasq
    _check_before_apply(client, "/v1/dnsmasq/check", "valid", "dnsmasq")
    _print_step("Applying dnsmasq configuration")
    result = client.post("/v1/dnsmasq/apply", description="Apply dnsmasq config and restart")
    if result.get("success"):
        _print_ok("dnsmasq applied and running")
    else:
        _print_warn(f"dnsmasq apply result: {result}")

    # 9. Firewall
    if fw_cfg:
        if not fw_cfg.get("lan_subnet") and lan_address:
            fw_cfg["lan_subnet"] = _network_of(lan_address)
        _apply_firewall_rules(client, fw_cfg)

    # 10. Host user
    if user_cfg:
        _apply_host_user(client, user_cfg)

    _print_header("Gateway setup complete!")
    if aliases:
        print("  Interface macros ready to use in rules and config:")
        for alias_name, iface_name in aliases.items():
            print(f"    $interface.{alias_name}.name    → {iface_name}")
            # address resolved at rule-compile time from the running interface
            print(f"    $interface.{alias_name}.address → (L3 address of {iface_name})")


# ---------------------------------------------------------------------------
# Shared: host user creation
# ---------------------------------------------------------------------------


def _apply_host_user(client: FFClient, user_cfg: dict[str, Any]) -> None:
    username = user_cfg.get("username")
    if not username:
        return
    _print_step(f"Creating user '{username}'")
    user_body: dict[str, Any] = {"shell": user_cfg.get("shell", "/bin/bash")}
    if user_cfg.get("home_dir"):
        user_body["home_dir"] = user_cfg["home_dir"]
    if user_cfg.get("comment"):
        user_body["comment"] = user_cfg["comment"]
    client.post(
        f"/v1/host/users/{username}",
        user_body,
        description=f"Create user {username}",
    )
    _print_ok(f"User '{username}' created (shell: {user_body['shell']})")

    if user_cfg.get("sudo"):
        _print_step(f"Adding '{username}' to sudo group")
        try:
            client.post(
                "/v1/host/groups/sudo/import",
                description="Import sudo group into FF management",
            )
            _print_ok("sudo group imported into FF management")
        except FFError:
            pass  # sudo group may not exist on this distro (e.g. wheel-based systems)
        groups = client.get("/v1/host/groups", description="Verify sudo group is FF-managed")
        sudo_managed = groups.get("groups", {}).get("sudo", {}).get("ff_managed", False)
        if sudo_managed:
            client.post(
                "/v1/host/groups/sudo/members",
                {"username": username},
                description=f"Add {username} to sudo group",
            )
            _print_ok(f"Added '{username}' to sudo group")
        else:
            _print_warn(f"sudo group not found — add '{username}' to sudo manually: usermod -aG sudo {username}")


# ---------------------------------------------------------------------------
# Scenario: firewall only
# ---------------------------------------------------------------------------


def run_firewall_only(client: FFClient, cfg: dict[str, Any]) -> None:
    _print_header("Firewall-Only Setup")
    _apply_firewall_rules(client, cfg.get("firewall", {}))
    if cfg.get("user"):
        _apply_host_user(client, cfg["user"])
    _print_header("Firewall setup complete!")


# ---------------------------------------------------------------------------
# Scenario: DNS + DHCP only
# ---------------------------------------------------------------------------


def run_dns_dhcp(client: FFClient, cfg: dict[str, Any]) -> None:
    _print_header("DNS + DHCP Setup")

    dns_cfg = cfg.get("dns", {})
    dhcp_cfg = cfg.get("dhcp", {})
    lan_address = cfg.get("network", {}).get("lan", {}).get("address")

    if dns_cfg:
        _print_step("Configuring DNS")
        dns_body: dict[str, Any] = {"rebind_protection": True}
        if dns_cfg.get("domain"):
            dns_body["domain"] = dns_cfg["domain"]
        if dns_cfg.get("upstream"):
            dns_body["upstream"] = dns_cfg["upstream"]
        listen_ip = dns_cfg.get("listen_address") or (lan_address and _host_of(lan_address))
        if listen_ip:
            dns_body["listen_addresses"] = [listen_ip]
        client.put("/v1/dnsmasq/dns", dns_body, description="Configure DNS settings")
        _print_ok("DNS settings applied")

        for record in dns_cfg.get("records", []):
            client.post(
                "/v1/dnsmasq/dns/records",
                record,
                description=f"Add DNS record {record.get('name')}",
            )
            _print_ok(f"DNS record: {record.get('type')} {record.get('name')} → {record.get('value')}")

    if dhcp_cfg:
        _print_step("Configuring DHCP")
        client.put(
            "/v1/dnsmasq/dhcp",
            {"enabled": True, "authoritative": True},
            description="Enable authoritative DHCP",
        )

        scope: dict[str, Any] = {
            "start": dhcp_cfg["start"],
            "end": dhcp_cfg["end"],
            "lease_time": dhcp_cfg.get("lease_time", "24h"),
        }
        if dhcp_cfg.get("netmask"):
            scope["netmask"] = dhcp_cfg["netmask"]
        if dhcp_cfg.get("interface"):
            scope["interface"] = dhcp_cfg["interface"]
        client.post("/v1/dnsmasq/dhcp/ranges", scope, description="Add DHCP scope")
        _print_ok(f"DHCP scope {dhcp_cfg['start']}–{dhcp_cfg['end']}")

        options: dict[str, str] = {}
        if dhcp_cfg.get("gateway"):
            options["3"] = dhcp_cfg["gateway"]
        dns_ip = dhcp_cfg.get("dns") or (lan_address and _host_of(lan_address))
        if dns_ip:
            options["6"] = dns_ip
        if dns_cfg.get("domain"):
            options["15"] = dns_cfg["domain"]
        if options:
            client.put(
                "/v1/dnsmasq/dhcp",
                {"options": options},
                description="Set DHCP options",
            )
            _print_ok(f"DHCP options set: {options}")

    _check_before_apply(client, "/v1/dnsmasq/check", "valid", "dnsmasq")
    _print_step("Applying dnsmasq configuration")
    result = client.post("/v1/dnsmasq/apply", description="Apply dnsmasq config and restart")
    if result.get("success"):
        _print_ok("dnsmasq applied and running")
    else:
        _print_warn(f"dnsmasq apply result: {result}")

    if cfg.get("user"):
        _apply_host_user(client, cfg["user"])
    _print_header("DNS + DHCP setup complete!")


# ---------------------------------------------------------------------------
# Apply confirmation
# ---------------------------------------------------------------------------


def _confirm_apply(cfg: dict[str, Any]) -> None:
    """Print a plain-English summary of what will be applied and ask for confirmation."""
    scenario = cfg.get("scenario", "gateway")
    server = cfg.get("server", {})
    net = cfg.get("network", {})
    dns_cfg = cfg.get("dns", {})
    dhcp_cfg = cfg.get("dhcp", {})
    fw_cfg = cfg.get("firewall", {})
    user_cfg = cfg.get("user", {})

    _print_header("Review — changes that will be applied")

    print(f"  Server   : {server.get('host', 'http://localhost:8000')}")
    print(f"  Scenario : {scenario}")

    if cfg.get("hostname"):
        print(f"  Hostname : {cfg['hostname']}")

    wan = net.get("wan", {})
    lan = net.get("lan", {})
    wan_alias = wan.get("alias", "wan")
    lan_alias = lan.get("alias", "lan")
    if wan.get("interface"):
        mode = wan.get("mode", "dhcp")
        addr = f"  ({wan['address']})" if mode == "static" and wan.get("address") else ""
        print(f"  WAN      : {wan['interface']} — {mode}{addr}  ($interface.{wan_alias}.name / .address)")
    if lan.get("interface") and lan.get("address"):
        print(f"  LAN      : {lan['interface']} — {lan['address']}  ($interface.{lan_alias}.name / .address)")

    if dns_cfg.get("domain"):
        upstream = ", ".join(dns_cfg.get("upstream", []))
        print(f"  DNS      : domain={dns_cfg['domain']}  upstream={upstream}")
        records = dns_cfg.get("records", [])
        if records:
            print(f"             {len(records)} static record(s)")

    if dhcp_cfg.get("start"):
        print(f"  DHCP     : {dhcp_cfg['start']} – {dhcp_cfg['end']}  lease={dhcp_cfg.get('lease_time', '24h')}")

    if fw_cfg.get("lan_subnet"):
        flags = [k.replace("allow_", "").replace("_from_lan", "") for k, v in fw_cfg.items() if k.startswith("allow_") and v]
        print(f"  Firewall : LAN subnet {fw_cfg['lan_subnet']}  allow: {', '.join(flags) or 'none'}")

    if user_cfg and user_cfg.get("username"):
        sudo_note = " (sudo)" if user_cfg.get("sudo") else ""
        print(f"  User     : {user_cfg['username']}  shell={user_cfg.get('shell', '/bin/bash')}{sudo_note}")

    print()
    if not _prompt_yn("Apply these changes?", default=True):
        print("  Aborted — no changes made.")
        sys.exit(0)


# ---------------------------------------------------------------------------
# Interactive wizard — config gathering
# ---------------------------------------------------------------------------

_SCENARIOS: list[tuple[str, str]] = [
    ("gateway",  "Full gateway — networking + firewall + DNS/DHCP + host user"),
    ("firewall", "Firewall rules only"),
    ("dns-dhcp", "DNS and DHCP only (via dnsmasq)"),
]


def _gather_server(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "host": args.host or _prompt("Server URL", "http://localhost:8000"),
        "username": args.username or _prompt("Username", "admin"),
        "password": args.password or _prompt("Password", secret=True),
    }


def _fetch_interfaces(server: dict[str, Any]) -> dict[str, Any]:
    """Return {name: info} from /networking/identify, falling back to /networking/interfaces."""
    def _extract(data: dict[str, Any]) -> dict[str, Any]:
        nested = data.get("interfaces")
        return nested if isinstance(nested, dict) else data

    try:
        client = FFClient(
            server.get("host", "http://localhost:8000"),
            server.get("username", "admin"),
            server.get("password", "admin"),
        )
        try:
            ifaces = _extract(client.get("/v1/networking/identify"))
            if ifaces:
                return ifaces
        except FFError:
            pass
        return _extract(client.get("/v1/networking/interfaces"))
    except FFError:
        return {}


def _pick_interface(prompt: str, ifaces: dict[str, Any], exclude: str | None = None) -> str:
    available = [(name, info) for name, info in ifaces.items() if name != exclude]
    if not available:
        return _prompt(prompt, default=None)
    options: list[tuple[str, str]] = []
    for name, info in available:
        state = ""
        if isinstance(info, dict):
            link = info.get("link") or {}
            s = (link.get("state") if isinstance(link, dict) else None) or info.get("state")
            if s:
                state = f"  [{s}]"
        options.append((name, f"{name}{state}"))
    options.append(("__other__", "Other (enter manually)"))
    choice = _prompt_choice(prompt, options)
    return _prompt(prompt, default=None) if choice == "__other__" else choice


def _gather_network(server: dict[str, Any]) -> dict[str, Any]:
    print("\n  -- Network interfaces --")
    ifaces = _fetch_interfaces(server)
    if not ifaces:
        _print_warn("Could not fetch interfaces from server — enter names manually.")

    wan_iface = _pick_interface("WAN interface", ifaces)
    wan_mode = _prompt_choice("WAN mode", [("dhcp", "DHCP (automatic)"), ("static", "Static IP")])
    wan: dict[str, Any] = {"interface": wan_iface, "mode": wan_mode}
    if wan_mode == "static":
        wan["address"] = _prompt("WAN address (CIDR, e.g. 203.0.113.5/24)")
        wan["gateway"] = _prompt("WAN gateway IP")

    lan_iface = _pick_interface("LAN interface", ifaces, exclude=wan_iface)
    lan_address = _prompt("LAN address (CIDR)", "192.168.0.1/24")
    return {"wan": wan, "lan": {"interface": lan_iface, "address": lan_address}}


def _gather_dns() -> dict[str, Any]:
    print("\n  -- DNS --")
    domain = _prompt("Local domain name", "home.lan")
    upstream_raw = _prompt("Upstream DNS servers (comma-separated)", "8.8.8.8,1.1.1.1")
    upstream = [s.strip() for s in upstream_raw.split(",") if s.strip()]
    return {"domain": domain, "upstream": upstream, "records": []}


def _gather_dhcp() -> dict[str, Any]:
    print("\n  -- DHCP --")
    start = _prompt("DHCP range start", "192.168.0.100")
    end = _prompt("DHCP range end", "192.168.0.200")
    lease_time = _prompt("Lease time", "24h")
    return {"start": start, "end": end, "lease_time": lease_time}


def _gather_firewall() -> dict[str, Any]:
    print("\n  -- Firewall --")
    lan_subnet = _prompt("LAN subnet to allow traffic from (CIDR)", "192.168.0.0/24")
    allow_ssh = _prompt_yn("Allow SSH from LAN?", True)
    allow_http = _prompt_yn("Allow HTTP from LAN?", True)
    allow_https = _prompt_yn("Allow HTTPS from LAN?", True)
    return {
        "lan_subnet": lan_subnet,
        "allow_ssh_from_lan": allow_ssh,
        "allow_http_from_lan": allow_http,
        "allow_https_from_lan": allow_https,
    }


def _gather_user() -> dict[str, Any]:
    print("\n  -- Host user --")
    username = _prompt("New username")
    shell = _prompt("Shell", "/bin/bash")
    sudo = _prompt_yn("Grant sudo rights?", True)
    return {"username": username, "shell": shell, "sudo": sudo}


def interactive_wizard(args: argparse.Namespace) -> dict[str, Any]:
    _print_header("FastFirewall Bootstrap Wizard")
    cfg: dict[str, Any] = {}
    cfg["server"] = _gather_server(args)
    scenario = _prompt_choice("Choose a scenario", _SCENARIOS)
    cfg["scenario"] = scenario

    if scenario == "gateway":
        cfg["network"] = _gather_network(cfg["server"])
        cfg["hostname"] = _prompt("System hostname", "gateway")
        cfg["dns"] = _gather_dns()
        cfg["dhcp"] = _gather_dhcp()
        cfg["firewall"] = _gather_firewall()
        if _prompt_yn("Create a new host user?", True):
            cfg["user"] = _gather_user()

    elif scenario == "firewall":
        cfg["firewall"] = _gather_firewall()
        if _prompt_yn("Create a new host user?", False):
            cfg["user"] = _gather_user()

    elif scenario == "dns-dhcp":
        lan_address = _prompt("LAN address (CIDR, used for DNS/DHCP binding)", "192.168.0.1/24")
        cfg["network"] = {"lan": {"address": lan_address}}
        cfg["dns"] = _gather_dns()
        cfg["dhcp"] = _gather_dhcp()
        if _prompt_yn("Create a new host user?", False):
            cfg["user"] = _gather_user()

    if not args.save:
        print()
        save_path = input("  Save session to file (leave blank to skip): ").strip()
        if save_path:
            args.save = save_path
        else:
            _print_warn("Session not saved — use --save <file> to record API calls for replay with --apply.")

    return cfg


# ---------------------------------------------------------------------------
# Scenario dispatch
# ---------------------------------------------------------------------------


def _run_scenario(client: FFClient, cfg: dict[str, Any]) -> None:
    scenario = cfg.get("scenario", "gateway")
    if scenario == "gateway":
        run_gateway(client, cfg)
    elif scenario == "firewall":
        run_firewall_only(client, cfg)
    elif scenario == "dns-dhcp":
        run_dns_dhcp(client, cfg)
    else:
        print(f"Unknown scenario: {scenario!r}. Choose: gateway, firewall, dns-dhcp",
              file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Config file loading
# ---------------------------------------------------------------------------


def load_config(path: str) -> dict[str, Any]:
    with open(path) as fh:
        if path.endswith(".json"):
            return json.load(fh)
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def replay_session(
    replay_path: str,
    host: str | None,
    username: str | None,
    password: str | None,
) -> None:
    _print_header(f"Replaying {replay_path}")

    with open(replay_path) as fh:
        entries: list[dict[str, Any]] = json.load(fh)

    if not entries:
        _print_warn("Replay file is empty.")
        return

    # Derive host from the first logged URL so we can re-map paths
    first_url = entries[0]["url"]
    parsed = urlparse(first_url)
    default_host = f"{parsed.scheme}://{parsed.netloc}"

    actual_host = host or default_host
    actual_username = username or _prompt("Username", "admin")
    actual_password = password or _prompt("Password", secret=True)

    client = FFClient(actual_host, actual_username, actual_password)

    print(f"\n  Replaying {len(entries)} requests against {actual_host}\n")

    for i, entry in enumerate(entries, 1):
        method = entry["method"]
        original_url = entry["url"]
        body = entry.get("body")
        description = entry.get("description", "")

        # Re-map path to the actual host (handles host override)
        parsed_entry = urlparse(original_url)
        path = parsed_entry.path
        if parsed_entry.query:
            path += "?" + parsed_entry.query

        print(f"  [{i}/{len(entries)}] {method} {path}  — {description}")
        try:
            client.request(method, path, body, description=description)
            _print_ok("OK")
        except FFError as exc:
            _print_warn(str(exc))
            if not _prompt_yn("Continue despite error?", True):
                sys.exit(1)

    _print_header("Replay complete")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bootstrap",
        description="FastFirewall bootstrap wizard — configure common appliance scenarios via the API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Scenarios:
              gateway    Full router/gateway: networking, firewall, DNS/DHCP, host user
              firewall   Minimal: firewall rules only
              dns-dhcp   DNS and DHCP via dnsmasq only

            Examples:
              # Interactive wizard
              uv run tools/bootstrap.py

              # Run from a config file (non-interactive)
              uv run tools/bootstrap.py --config tools/examples/gateway.yaml

              # Interactive wizard + save every API call for later replay
              uv run tools/bootstrap.py --save my-setup.json

              # Apply a previously saved session (re-authenticates fresh)
              uv run tools/bootstrap.py --apply my-setup.json

              # Apply against a different server
              uv run tools/bootstrap.py --apply my-setup.json --host http://10.0.0.1:8000
        """),
    )
    parser.add_argument("--config", metavar="FILE",
                        help="YAML or JSON config file; skips interactive prompts")
    parser.add_argument("--save", metavar="FILE",
                        help="Write all API calls to FILE as a JSON session log")
    parser.add_argument("--apply", metavar="FILE",
                        help="Apply a previously saved JSON session log")
    parser.add_argument("--host", metavar="URL",
                        help="Server base URL (default: http://localhost:8000)")
    parser.add_argument("--username", "-u", metavar="USER", help="API username")
    parser.add_argument("--password", "-p", metavar="PASS",
                        help="API password (avoid on shared systems; prefer the interactive prompt)")

    args = parser.parse_args()

    try:
        if args.apply:
            replay_session(args.apply, args.host, args.username, args.password)
            return

        if args.config:
            cfg = load_config(args.config)
            if args.host:
                cfg.setdefault("server", {})["host"] = args.host
            if args.username:
                cfg.setdefault("server", {})["username"] = args.username
            if args.password:
                cfg.setdefault("server", {})["password"] = args.password
        else:
            cfg = interactive_wizard(args)

        server = cfg.get("server", {})
        host = server.get("host", "http://localhost:8000")

        if args.save:
            # Plan pass: build the full call list without touching the server,
            # then write the file before the confirm prompt so it always exists.
            plan = FFClient(host, "", "", export_path=args.save, simulate=True)
            _run_scenario(plan, cfg)
            plan.flush_export()

        _confirm_apply(cfg)

        client = FFClient(
            host,
            server.get("username", "admin"),
            server.get("password", "admin"),
        )
        _run_scenario(client, cfg)

    except FFError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
