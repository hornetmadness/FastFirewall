"""
Networking Plugin
─────────────────
Manages network interfaces and routes declaratively via systemd-networkd.
Desired state is stored in a JSON file; call POST /apply to push it to the
running kernel via INI-format .network files in /etc/systemd/network/.

Routes mount at /v1/networking/.

Events emitted:
  networking.interface.configured – payload: {name, addresses?, link?}
  networking.interface.removed    – payload: {name}
  networking.route.added          – payload: {route_id, to}
  networking.route.removed        – payload: {route_id, to}
  networking.aliases_updated      – payload: {aliases: {alias: iface, ...}}
  networking.applied              – payload: {success, returncode}

Sysctl management is delegated to the host plugin. To set a sysctl from
this plugin emit host.sysctl.set instead of calling sysctl directly.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
import socket
import subprocess
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

from pyroute2 import IPRoute

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator
from pyinfra.operations import files as files_ops

from infra import pyinfra_run_batch
from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, MacroProviderPlugin, Service
from plugin_system.core.events import Event, bus


# ── module-level constants ─────────────────────────────────────────────────────

_SYS_NET_DIR = Path("/sys/class/net")

# Linux IFF_* flag bits used for state/loopback detection
_IFF_UP       = 0x0001
_IFF_LOOPBACK = 0x0008

# RTPROT_* values used to skip kernel-managed and redirect routes
_RTPROT_REDIRECT = 1
_RTPROT_KERNEL   = 2

# proto int → name string (subset used by ip route show)
_RTPROT_NAMES: dict[int, str] = {
    0: "unspec", 1: "redirect", 2: "kernel", 3: "boot", 4: "static",
    16: "dhcp", 42: "babel", 186: "bgp", 187: "isis", 188: "ospf",
    189: "rip", 192: "eigrp",
}


# ── Pydantic models ────────────────────────────────────────────────────────────

def _validate_cidr(value: str) -> str:
    """Accept a host-address-with-prefix like '192.168.1.1/24' or '::1/128'."""
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        raise ValueError(f"{value!r} is not a valid CIDR address (e.g. '192.168.1.1/24')")
    return value


class LinkConfig(BaseModel):
    state: Optional[Literal["up", "down"]] = None
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)
    kind: Optional[str] = Field(default=None, max_length=16)
    master: Optional[str] = Field(default=None, max_length=15)


class WifiConfig(BaseModel):
    ssid: str = Field(max_length=32)
    psk: str = Field(max_length=64)


class WireguardPeer(BaseModel):
    public_key: str = Field(max_length=64)
    allowed_ips: list[Annotated[str, Field(max_length=43)]] = Field(default_factory=list)
    endpoint: Optional[str] = Field(default=None, max_length=253)
    preshared_key: Optional[str] = Field(default=None, max_length=64)
    persistent_keepalive: Optional[int] = Field(default=None, ge=0, le=65535)


class WireguardConfig(BaseModel):
    private_key: str = Field(max_length=64)
    listen_port: Optional[int] = Field(default=None, ge=1, le=65535)
    peers: list[WireguardPeer] = Field(default_factory=list)


class InterfaceUpdate(BaseModel):
    addresses: Optional[list[str]] = None
    link: Optional[LinkConfig] = None
    dhcp4: Optional[bool] = None
    dhcp6: Optional[bool] = None
    wifi: Optional[WifiConfig] = None
    wireguard: Optional[WireguardConfig] = None

    @field_validator("addresses", mode="before")
    @classmethod
    def validate_addresses(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("addresses must be a list")
        return [_validate_cidr(addr) for addr in v]


BondMode = Literal[
    "802.3ad", "active-backup", "balance-rr", "balance-xor",
    "broadcast", "balance-tlb", "balance-alb",
]


class BondCreate(BaseModel):
    name: str = Field(max_length=15)
    mode: BondMode = "802.3ad"
    members: list[Annotated[str, Field(max_length=15)]] = Field(min_length=1)
    addresses: Optional[list[str]] = None
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)
    ad_lacp_rate: Optional[Literal["slow", "fast"]] = None
    xmit_hash_policy: Optional[Literal[
        "layer2", "layer2+3", "layer3+4", "encap2+3", "encap3+4", "vlan+srcmac"
    ]] = None
    miimon: Optional[int] = Field(default=None, ge=0, le=10000)
    updelay: Optional[int] = Field(default=None, ge=0, le=60000)
    downdelay: Optional[int] = Field(default=None, ge=0, le=60000)
    min_links: Optional[int] = Field(default=None, ge=0, le=64)

    @field_validator("addresses", mode="before")
    @classmethod
    def validate_addresses(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("addresses must be a list")
        return [_validate_cidr(addr) for addr in v]


class BondUpdate(BaseModel):
    mode: Optional[BondMode] = None
    members: Optional[list[Annotated[str, Field(max_length=15)]]] = None
    addresses: Optional[list[str]] = None
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)
    ad_lacp_rate: Optional[Literal["slow", "fast"]] = None
    xmit_hash_policy: Optional[Literal[
        "layer2", "layer2+3", "layer3+4", "encap2+3", "encap3+4", "vlan+srcmac"
    ]] = None
    miimon: Optional[int] = Field(default=None, ge=0, le=10000)
    updelay: Optional[int] = Field(default=None, ge=0, le=60000)
    downdelay: Optional[int] = Field(default=None, ge=0, le=60000)
    min_links: Optional[int] = Field(default=None, ge=0, le=64)

    @field_validator("addresses", mode="before")
    @classmethod
    def validate_addresses(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("addresses must be a list")
        return [_validate_cidr(addr) for addr in v]


class BondAddMember(BaseModel):
    interface: str = Field(max_length=15)


class BridgeCreate(BaseModel):
    name: str = Field(max_length=15)
    members: list[Annotated[str, Field(max_length=15)]] = Field(default_factory=list)
    addresses: Optional[list[str]] = None
    stp: bool = False
    forward_delay_sec: float = Field(default=0.0, ge=0.0, le=30.0)
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)

    @field_validator("addresses", mode="before")
    @classmethod
    def validate_addresses(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("addresses must be a list")
        return [_validate_cidr(addr) for addr in v]


class BridgeUpdate(BaseModel):
    members: Optional[list[Annotated[str, Field(max_length=15)]]] = None
    addresses: Optional[list[str]] = None
    stp: Optional[bool] = None
    forward_delay_sec: Optional[float] = Field(default=None, ge=0.0, le=30.0)
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)

    @field_validator("addresses", mode="before")
    @classmethod
    def validate_addresses(cls, v: object) -> object:
        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("addresses must be a list")
        return [_validate_cidr(addr) for addr in v]


class BridgeMemberAdd(BaseModel):
    interface: str = Field(max_length=15)


class RouteCreate(BaseModel):
    to: str = Field(max_length=43)
    via: Optional[str] = Field(default=None, max_length=39)
    dev: Optional[str] = Field(default=None, max_length=15)
    preference: Optional[int] = None
    table: Optional[int] = None

    @field_validator("to")
    @classmethod
    def validate_to(cls, v: str) -> str:
        if v == "default":
            return v
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"{v!r} is not 'default' or a valid CIDR network (e.g. '10.0.0.0/8')")
        return v

    @field_validator("via")
    @classmethod
    def validate_via(cls, v: object) -> object:
        if v is None:
            return v
        try:
            ipaddress.ip_address(str(v))
        except ValueError:
            raise ValueError(f"{v!r} is not a valid IP address")
        return v


class ImportInterfacesRequest(BaseModel):
    names: Optional[list[Annotated[str, Field(max_length=15)]]] = None
    overwrite: bool = False


class ImportRoutesRequest(BaseModel):
    destinations: Optional[list[Annotated[str, Field(max_length=43)]]] = None
    overwrite: bool = False


class AliasCreate(BaseModel):
    interface: str = Field(max_length=15)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("interface must not be empty")
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_:.@-]*$', v):
            raise ValueError(f"{v!r} is not a valid interface name")
        return v


class WireguardPeerUpdate(BaseModel):
    allowed_ips: Optional[list[Annotated[str, Field(max_length=43)]]] = None
    endpoint: Optional[str] = Field(default=None, max_length=253)
    preshared_key: Optional[str] = Field(default=None, max_length=64)
    persistent_keepalive: Optional[int] = Field(default=None, ge=0, le=65535)


_ALIAS_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')

_LO_ADDRESSES = ["127.0.0.1/8", "::1/128"]


def _validate_host(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("host must not be empty")
    if re.search(r"[;&|`$<>()\n\r]", value):
        raise ValueError(f"{value!r} contains invalid characters")
    return value


class PingRequest(BaseModel):
    host: str
    count: int = Field(default=4, ge=1, le=100)
    timeout: int = Field(default=30, ge=1, le=120)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host(v)


class MtrRequest(BaseModel):
    host: str
    count: int = Field(default=10, ge=1, le=100)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host(v)


# ── state diff ─────────────────────────────────────────────────────────────────

def _diff_state(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    diff: dict[str, Any] = {}
    for section in ("interfaces", "routes"):
        o: dict = old.get(section) or {}
        n: dict = new.get(section) or {}
        added = {k: n[k] for k in n if k not in o}
        removed = {k: o[k] for k in o if k not in n}
        modified = {k: {"from": o[k], "to": n[k]} for k in n if k in o and o[k] != n[k]}
        if added or removed or modified:
            diff[section] = {}
            if added:
                diff[section]["added"] = added
            if removed:
                diff[section]["removed"] = removed
            if modified:
                diff[section]["modified"] = modified
    return diff


# ── bond procfs parser ─────────────────────────────────────────────────────────

def _parse_proc_bond(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    slaves: list[dict[str, Any]] = []
    current_slave: dict[str, Any] | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Slave Interface:"):
            if current_slave:
                slaves.append(current_slave)
            current_slave = {"name": line.split(":", 1)[1].strip()}
        elif current_slave is not None:
            if ":" in line:
                key, _, val = line.partition(":")
                current_slave[key.strip().lower().replace(" ", "_")] = val.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            result[key.strip().lower().replace(" ", "_")] = val.strip()
    if current_slave:
        slaves.append(current_slave)
    if slaves:
        result["slaves"] = slaves
    return result


# ── plugin class ───────────────────────────────────────────────────────────────

class NetworkingPlugin(PluginBase, ApiRouterPlugin, MacroProviderPlugin):
    services = [Service.NETWORKING]

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "networking_state.json", self.logger,
            mutation_model="deferred", data_dir=self.data_dir,
        )
        self._interfaces: dict[str, dict[str, Any]] = {}
        self._routes: dict[str, dict[str, Any]] = {}
        self._aliases: dict[str, str] = {}
        if not self.config.get("ignore_state_on_boot", False):
            self._load_state()
            if not any([self._interfaces, self._routes]):
                self._import_state_from_system()
            else:
                self._apply_state()
        self.logger.info(
            "Networking plugin loaded: %d interface(s), %d route(s), %d alias(es)",
            len(self._interfaces), len(self._routes), len(self._aliases),
        )
        if self._aliases:
            bus.emit(Event(
                name="networking.aliases_updated",
                payload={"aliases": dict(self._aliases)},
            ))
        self.add_macro_namespace("interface", self._resolve_interface_macro)
        self._register_routes()
        self._sync_os_boot_service()

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("Networking plugin shut down — state saved")

    # ── state persistence ──────────────────────────────────────────────

    def _load_state(self) -> None:
        desired = self._state_file.load_desired(default={})
        self._interfaces = desired.get("interfaces", {})
        self._routes = desired.get("routes", {})
        self._aliases = desired.get("aliases", {})
        self._ensure_default_aliases()

    def _resolve_interface_macro(self, *segments: str) -> Any:
        if len(segments) < 2:
            return None
        alias, field = segments[0], segments[1]
        device = self._aliases.get(alias)
        if device is None:
            return None
        if field == "name":
            return device
        addresses = self._interfaces.get(device, {}).get("addresses") or (
            _LO_ADDRESSES if device == "lo" else []
        )
        if field == "address":
            return [str(ipaddress.ip_interface(a).ip) for a in addresses]
        if field == "net_addr":
            return [str(ipaddress.ip_interface(a).network) for a in addresses]
        return None

    def macro_snapshot(self) -> dict[str, dict[str, Any]]:
        entries: dict[str, Any] = {}
        for alias, device in self._aliases.items():
            entries[f"{alias}.name"] = device
            addresses = self._interfaces.get(device, {}).get("addresses") or (
                _LO_ADDRESSES if device == "lo" else []
            )
            addrs = [str(ipaddress.ip_interface(a).ip) for a in addresses]
            if addrs:
                entries[f"{alias}.address"] = addrs
            nets = [str(ipaddress.ip_interface(a).network) for a in addresses]
            if nets:
                entries[f"{alias}.net_addr"] = nets
        return {"interface": entries}

    def _ensure_default_aliases(self) -> None:
        for name in self._interfaces:
            self._aliases.setdefault(name, name)
        self._aliases.setdefault("lo", "lo")

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps({
            "interfaces": self._interfaces,
            "routes": self._routes,
            "aliases": self._aliases,
        }))

    # ── pyinfra wrapper ────────────────────────────────────────────────

    def _pyinfra_run(self, op: Any, **kwargs: Any) -> None:
        norm_kwargs = {
            k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
            for k, v in kwargs.items()
        }
        success, err = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])[0]
        if not success:
            raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")

    # ── ip command helpers ─────────────────────────────────────────────

    def _ip_addr_show(self) -> list[dict[str, Any]]:
        entries: dict[int, dict[str, Any]] = {}
        with IPRoute() as ipr:
            for link in ipr.get_links():
                idx = link["index"]
                attrs = dict(link["attrs"])
                flags_int = link.get("flags", 0)
                flag_names: list[str] = []
                if flags_int & _IFF_UP:       flag_names.append("UP")
                if flags_int & _IFF_LOOPBACK: flag_names.append("LOOPBACK")
                entries[idx] = {
                    "ifname": attrs.get("IFLA_IFNAME", ""),
                    "flags": flag_names,
                    "mtu": attrs.get("IFLA_MTU"),
                    "address": attrs.get("IFLA_ADDRESS"),
                    "addr_info": [],
                }
            for addr in ipr.get_addr():
                idx = addr["index"]
                if idx not in entries:
                    continue
                family = addr.get("family")
                if family == socket.AF_INET:
                    fam_str = "inet"
                elif family == socket.AF_INET6:
                    fam_str = "inet6"
                else:
                    continue
                a = dict(addr["attrs"])
                local = a.get("IFA_LOCAL") or a.get("IFA_ADDRESS")
                prefixlen = addr.get("prefixlen")
                if local and prefixlen is not None:
                    entries[idx]["addr_info"].append({
                        "family": fam_str,
                        "local": local,
                        "prefixlen": prefixlen,
                    })
        return list(entries.values())

    def _ip_route_show(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        with IPRoute() as ipr:
            ifmap = {
                link["index"]: dict(link["attrs"]).get("IFLA_IFNAME", "")
                for link in ipr.get_links()
            }
            for family in (socket.AF_INET, socket.AF_INET6):
                for route in ipr.get_routes(family=family):
                    attrs = dict(route["attrs"])
                    proto = route.get("proto", 0)
                    dst_addr = attrs.get("RTA_DST")
                    dst_len = route.get("dst_len", 0)
                    dst = f"{dst_addr}/{dst_len}" if dst_addr and dst_len else "default"
                    entry: dict[str, Any] = {
                        "dst": dst,
                        "protocol": _RTPROT_NAMES.get(proto, str(proto)),
                    }
                    gw = attrs.get("RTA_GATEWAY")
                    if gw:
                        entry["gateway"] = gw
                    oif = attrs.get("RTA_OIF")
                    if oif and oif in ifmap:
                        entry["dev"] = ifmap[oif]
                    metric = attrs.get("RTA_PRIORITY")
                    if metric is not None:
                        entry["metric"] = metric
                    result.append(entry)
        return result

    # ── systemd-networkd file builders ────────────────────────────────

    @staticmethod
    def _networkd_filename(name: str) -> str:
        return f"10-ff-{name}.network"

    def _build_networkd_file(
        self, name: str, iface: dict[str, Any], routes: list[dict[str, Any]]
    ) -> str:
        lines = ["[Match]", f"Name={name}", ""]

        net_lines: list[str] = []
        for addr in (iface.get("addresses") or []):
            net_lines.append(f"Address={addr}")

        dhcp4 = iface.get("dhcp4", False)
        dhcp6 = iface.get("dhcp6", False)
        if dhcp4 and dhcp6:
            net_lines.append("DHCP=yes")
        elif dhcp4:
            net_lines.append("DHCP=ipv4")
        elif dhcp6:
            net_lines.append("DHCP=ipv6")
        else:
            net_lines.append("DHCP=no")

        kind = (iface.get("link") or {}).get("kind")
        if kind == "wifi":
            net_lines.append("IgnoreCarrierLoss=3s")

        lines.append("[Network]")
        lines.extend(net_lines)

        link = iface.get("link") or {}
        link_lines: list[str] = []
        if link.get("mtu") is not None:
            link_lines.append(f"MTUBytes={link['mtu']}")
        state = link.get("state")
        if state == "up":
            link_lines.append("ActivationPolicy=always-up")
        elif state == "down":
            link_lines.append("ActivationPolicy=always-down")
        if link_lines:
            lines.append("")
            lines.append("[Link]")
            lines.extend(link_lines)

        for route in routes:
            lines.append("")
            lines.append("[Route]")
            dst = route.get("to", "")
            if dst == "default":
                dst = "0.0.0.0/0"
            lines.append(f"Destination={dst}")
            if route.get("via") is not None:
                lines.append(f"Gateway={route['via']}")
            if route.get("preference") is not None:
                lines.append(f"Metric={route['preference']}")
            if route.get("table") is not None:
                lines.append(f"Table={route['table']}")

        return "\n".join(lines) + "\n"

    def _build_netdev_file(self, name: str, iface: dict[str, Any]) -> str:
        kind = (iface.get("link") or {}).get("kind", "")
        lines = ["[NetDev]", f"Name={name}", f"Kind={kind}", ""]

        if kind == "bond":
            bond = iface.get("bond") or {}
            lines.append("[Bond]")
            lines.append(f"Mode={bond.get('mode', '802.3ad')}")
            if bond.get("miimon") is not None:
                lines.append(f"MIIMonitorSec={bond['miimon'] / 1000}")
            if bond.get("ad_lacp_rate") is not None:
                lines.append(f"LACPTransmitRate={bond['ad_lacp_rate']}")
            if bond.get("xmit_hash_policy") is not None:
                lines.append(f"TransmitHashPolicy={bond['xmit_hash_policy']}")
            if bond.get("updelay") is not None:
                lines.append(f"UpDelaySec={bond['updelay'] / 1000}")
            if bond.get("downdelay") is not None:
                lines.append(f"DownDelaySec={bond['downdelay'] / 1000}")
            if bond.get("min_links") is not None:
                lines.append(f"MinLinks={bond['min_links']}")

        elif kind == "bridge":
            bridge = iface.get("bridge") or {}
            lines.append("[Bridge]")
            lines.append(f"STP={'yes' if bridge.get('stp', False) else 'no'}")
            lines.append(f"ForwardDelaySec={bridge.get('forward_delay_sec', 0.0)}")

        elif kind == "wireguard":
            wg = iface.get("wireguard") or {}
            lines.append("[WireGuard]")
            if wg.get("private_key"):
                lines.append(f"PrivateKey={wg['private_key']}")
            if wg.get("listen_port") is not None:
                lines.append(f"ListenPort={wg['listen_port']}")
            for peer in (wg.get("peers") or []):
                lines.append("")
                lines.append("[WireGuardPeer]")
                lines.append(f"PublicKey={peer['public_key']}")
                for ip in (peer.get("allowed_ips") or []):
                    lines.append(f"AllowedIPs={ip}")
                if peer.get("endpoint"):
                    lines.append(f"Endpoint={peer['endpoint']}")
                if peer.get("preshared_key"):
                    lines.append(f"PresharedKey={peer['preshared_key']}")
                if peer.get("persistent_keepalive") is not None:
                    lines.append(f"PersistentKeepalive={peer['persistent_keepalive']}")

        return "\n".join(lines) + "\n"

    def _find_route_interface(self, route: dict[str, Any]) -> str | None:
        via = route.get("via")
        if not via:
            return None
        try:
            gw = ipaddress.ip_address(via)
        except ValueError:
            return None
        for name, iface in self._interfaces.items():
            for addr in (iface.get("addresses") or []):
                try:
                    net = ipaddress.ip_interface(addr).network
                    if gw in net:
                        return name
                except ValueError:
                    continue
        return None

    def _build_all_networkd_configs(self) -> dict[str, str]:
        # Assign routes to interfaces
        interface_routes: dict[str, list[dict[str, Any]]] = {n: [] for n in self._interfaces}
        unroutable: list[str] = []

        for route in self._routes.values():
            dev = route.get("dev")
            if dev and dev in interface_routes:
                interface_routes[dev].append(route)
            elif dev:
                pass  # dev not managed — silently skip
            else:
                matched = self._find_route_interface(route)
                if matched:
                    interface_routes[matched].append(route)
                else:
                    unroutable.append(route.get("to", "unknown"))

        if unroutable:
            raise ValueError(
                f"Unroutable routes (no dev and no gateway subnet match): {', '.join(unroutable)}"
            )

        files: dict[str, str] = {}

        for name, iface in self._interfaces.items():
            link = iface.get("link") or {}
            kind = link.get("kind")
            master = link.get("master")

            if master:
                # Member interface — bare .network pointing to virtual device
                parent_kind = (self._interfaces.get(master, {}).get("link") or {}).get("kind")
                net_lines = ["[Match]", f"Name={name}", "", "[Network]"]
                if parent_kind == "bond":
                    net_lines.append(f"Bond={master}")
                elif parent_kind == "bridge":
                    net_lines.append(f"Bridge={master}")
                files[self._networkd_filename(name)] = "\n".join(net_lines) + "\n"

            elif kind in ("bond", "bridge", "wireguard"):
                files[f"10-ff-{name}.netdev"] = self._build_netdev_file(name, iface)
                files[self._networkd_filename(name)] = self._build_networkd_file(
                    name, iface, interface_routes.get(name, [])
                )

            else:
                # Regular interface or WiFi
                files[self._networkd_filename(name)] = self._build_networkd_file(
                    name, iface, interface_routes.get(name, [])
                )

        return files

    # ── networkd file writer / pruner ──────────────────────────────────

    @property
    def _networkd_staging_dir(self) -> Path:
        return self.data_dir / "networkd"

    def _write_networkd_files(self, files: dict[str, str]) -> None:
        staging = self._networkd_staging_dir
        staging.mkdir(parents=True, exist_ok=True)
        for filename, content in files.items():
            (staging / filename).write_text(content)
            dest = f"/etc/systemd/network/{filename}"
            mode = "644"
            group: str | None = None
            if filename.endswith(".netdev"):
                iface_name = filename[len("10-ff-"):-len(".netdev")]
                kind = (self._interfaces.get(iface_name, {}).get("link") or {}).get("kind")
                if kind == "wireguard":
                    mode = "640"
                    group = "systemd-network"
            kwargs: dict[str, Any] = dict(
                name=f"Write {filename}",
                src=str(staging / filename),
                dest=dest,
                mode=mode,
                _sudo=True,
            )
            if group:
                kwargs["group"] = group
            self._pyinfra_run(files_ops.put, **kwargs)

    def _prune_networkd_files(self, active_names: set[str]) -> None:
        staging = self._networkd_staging_dir
        if not staging.exists():
            return
        for local_path in staging.glob("10-ff-*"):
            filename = local_path.name
            for suffix in (".network", ".netdev"):
                if filename.endswith(suffix):
                    iface_name = filename[len("10-ff-"):-len(suffix)]
                    if iface_name not in active_names:
                        local_path.unlink(missing_ok=True)
                        try:
                            self._pyinfra_run(
                                files_ops.file,
                                path=f"/etc/systemd/network/{filename}",
                                present=False,
                                _sudo=True,
                            )
                        except RuntimeError as exc:
                            self.logger.warning("Could not prune %s: %s", filename, exc)
                    break

    def _write_wpa_supplicant_configs(self) -> None:
        for name, iface in self._interfaces.items():
            if (iface.get("link") or {}).get("kind") != "wifi":
                continue
            wifi = iface.get("wifi")
            if not wifi:
                continue
            content = (
                "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n"
                "update_config=1\n\n"
                "network={\n"
                f'    ssid="{wifi["ssid"]}"\n'
                f'    psk="{wifi["psk"]}"\n'
                "}\n"
            )
            self._pyinfra_run(
                files_ops.put,
                name=f"Write wpa_supplicant config for {name}",
                src=io.StringIO(content),
                dest=f"/etc/wpa_supplicant/wpa_supplicant-{name}.conf",
                mode="600",
                _sudo=True,
            )
            bus.emit(Event(
                "initsys.service.start",
                payload={"service_name": f"wpa_supplicant@{name}.service"},
            ))

    # ── boot-time apply / import ───────────────────────────────────────

    def _apply_state(self) -> None:
        if not any([self._interfaces, self._routes]):
            return
        try:
            self.logger.info(
                "Applying networking config on boot: %d interface(s), %d route(s)",
                len(self._interfaces), len(self._routes),
            )
            files = self._build_all_networkd_configs()
            self._write_networkd_files(files)
            subprocess.run(
                ["sudo", "networkctl", "reload"],
                capture_output=True, text=True, timeout=15,
            )
            for name in self._interfaces:
                subprocess.run(
                    ["sudo", "networkctl", "reconfigure", name],
                    capture_output=True, text=True, timeout=10,
                )
            # Sync desired (aliases may have been added in-memory) then commit current = desired
            self._save_state()
            self._state_file.commit(self._desired_snapshot())
            self.logger.info("Re-applied networking config on boot via systemd-networkd")
        except Exception as exc:
            self.logger.warning("Could not re-apply networking config on boot: %s", exc)

    def _sync_os_boot_service(self) -> None:
        if self.config.get("use_systemd_networkd", False):
            for mgr in self.config.get("disable_os_managers", []):
                results = bus.emit(Event("initsys.service.disable", payload={"service_name": mgr}))
                if not results or not (results[0] or {}).get("success"):
                    self.logger.warning("Could not disable competing network manager %r", mgr)
            bus.emit(Event(
                "initsys.service.start",
                payload={"service_name": "systemd-networkd.service"},
            ))
        else:
            bus.emit(Event(
                "initsys.service.remove",
                payload={"service_name": "fastfirewall-networking"},
            ))

    def _import_state_from_system(self) -> None:
        try:
            addr_data = self._ip_addr_show()
            route_data = self._ip_route_show()
        except Exception as exc:
            self.logger.warning("Boot-time import failed: %s", exc)
            return

        for entry in addr_data:
            name = entry.get("ifname", "")
            flags = entry.get("flags") or []
            if "LOOPBACK" in flags:
                continue
            addr_info = entry.get("addr_info") or []
            addresses = []
            for ai in addr_info:
                if ai.get("family") in ("inet", "inet6"):
                    local = ai.get("local")
                    prefixlen = ai.get("prefixlen")
                    if local and prefixlen is not None:
                        addresses.append(f"{local}/{prefixlen}")
            iface_entry: dict[str, Any] = {"dhcp4": False, "dhcp6": False}
            if addresses:
                iface_entry["addresses"] = addresses
            link_entry: dict[str, Any] = {"state": "up" if "UP" in flags else "down"}
            if entry.get("mtu") is not None:
                link_entry["mtu"] = entry["mtu"]
            iface_entry["link"] = link_entry
            self._interfaces[name] = iface_entry

        for r in route_data:
            if r.get("protocol") in ("kernel", "redirect"):
                continue
            dst = r.get("dst", "default")
            route: dict[str, Any] = {"to": dst}
            if r.get("gateway") is not None:
                route["via"] = r["gateway"]
            if r.get("dev") is not None:
                route["dev"] = r["dev"]
            if r.get("metric") is not None:
                route["preference"] = r["metric"]
            route_id = hashlib.sha256(
                json.dumps(route, sort_keys=True).encode()
            ).hexdigest()[:16]
            self._routes[route_id] = route

        if self._interfaces or self._routes:
            self._ensure_default_aliases()
            self._state_file.save_and_commit(self._desired_snapshot())
            self.logger.info(
                "Boot-time import: %d interface(s), %d route(s), %d alias(es)",
                len(self._interfaces), len(self._routes), len(self._aliases),
            )

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route

        add("/status",                   self._status,                 methods=["GET"],    summary="Plugin status and counts")

        add("/interfaces",               self._show_interfaces,        methods=["GET"],    summary="Current interface state (ip -j addr show)")
        add("/interfaces/{name}",        self._show_interface,         methods=["GET"],    summary="Single interface running state")
        add("/identify",                 self._identify,               methods=["GET"],    summary="Identify physical interfaces via sysfs")

        add("/config/interfaces",        self._list_config_interfaces, methods=["GET"],    summary="List configured interfaces")
        add("/config/interfaces/import", self._import_interfaces,      methods=["POST"],   summary="Import existing interfaces from running state")
        add("/config/interfaces/{name}", self._get_config_interface,   methods=["GET"],    summary="Get one interface config")
        add("/config/interfaces/{name}", self._set_interface,          methods=["PUT"],    summary="Configure an interface")
        add("/config/interfaces/{name}", self._delete_interface,       methods=["DELETE"], summary="Remove interface from config")

        add("/config/interfaces/{name}/peers", self._list_wg_peers,    methods=["GET"],    summary="List WireGuard peers")
        add("/config/interfaces/{name}/peers", self._add_wg_peer,      methods=["POST"],   summary="Add WireGuard peer", status_code=201)
        add("/config/interfaces/{name}/peers/{peer_id}", self._get_wg_peer,    methods=["GET"],    summary="Get WireGuard peer")
        add("/config/interfaces/{name}/peers/{peer_id}", self._update_wg_peer, methods=["PUT"],    summary="Update WireGuard peer")
        add("/config/interfaces/{name}/peers/{peer_id}", self._delete_wg_peer, methods=["DELETE"], summary="Delete WireGuard peer")

        add("/config/routes",            self._list_routes,            methods=["GET"],    summary="List configured routes")
        add("/config/routes/import",     self._import_routes,          methods=["POST"],   summary="Import existing routes from running state")
        add("/config/routes",            self._add_route,              methods=["POST"],   summary="Add a route", status_code=201)
        add("/config/routes/{route_id}", self._delete_route,           methods=["DELETE"], summary="Remove a route")

        add("/config/bonds",             self._list_bonds,             methods=["GET"],    summary="List configured bonds")
        add("/config/bonds",             self._create_bond,            methods=["POST"],   summary="Create a bond interface", status_code=201)
        add("/config/bonds/{name}",      self._get_bond,               methods=["GET"],    summary="Get bond config")
        add("/config/bonds/{name}",      self._update_bond,            methods=["PUT"],    summary="Update bond config")
        add("/config/bonds/{name}",      self._delete_bond,            methods=["DELETE"], summary="Delete bond interface")
        add("/bonds/{name}/status",      self._get_bond_status,        methods=["GET"],    summary="Live bond status from /proc")
        add("/config/bonds/{name}/members", self._add_bond_member,     methods=["POST"],   summary="Add bond member", status_code=201)
        add("/config/bonds/{name}/members/{member}", self._delete_bond_member, methods=["DELETE"], summary="Remove bond member")

        add("/config/bridges",           self._list_bridges,           methods=["GET"],    summary="List configured bridges")
        add("/config/bridges",           self._create_bridge,          methods=["POST"],   summary="Create a bridge", status_code=201)
        add("/config/bridges/{name}",    self._get_bridge,             methods=["GET"],    summary="Get bridge config")
        add("/config/bridges/{name}",    self._update_bridge,          methods=["PUT"],    summary="Update bridge config")
        add("/config/bridges/{name}",    self._delete_bridge,          methods=["DELETE"], summary="Delete bridge interface")
        add("/config/bridges/{name}/members", self._add_bridge_member,  methods=["POST"],   summary="Add bridge member", status_code=201)
        add("/config/bridges/{name}/members/{member}", self._delete_bridge_member, methods=["DELETE"], summary="Remove bridge member")

        add("/config",                   self._get_config,             methods=["GET"],    summary="All systemd-networkd file contents")
        add("/config/diff",              self._diff,                   methods=["GET"],    summary="Diff between current (applied) and desired state")
        add("/apply",                    self._apply,                  methods=["POST"],   summary="Apply config via systemd-networkd")
        add("/check",                    self._check,                  methods=["POST"],   summary="Preview networkd files (dry-run)")
        add("/discard",                  self._discard,                methods=["POST"],   summary="Discard pending changes and restore last applied state")

        add("/config/aliases",           self._list_aliases,           methods=["GET"],    summary="List interface aliases")
        add("/config/aliases/{name}",    self._set_alias,              methods=["PUT"],    summary="Set an interface alias")
        add("/config/aliases/{name}",    self._delete_alias,           methods=["DELETE"], summary="Delete an interface alias")

        add("/ping",                     self._ping,                   methods=["POST"],   summary="Ping a host")
        add("/mtr",                      self._mtr,                    methods=["POST"],   summary="Run mtr traceroute to a host")

    # ── status ─────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "ff_managed": {
                "interfaces": len(self._interfaces),
                "routes": len(self._routes),
                "aliases": len(self._aliases),
            },
            "pending_changes": self._state_file.pending_changes,
            "state_file": str(self._state_file.path),
            "networkd_dir": "/etc/systemd/network",
            "networkd_prefix": "10-ff-",
            "networkd_staging_dir": str(self._networkd_staging_dir),
        }

    # ── live state ─────────────────────────────────────────────────────

    def _show_interfaces(self) -> dict:
        try:
            entries = self._ip_addr_show()
        except RuntimeError:
            self.logger.error("ip addr show failed")
            raise HTTPException(500, "Failed to read interface state; check server logs")
        interfaces: dict[str, Any] = {}
        for entry in entries:
            name = entry.get("ifname", "")
            flags = entry.get("flags") or []
            addr_info = entry.get("addr_info") or []
            addresses = [
                f"{ai['local']}/{ai['prefixlen']}"
                for ai in addr_info
                if ai.get("family") in ("inet", "inet6")
                and ai.get("local") and ai.get("prefixlen") is not None
            ]
            interfaces[name] = {
                "addresses": addresses,
                "link": {
                    "state": "up" if "UP" in flags else "down",
                    "mtu": entry.get("mtu"),
                    "address": entry.get("address"),
                },
                "ff_managed": name in self._interfaces,
            }
        return {"interfaces": interfaces, "source": "running"}

    def _show_interface(self, name: str) -> dict:
        try:
            entries = self._ip_addr_show()
        except RuntimeError:
            self.logger.error("ip addr show failed")
            raise HTTPException(500, "Failed to read interface state; check server logs")
        for entry in entries:
            if entry.get("ifname") == name:
                flags = entry.get("flags") or []
                addr_info = entry.get("addr_info") or []
                addresses = [
                    f"{ai['local']}/{ai['prefixlen']}"
                    for ai in addr_info
                    if ai.get("family") in ("inet", "inet6")
                    and ai.get("local") and ai.get("prefixlen") is not None
                ]
                return {
                    "name": name,
                    "addresses": addresses,
                    "link": {
                        "state": "up" if "UP" in flags else "down",
                        "mtu": entry.get("mtu"),
                        "address": entry.get("address"),
                    },
                    "ff_managed": name in self._interfaces,
                }
        raise HTTPException(404, f"Interface {name!r} not found in running state")

    def _identify(self) -> dict:
        result: dict[str, dict[str, str]] = {}
        try:
            for entry in _SYS_NET_DIR.iterdir():
                iface_name = entry.name
                perm_path = entry / "perm_hwaddr"
                addr_path = entry / "address"
                mac: str | None = None
                if perm_path.exists():
                    mac = perm_path.read_text().strip()
                elif addr_path.exists():
                    mac = addr_path.read_text().strip()
                if mac:
                    result[iface_name] = {"perm_address": mac}
        except OSError as exc:
            self.logger.error("Failed to read %s: %s", _SYS_NET_DIR, exc)
            raise HTTPException(500, "Failed to identify interfaces; check server logs")
        return result

    # ── managed config — interfaces ────────────────────────────────────

    def _list_config_interfaces(self) -> dict:
        return {
            "interfaces": [{"name": n, **cfg} for n, cfg in self._interfaces.items()],
            "count": len(self._interfaces),
        }

    def _get_config_interface(self, name: str) -> dict:
        if name not in self._interfaces:
            raise HTTPException(404, f"Interface {name!r} not in managed config")
        return {"name": name, **self._interfaces[name]}

    def _set_interface(self, name: str, body: InterfaceUpdate) -> dict:
        existing = dict(self._interfaces.get(name, {}))
        updates = body.model_dump(exclude_unset=True)
        if "link" in updates and updates["link"] is not None:
            updates["link"] = {k: v for k, v in updates["link"].items() if v is not None}
        if "wifi" in updates and updates["wifi"] is not None:
            updates["wifi"] = {k: v for k, v in updates["wifi"].items() if v is not None}
        if "wireguard" in updates and updates["wireguard"] is not None:
            updates["wireguard"] = {
                k: v for k, v in updates["wireguard"].items() if v is not None
            }
        existing.update(updates)
        existing.setdefault("dhcp4", False)
        existing.setdefault("dhcp6", False)
        self._interfaces[name] = existing
        self._aliases.setdefault(name, name)
        self._save_state()
        bus.emit(Event(
            name="networking.interface.configured",
            payload={"name": name, **existing},
        ))
        return {"name": name, **existing}

    def _delete_interface(self, name: str) -> dict:
        if name not in self._interfaces:
            raise HTTPException(404, f"Interface {name!r} not in managed config")
        del self._interfaces[name]
        self._save_state()
        bus.emit(Event(
            name="networking.interface.removed",
            payload={"name": name},
        ))
        return {"deleted": name}

    def _import_interfaces(self, body: ImportInterfacesRequest) -> dict:
        try:
            addr_data = self._ip_addr_show()
        except RuntimeError:
            self.logger.error("ip addr show failed during import")
            raise HTTPException(500, "Failed to read interface state; check server logs")

        running: dict[str, Any] = {}
        for entry in addr_data:
            iface_name = entry.get("ifname", "")
            flags = entry.get("flags") or []
            addr_info = entry.get("addr_info") or []
            addresses = [
                f"{ai['local']}/{ai['prefixlen']}"
                for ai in addr_info
                if ai.get("family") in ("inet", "inet6")
                and ai.get("local") and ai.get("prefixlen") is not None
            ]
            iface_entry: dict[str, Any] = {}
            if addresses:
                iface_entry["addresses"] = addresses
            iface_entry["link"] = {"state": "up" if "UP" in flags else "down"}
            running[iface_name] = iface_entry

        names_to_import = body.names if body.names is not None else list(running.keys())
        imported: list[str] = []
        skipped: list[str] = []
        not_found: list[str] = []

        for iface_name in names_to_import:
            if iface_name not in running:
                not_found.append(iface_name)
                continue
            if iface_name in self._interfaces and not body.overwrite:
                skipped.append(iface_name)
                continue
            entry = dict(running[iface_name])
            entry.setdefault("dhcp4", False)
            entry.setdefault("dhcp6", False)
            self._interfaces[iface_name] = entry
            self._aliases.setdefault(iface_name, iface_name)
            imported.append(iface_name)
            bus.emit(Event(
                name="networking.interface.configured",
                payload={"name": iface_name, **entry},
            ))

        if imported:
            self._save_state()

        return {"imported": imported, "skipped": skipped, "not_found": not_found}

    # ── managed config — routes ────────────────────────────────────────

    def _list_routes(self) -> dict:
        routes = [{"id": rid, **r} for rid, r in self._routes.items()]
        return {"routes": routes, "count": len(routes)}

    def _add_route(self, body: RouteCreate) -> dict:
        if body.dev is not None and body.dev not in self._interfaces:
            raise HTTPException(422, f"Interface {body.dev!r} is not in managed config")
        route = body.model_dump(exclude_none=True)
        route_id = hashlib.sha256(
            json.dumps(route, sort_keys=True).encode()
        ).hexdigest()[:16]
        if route_id in self._routes:
            raise HTTPException(409, f"Route to {route['to']!r} already exists using id {route_id}")
        self._routes[route_id] = route
        self._save_state()
        bus.emit(Event(
            name="networking.route.added",
            payload={"route_id": route_id, "to": route["to"]},
        ))
        return {"id": route_id, **route}

    def _delete_route(self, route_id: str) -> dict:
        if route_id not in self._routes:
            raise HTTPException(404, f"Route {route_id!r} not found")
        route = self._routes.pop(route_id)
        self._save_state()
        bus.emit(Event(
            name="networking.route.removed",
            payload={"route_id": route_id, "to": route.get("to")},
        ))
        return {"deleted": route_id}

    def _import_routes(self, body: ImportRoutesRequest) -> dict:
        try:
            route_data = self._ip_route_show()
        except RuntimeError:
            self.logger.error("ip route show failed during import")
            raise HTTPException(500, "Failed to read route state; check server logs")

        running_routes: list[dict[str, Any]] = []
        for r in route_data:
            if r.get("protocol") in ("kernel", "redirect"):
                continue
            dst = r.get("dst", "default")
            route: dict[str, Any] = {"to": dst}
            if r.get("gateway") is not None:
                route["via"] = r["gateway"]
            if r.get("dev") is not None:
                route["dev"] = r["dev"]
            if r.get("metric") is not None:
                route["preference"] = r["metric"]
            running_routes.append(route)

        if body.destinations is not None:
            running_routes = [r for r in running_routes if r.get("to") in body.destinations]

        not_found: list[str] = []
        if body.destinations is not None:
            found_destinations = {r.get("to") for r in running_routes}
            not_found = [d for d in body.destinations if d not in found_destinations]

        imported: list[str] = []
        skipped: list[str] = []

        for route in running_routes:
            route_id = hashlib.sha256(
                json.dumps(route, sort_keys=True).encode()
            ).hexdigest()[:16]
            if route_id in self._routes and not body.overwrite:
                skipped.append(route_id)
                continue
            self._routes[route_id] = route
            imported.append(route_id)
            bus.emit(Event(
                name="networking.route.added",
                payload={"route_id": route_id, "to": route["to"]},
            ))

        if imported:
            self._save_state()

        return {"imported": imported, "skipped": skipped, "not_found": not_found}

    # ── managed config — bonds ─────────────────────────────────────────

    def _list_bonds(self) -> dict:
        bonds = [
            {"name": n, **cfg}
            for n, cfg in self._interfaces.items()
            if (cfg.get("link") or {}).get("kind") == "bond"
        ]
        return {"bonds": bonds, "count": len(bonds)}

    def _create_bond(self, body: BondCreate) -> dict:
        if body.name in self._interfaces:
            raise HTTPException(409, f"Interface {body.name!r} already exists")
        for member in body.members:
            existing_master = (self._interfaces.get(member, {}).get("link") or {}).get("master")
            if existing_master and existing_master != body.name:
                raise HTTPException(409, f"Interface {member!r} is already a member of {existing_master!r}")

        bond_cfg: dict[str, Any] = {"mode": body.mode}
        for field in ("miimon", "ad_lacp_rate", "xmit_hash_policy", "updelay", "downdelay", "min_links"):
            val = getattr(body, field, None)
            if val is not None:
                bond_cfg[field] = val

        iface: dict[str, Any] = {
            "link": {"kind": "bond", "state": "up"},
            "bond": bond_cfg,
            "dhcp4": False,
            "dhcp6": False,
        }
        if body.addresses:
            iface["addresses"] = body.addresses
        if body.mtu is not None:
            iface["link"]["mtu"] = body.mtu

        self._interfaces[body.name] = iface
        self._aliases.setdefault(body.name, body.name)

        # Redirect aliases from members to bond
        for member in body.members:
            for alias, target in list(self._aliases.items()):
                if target == member:
                    self._aliases[alias] = body.name

            member_cfg = dict(self._interfaces.get(member, {}))
            member_link = dict(member_cfg.get("link") or {})
            member_link["master"] = body.name
            if "kind" not in member_link:
                member_link["kind"] = "physical"
            member_cfg["link"] = member_link
            self._interfaces[member] = member_cfg
            self._aliases.setdefault(member, member)

        self._save_state()
        bus.emit(Event("networking.interface.configured", payload={"name": body.name, **iface}))
        return {"name": body.name, **iface}

    def _get_bond(self, name: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        return {"name": name, **iface}

    def _update_bond(self, name: str, body: BondUpdate) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")

        updates = body.model_dump(exclude_unset=True)
        if "addresses" in updates:
            iface["addresses"] = updates.pop("addresses")
        if "mtu" in updates:
            iface.setdefault("link", {})["mtu"] = updates.pop("mtu")
        if "members" in updates:
            new_members = updates.pop("members") or []
            # Remove master from old members not in new list
            for n, cfg in self._interfaces.items():
                if (cfg.get("link") or {}).get("master") == name and n not in new_members:
                    link = dict(cfg.get("link") or {})
                    link.pop("master", None)
                    cfg["link"] = link
            # Add master to new members
            for member in new_members:
                member_cfg = dict(self._interfaces.get(member, {}))
                member_link = dict(member_cfg.get("link") or {})
                member_link["master"] = name
                if "kind" not in member_link:
                    member_link["kind"] = "physical"
                member_cfg["link"] = member_link
                self._interfaces[member] = member_cfg

        bond_fields = ("mode", "miimon", "ad_lacp_rate", "xmit_hash_policy", "updelay", "downdelay", "min_links")
        bond_updates = {k: updates[k] for k in bond_fields if k in updates}
        if bond_updates:
            iface.setdefault("bond", {}).update(bond_updates)

        self._interfaces[name] = iface
        self._save_state()
        bus.emit(Event("networking.interface.configured", payload={"name": name, **iface}))
        return {"name": name, **iface}

    def _delete_bond(self, name: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        # Remove member entries
        for n in [k for k, v in self._interfaces.items() if (v.get("link") or {}).get("master") == name]:
            del self._interfaces[n]
        del self._interfaces[name]
        self._save_state()
        bus.emit(Event("networking.interface.removed", payload={"name": name}))
        return {"deleted": name}

    def _get_bond_status(self, name: str) -> dict:
        proc_path = Path(f"/proc/net/bonding/{name}")
        if not proc_path.exists():
            raise HTTPException(404, f"Bond {name!r} not found in /proc/net/bonding/")
        try:
            text = proc_path.read_text()
        except OSError as exc:
            self.logger.error("Failed to read %s: %s", proc_path, exc)
            raise HTTPException(500, "Failed to read bond status; check server logs")
        return {"name": name, **_parse_proc_bond(text)}

    def _add_bond_member(self, name: str, body: BondAddMember) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        member = body.interface
        existing_master = (self._interfaces.get(member, {}).get("link") or {}).get("master")
        if existing_master and existing_master != name:
            raise HTTPException(409, f"Interface {member!r} is already a member of {existing_master!r}")
        member_cfg = dict(self._interfaces.get(member, {}))
        member_link = dict(member_cfg.get("link") or {})
        member_link["master"] = name
        if "kind" not in member_link:
            member_link["kind"] = "physical"
        member_cfg["link"] = member_link
        member_cfg.setdefault("dhcp4", False)
        member_cfg.setdefault("dhcp6", False)
        self._interfaces[member] = member_cfg
        self._aliases.setdefault(member, member)
        self._save_state()
        return {"bond": name, "member": member}

    def _delete_bond_member(self, name: str, member: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        member_iface = self._interfaces.get(member)
        if not member_iface or (member_iface.get("link") or {}).get("master") != name:
            raise HTTPException(404, f"Interface {member!r} is not a member of bond {name!r}")
        link = dict(member_iface.get("link") or {})
        link.pop("master", None)
        member_iface = dict(member_iface)
        member_iface["link"] = link
        self._interfaces[member] = member_iface
        self._save_state()
        return {"bond": name, "removed_member": member}

    # ── managed config — bridges ───────────────────────────────────────

    def _list_bridges(self) -> dict:
        bridges = [
            {"name": n, **cfg}
            for n, cfg in self._interfaces.items()
            if (cfg.get("link") or {}).get("kind") == "bridge"
        ]
        return {"bridges": bridges, "count": len(bridges)}

    def _create_bridge(self, body: BridgeCreate) -> dict:
        if body.name in self._interfaces:
            raise HTTPException(409, f"Interface {body.name!r} already exists")
        for member in body.members:
            existing_master = (self._interfaces.get(member, {}).get("link") or {}).get("master")
            if existing_master and existing_master != body.name:
                raise HTTPException(409, f"Interface {member!r} is already a member of {existing_master!r}")

        bridge_cfg: dict[str, Any] = {
            "stp": body.stp,
            "forward_delay_sec": body.forward_delay_sec,
        }
        iface: dict[str, Any] = {
            "link": {"kind": "bridge", "state": "up"},
            "bridge": bridge_cfg,
            "dhcp4": False,
            "dhcp6": False,
        }
        if body.addresses:
            iface["addresses"] = body.addresses
        if body.mtu is not None:
            iface["link"]["mtu"] = body.mtu

        self._interfaces[body.name] = iface
        self._aliases.setdefault(body.name, body.name)

        for member in body.members:
            member_cfg = dict(self._interfaces.get(member, {}))
            member_link = dict(member_cfg.get("link") or {})
            member_link["master"] = body.name
            if "kind" not in member_link:
                member_link["kind"] = "physical"
            member_cfg["link"] = member_link
            self._interfaces[member] = member_cfg
            self._aliases.setdefault(member, member)

        self._save_state()
        bus.emit(Event("networking.interface.configured", payload={"name": body.name, **iface}))
        return {"name": body.name, **iface}

    def _get_bridge(self, name: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bridge":
            raise HTTPException(404, f"Bridge {name!r} not found")
        return {"name": name, **iface}

    def _update_bridge(self, name: str, body: BridgeUpdate) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bridge":
            raise HTTPException(404, f"Bridge {name!r} not found")

        updates = body.model_dump(exclude_unset=True)
        if "addresses" in updates:
            iface["addresses"] = updates.pop("addresses")
        if "mtu" in updates:
            iface.setdefault("link", {})["mtu"] = updates.pop("mtu")
        if "members" in updates:
            new_members = updates.pop("members") or []
            for n, cfg in self._interfaces.items():
                if (cfg.get("link") or {}).get("master") == name and n not in new_members:
                    link = dict(cfg.get("link") or {})
                    link.pop("master", None)
                    cfg["link"] = link
            for member in new_members:
                member_cfg = dict(self._interfaces.get(member, {}))
                member_link = dict(member_cfg.get("link") or {})
                member_link["master"] = name
                if "kind" not in member_link:
                    member_link["kind"] = "physical"
                member_cfg["link"] = member_link
                self._interfaces[member] = member_cfg

        bridge_fields = ("stp", "forward_delay_sec")
        bridge_updates = {k: updates[k] for k in bridge_fields if k in updates}
        if bridge_updates:
            iface.setdefault("bridge", {}).update(bridge_updates)

        self._interfaces[name] = iface
        self._save_state()
        bus.emit(Event("networking.interface.configured", payload={"name": name, **iface}))
        return {"name": name, **iface}

    def _delete_bridge(self, name: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bridge":
            raise HTTPException(404, f"Bridge {name!r} not found")
        for n in [k for k, v in self._interfaces.items() if (v.get("link") or {}).get("master") == name]:
            del self._interfaces[n]
        del self._interfaces[name]
        self._save_state()
        bus.emit(Event("networking.interface.removed", payload={"name": name}))
        return {"deleted": name}

    def _add_bridge_member(self, name: str, body: BridgeMemberAdd) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bridge":
            raise HTTPException(404, f"Bridge {name!r} not found")
        member = body.interface
        existing_master = (self._interfaces.get(member, {}).get("link") or {}).get("master")
        if existing_master and existing_master != name:
            raise HTTPException(409, f"Interface {member!r} is already a member of {existing_master!r}")
        member_cfg = dict(self._interfaces.get(member, {}))
        member_link = dict(member_cfg.get("link") or {})
        member_link["master"] = name
        if "kind" not in member_link:
            member_link["kind"] = "physical"
        member_cfg["link"] = member_link
        member_cfg.setdefault("dhcp4", False)
        member_cfg.setdefault("dhcp6", False)
        self._interfaces[member] = member_cfg
        self._aliases.setdefault(member, member)
        self._save_state()
        return {"bridge": name, "member": member}

    def _delete_bridge_member(self, name: str, member: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bridge":
            raise HTTPException(404, f"Bridge {name!r} not found")
        member_iface = self._interfaces.get(member)
        if not member_iface or (member_iface.get("link") or {}).get("master") != name:
            raise HTTPException(404, f"Interface {member!r} is not a member of bridge {name!r}")
        link = dict(member_iface.get("link") or {})
        link.pop("master", None)
        member_iface = dict(member_iface)
        member_iface["link"] = link
        self._interfaces[member] = member_iface
        self._save_state()
        return {"bridge": name, "removed_member": member}

    # ── WireGuard peers ────────────────────────────────────────────────

    def _get_wg_iface(self, name: str) -> dict[str, Any]:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "wireguard":
            raise HTTPException(404, f"WireGuard interface {name!r} not found")
        return iface

    def _list_wg_peers(self, name: str) -> dict:
        iface = self._get_wg_iface(name)
        peers = (iface.get("wireguard") or {}).get("peers") or []
        return {"peers": peers, "count": len(peers)}

    def _add_wg_peer(self, name: str, body: WireguardPeer) -> dict:
        iface = self._get_wg_iface(name)
        peer_id = hashlib.sha256(body.public_key.encode()).hexdigest()[:8]
        wg = iface.setdefault("wireguard", {"peers": []})
        peers: list[dict[str, Any]] = wg.setdefault("peers", [])
        if any(p.get("public_key") == body.public_key for p in peers):
            raise HTTPException(409, f"Peer with public_key already exists (id={peer_id})")
        peer = body.model_dump(exclude_none=True)
        peer["id"] = peer_id
        peers.append(peer)
        self._interfaces[name] = iface
        self._save_state()
        return peer

    def _get_wg_peer(self, name: str, peer_id: str) -> dict:
        iface = self._get_wg_iface(name)
        peers = (iface.get("wireguard") or {}).get("peers") or []
        for peer in peers:
            if peer.get("id") == peer_id:
                return peer
        raise HTTPException(404, f"Peer {peer_id!r} not found on {name!r}")

    def _update_wg_peer(self, name: str, peer_id: str, body: WireguardPeerUpdate) -> dict:
        iface = self._get_wg_iface(name)
        peers = (iface.get("wireguard") or {}).get("peers") or []
        for i, peer in enumerate(peers):
            if peer.get("id") == peer_id:
                updates = body.model_dump(exclude_unset=True)
                peer.update(updates)
                peers[i] = peer
                self._interfaces[name] = iface
                self._save_state()
                return peer
        raise HTTPException(404, f"Peer {peer_id!r} not found on {name!r}")

    def _delete_wg_peer(self, name: str, peer_id: str) -> dict:
        iface = self._get_wg_iface(name)
        wg = iface.get("wireguard") or {}
        peers = wg.get("peers") or []
        for i, peer in enumerate(peers):
            if peer.get("id") == peer_id:
                peers.pop(i)
                wg["peers"] = peers
                iface["wireguard"] = wg
                self._interfaces[name] = iface
                self._save_state()
                return {"deleted": peer_id}
        raise HTTPException(404, f"Peer {peer_id!r} not found on {name!r}")

    # ── full config / apply / check / discard / diff ───────────────────

    def _get_config(self) -> Any:
        try:
            return self._build_all_networkd_configs()
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    def _diff(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot or {}
        desired = self._desired_snapshot()
        changes = _diff_state(current, desired)
        return {
            "pending_changes": self._state_file.pending_changes,
            "diff": changes,
        }

    def _apply(self) -> dict[str, Any]:
        debug: bool = bool(self.config.get("debug", False))
        desired = self._desired_snapshot()
        changes = _diff_state(self._state_file.current_snapshot or {}, desired)
        success = True
        output: list[str] = []
        errors: list[str] = []
        files: dict[str, str] = {}

        if self._interfaces or self._routes:
            try:
                files = self._build_all_networkd_configs()
                self._prune_networkd_files(set(self._interfaces))
                self._write_networkd_files(files)
                self._write_wpa_supplicant_configs()
                r = subprocess.run(
                    ["sudo", "networkctl", "reload"],
                    capture_output=True, text=True, timeout=15,
                )
                output = (r.stdout + r.stderr).strip().splitlines()
                if r.returncode != 0:
                    success = False
                    errors = output
                else:
                    for iface_name in self._interfaces:
                        subprocess.run(
                            ["sudo", "networkctl", "reconfigure", iface_name],
                            capture_output=True, text=True, timeout=10,
                        )
            except ValueError as exc:
                success = False
                errors = [str(exc)]
            except RuntimeError as exc:
                success = False
                errors = [str(exc)]

        if success:
            self._state_file.commit(desired)

        bus.emit(Event(
            name="networking.applied",
            payload={"success": success, "returncode": 0 if success else 1},
        ))

        resp: dict[str, Any] = {
            "success": success,
            "returncode": 0 if success else 1,
            "changes": changes,
            "output": output,
        }
        if errors:
            resp["errors"] = errors
        if debug:
            resp["debug"] = {"networkd_files": list(files.keys()), "output": output}
        return resp

    def _discard(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot
        if current is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        changes = _diff_state(self._desired_snapshot(), current)
        self._interfaces = dict(current.get("interfaces", {}))
        self._routes = dict(current.get("routes", {}))
        self._aliases = dict(current.get("aliases", {}))
        self._save_state()
        return {"discarded": True, "changes": changes}

    def _check(self) -> dict[str, Any]:
        changes = _diff_state(self._state_file.current_snapshot or {}, self._desired_snapshot())
        try:
            preview = self._build_all_networkd_configs()
        except ValueError as exc:
            return {
                "success": False,
                "returncode": 1,
                "changes": changes,
                "errors": [str(exc)],
                "preview": {},
            }
        return {"success": True, "returncode": 0, "changes": changes, "preview": preview}

    # ── interface aliases ──────────────────────────────────────────────

    def _list_aliases(self) -> dict:
        return {"aliases": dict(self._aliases), "count": len(self._aliases)}

    def _set_alias(self, name: str, body: AliasCreate) -> dict:
        if not _ALIAS_NAME_RE.match(name):
            raise HTTPException(
                422,
                f"Alias name {name!r} must start with a letter and contain only "
                "letters, digits, and underscores",
            )
        self._aliases[name] = body.interface
        self._save_state()
        self._state_file.commit(self._desired_snapshot())
        bus.emit(Event(
            name="networking.aliases_updated",
            payload={"aliases": dict(self._aliases)},
        ))
        return {"name": name, "interface": body.interface}

    def _delete_alias(self, name: str) -> dict:
        if name not in self._aliases:
            raise HTTPException(404, f"Alias {name!r} not found")
        del self._aliases[name]
        self._save_state()
        self._state_file.commit(self._desired_snapshot())
        bus.emit(Event(
            name="networking.aliases_updated",
            payload={"aliases": dict(self._aliases)},
        ))
        return {"deleted": name}

    # ── diagnostics ────────────────────────────────────────────────────

    def _ping(self, body: PingRequest) -> dict[str, Any]:
        result = subprocess.run(
            ["ping", "-c", str(body.count), body.host],
            capture_output=True, text=True, timeout=body.timeout,
        )
        lines = (result.stdout + result.stderr).strip().splitlines()
        return {"host": body.host, "returncode": result.returncode, "output": lines}

    def _mtr(self, body: MtrRequest) -> dict[str, Any]:
        result = subprocess.run(
            ["mtr", "--report", "--json", "--report-cycles", str(body.count), body.host],
            capture_output=True, text=True, timeout=120,
        )
        try:
            data = json.loads(result.stdout)
            hubs = sorted(data.get("report", {}).get("hubs", []), key=lambda h: h["count"])
            header = (
                f"{'Hop':<4} {'Ip':<45} {'Status':<8} {'Loss%':>7}  "
                f"{'Snt':>3}  {'Last':>7}  {'Avg':>7}  {'Best':>7}  {'Wrst':>7}  {'StDev':>7}"
            )
            lines = [header] + [
                f"{hub['count']:<4} {hub['host']:<40} "
                f"{'timeout' if hub['host'] == '???' else 'ok':<8}"
                f" {hub['Loss%']:>6}%  {hub['Snt']:>3}  {hub['Last']:>7.2f}"
                f"  {hub['Avg']:>7.2f}  {hub['Best']:>7.2f}  {hub['Wrst']:>7.2f}  {hub['StDev']:>7.2f}"
                for hub in hubs
            ]
        except (json.JSONDecodeError, KeyError):
            lines = (result.stdout + result.stderr).strip().splitlines()
        return {"host": body.host, "returncode": result.returncode, "output": lines}
