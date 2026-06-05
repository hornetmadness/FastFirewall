from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ── constants ──────────────────────────────────────────────────────────────────

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

_LO_ADDRESSES = ["127.0.0.1/8", "::1/128"]

_ALIAS_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')


# ── utility functions ──────────────────────────────────────────────────────────

def _validate_cidr(value: str) -> str:
    """Accept a host-address-with-prefix like '192.168.1.1/24' or '::1/128'."""
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        raise ValueError(f"{value!r} is not a valid CIDR address (e.g. '192.168.1.1/24')")
    return value


def _validate_host(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("host must not be empty")
    if re.search(r"[;&|`$<>()\n\r]", value):
        raise ValueError(f"{value!r} contains invalid characters")
    return value


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


# ── Pydantic models ────────────────────────────────────────────────────────────

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
