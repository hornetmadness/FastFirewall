import re
from typing import Annotated, Any, Literal, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator


_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class DnsUpdate(BaseModel):
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    listen_addresses: Optional[list[Annotated[str, Field(max_length=39)]]] = None
    interface: Optional[str] = Field(default=None, max_length=15)
    upstream: Optional[list[Annotated[str, Field(max_length=50)]]] = None
    cache_size: Optional[int] = Field(default=None, ge=0)
    no_resolv: Optional[bool] = None
    dnssec: Optional[bool] = None
    log_queries: Optional[bool] = None
    domain: Optional[str] = Field(default=None, max_length=253)
    local_ttl: Optional[int] = Field(default=None, ge=0)
    neg_ttl: Optional[int] = Field(default=None, ge=0)
    strict_order: Optional[bool] = None
    rebind_protection: Optional[bool] = None
    rebind_localhost_ok: Optional[bool] = None
    domain_servers: Optional[dict[str, list[str]]] = None
    local: Optional[list[Annotated[str, Field(max_length=253)]]] = None


class DnsRecordCreate(BaseModel):
    type: Literal["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR"]
    name: str = Field(max_length=253)
    value: str = Field(max_length=253)
    ttl: Optional[int] = Field(default=None, ge=0)
    priority: Optional[int] = Field(default=None, ge=0, le=65535)
    weight: Optional[int] = Field(default=None, ge=0, le=65535)
    port: Optional[int] = Field(default=None, ge=1, le=65535)


class DhcpUpdate(BaseModel):
    enabled: Optional[bool] = None
    authoritative: Optional[bool] = None
    options: Optional[dict[str, str]] = None


class DhcpRangeCreate(BaseModel):
    start: str = Field(max_length=39)
    end: str = Field(max_length=39)
    netmask: Optional[str] = Field(default=None, max_length=39)
    lease_time: str = Field(default="12h", max_length=20)
    interface: Optional[str] = Field(default=None, max_length=15)
    mode: Literal["dhcp", "proxy", "ra-only", "slaac", "ra-stateless", "ra-names"] = "dhcp"


class DhcpRangeUpdate(BaseModel):
    start: Optional[str] = Field(default=None, max_length=39)
    end: Optional[str] = Field(default=None, max_length=39)
    netmask: Optional[str] = Field(default=None, max_length=39)
    lease_time: Optional[str] = Field(default=None, max_length=20)
    interface: Optional[str] = Field(default=None, max_length=15)
    mode: Optional[Literal["dhcp", "proxy", "ra-only", "slaac", "ra-stateless", "ra-names"]] = None


class StaticLeaseCreate(BaseModel):
    mac: str
    ip: str = Field(max_length=39)
    hostname: Optional[str] = Field(default=None, max_length=253)
    lease_time: Optional[str] = Field(default=None, max_length=20)

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not _MAC_RE.match(v):
            raise ValueError(f"{v!r} is not a valid MAC address (expected xx:xx:xx:xx:xx:xx)")
        return v.lower()


class StaticLeaseUpdate(BaseModel):
    mac: Optional[str] = None
    ip: Optional[str] = Field(default=None, max_length=39)
    hostname: Optional[str] = Field(default=None, max_length=253)
    lease_time: Optional[str] = Field(default=None, max_length=20)

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
    root: Optional[str] = Field(default=None, max_length=4096)
    secure: Optional[bool] = None
    no_fail: Optional[bool] = None


class PxeUpdate(BaseModel):
    enabled: Optional[bool] = None
    prompt: Optional[str] = Field(default=None, max_length=128)


class PxeServiceCreate(BaseModel):
    type: str = Field(max_length=32)
    menu_name: str = Field(max_length=128)
    boot_file: Optional[str] = Field(default=None, max_length=255)
    server: Optional[str] = Field(default=None, max_length=253)


class PxeImageRename(BaseModel):
    name: str = Field(max_length=255)


class MdnsUpdate(BaseModel):
    enabled: Optional[bool] = None
    interfaces: Optional[list[Annotated[str, Field(max_length=15)]]] = None


class BlocklistCreate(BaseModel):
    url: str = Field(max_length=2048)
    name: str = Field(max_length=100)
    format: Literal["hosts", "domains"] = "hosts"
