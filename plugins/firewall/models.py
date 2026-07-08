"""Pydantic request/response models for the firewall plugin."""
from __future__ import annotations

import hashlib
import os
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator

from plugin_system.core.macros import validate_macro_syntax


def _validate_port_field(v: object) -> object:
    if isinstance(v, str):
        validate_macro_syntax(v)
    return v


_TcpFlag = Literal["syn", "ack", "fin", "rst", "urg", "psh", "ece", "cwr"]
_CtState = Literal["new", "established", "related", "invalid", "untracked"]
_NatFlag = Literal["random", "fully-random", "persistent"]


class RateLimit(BaseModel):
    rate: int
    unit: Literal["second", "minute", "hour", "day", "kbytes", "mbytes"] = "second"
    burst: Optional[int] = None
    burst_unit: Literal["packets", "kbytes", "mbytes"] = "packets"
    over: bool = False


class LogConfig(BaseModel):
    prefix: str = Field(default="FF: ", max_length=64)
    level: Literal["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"] = "warn"
    group: Optional[int] = None
    flags: Optional[str] = Field(default=None, max_length=64)
    snaplen: Optional[int] = None


class CustomChain(BaseModel):
    name: str = Field(max_length=100)
    comment: Optional[str] = Field(default=None, max_length=255)


class IngressRule(BaseModel):
    id: str = Field(default_factory=lambda: hashlib.sha256(os.urandom(16)).hexdigest()[:16])
    name: str = Field(max_length=100)
    device: str = Field(max_length=15)
    action: Literal["accept", "deny", "reject"] = "deny"
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: str = Field(default="any", max_length=43)
    dst_address: str = Field(default="any", max_length=43)
    src_address_set: Optional[str] = Field(default=None, max_length=64)
    dst_address_set: Optional[str] = Field(default=None, max_length=64)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    rate_limit: Optional[RateLimit] = None
    log: Optional[LogConfig] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class IngressRuleCreate(BaseModel):
    name: str = Field(max_length=100)
    device: str = Field(max_length=15)
    action: Literal["accept", "deny", "reject"] = "deny"
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: str = Field(default="any", max_length=43)
    dst_address: str = Field(default="any", max_length=43)
    src_address_set: Optional[str] = Field(default=None, max_length=64)
    dst_address_set: Optional[str] = Field(default=None, max_length=64)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    rate_limit: Optional[RateLimit] = None
    log: Optional[LogConfig] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class IngressRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)
    device: Optional[str] = Field(default=None, max_length=15)
    action: Optional[Literal["accept", "deny", "reject"]] = None
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: Optional[str] = Field(default=None, max_length=43)
    dst_address: Optional[str] = Field(default=None, max_length=43)
    src_address_set: Optional[str] = Field(default=None, max_length=64)
    dst_address_set: Optional[str] = Field(default=None, max_length=64)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    rate_limit: Optional[RateLimit] = None
    log: Optional[LogConfig] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = None
    enabled: Optional[bool] = None

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class FirewallRule(BaseModel):
    id: str = Field(default_factory=lambda: hashlib.sha256(os.urandom(16)).hexdigest()[:16])
    name: str = Field(max_length=100)
    chain: str = Field(default="input", max_length=100)
    action: Literal["accept", "deny", "reject", "jump", "return"] = "deny"
    jump_target: Optional[str] = Field(default=None, max_length=100)
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: str = Field(default="any", max_length=43)
    dst_address: str = Field(default="any", max_length=43)
    src_address_set: Optional[str] = Field(default=None, max_length=64)
    dst_address_set: Optional[str] = Field(default=None, max_length=64)
    counter_name: Optional[str] = Field(default=None, max_length=100)
    quota_name: Optional[str] = Field(default=None, max_length=100)
    src_interface: Optional[str] = Field(default=None, max_length=15)
    dst_interface: Optional[str] = Field(default=None, max_length=15)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    src_port_range: Optional[tuple[int, int]] = None
    dst_port_range: Optional[tuple[int, int]] = None
    tcp_flags: Optional[list[_TcpFlag]] = None
    tcp_flags_mask: Optional[list[_TcpFlag]] = None
    icmp_type: Optional[Union[int, Annotated[str, Field(max_length=32)]]] = None
    ct_state: Optional[list[_CtState]] = None
    mark: Optional[int] = None
    dscp: Optional[Union[int, Annotated[str, Field(max_length=16)]]] = None
    pkttype: Optional[Literal["unicast", "broadcast", "multicast"]] = None
    rate_limit: Optional[RateLimit] = None
    log: Optional[LogConfig] = None
    dst_port_vmap: Optional[str] = Field(default=None, max_length=100)
    src_port_vmap: Optional[str] = Field(default=None, max_length=100)
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class RuleCreate(BaseModel):
    name: str = Field(max_length=100)
    chain: str = Field(default="input", max_length=100)
    action: Literal["accept", "deny", "reject", "jump", "return"] = "deny"
    jump_target: Optional[str] = Field(default=None, max_length=100)
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: str = Field(default="any", max_length=43)
    dst_address: str = Field(default="any", max_length=43)
    src_address_set: Optional[str] = Field(default=None, max_length=64)
    dst_address_set: Optional[str] = Field(default=None, max_length=64)
    counter_name: Optional[str] = Field(default=None, max_length=100)
    quota_name: Optional[str] = Field(default=None, max_length=100)
    src_interface: Optional[str] = Field(default=None, max_length=15)
    dst_interface: Optional[str] = Field(default=None, max_length=15)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    src_port_range: Optional[tuple[int, int]] = None
    dst_port_range: Optional[tuple[int, int]] = None
    tcp_flags: Optional[list[_TcpFlag]] = None
    tcp_flags_mask: Optional[list[_TcpFlag]] = None
    icmp_type: Optional[Union[int, Annotated[str, Field(max_length=32)]]] = None
    ct_state: Optional[list[_CtState]] = None
    mark: Optional[int] = None
    dscp: Optional[Union[int, Annotated[str, Field(max_length=16)]]] = None
    pkttype: Optional[Literal["unicast", "broadcast", "multicast"]] = None
    rate_limit: Optional[RateLimit] = None
    log: Optional[LogConfig] = None
    dst_port_vmap: Optional[str] = Field(default=None, max_length=100)
    src_port_vmap: Optional[str] = Field(default=None, max_length=100)
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)
    chain: Optional[str] = Field(default=None, max_length=100)
    action: Optional[Literal["accept", "deny", "reject", "jump", "return"]] = None
    jump_target: Optional[str] = Field(default=None, max_length=100)
    protocol: Optional[Literal["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "any"]] = None
    src_address: Optional[str] = Field(default=None, max_length=43)
    dst_address: Optional[str] = Field(default=None, max_length=43)
    src_address_set: Optional[str] = Field(default=None, max_length=64)
    dst_address_set: Optional[str] = Field(default=None, max_length=64)
    counter_name: Optional[str] = Field(default=None, max_length=100)
    quota_name: Optional[str] = Field(default=None, max_length=100)
    src_interface: Optional[str] = Field(default=None, max_length=15)
    dst_interface: Optional[str] = Field(default=None, max_length=15)
    src_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None
    src_port_range: Optional[tuple[int, int]] = None
    dst_port_range: Optional[tuple[int, int]] = None
    tcp_flags: Optional[list[_TcpFlag]] = None
    tcp_flags_mask: Optional[list[_TcpFlag]] = None
    icmp_type: Optional[Union[int, Annotated[str, Field(max_length=32)]]] = None
    ct_state: Optional[list[_CtState]] = None
    mark: Optional[int] = None
    dscp: Optional[Union[int, Annotated[str, Field(max_length=16)]]] = None
    pkttype: Optional[Literal["unicast", "broadcast", "multicast"]] = None
    rate_limit: Optional[RateLimit] = None
    log: Optional[LogConfig] = None
    dst_port_vmap: Optional[str] = Field(default=None, max_length=100)
    src_port_vmap: Optional[str] = Field(default=None, max_length=100)
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = None
    enabled: Optional[bool] = None

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_port(cls, v: object) -> object:
        return _validate_port_field(v)


class ChainConfig(BaseModel):
    policy: Literal["accept", "drop"] = "drop"
    priority: int = 0
    preamble: list[str] = []
    epilogue: list[str] = []


class ChainUpdate(BaseModel):
    policy: Optional[Literal["accept", "drop"]] = None
    priority: Optional[int] = None
    preamble: Optional[list[Annotated[str, Field(max_length=512)]]] = None
    epilogue: Optional[list[Annotated[str, Field(max_length=512)]]] = None


class CompileRequest(BaseModel):
    filter_name: str = Field(default="fastfirewall", max_length=64)


class CompileResult(BaseModel):
    filter_name: str
    output: list[str]
    rule_count: int
    output_path: str


class FirewallSet(BaseModel):
    name: str = Field(max_length=64)
    type: Literal["ipv4_addr", "ipv6_addr", "inet_service"] = "ipv4_addr"
    flags: list[Literal["interval", "timeout", "dynamic"]] = []
    auto_merge: bool = False
    timeout: Optional[int] = None
    elements: list[Annotated[str, Field(max_length=43)]] = []
    comment: Optional[str] = Field(default=None, max_length=255)


class SetCreate(BaseModel):
    name: str = Field(max_length=64)
    type: Literal["ipv4_addr", "ipv6_addr", "inet_service"] = "ipv4_addr"
    flags: list[Literal["interval", "timeout", "dynamic"]] = []
    auto_merge: bool = False
    timeout: Optional[int] = None
    elements: list[Annotated[str, Field(max_length=43)]] = []
    comment: Optional[str] = Field(default=None, max_length=255)


class SetElementsBody(BaseModel):
    elements: list[Annotated[str, Field(max_length=43)]]


class Flowtable(BaseModel):
    name: str = Field(max_length=100)
    priority: int = 0
    devices: list[Annotated[str, Field(max_length=15)]] = []
    offload_forward: bool = True
    comment: Optional[str] = Field(default=None, max_length=255)


class NatRule(BaseModel):
    id: str = Field(default_factory=lambda: hashlib.sha256(os.urandom(16)).hexdigest()[:16])
    name: str = Field(max_length=100)
    type: Literal["masquerade", "snat", "dnat", "redirect"] = "masquerade"
    chain: Literal["prerouting", "postrouting"] = "postrouting"
    protocol: Optional[Literal["tcp", "udp"]] = None
    in_interface: Optional[str] = Field(default=None, max_length=15)
    out_interface: Optional[str] = Field(default=None, max_length=15)
    src_address: Optional[str] = Field(default=None, max_length=43)
    dst_address: Optional[str] = Field(default=None, max_length=43)
    src_port: Optional[int] = None
    dst_port: Optional[Union[int, str]] = None
    to_address: Optional[str] = Field(default=None, max_length=43)
    to_port: Optional[int] = None
    flags: list[_NatFlag] = []
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("dst_port", mode="before")
    @classmethod
    def validate_dst_port(cls, v: object) -> object:
        return _validate_port_field(v)


class NatRuleCreate(BaseModel):
    name: str = Field(max_length=100)
    type: Literal["masquerade", "snat", "dnat", "redirect"] = "masquerade"
    chain: Literal["prerouting", "postrouting"] = "postrouting"
    protocol: Optional[Literal["tcp", "udp"]] = None
    in_interface: Optional[str] = Field(default=None, max_length=15)
    out_interface: Optional[str] = Field(default=None, max_length=15)
    src_address: Optional[str] = Field(default=None, max_length=43)
    dst_address: Optional[str] = Field(default=None, max_length=43)
    src_port: Optional[int] = None
    dst_port: Optional[Union[int, str]] = None
    to_address: Optional[str] = Field(default=None, max_length=43)
    to_port: Optional[int] = None
    flags: list[_NatFlag] = []
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: int = 100
    enabled: bool = True

    @field_validator("dst_port", mode="before")
    @classmethod
    def validate_dst_port(cls, v: object) -> object:
        return _validate_port_field(v)


class NatRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)
    type: Optional[Literal["masquerade", "snat", "dnat", "redirect"]] = None
    chain: Optional[Literal["prerouting", "postrouting"]] = None
    protocol: Optional[Literal["tcp", "udp"]] = None
    in_interface: Optional[str] = Field(default=None, max_length=15)
    out_interface: Optional[str] = Field(default=None, max_length=15)
    src_address: Optional[str] = Field(default=None, max_length=43)
    dst_address: Optional[str] = Field(default=None, max_length=43)
    src_port: Optional[int] = None
    dst_port: Optional[Union[int, str]] = None
    to_address: Optional[str] = Field(default=None, max_length=43)
    to_port: Optional[int] = None
    flags: Optional[list[_NatFlag]] = None
    comment: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = None
    enabled: Optional[bool] = None

    @field_validator("dst_port", mode="before")
    @classmethod
    def validate_dst_port(cls, v: object) -> object:
        return _validate_port_field(v)


class FirewallQuota(BaseModel):
    name: str = Field(max_length=100)
    amount: int
    unit: Literal["bytes", "kbytes", "mbytes", "gbytes"] = "mbytes"
    over: bool = False
    comment: Optional[str] = Field(default=None, max_length=255)


class VerdictMapEntry(BaseModel):
    key: str = Field(max_length=64)
    verdict: Literal["accept", "drop", "return", "jump", "continue"] = "accept"
    jump_target: Optional[str] = Field(default=None, max_length=100)


class VerdictMap(BaseModel):
    name: str = Field(max_length=100)
    key_type: Literal["inet_service", "ipv4_addr", "ipv6_addr"] = "inet_service"
    flags: list[Literal["interval", "timeout"]] = []
    entries: list[VerdictMapEntry] = []
    comment: Optional[str] = Field(default=None, max_length=255)


class VerdictMapEntryBody(BaseModel):
    entries: list[VerdictMapEntry]


class VerdictMapKeyBody(BaseModel):
    keys: list[Annotated[str, Field(max_length=64)]]
