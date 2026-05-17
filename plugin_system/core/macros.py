"""
Plugin macro resolver.

Macros let plugin configs reference dynamic values by namespace instead of
hard-coding them.  General syntax: $<namespace>.<segment>[.<segment>...]

Built-in namespaces:

  service_port  —  ports declared by a loaded plugin's service_ports block
    $service_port.dns.udp   →  UDP ports owned by the dns service
    $service_port.smtp.tcp  →  TCP ports owned by the smtp service

  interface  —  user-defined aliases for network interface names
    $interface.LAN1  →  OS interface name mapped to alias "LAN1"
    $interface.WAN   →  OS interface name mapped to alias "WAN"

Adding a new namespace:
  1. Write a resolver returning list[int] and add it to ``_NAMESPACE_RESOLVERS``,
     or returning Optional[str] and add it to ``_STRING_NAMESPACE_RESOLVERS``.
  2. Populate it by consuming events that call the appropriate
     registry-update helper (e.g. ``merge_service_ports``, ``merge_interface_aliases``).

The registry passed to ``resolve_macro`` / ``resolve_string_macro`` is a plain
dict keyed by namespace; only plugins that successfully loaded contribute data
to it (fail-closed).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional, Union

# Validates the general macro shape: $namespace.seg1[.seg2...]
# Namespace must be lowercase; segments may be mixed-case (e.g. $interface.LAN1).
MACRO_RE = re.compile(r'^\$([a-z][a-z0-9_]*)(\.[a-zA-Z0-9_]+)+$')

# Extracts namespace + everything after the first dot for dispatch.
_PARSE_RE = re.compile(r'^\$([a-z][a-z0-9_]*)\.(.+)$')


def is_macro(value: object) -> bool:
    return isinstance(value, str) and MACRO_RE.match(value) is not None


def validate_macro_syntax(value: str) -> str:
    """Raise ValueError if *value* looks like a macro but is malformed."""
    if value.startswith("$") and not MACRO_RE.match(value):
        raise ValueError(
            f"Invalid macro {value!r}. Expected: $<namespace>.<segment>[.<segment>...] "
            "(e.g. $service_port.dns.udp, $interface.LAN1)"
        )
    return value


# ── integer-returning namespace resolvers (ports) ─────────────────────────────

def _resolve_service_port(rest: str, ns_data: dict[str, dict[str, list[int]]]) -> list[int]:
    """Resolve $service_port.<service>.<proto> → port list."""
    parts = rest.split(".", 1)
    if len(parts) != 2:
        return []
    svc, proto = parts
    return ns_data.get(svc, {}).get(proto, [])


_NAMESPACE_RESOLVERS: dict[str, Callable[[str, dict[str, Any]], list[int]]] = {
    "service_port": _resolve_service_port,
}


# ── string-returning namespace resolvers ──────────────────────────────────────

def _resolve_interface(rest: str, ns_data: dict[str, str]) -> Optional[str]:
    """Resolve $interface.<alias> → actual OS interface name."""
    return ns_data.get(rest)


_STRING_NAMESPACE_RESOLVERS: dict[str, Callable[[str, dict[str, Any]], Optional[str]]] = {
    "interface": _resolve_interface,
}


# ── public API ─────────────────────────────────────────────────────────────────

def resolve_macro(
    value: Union[int, str],
    registry: dict[str, Any],
) -> list[int]:
    """
    Resolve a macro or literal to a list of concrete integers (e.g. port numbers).

    - int            → [value]
    - macro string   → dispatch to the namespace resolver; [] if namespace
                       unknown or data missing (caller should skip the rule).
    """
    if isinstance(value, int):
        return [value]

    m = _PARSE_RE.match(value)
    if m is None:
        return []

    namespace, rest = m.group(1), m.group(2)
    resolver = _NAMESPACE_RESOLVERS.get(namespace)
    if resolver is None:
        return []
    return resolver(rest, registry.get(namespace, {}))


def resolve_string_macro(
    value: str,
    registry: dict[str, Any],
) -> Optional[str]:
    """
    Resolve a string macro like $interface.LAN1 → 'eth0'.
    Returns None if the namespace is unknown or the key is not registered.
    """
    m = _PARSE_RE.match(value)
    if m is None:
        return None
    namespace, rest = m.group(1), m.group(2)
    resolver = _STRING_NAMESPACE_RESOLVERS.get(namespace)
    if resolver is None:
        return None
    return resolver(rest, registry.get(namespace, {}))


def merge_service_ports(
    registry: dict[str, Any],
    service_ports: dict[str, dict[str, list[int]]],
) -> None:
    """Merge a plugin's service_ports block into registry["service_port"] in-place."""
    ns: dict[str, dict[str, list[int]]] = registry.setdefault("service_port", {})
    for svc_name, proto_map in service_ports.items():
        ns[svc_name] = {
            proto: [p for p in ports if p != -1]
            for proto, ports in proto_map.items()
        }


def merge_interface_aliases(
    registry: dict[str, Any],
    aliases: dict[str, str],
) -> None:
    """Replace registry["interface"] with the given alias mapping."""
    registry["interface"] = dict(aliases)
