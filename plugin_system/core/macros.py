"""
Plugin macro resolver.

Macros let plugin configs reference dynamic values by namespace instead of
hard-coding them.  General syntax: $<namespace>.<segment>[.<segment>...]

Built-in namespaces (managed by the loader):

  service_port  —  ports declared by a loaded plugin's service_ports block
    $service_port.dns.udp   →  UDP ports owned by the dns service
    $service_port.smtp.tcp  →  TCP ports owned by the smtp service

Plugin-defined namespaces:

  Any plugin can claim a namespace by inheriting ``MacroProviderPlugin``
  and declaring ``macro_namespace = "myns"``.  The loader registers the
  plugin in the shared ``macro_registry`` singleton after ``setup()``
  completes — consumers call ``macro_registry.resolve_ports()`` or
  ``macro_registry.resolve_string()`` directly.

  Example (networking plugin owns the ``interface`` namespace):
    $interface.LAN1.name     →  OS device name mapped to alias "LAN1"
    $interface.LAN1.address  →  list of L3 addresses on that device (no prefix)
    $interface.WAN.name      →  OS device name mapped to alias "WAN"
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


def _resolve_service_port(rest: str, data: dict[str, dict[str, list[int]]]) -> list[int]:
    """Resolve $service_port.<service>.<proto> → port list."""
    parts = rest.split(".", 1)
    if len(parts) != 2:
        return []
    svc, proto = parts
    return data.get(svc, {}).get(proto, [])


class MacroRegistry:
    """
    Shared registry that maps macro namespaces to resolver callables.

    The ``service_port`` namespace is built-in and populated by the loader
    from plugin.yaml declarations.  Plugins register additional namespaces
    by calling ``add_macro_namespace()`` inside ``setup()`` via the
    ``MacroProviderPlugin`` mixin.

    Resolved macro values are cached in a dict keyed by (method, macro_str)
    and invalidated whenever the registry changes (register/unregister/set).
    """

    def __init__(self) -> None:
        self._resolvers: dict[str, Callable[..., Any]] = {}
        self._service_ports: dict[str, dict[str, list[int]]] = {}
        self._cache: dict[tuple[str, str], Any] = {}

    def _invalidate(self) -> None:
        self._cache.clear()

    def register_namespace(self, name: str, resolver: Callable[..., Any]) -> None:
        """Map *name* to *resolver* (called by the loader after each plugin setup)."""
        self._resolvers[name] = resolver
        self._invalidate()

    def unregister_namespace(self, name: str) -> None:
        """Remove a namespace (called by the loader on plugin unload)."""
        self._resolvers.pop(name, None)
        self._invalidate()

    def set_service_ports(self, service_ports: dict[str, dict[str, list[int]]]) -> None:
        """Called by the loader after all plugins are loaded."""
        self._service_ports = dict(service_ports)
        self._invalidate()

    @property
    def namespaces(self) -> list[str]:
        """Names of all currently registered macro namespaces."""
        result: list[str] = []
        if self._service_ports:
            result.append("service_port")
        result.extend(self._resolvers.keys())
        return result

    def resolve_ports(self, value: Union[int, str]) -> list[int]:
        """
        Resolve a port macro or literal to a list of port numbers.

        - int            → [value]
        - literal string → []  (use int() on the caller side if needed)
        - macro string   → dispatch to namespace; [] if unresolvable.
        """
        if isinstance(value, int):
            return [value]
        m = _PARSE_RE.match(value)
        if m is None:
            return []
        cache_key = ("ports", value)
        if cache_key in self._cache:
            return self._cache[cache_key]
        namespace, rest = m.group(1), m.group(2)
        if namespace == "service_port":
            result: list[int] = _resolve_service_port(rest, self._service_ports)
        else:
            resolver = self._resolvers.get(namespace)
            if resolver is None:
                result = []
            else:
                raw = resolver(*rest.split("."))
                if isinstance(raw, list):
                    try:
                        result = [int(x) for x in raw]
                    except (TypeError, ValueError):
                        result = []
                elif isinstance(raw, int):
                    result = [raw]
                else:
                    result = []
        self._cache[cache_key] = result
        return result

    def resolve(self, value: str) -> Any:
        """Resolve a macro and return the raw result without type coercion.
        Returns None if the namespace is unknown, the macro is malformed, or the
        resolver returns None."""
        m = _PARSE_RE.match(value)
        if m is None:
            return None
        cache_key = ("raw", value)
        if cache_key in self._cache:
            return self._cache[cache_key]
        namespace, rest = m.group(1), m.group(2)
        resolver = self._resolvers.get(namespace)
        if resolver is None:
            return None
        result = resolver(*rest.split("."))
        self._cache[cache_key] = result
        return result

    def resolve_string(self, value: str) -> Optional[str]:
        """
        Resolve a string macro like $interface.LAN1 → 'eth0'.
        Returns None if the namespace is unknown or the key is not registered.
        """
        m = _PARSE_RE.match(value)
        if m is None:
            return None
        cache_key = ("string", value)
        if cache_key in self._cache:
            return self._cache[cache_key]
        namespace, rest = m.group(1), m.group(2)
        resolver = self._resolvers.get(namespace)
        if resolver is None:
            return None
        result = resolver(*rest.split("."))
        resolved = str(result) if result is not None else None
        self._cache[cache_key] = resolved
        return resolved


macro_registry = MacroRegistry()
