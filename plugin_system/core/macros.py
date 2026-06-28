"""
Plugin macro resolver.

Macros let plugin configs reference dynamic values by namespace instead of
hard-coding them.  Syntax: $<namespace>.<segment>[.<segment>...][<N>]

  $service_port.dns.udp       →  [53]
  $service_port.dns.udp[0]    →  53
  $interface.lo.address       →  ["127.0.0.1", "::1"]
  $interface.lo.address[0]    →  "127.0.0.1"
  $host.fqdn                  →  "myhost.example.com"

The registry is backed by a Box so all dot-path and [N] traversal is native.
Plugins call register() / unregister() directly; the loader registers
service_port entries after all plugins load.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Union

from box import Box, BoxKeyError

_ETC_SERVICES = Path("/etc/services")

_SERVICE_PORT_RE = re.compile(
    r"^\$service_port\.([A-Za-z0-9_-]+)\.([a-z]+)(?:\[(\d+)\])?$"
)


@lru_cache(maxsize=1)
def _parse_etc_services() -> dict[tuple[str, str], list[int]]:
    """Parse /etc/services → {(service_name, proto): [port, ...]}. Returns {} on error."""
    result: dict[tuple[str, str], list[int]] = {}
    try:
        for line in _ETC_SERVICES.read_text().splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2 or "/" not in parts[1]:
                continue
            name = parts[0].lower()
            port_str, proto = parts[1].split("/", 1)
            try:
                port = int(port_str)
            except ValueError:
                continue
            result.setdefault((name, proto.lower()), []).append(port)
    except OSError:
        pass
    return result


# Validates the general macro shape: $namespace.seg1[.seg2...][\d+]
# Namespace must be lowercase; segments may be mixed-case.
MACRO_RE = re.compile(r'^\$([a-z][a-z0-9_]*)(\.[a-zA-Z0-9_-]+)+(\[\d+\])?$')


def extract_macros(data: object) -> set[str]:
    """Recursively collect every macro string found in a nested structure."""
    macros: set[str] = set()
    if isinstance(data, str) and is_macro(data):
        macros.add(data)
    elif isinstance(data, dict):
        for v in data.values():
            macros |= extract_macros(v)
    elif isinstance(data, (list, tuple)):
        for item in data:
            macros |= extract_macros(item)
    return macros


def is_macro(value: object) -> bool:
    return isinstance(value, str) and MACRO_RE.match(value) is not None


def validate_macro_syntax(value: str) -> str:
    """Raise ValueError if *value* looks like a macro but is malformed."""
    if value.startswith("$") and not MACRO_RE.match(value):
        raise ValueError(
            f"Invalid macro {value!r}. Expected: $<namespace>.<segment>[.<segment>...][<N>] "
            "(e.g. $service_port.dns.udp, $interface.lo.address[0])"
        )
    return value


def _etc_services_fallback(value: str) -> Any:
    """Return ports from /etc/services for an unresolved $service_port.<name>.<proto>[N] macro."""
    m = _SERVICE_PORT_RE.match(value)
    if m is None:
        return None
    ports = _parse_etc_services().get((m.group(1).lower(), m.group(2)))
    if not ports:
        return None
    if m.group(3) is not None:
        idx = int(m.group(3))
        return ports[idx] if idx < len(ports) else None
    return ports


class MacroRegistry:
    """
    Shared registry backed by a Box(box_dots=True, default_box=True).

    register("$interface.lo.address", ["127.0.0.1", "::1"])
    resolve("$interface.lo.address[0]")  →  "127.0.0.1"
    unregister("$interface.lo")          →  removes lo subtree
    """

    def __init__(self) -> None:
        self._box: Box = Box({}, box_dots=True, default_box=True)

    def register(self, key: str, value: Any) -> None:
        self._box[key.removeprefix("$")] = value

    def unregister(self, key: str) -> None:
        try:
            del self._box[key.removeprefix("$")]
        except (KeyError, BoxKeyError):
            pass

    def resolve(self, value: Union[int, str]) -> Any:
        """Resolve a macro string; return the value unchanged for non-macros.

        - non-macro str or int  → returned as-is
        - $macro[N]             → scalar element at index N
        - $macro                → raw value (list, str, int, …)
        - unknown path          → /etc/services fallback for $service_port.*, else None
        """
        if not isinstance(value, str) or not value.startswith("$"):
            return value
        try:
            result = self._box[value.removeprefix("$")]
            # An empty Box means the path didn't resolve to a real leaf value
            if isinstance(result, Box) and not result:
                return _etc_services_fallback(value)
            return result
        except (KeyError, BoxKeyError):
            return _etc_services_fallback(value)
        except IndexError:
            # [N] index is out of bounds on a declared value — no fallback
            return None

    @property
    def namespaces(self) -> list[str]:
        """Top-level namespace names currently registered."""
        return [k for k, v in self._box.items() if not (isinstance(v, Box) and not v)]


macro_registry = MacroRegistry()
