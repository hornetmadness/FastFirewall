"""Tests for MacroRegistry — resolution logic and cache invalidation."""
from __future__ import annotations

import pytest

from plugin_system.core.macros import MacroRegistry


@pytest.fixture()
def reg() -> MacroRegistry:
    return MacroRegistry()


# ── resolve_ports ─────────────────────────────────────────────────────────────

def test_resolve_ports_int_passthrough(reg):
    assert reg.resolve_ports(53) == [53]


def test_resolve_ports_non_macro_string(reg):
    assert reg.resolve_ports("not-a-macro") == []


def test_resolve_ports_service_port(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    assert reg.resolve_ports("$service_port.dns.udp") == [53]


def test_resolve_ports_missing_service(reg):
    reg.set_service_ports({})
    assert reg.resolve_ports("$service_port.dns.udp") == []


def test_resolve_ports_unknown_namespace(reg):
    assert reg.resolve_ports("$unknown.foo.bar") == []


def test_resolve_ports_plugin_namespace_list(reg):
    reg.register_namespace("myns", lambda *s: [80, 443] if s == ("web",) else None)
    assert reg.resolve_ports("$myns.web") == [80, 443]


def test_resolve_ports_plugin_namespace_int(reg):
    reg.register_namespace("myns", lambda *s: 8080)
    assert reg.resolve_ports("$myns.anything") == [8080]


# ── resolve / resolve_string ──────────────────────────────────────────────────

def test_resolve_returns_raw(reg):
    reg.register_namespace("iface", lambda *s: ["10.0.0.1"])
    assert reg.resolve("$iface.lan.address") == ["10.0.0.1"]


def test_resolve_unknown_namespace(reg):
    assert reg.resolve("$nope.x") is None


def test_resolve_malformed(reg):
    assert reg.resolve("not-a-macro") is None


def test_resolve_string(reg):
    reg.register_namespace("iface", lambda *s: "eth0" if s == ("lan", "name") else None)
    assert reg.resolve_string("$iface.lan.name") == "eth0"


def test_resolve_string_none_result(reg):
    reg.register_namespace("iface", lambda *s: None)
    assert reg.resolve_string("$iface.lan.name") is None


# ── service_port cache ────────────────────────────────────────────────────────

def test_service_port_cache_hit(reg):
    """resolve_ports for service_port should invoke _resolve_service_port only once."""
    reg.set_service_ports({"dns": {"udp": [53]}})
    first = reg.resolve_ports("$service_port.dns.udp")
    second = reg.resolve_ports("$service_port.dns.udp")
    assert first == second == [53]
    assert ("ports", "$service_port.dns.udp") in reg._cache


def test_service_port_cache_invalidated_on_set_service_ports(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    assert reg.resolve_ports("$service_port.dns.udp") == [53]
    reg.set_service_ports({"dns": {"udp": [5353]}})
    assert reg.resolve_ports("$service_port.dns.udp") == [5353], \
        "cache must reflect updated service ports after set_service_ports()"


def test_service_port_cache_invalidated_on_register_namespace(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    reg.resolve_ports("$service_port.dns.udp")
    assert len(reg._cache) == 1
    reg.register_namespace("other", lambda *s: None)
    assert len(reg._cache) == 0, "register_namespace should wipe the cache"


def test_service_port_cache_invalidated_on_unregister_namespace(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    reg.register_namespace("other", lambda *s: None)
    reg.resolve_ports("$service_port.dns.udp")
    assert len(reg._cache) == 1
    reg.unregister_namespace("other")
    assert len(reg._cache) == 0, "unregister_namespace should wipe the cache"


# ── plugin-defined namespaces are NOT cached ──────────────────────────────────

def test_plugin_namespace_resolve_ports_not_cached(reg):
    """Plugin-defined namespace results must not be cached: their resolvers read live state."""
    calls = []
    def resolver(*s):
        calls.append(s)
        return [80]
    reg.register_namespace("ns", resolver)
    reg.resolve_ports("$ns.web")
    reg.resolve_ports("$ns.web")
    assert len(calls) == 2, "resolver must be called on every invocation — plugin state can change"
    assert len(reg._cache) == 0


def test_resolve_not_cached(reg):
    calls = []
    reg.register_namespace("ns", lambda *s: calls.append(s) or "eth0")
    reg.resolve("$ns.lan.name")
    reg.resolve("$ns.lan.name")
    assert len(calls) == 2
    assert len(reg._cache) == 0


def test_resolve_string_not_cached(reg):
    calls = []
    reg.register_namespace("ns", lambda *s: calls.append(s) or "eth0")
    reg.resolve_string("$ns.lan.name")
    reg.resolve_string("$ns.lan.name")
    assert len(calls) == 2
    assert len(reg._cache) == 0


def test_non_macro_strings_not_cached(reg):
    reg.resolve_ports("plain")
    reg.resolve("plain")
    reg.resolve_string("plain")
    assert len(reg._cache) == 0


def test_int_literal_not_cached(reg):
    reg.resolve_ports(8080)
    assert len(reg._cache) == 0
