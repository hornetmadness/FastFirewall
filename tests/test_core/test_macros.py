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


# ── cache behaviour ───────────────────────────────────────────────────────────

def test_cache_hit_returns_same_result(reg):
    calls = []
    def resolver(*s):
        calls.append(s)
        return [53]
    reg.register_namespace("ns", resolver)
    reg.resolve_ports("$ns.dns")
    reg.resolve_ports("$ns.dns")
    assert len(calls) == 1, "resolver should only be called once; second call should hit cache"


def test_cache_invalidated_on_register_namespace(reg):
    calls = []
    def resolver(*s):
        calls.append(s)
        return [53]
    reg.register_namespace("ns", resolver)
    reg.resolve_ports("$ns.dns")
    assert len(calls) == 1
    reg.register_namespace("ns", resolver)  # re-register, same resolver
    reg.resolve_ports("$ns.dns")
    assert len(calls) == 2, "cache should be cleared on register_namespace"


def test_cache_invalidated_on_unregister_namespace(reg):
    reg.register_namespace("ns", lambda *s: [80])
    assert reg.resolve_ports("$ns.x") == [80]
    reg.unregister_namespace("ns")
    assert reg.resolve_ports("$ns.x") == [], "after unregister, macro should be unresolvable"


def test_cache_invalidated_on_set_service_ports(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    assert reg.resolve_ports("$service_port.dns.udp") == [53]
    reg.set_service_ports({"dns": {"udp": [5353]}})
    assert reg.resolve_ports("$service_port.dns.udp") == [5353], "cache should reflect updated service ports"


def test_cache_separate_per_method(reg):
    reg.register_namespace("ns", lambda *s: ["eth0"])
    ports = reg.resolve_ports("$ns.lan")
    raw = reg.resolve("$ns.lan")
    string = reg.resolve_string("$ns.lan")
    assert ports == []        # ["eth0"] can't be coerced to int list
    assert raw == ["eth0"]
    assert string == "['eth0']"


def test_cache_not_populated_for_non_macro_strings(reg):
    reg.resolve_ports("plain")
    reg.resolve("plain")
    reg.resolve_string("plain")
    assert len(reg._cache) == 0, "non-macro strings should not pollute the cache"


def test_cache_not_populated_for_int_literal(reg):
    reg.resolve_ports(8080)
    assert len(reg._cache) == 0, "int literals bypass the cache path entirely"
