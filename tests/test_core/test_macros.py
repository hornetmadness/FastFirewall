"""Tests for MacroRegistry — resolution logic and cache invalidation."""
from __future__ import annotations

import pytest

from plugin_system.core.macros import MacroRegistry, extract_macros


@pytest.fixture()
def reg() -> MacroRegistry:
    return MacroRegistry()


# ── register_service_port ──────────────────────────────────────────────────────

def test_resolve_ports_plugin_declaration_beats_etc_services(reg):
    reg.set_service_ports({"ssh": {"tcp": [2222]}})
    assert reg.resolve("$service_port.ssh.tcp") == [2222]


def test_register_service_port(reg):
    reg.register_service_port("fastfirewall-api", "tcp", [8000])
    assert reg.resolve("$service_port.fastfirewall-api.tcp") == [8000]


def test_register_service_port_cached(reg):
    reg.register_service_port("fastfirewall-api", "tcp", [8000])
    reg.resolve("$service_port.fastfirewall-api.tcp")
    assert ("resolve", "$service_port.fastfirewall-api.tcp") in reg._cache


def test_register_service_port_does_not_clobber_existing(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    reg.register_service_port("fastfirewall-api", "tcp", [8000])
    assert reg.resolve("$service_port.dns.udp") == [53]
    assert reg.resolve("$service_port.fastfirewall-api.tcp") == [8000]


def test_etc_services_cached(reg):
    reg.set_service_ports({})
    reg.resolve("$service_port.ssh.tcp")
    assert ("resolve", "$service_port.ssh.tcp") in reg._cache


# ── resolve / resolve_string ──────────────────────────────────────────────────

def test_resolve_returns_raw(reg):
    reg.register_namespace("iface", lambda *s: ["10.0.0.1"])
    assert reg.resolve("$iface.lan.address") == ["10.0.0.1"]


def test_resolve_unknown_namespace(reg):
    assert reg.resolve("$nope.x") is None


def test_resolve_passthrough(reg):
    assert reg.resolve("not-a-macro") == "not-a-macro"
    assert reg.resolve("192.168.1.1") == "192.168.1.1"
    assert reg.resolve(53) == 53


def test_resolve_string(reg):
    reg.register_namespace("iface", lambda *s: "eth0" if s == ("lan", "name") else None)
    assert reg.resolve_string("$iface.lan.name") == "eth0"


def test_resolve_string_none_result(reg):
    reg.register_namespace("iface", lambda *s: None)
    assert reg.resolve_string("$iface.lan.name") is None


# ── service_port cache ────────────────────────────────────────────────────────

def test_service_port_cache_hit(reg):
    """service_port results are cached — resolver only called once."""
    reg.set_service_ports({"dns": {"udp": [53]}})
    first = reg.resolve("$service_port.dns.udp")
    second = reg.resolve("$service_port.dns.udp")
    assert first == second == [53]
    assert ("resolve", "$service_port.dns.udp") in reg._cache


def test_service_port_cache_invalidated_on_set_service_ports(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    assert reg.resolve("$service_port.dns.udp") == [53]
    reg.set_service_ports({"dns": {"udp": [5353]}})
    assert reg.resolve("$service_port.dns.udp") == [5353], \
        "cache must reflect updated service ports after set_service_ports()"


def test_service_port_cache_invalidated_on_register_namespace(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    reg.resolve("$service_port.dns.udp")
    assert len(reg._cache) == 1
    reg.register_namespace("other", lambda *s: None)
    assert len(reg._cache) == 0, "register_namespace should wipe the cache"


def test_service_port_cache_invalidated_on_unregister_namespace(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    reg.register_namespace("other", lambda *s: None)
    reg.resolve("$service_port.dns.udp")
    assert len(reg._cache) == 1
    reg.unregister_namespace("other")
    assert len(reg._cache) == 0, "unregister_namespace should wipe the cache"


# ── plugin-defined namespaces are NOT cached ──────────────────────────────────

def test_plugin_namespace_not_cached(reg):
    """Plugin-defined namespace results must not be cached: their resolvers read live state."""
    calls = []
    def resolver(*s):
        calls.append(s)
        return [80]
    reg.register_namespace("ns", resolver)
    reg.resolve("$ns.web")
    reg.resolve("$ns.web")
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
    reg.resolve("plain")
    reg.resolve_string("plain")
    assert len(reg._cache) == 0


def test_int_literal_not_cached(reg):
    reg.resolve(8080)
    assert len(reg._cache) == 0


# ── resolve() service_port namespace ─────────────────────────────────────────

def test_resolve_returns_service_port_list(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    assert reg.resolve("$service_port.dns.udp") == [53]


def test_resolve_returns_etc_services_fallback(reg):
    reg.set_service_ports({})
    assert reg.resolve("$service_port.ssh.tcp") == [22]


def test_resolve_returns_empty_list_for_truly_unknown_service(reg):
    reg.set_service_ports({})
    assert reg.resolve("$service_port.unknown_xyz_service.tcp") == []


def test_resolve_service_port_not_overridden_by_resolver(reg):
    reg.set_service_ports({"dns": {"udp": [53]}})
    reg.register_namespace("service_port", lambda *s: None)  # should be ignored
    assert reg.resolve("$service_port.dns.udp") == [53]


# ── extract_macros ────────────────────────────────────────────────────────────

def test_extract_macros_from_string():
    assert extract_macros("$service_port.dns.udp") == {"$service_port.dns.udp"}


def test_extract_macros_ignores_plain_string():
    assert extract_macros("not-a-macro") == set()


def test_extract_macros_from_dict():
    data = {"dst_port": "$service_port.dns.udp", "name": "allow-dns"}
    assert extract_macros(data) == {"$service_port.dns.udp"}


def test_extract_macros_from_nested_dict():
    data = {"rules": [{"dst_port": "$service_port.smtp.tcp", "src_port": "$service_port.dns.udp"}]}
    assert extract_macros(data) == {"$service_port.smtp.tcp", "$service_port.dns.udp"}


def test_extract_macros_from_list():
    data = ["$service_port.dns.udp", "plain", "$interface.lan.name"]
    assert extract_macros(data) == {"$service_port.dns.udp", "$interface.lan.name"}


def test_extract_macros_from_deeply_nested():
    data = {"a": {"b": {"c": "$service_port.http.tcp"}}}
    assert extract_macros(data) == {"$service_port.http.tcp"}


def test_extract_macros_returns_empty_set_for_no_macros():
    assert extract_macros({"name": "foo", "port": 80}) == set()


def test_extract_macros_integer_ignored():
    assert extract_macros(42) == set()


def test_extract_macros_none_ignored():
    assert extract_macros(None) == set()
