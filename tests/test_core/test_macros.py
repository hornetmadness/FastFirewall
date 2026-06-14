"""Tests for MacroRegistry — Box-backed resolution with [N] indexing."""
from __future__ import annotations

import pytest

from plugin_system.core.macros import MacroRegistry, extract_macros, is_macro


@pytest.fixture()
def reg() -> MacroRegistry:
    return MacroRegistry()


# ── register / resolve ────────────────────────────────────────────────────────

def test_register_and_resolve_list(reg):
    reg.register("$service_port.dns.udp", [53])
    assert reg.resolve("$service_port.dns.udp") == [53]


def test_register_and_resolve_scalar(reg):
    reg.register("$host.hostname", "myhost")
    assert reg.resolve("$host.hostname") == "myhost"


def test_resolve_indexed(reg):
    reg.register("$interface.lo.address", ["127.0.0.1", "::1"])
    assert reg.resolve("$interface.lo.address[0]") == "127.0.0.1"
    assert reg.resolve("$interface.lo.address[1]") == "::1"


def test_resolve_indexed_out_of_bounds(reg):
    reg.register("$interface.lo.address", ["127.0.0.1"])
    assert reg.resolve("$interface.lo.address[99]") is None


def test_resolve_non_indexed_returns_full_list(reg):
    reg.register("$interface.lo.address", ["127.0.0.1", "::1"])
    assert reg.resolve("$interface.lo.address") == ["127.0.0.1", "::1"]


def test_resolve_service_port_indexed(reg):
    reg.register("$service_port.dns.udp", [53])
    assert reg.resolve("$service_port.dns.udp[0]") == 53


def test_resolve_passthrough_non_macro(reg):
    assert reg.resolve("not-a-macro") == "not-a-macro"
    assert reg.resolve("192.168.1.1") == "192.168.1.1"
    assert reg.resolve(53) == 53


def test_resolve_unknown_path_returns_none(reg):
    assert reg.resolve("$nope.x") is None
    assert reg.resolve("$interface.lan.address") is None


# ── unregister ────────────────────────────────────────────────────────────────

def test_unregister_leaf(reg):
    reg.register("$interface.lo.address", ["127.0.0.1"])
    reg.unregister("$interface.lo.address")
    assert reg.resolve("$interface.lo.address") is None


def test_unregister_subtree(reg):
    reg.register("$interface.lo.address", ["127.0.0.1"])
    reg.register("$interface.lo.name", "lo")
    reg.unregister("$interface.lo")
    assert reg.resolve("$interface.lo.address") is None
    assert reg.resolve("$interface.lo.name") is None


def test_unregister_missing_is_noop(reg):
    reg.unregister("$nonexistent.key")  # must not raise


# ── multiple namespaces ───────────────────────────────────────────────────────

def test_multiple_namespaces_coexist(reg):
    reg.register("$service_port.dns.udp", [53])
    reg.register("$interface.lan.address", ["192.168.1.1"])
    reg.register("$host.hostname", "myhost")
    assert reg.resolve("$service_port.dns.udp") == [53]
    assert reg.resolve("$interface.lan.address") == ["192.168.1.1"]
    assert reg.resolve("$host.hostname") == "myhost"


def test_namespaces_property(reg):
    reg.register("$service_port.dns.udp", [53])
    reg.register("$interface.lo.address", ["127.0.0.1"])
    ns = reg.namespaces
    assert "service_port" in ns
    assert "interface" in ns


# ── service_port — hyphenated service names ───────────────────────────────────

def test_hyphenated_service_name(reg):
    reg.register("$service_port.fastfirewall-api.tcp", [8000])
    assert reg.resolve("$service_port.fastfirewall-api.tcp") == [8000]
    assert reg.resolve("$service_port.fastfirewall-api.tcp[0]") == 8000


# ── is_macro ──────────────────────────────────────────────────────────────────

def test_is_macro_valid(reg):
    assert is_macro("$service_port.dns.udp") is True
    assert is_macro("$interface.lo.address") is True
    assert is_macro("$interface.lo.address[0]") is True


def test_is_macro_invalid(reg):
    assert is_macro("not-a-macro") is False
    assert is_macro("192.168.1.1") is False
    assert is_macro(53) is False  # type: ignore[arg-type]


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


def test_extract_macros_returns_empty_set_for_no_macros():
    assert extract_macros({"name": "foo", "port": 80}) == set()


def test_extract_macros_integer_ignored():
    assert extract_macros(42) == set()


def test_extract_macros_none_ignored():
    assert extract_macros(None) == set()
