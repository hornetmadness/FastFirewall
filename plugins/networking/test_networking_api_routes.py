"""
Tests for networking_plugin routes (/v1/networking/*).

systemd-networkd interactions are mocked via plugin._pyinfra_run and
patch("subprocess.run") — no real system changes are made.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure repo root is importable
_REPO_ROOT = str(Path(__file__).parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plugin_system.core.events import bus as global_bus

PLUGIN_PY = Path(__file__).parent / "plugin.py"


# ── helpers ────────────────────────────────────────────────────────────────────

def _load_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    name = "_test_networking"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_PY)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _ip_run_ok(stdout="[]"):
    return MagicMock(returncode=0, stdout=stdout, stderr="")


def _ip_run_err(stderr="error"):
    return MagicMock(returncode=1, stdout="", stderr=stderr)


def _make_ip_addr_list(interfaces: dict) -> list[dict]:
    """Build ip -j addr show style list from {name: {addresses, flags, mtu}} dict."""
    result = []
    for name, cfg in interfaces.items():
        flags = cfg.get("flags", ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"])
        addr_info = []
        for addr in cfg.get("addresses", []):
            ip_str, _, prefix = addr.partition("/")
            family = "inet6" if ":" in ip_str else "inet"
            addr_info.append({"family": family, "local": ip_str, "prefixlen": int(prefix)})
        entry: dict = {
            "ifname": name,
            "flags": flags,
            "mtu": cfg.get("mtu", 1500),
            "address": cfg.get("mac", "00:00:00:00:00:00"),
            "addr_info": addr_info,
        }
        result.append(entry)
    return result


def _make_ip_route_list(routes: list[dict]) -> list[dict]:
    """Build ip -j route show style list from route dicts."""
    result = []
    for r in routes:
        entry: dict = {"dst": r.get("to", "default"), "protocol": r.get("protocol", "static")}
        if r.get("via"):
            entry["gateway"] = r["via"]
        if r.get("dev"):
            entry["dev"] = r["dev"]
        if r.get("preference") is not None:
            entry["metric"] = r["preference"]
        result.append(entry)
    return result


def _subprocess_run_ok(*args, **kwargs):
    return MagicMock(returncode=0, stdout="", stderr="")


def _make_plugin(tmp_path, config=None):
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock()
    plugin._ip_addr_show = MagicMock(return_value=[])
    plugin._ip_route_show = MagicMock(return_value=[])
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        plugin.setup()
    plugin._pyinfra_run.reset_mock()
    plugin._ip_addr_show.reset_mock()
    plugin._ip_route_show.reset_mock()
    return plugin


def _make_client(plugin) -> TestClient:
    app = FastAPI()
    app.include_router(plugin.router, prefix="/v1/networking")
    return TestClient(app)


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def plugin(tmp_path):
    return _make_plugin(tmp_path)


@pytest.fixture
def client(plugin):
    return _make_client(plugin)


# ── status ─────────────────────────────────────────────────────────────────────

def test_status_returns_plugin_metadata(client):
    r = client.get("/v1/networking/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "Networking Plugin"
    assert data["version"] == "1.0.0"


def test_status_managed_counts_start_at_zero(client):
    data = client.get("/v1/networking/status").json()
    assert data["ff_managed"] == {"interfaces": 0, "routes": 0, "aliases": 1}
    assert data["pending_changes"] is False


def test_status_counts_reflect_additions(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1"})
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    managed = client.get("/v1/networking/status").json()["ff_managed"]
    assert managed == {"interfaces": 1, "routes": 1, "aliases": 3}


def test_status_has_networkd_dir(client):
    data = client.get("/v1/networking/status").json()
    assert data["networkd_dir"] == "/etc/systemd/network"
    assert data["networkd_prefix"] == "10-ff-"


# ── live state (ip addr show) ──────────────────────────────────────────────────

def test_show_interfaces_parses_ip_output(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list(
        {"eth0": {"addresses": ["192.168.1.100/24"]}}
    ))
    r = client.get("/v1/networking/interfaces")
    assert r.status_code == 200
    assert "eth0" in r.json()["interfaces"]
    assert r.json()["source"] == "running"


def test_show_interfaces_managed_false_when_not_in_config(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({"eth0": {}}))
    r = client.get("/v1/networking/interfaces")
    assert r.json()["interfaces"]["eth0"]["ff_managed"] is False


def test_show_interfaces_managed_true_when_in_config(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({"eth0": {}}))
    r = client.get("/v1/networking/interfaces")
    assert r.json()["interfaces"]["eth0"]["ff_managed"] is True


def test_show_interfaces_calls_ip_addr_show(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=[])
    client.get("/v1/networking/interfaces")
    plugin._ip_addr_show.assert_called_once()


def test_show_interfaces_500_on_error(plugin, client):
    plugin._ip_addr_show = MagicMock(side_effect=RuntimeError("permission denied"))
    r = client.get("/v1/networking/interfaces")
    assert r.status_code == 500


def test_show_interfaces_includes_link_state(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list(
        {"eth0": {"flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]}}
    ))
    r = client.get("/v1/networking/interfaces")
    assert r.json()["interfaces"]["eth0"]["link"]["state"] == "up"


def test_show_single_interface_found(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list(
        {"eth0": {"addresses": ["10.0.0.1/24"]}, "eth1": {}}
    ))
    r = client.get("/v1/networking/interfaces/eth0")
    assert r.status_code == 200
    assert r.json()["name"] == "eth0"
    assert "addresses" in r.json()


def test_show_single_interface_managed_false(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({"eth0": {}}))
    r = client.get("/v1/networking/interfaces/eth0")
    assert r.json()["ff_managed"] is False


def test_show_single_interface_managed_true(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({"eth0": {}}))
    r = client.get("/v1/networking/interfaces/eth0")
    assert r.json()["ff_managed"] is True


def test_show_single_interface_404_when_not_present(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=[])
    r = client.get("/v1/networking/interfaces/eth99")
    assert r.status_code == 404


# ── identify ───────────────────────────────────────────────────────────────────

def test_identify_reads_perm_hwaddr(plugin, client, tmp_path):
    net_dir = tmp_path / "net"
    eth0_dir = net_dir / "eth0"
    eth0_dir.mkdir(parents=True)
    (eth0_dir / "perm_hwaddr").write_text("aa:bb:cc:dd:ee:ff\n")

    mod = sys.modules["_test_networking"]
    original = getattr(mod, "_SYS_NET_DIR")
    setattr(mod, "_SYS_NET_DIR", net_dir)
    try:
        r = client.get("/v1/networking/identify")
    finally:
        setattr(mod, "_SYS_NET_DIR", original)

    assert r.status_code == 200
    assert r.json() == {"eth0": {"perm_address": "aa:bb:cc:dd:ee:ff"}}


def test_identify_falls_back_to_address(plugin, client, tmp_path):
    net_dir = tmp_path / "net"
    eth0_dir = net_dir / "eth0"
    eth0_dir.mkdir(parents=True)
    (eth0_dir / "address").write_text("11:22:33:44:55:66\n")

    mod = sys.modules["_test_networking"]
    original = getattr(mod, "_SYS_NET_DIR")
    setattr(mod, "_SYS_NET_DIR", net_dir)
    try:
        r = client.get("/v1/networking/identify")
    finally:
        setattr(mod, "_SYS_NET_DIR", original)

    assert r.status_code == 200
    assert r.json()["eth0"]["perm_address"] == "11:22:33:44:55:66"


def test_identify_500_on_os_error(plugin, client):
    mod = sys.modules["_test_networking"]
    original = getattr(mod, "_SYS_NET_DIR")
    setattr(mod, "_SYS_NET_DIR", Path("/nonexistent/path"))
    try:
        r = client.get("/v1/networking/identify")
    finally:
        setattr(mod, "_SYS_NET_DIR", original)
    assert r.status_code == 500


# ── config — interfaces ────────────────────────────────────────────────────────

def test_list_config_interfaces_empty(client):
    r = client.get("/v1/networking/config/interfaces")
    assert r.status_code == 200
    assert r.json() == {"interfaces": [], "count": 0}


def test_set_interface_creates_entry(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["192.168.1.1/24"]})
    assert r.status_code == 200
    assert r.json()["name"] == "eth0"
    assert r.json()["addresses"] == ["192.168.1.1/24"]


def test_set_interface_link_state(client):
    r = client.put("/v1/networking/config/interfaces/eth1", json={"link": {"state": "down"}})
    assert r.status_code == 200
    assert r.json()["link"]["state"] == "down"


def test_set_interface_link_mtu(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"link": {"mtu": 9000}})
    assert r.json()["link"]["mtu"] == 9000


def test_set_interface_updates_existing(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    r = client.get("/v1/networking/config/interfaces/eth0")
    assert r.json()["addresses"] == ["10.0.0.1/24"]
    assert r.json()["link"]["state"] == "up"


def test_list_config_interfaces_shows_added(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    r = client.get("/v1/networking/config/interfaces")
    names = [i["name"] for i in r.json()["interfaces"]]
    assert "eth0" in names
    assert r.json()["count"] == 1


def test_get_config_interface_not_found(client):
    r = client.get("/v1/networking/config/interfaces/eth99")
    assert r.status_code == 404


def test_delete_interface_removes_entry(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    r = client.delete("/v1/networking/config/interfaces/eth0")
    assert r.status_code == 200
    assert r.json() == {"deleted": "eth0"}
    assert client.get("/v1/networking/config/interfaces/eth0").status_code == 404


def test_delete_interface_not_configured_returns_404(client):
    assert client.delete("/v1/networking/config/interfaces/eth99").status_code == 404


def test_set_interface_emits_event(plugin, client):
    received = []
    global_bus.subscribe("networking.interface.configured", received.append)
    try:
        client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
        assert len(received) == 1
        assert received[0].payload["name"] == "eth0"
    finally:
        global_bus.unsubscribe("networking.interface.configured", received.append)


def test_delete_interface_emits_event(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    received = []
    global_bus.subscribe("networking.interface.removed", received.append)
    try:
        client.delete("/v1/networking/config/interfaces/eth0")
        assert len(received) == 1
        assert received[0].payload["name"] == "eth0"
    finally:
        global_bus.unsubscribe("networking.interface.removed", received.append)


# ── input validation ──────────────────────────────────────────────────────────

def test_address_must_be_cidr(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["string"]})
    assert r.status_code == 422


def test_address_invalid_ip_rejected(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["999.0.0.1/24"]})
    assert r.status_code == 422


def test_address_plain_string_rejected(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["not-an-address"]})
    assert r.status_code == 422


def test_valid_ipv4_cidr_accepted(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["192.168.1.1/24"]})
    assert r.status_code == 200


def test_valid_ipv6_cidr_accepted(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["::1/128"]})
    assert r.status_code == 200


def test_multiple_addresses_all_validated(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24", "bad"]})
    assert r.status_code == 422


def test_mtu_below_minimum_rejected(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"link": {"mtu": 10}})
    assert r.status_code == 422


def test_mtu_above_maximum_rejected(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"link": {"mtu": 99999}})
    assert r.status_code == 422


def test_mtu_valid_accepted(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"link": {"mtu": 1500}})
    assert r.status_code == 200


def test_mtu_jumbo_frame_accepted(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"link": {"mtu": 9000}})
    assert r.status_code == 200


def test_route_to_invalid_cidr_rejected(client):
    r = client.post("/v1/networking/config/routes", json={"to": "not-a-cidr"})
    assert r.status_code == 422


def test_route_to_invalid_ip_rejected(client):
    r = client.post("/v1/networking/config/routes", json={"to": "999.0.0.0/8"})
    assert r.status_code == 422


def test_route_to_default_accepted(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default"})
    assert r.status_code == 201


def test_route_to_valid_cidr_accepted(client):
    r = client.post("/v1/networking/config/routes", json={"to": "10.0.0.0/8"})
    assert r.status_code == 201


def test_route_via_invalid_ip_rejected(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "not-an-ip"})
    assert r.status_code == 422


def test_route_via_valid_ip_accepted(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1"})
    assert r.status_code == 201


def test_route_via_ipv6_accepted(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "fe80::1"})
    assert r.status_code == 201


def test_route_via_with_prefix_rejected(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1/24"})
    assert r.status_code == 422


def test_route_dev_not_in_managed_config_rejected(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "dev": "bogus0"})
    assert r.status_code == 422


def test_route_dev_in_managed_config_accepted(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    r = client.post("/v1/networking/config/routes", json={"to": "default", "dev": "eth0"})
    assert r.status_code == 201
    assert r.json()["dev"] == "eth0"


# ── config — routes ────────────────────────────────────────────────────────────

def test_list_routes_empty(client):
    r = client.get("/v1/networking/config/routes")
    assert r.json() == {"routes": [], "count": 0}


def test_add_route_default_gateway(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1"})
    assert r.status_code == 201
    data = r.json()
    assert data["to"] == "default"
    assert data["via"] == "192.168.1.1"
    assert "id" in data


def test_add_route_with_dev_and_preference(client):
    client.put("/v1/networking/config/interfaces/eth1", json={})
    r = client.post("/v1/networking/config/routes", json={"to": "10.0.0.0/8", "dev": "eth1", "preference": 100})
    assert r.status_code == 201
    assert r.json()["dev"] == "eth1"
    assert r.json()["preference"] == 100


def test_add_route_minimal(client):
    r = client.post("/v1/networking/config/routes", json={"to": "172.16.0.0/12"})
    assert r.status_code == 201
    assert r.json()["to"] == "172.16.0.0/12"


def test_list_routes_shows_added(client):
    client.post("/v1/networking/config/routes", json={"to": "default", "via": "10.0.0.1"})
    r = client.get("/v1/networking/config/routes")
    assert r.json()["count"] == 1
    assert r.json()["routes"][0]["to"] == "default"


def test_delete_route_removes_entry(client):
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1"})
    route_id = r.json()["id"]
    del_r = client.delete(f"/v1/networking/config/routes/{route_id}")
    assert del_r.status_code == 200
    assert del_r.json() == {"deleted": route_id}
    assert client.get("/v1/networking/config/routes").json()["count"] == 0


def test_delete_route_not_found_returns_404(client):
    assert client.delete("/v1/networking/config/routes/nonexistent-uuid").status_code == 404


def test_add_route_emits_event(plugin, client):
    received = []
    global_bus.subscribe("networking.route.added", received.append)
    try:
        client.post("/v1/networking/config/routes", json={"to": "default", "via": "10.0.0.1"})
        assert len(received) == 1
        assert received[0].payload["to"] == "default"
    finally:
        global_bus.unsubscribe("networking.route.added", received.append)


def test_delete_route_emits_event(plugin, client):
    r = client.post("/v1/networking/config/routes", json={"to": "0.0.0.0/0", "via": "10.0.0.1"})
    route_id = r.json()["id"]
    received = []
    global_bus.subscribe("networking.route.removed", received.append)
    try:
        client.delete(f"/v1/networking/config/routes/{route_id}")
        assert len(received) == 1
        assert received[0].payload["route_id"] == route_id
    finally:
        global_bus.unsubscribe("networking.route.removed", received.append)


# ── GET /config ────────────────────────────────────────────────────────────────

def test_get_config_returns_dict(client):
    r = client.get("/v1/networking/config")
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_get_config_returns_dict_of_network_files(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.get("/v1/networking/config")
    assert r.status_code == 200
    data = r.json()
    assert "10-ff-eth0.network" in data


def test_get_config_file_content_contains_address(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.get("/v1/networking/config")
    content = r.json()["10-ff-eth0.network"]
    assert "Address=10.0.0.1/24" in content


def test_get_config_file_content_has_match_section(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    content = client.get("/v1/networking/config").json()["10-ff-eth0.network"]
    assert "[Match]" in content
    assert "Name=eth0" in content


def test_get_config_empty_state_returns_empty_dict(client):
    r = client.get("/v1/networking/config")
    assert r.json() == {}


# ── networkd file builder unit tests ──────────────────────────────────────────

def test_build_networkd_file_static_address(tmp_path):
    plugin = _make_plugin(tmp_path)
    content = plugin._build_networkd_file("eth0", {"addresses": ["192.168.1.1/24"]}, [])
    assert "[Match]" in content
    assert "Name=eth0" in content
    assert "[Network]" in content
    assert "Address=192.168.1.1/24" in content


def test_build_networkd_file_mtu_in_link_section(tmp_path):
    plugin = _make_plugin(tmp_path)
    content = plugin._build_networkd_file("eth0", {"link": {"mtu": 9000}}, [])
    assert "[Link]" in content
    assert "MTUBytes=9000" in content


def test_build_networkd_file_activation_policy_up(tmp_path):
    plugin = _make_plugin(tmp_path)
    content = plugin._build_networkd_file("eth0", {"link": {"state": "up"}}, [])
    assert "ActivationPolicy=always-up" in content


def test_build_networkd_file_activation_policy_down(tmp_path):
    plugin = _make_plugin(tmp_path)
    content = plugin._build_networkd_file("eth0", {"link": {"state": "down"}}, [])
    assert "ActivationPolicy=always-down" in content


def test_build_networkd_file_no_activation_policy_when_state_not_set(tmp_path):
    plugin = _make_plugin(tmp_path)
    content = plugin._build_networkd_file("eth0", {}, [])
    assert "ActivationPolicy" not in content


def test_build_networkd_file_route_section(tmp_path):
    plugin = _make_plugin(tmp_path)
    route = {"to": "10.0.0.0/8", "via": "192.168.1.1", "preference": 100}
    content = plugin._build_networkd_file("eth0", {"addresses": ["192.168.1.2/24"]}, [route])
    assert "[Route]" in content
    assert "Destination=10.0.0.0/8" in content
    assert "Gateway=192.168.1.1" in content
    assert "Metric=100" in content


def test_build_networkd_file_default_route_normalized(tmp_path):
    plugin = _make_plugin(tmp_path)
    route = {"to": "default", "via": "192.168.1.1"}
    content = plugin._build_networkd_file("eth0", {}, [route])
    assert "Destination=0.0.0.0/0" in content


def test_build_all_networkd_configs_raises_on_orphan_route(tmp_path):
    plugin = _make_plugin(tmp_path)
    import json as _json, hashlib as _hashlib
    route = {"to": "172.16.0.0/12"}
    route_id = _hashlib.sha256(_json.dumps(route, sort_keys=True).encode()).hexdigest()[:16]
    plugin._interfaces["eth0"] = {"addresses": ["10.0.0.1/24"]}
    plugin._routes[route_id] = route
    with pytest.raises(ValueError, match="Unroutable routes"):
        plugin._build_all_networkd_configs()


def test_build_all_networkd_configs_assigns_route_by_dev(tmp_path):
    plugin = _make_plugin(tmp_path)
    import json as _json, hashlib as _hashlib
    route = {"to": "10.0.0.0/8", "dev": "eth0"}
    route_id = _hashlib.sha256(_json.dumps(route, sort_keys=True).encode()).hexdigest()[:16]
    plugin._interfaces["eth0"] = {"addresses": ["192.168.1.1/24"]}
    plugin._routes[route_id] = route
    files = plugin._build_all_networkd_configs()
    assert "Destination=10.0.0.0/8" in files["10-ff-eth0.network"]


def test_build_all_networkd_configs_assigns_route_by_gateway_subnet(tmp_path):
    plugin = _make_plugin(tmp_path)
    import json as _json, hashlib as _hashlib
    route = {"to": "default", "via": "192.168.1.254"}
    route_id = _hashlib.sha256(_json.dumps(route, sort_keys=True).encode()).hexdigest()[:16]
    plugin._interfaces["eth0"] = {"addresses": ["192.168.1.1/24"]}
    plugin._routes[route_id] = route
    files = plugin._build_all_networkd_configs()
    assert "Gateway=192.168.1.254" in files["10-ff-eth0.network"]


# ── apply & check ──────────────────────────────────────────────────────────────

def test_apply_writes_networkd_file(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        r = client.post("/v1/networking/apply")
    assert r.status_code == 200
    plugin._pyinfra_run.assert_called()
    calls_dest = [
        c.kwargs.get("dest") or (c.args[1] if len(c.args) > 1 else "")
        for c in plugin._pyinfra_run.call_args_list
    ]
    assert any("10-ff-eth0.network" in str(d) for d in calls_dest)


def test_apply_returns_success_true_on_zero_exit(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        r = client.post("/v1/networking/apply")
    assert r.json()["success"] is True
    assert r.json()["returncode"] == 0


def test_apply_returns_success_false_on_networkctl_failure(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="", stderr="failed")):
        r = client.post("/v1/networking/apply")
    assert r.status_code == 200
    assert r.json()["success"] is False
    assert r.json()["returncode"] == 1


def test_apply_returns_success_false_on_pyinfra_failure(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._pyinfra_run.side_effect = RuntimeError("write failed")
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        r = client.post("/v1/networking/apply")
    assert r.json()["success"] is False
    assert r.json()["returncode"] == 1


def test_apply_returns_success_false_on_orphan_route(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    client.post("/v1/networking/config/routes", json={"to": "172.16.0.0/12"})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        r = client.post("/v1/networking/apply")
    assert r.json()["success"] is False
    assert "errors" in r.json()


def test_apply_changes_shows_added_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        r = client.post("/v1/networking/apply")
    assert r.json()["changes"]["interfaces"]["added"]["eth0"]["addresses"] == ["10.0.0.1/24"]


def test_apply_changes_empty_when_nothing_pending(plugin, client):
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
        plugin._pyinfra_run.reset_mock()
        r = client.post("/v1/networking/apply")
    assert r.json()["changes"] == {}


def test_apply_updates_current_state_on_success(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    assert plugin._state_file.current_snapshot is not None
    assert "eth0" in plugin._state_file.current_snapshot["interfaces"]


def test_apply_does_not_update_current_state_on_failure(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="", stderr="err")):
        client.post("/v1/networking/apply")
    assert plugin._state_file.current_snapshot is None


def test_apply_emits_event(plugin, client):
    received = []
    global_bus.subscribe("networking.applied", received.append)
    try:
        with patch("subprocess.run", side_effect=_subprocess_run_ok):
            client.post("/v1/networking/apply")
        assert len(received) == 1
        assert received[0].payload["success"] is True
    finally:
        global_bus.unsubscribe("networking.applied", received.append)


def test_apply_calls_networkctl_reload(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    calls = []
    def capture_run(*args, **kwargs):
        calls.append(args[0] if args else [])
        return MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", side_effect=capture_run):
        client.post("/v1/networking/apply")
    assert any(c and "networkctl" in c and "reload" in c for c in calls)


def test_apply_calls_networkctl_reconfigure_per_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    calls = []
    def capture_run(*args, **kwargs):
        calls.append(args[0] if args else [])
        return MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", side_effect=capture_run):
        client.post("/v1/networking/apply")
    reconfigure_calls = [c for c in calls if c and "networkctl" in c and "reconfigure" in c]
    assert len(reconfigure_calls) == 2


def test_apply_writes_networkd_file_with_correct_content(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["192.168.1.1/24"]})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    # Find the put call for eth0
    put_calls = [
        c for c in plugin._pyinfra_run.call_args_list
        if c.kwargs.get("dest") == "/etc/systemd/network/10-ff-eth0.network"
    ]
    assert len(put_calls) == 1


def test_apply_skips_networkd_when_no_interfaces_or_routes(plugin, client):
    with patch("subprocess.run", side_effect=_subprocess_run_ok) as mock_run:
        r = client.post("/v1/networking/apply")
    plugin._pyinfra_run.assert_not_called()
    assert r.json()["success"] is True


def test_check_returns_preview_dict(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.post("/v1/networking/check")
    assert r.status_code == 200
    data = r.json()
    assert "preview" in data
    assert "10-ff-eth0.network" in data["preview"]


def test_check_preview_contains_address(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.post("/v1/networking/check")
    content = r.json()["preview"]["10-ff-eth0.network"]
    assert "Address=10.0.0.1/24" in content


def test_check_preview_contains_dhcp_line(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True})
    r = client.post("/v1/networking/check")
    content = r.json()["preview"]["10-ff-eth0.network"]
    assert "DHCP=ipv4" in content


def test_check_returns_error_on_orphan_route(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    client.post("/v1/networking/config/routes", json={"to": "172.16.0.0/12"})
    r = client.post("/v1/networking/check")
    assert r.json()["success"] is False
    assert "errors" in r.json()
    assert r.json()["preview"] == {}


def test_check_returns_valid_true_on_success(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    r = client.post("/v1/networking/check")
    assert r.status_code == 200
    assert r.json()["success"] is True


def test_check_shows_deleted_route(plugin, client):
    # Interface needed so gateway 10.0.0.1 is routable via subnet match
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.2/24"]})
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "10.0.0.1"})
    route_id = r.json()["id"]
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.delete(f"/v1/networking/config/routes/{route_id}")
    r = client.post("/v1/networking/check")
    assert r.status_code == 200
    assert route_id in r.json()["changes"]["routes"]["removed"]


# ── discard ────────────────────────────────────────────────────────────────────

def test_discard_409_when_no_snapshot(client):
    r = client.post("/v1/networking/discard")
    assert r.status_code == 409


def test_discard_restores_current_state(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={})
    assert client.get("/v1/networking/config/interfaces").json()["count"] == 2
    client.post("/v1/networking/discard")
    assert client.get("/v1/networking/config/interfaces").json()["count"] == 1
    names = [i["name"] for i in client.get("/v1/networking/config/interfaces").json()["interfaces"]]
    assert "eth1" not in names


def test_discard_returns_diff_of_what_was_reverted(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={})
    r = client.post("/v1/networking/discard")
    assert r.status_code == 200
    assert r.json()["discarded"] is True
    assert "eth1" in r.json()["changes"]["interfaces"]["removed"]


def test_discard_empty_changes_when_nothing_pending(plugin, client):
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    r = client.post("/v1/networking/discard")
    assert r.json()["changes"] == {}


# ── pending_changes in status ──────────────────────────────────────────────────

def test_status_pending_false_initially(client):
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


def test_status_pending_true_after_mutation_before_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={})
    assert client.get("/v1/networking/status").json()["pending_changes"] is True


def test_status_pending_false_after_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


def test_status_pending_false_after_discard(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/discard")
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


# ── state persistence ──────────────────────────────────────────────────────────

def test_state_persists_across_plugin_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    c1.post("/v1/networking/config/routes", json={"to": "default", "via": "10.0.0.254"})
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    names = [i["name"] for i in c2.get("/v1/networking/config/interfaces").json()["interfaces"]]
    assert "eth0" in names
    assert c2.get("/v1/networking/config/routes").json()["count"] == 1


def test_deleted_entries_absent_after_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/networking/config/interfaces/eth0", json={})
    c1.delete("/v1/networking/config/interfaces/eth0")
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    names = [i["name"] for i in c2.get("/v1/networking/config/interfaces").json()["interfaces"]]
    assert "eth0" not in names


def test_state_file_written_to_configured_path(tmp_path):
    p = _make_plugin(tmp_path, config={"state_file": "custom_net_state.json"})
    c = _make_client(p)
    c.put("/v1/networking/config/interfaces/eth0", json={})
    p.teardown()
    assert (tmp_path / "data" / "custom_net_state.json").exists()


# ── import interfaces ──────────────────────────────────────────────────────────

def test_import_all_interfaces(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({
        "eth0": {"addresses": ["10.0.0.1/24"]},
        "eth1": {"flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]},
    }))
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.status_code == 200
    data = r.json()
    assert set(data["imported"]) == {"eth0", "eth1"}
    assert data["skipped"] == []
    assert data["not_found"] == []


def test_import_specific_interfaces(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({
        "eth0": {"addresses": ["10.0.0.1/24"]},
        "eth1": {},
        "eth2": {},
    }))
    r = client.post("/v1/networking/config/interfaces/import", json={"names": ["eth0", "eth2"]})
    assert r.status_code == 200
    data = r.json()
    assert set(data["imported"]) == {"eth0", "eth2"}
    assert "eth1" not in data["imported"]


def test_import_not_found_interface(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({"eth0": {}}))
    r = client.post("/v1/networking/config/interfaces/import", json={"names": ["eth0", "eth99"]})
    assert r.status_code == 200
    data = r.json()
    assert "eth0" in data["imported"]
    assert "eth99" in data["not_found"]


def test_import_skips_already_managed_without_overwrite(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["1.2.3.4/24"]})
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list(
        {"eth0": {"addresses": ["10.0.0.1/24"]}}
    ))
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.status_code == 200
    data = r.json()
    assert "eth0" in data["skipped"]
    assert "eth0" not in data["imported"]
    cfg = client.get("/v1/networking/config/interfaces/eth0").json()
    assert cfg["addresses"] == ["1.2.3.4/24"]


def test_import_overwrites_managed_when_flag_set(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["1.2.3.4/24"]})
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list(
        {"eth0": {"addresses": ["10.0.0.1/24"]}}
    ))
    r = client.post("/v1/networking/config/interfaces/import", json={"overwrite": True})
    assert r.status_code == 200
    assert "eth0" in r.json()["imported"]
    cfg = client.get("/v1/networking/config/interfaces/eth0").json()
    assert cfg["addresses"] == ["10.0.0.1/24"]


def test_import_500_on_ip_failure(plugin, client):
    plugin._ip_addr_show = MagicMock(side_effect=RuntimeError("permission denied"))
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.status_code == 500


def test_import_calls_ip_addr_show(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=[])
    plugin._ip_addr_show.reset_mock()
    client.post("/v1/networking/config/interfaces/import", json={})
    plugin._ip_addr_show.assert_called_once()


def test_import_emits_event_per_interface(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({
        "eth0": {"addresses": ["10.0.0.1/24"]},
        "eth1": {},
    }))
    received = []
    global_bus.subscribe("networking.interface.configured", received.append)
    try:
        client.post("/v1/networking/config/interfaces/import", json={})
        names = [e.payload["name"] for e in received]
        assert "eth0" in names
        assert "eth1" in names
    finally:
        global_bus.unsubscribe("networking.interface.configured", received.append)


def test_import_no_event_when_nothing_imported(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=[])
    received = []
    global_bus.subscribe("networking.interface.configured", received.append)
    try:
        client.post("/v1/networking/config/interfaces/import", json={})
        assert received == []
    finally:
        global_bus.unsubscribe("networking.interface.configured", received.append)


def test_import_saves_state(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list(
        {"eth0": {"addresses": ["10.0.0.1/24"]}}
    ))
    client.post("/v1/networking/config/interfaces/import", json={})
    assert (plugin.plugin_dir / "data" / "networking_state.json").exists()


# ── boot-time state apply ──────────────────────────────────────────────────────

_BOOT_STATE = {
    "desired_state": {
        "interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}},
        "routes": {},
    },
}


def _write_boot_state(tmp_path, state=None):
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "data" / "networking_state.json").write_text(json.dumps(state or _BOOT_STATE))


def _make_plugin_raw(tmp_path, config=None):
    """Create a plugin without resetting the mock — used for boot-sequence assertions."""
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock()
    plugin._ip_addr_show = MagicMock(return_value=[])
    plugin._ip_route_show = MagicMock(return_value=[])
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        plugin.setup()
    return plugin


def test_boot_apply_calls_pyinfra_run_on_boot(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path)
    assert plugin._pyinfra_run.called


def test_ignore_state_on_boot_skips_load_and_apply(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path, config={"ignore_state_on_boot": True})
    plugin._pyinfra_run.assert_not_called()
    assert plugin._interfaces == {}


def test_apply_skipped_when_state_is_empty(tmp_path):
    plugin = _make_plugin_raw(tmp_path)
    plugin._pyinfra_run.assert_not_called()


def test_apply_state_does_not_crash_on_pyinfra_failure(tmp_path):
    _write_boot_state(tmp_path)
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock(side_effect=RuntimeError("permission denied"))
    plugin._ip_addr_show = MagicMock(return_value=[])
    plugin._ip_route_show = MagicMock(return_value=[])
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        plugin.setup()  # must not raise
    assert plugin._interfaces == {"eth0": {"addresses": ["10.0.0.1/24"]}}


def test_boot_apply_does_not_commit_current_state(tmp_path):
    # Boot-time apply writes files but does NOT auto-commit current_state on failure.
    # On success it DOES commit.
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path)
    # Successful boot apply commits
    assert plugin._state_file.current_snapshot is not None


def test_boot_apply_does_not_set_current_state_on_failure(tmp_path):
    _write_boot_state(tmp_path)
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock(side_effect=RuntimeError("failed"))
    plugin._ip_addr_show = MagicMock(return_value=[])
    plugin._ip_route_show = MagicMock(return_value=[])
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        plugin.setup()
    assert plugin._state_file.current_snapshot is None


def test_boot_apply_clears_pending_changes(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path)
    client = _make_client(plugin)
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


def test_boot_apply_calls_networkctl_reload(tmp_path):
    _write_boot_state(tmp_path)
    calls = []
    def capture_run(*args, **kwargs):
        calls.append(args[0] if args else [])
        return MagicMock(returncode=0, stdout="", stderr="")

    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock()
    plugin._ip_addr_show = MagicMock(return_value=[])
    plugin._ip_route_show = MagicMock(return_value=[])
    with patch("subprocess.run", side_effect=capture_run):
        plugin.setup()
    assert any(c and "networkctl" in c and "reload" in c for c in calls)


# ── boot-time auto-import ──────────────────────────────────────────────────────

def _make_plugin_boot_import(tmp_path, ip_addr_data=None, ip_route_data=None, config=None):
    """Create a plugin with custom ip output for boot-import tests."""
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock()
    plugin._ip_addr_show = MagicMock(return_value=ip_addr_data if ip_addr_data is not None else [])
    plugin._ip_route_show = MagicMock(return_value=ip_route_data if ip_route_data is not None else [])
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        plugin.setup()
    return plugin


def test_boot_import_interfaces_when_state_empty(tmp_path):
    addr_data = _make_ip_addr_list({
        "eth0": {"addresses": ["10.0.0.1/24"]},
        "eth1": {"flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]},
    })
    plugin = _make_plugin_boot_import(tmp_path, ip_addr_data=addr_data)
    assert "eth0" in plugin._interfaces
    assert "eth1" in plugin._interfaces
    assert plugin._interfaces["eth0"]["addresses"] == ["10.0.0.1/24"]


def test_boot_import_routes_when_state_empty(tmp_path):
    route_data = _make_ip_route_list([
        {"to": "default", "via": "192.168.1.1", "dev": "eth0"},
        {"to": "10.0.0.0/8", "dev": "eth0"},
    ])
    plugin = _make_plugin_boot_import(tmp_path, ip_route_data=route_data)
    destinations = {r["to"] for r in plugin._routes.values()}
    assert "default" in destinations
    assert "10.0.0.0/8" in destinations


def test_boot_import_route_fields_preserved(tmp_path):
    route_data = _make_ip_route_list([
        {"to": "default", "via": "10.0.0.1", "dev": "eth0", "preference": 100},
    ])
    plugin = _make_plugin_boot_import(tmp_path, ip_route_data=route_data)
    route = next(iter(plugin._routes.values()))
    assert route["via"] == "10.0.0.1"
    assert route["dev"] == "eth0"
    assert route["preference"] == 100


def test_boot_import_skips_kernel_routes(tmp_path):
    route_data = [
        {"dst": "192.168.1.0/24", "protocol": "kernel", "dev": "eth0"},
        {"dst": "default", "protocol": "static", "gateway": "192.168.1.1"},
    ]
    plugin = _make_plugin_boot_import(tmp_path, ip_route_data=route_data)
    destinations = {r["to"] for r in plugin._routes.values()}
    assert "192.168.1.0/24" not in destinations
    assert "default" in destinations


def test_boot_import_skips_loopback(tmp_path):
    addr_data = _make_ip_addr_list({"lo": {"flags": ["LOOPBACK", "UP"]}})
    plugin = _make_plugin_boot_import(tmp_path, ip_addr_data=addr_data)
    assert "lo" not in plugin._interfaces


def test_boot_import_saves_state_file(tmp_path):
    addr_data = _make_ip_addr_list({"eth0": {}})
    _make_plugin_boot_import(tmp_path, ip_addr_data=addr_data)
    assert (tmp_path / "data" / "networking_state.json").exists()


def test_boot_import_does_not_save_when_nothing_found(tmp_path):
    plugin = _make_plugin_boot_import(tmp_path)
    assert plugin._interfaces == {}
    assert plugin._routes == {}


def test_boot_import_skipped_when_state_has_data(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin(tmp_path)
    assert plugin._interfaces == {"eth0": {"addresses": ["10.0.0.1/24"]}}


def test_boot_import_skipped_with_ignore_state_on_boot(tmp_path):
    addr_data = _make_ip_addr_list({"eth0": {"addresses": ["10.0.0.1/24"]}})
    plugin = _make_plugin_boot_import(tmp_path, ip_addr_data=addr_data, config={"ignore_state_on_boot": True})
    assert plugin._interfaces == {}


def test_boot_import_does_not_crash_on_ip_failure(tmp_path):
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._pyinfra_run = MagicMock()
    plugin._ip_addr_show = MagicMock(side_effect=RuntimeError("permission denied"))
    plugin._ip_route_show = MagicMock(side_effect=RuntimeError("permission denied"))
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        plugin.setup()  # must not raise
    assert plugin._interfaces == {}
    assert plugin._routes == {}


# ── interface aliases ──────────────────────────────────────────────────────────

def test_list_aliases_empty(client):
    r = client.get("/v1/networking/config/aliases")
    assert r.status_code == 200
    assert r.json() == {"aliases": {"lo": "lo"}, "count": 1}


def test_set_alias_creates_entry(client):
    r = client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    assert r.status_code == 200
    assert r.json() == {"name": "LAN1", "interface": "eth0"}


def test_set_alias_appears_in_list(client):
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    client.put("/v1/networking/config/aliases/WAN", json={"interface": "eth1"})
    data = client.get("/v1/networking/config/aliases").json()
    assert data["count"] == 3
    assert data["aliases"]["LAN1"] == "eth0"
    assert data["aliases"]["WAN"] == "eth1"


def test_set_alias_overwrites_existing(client):
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "br0"})
    assert client.get("/v1/networking/config/aliases").json()["aliases"]["LAN1"] == "br0"


def test_delete_alias_removes_entry(client):
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    r = client.delete("/v1/networking/config/aliases/LAN1")
    assert r.status_code == 200
    assert r.json()["deleted"] == "LAN1"
    assert client.get("/v1/networking/config/aliases").json()["aliases"] == {"lo": "lo"}


def test_delete_alias_404_for_unknown(client):
    r = client.delete("/v1/networking/config/aliases/NOPE")
    assert r.status_code == 404


def test_set_alias_rejects_invalid_name(client):
    r = client.put("/v1/networking/config/aliases/123bad", json={"interface": "eth0"})
    assert r.status_code == 422


def test_set_alias_rejects_empty_interface(client):
    r = client.put("/v1/networking/config/aliases/LAN1", json={"interface": ""})
    assert r.status_code == 422


def test_aliases_persisted_across_plugin_instances(tmp_path):
    plugin1 = _make_plugin(tmp_path)
    _make_client(plugin1).put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    plugin2 = _make_plugin(tmp_path)
    data = _make_client(plugin2).get("/v1/networking/config/aliases").json()
    assert data["aliases"].get("LAN1") == "eth0"


def test_set_alias_emits_aliases_updated_event(plugin, client):
    received: list = []
    global_bus.subscribe("networking.aliases_updated", received.append)
    try:
        client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
        assert len(received) == 1
        assert received[0].payload["aliases"] == {"LAN1": "eth0", "lo": "lo"}
    finally:
        global_bus.unsubscribe("networking.aliases_updated", received.append)


def test_delete_alias_emits_aliases_updated_event(plugin, client):
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    received: list = []
    global_bus.subscribe("networking.aliases_updated", received.append)
    try:
        client.delete("/v1/networking/config/aliases/LAN1")
        assert len(received) == 1
        assert received[0].payload["aliases"] == {"lo": "lo"}
    finally:
        global_bus.unsubscribe("networking.aliases_updated", received.append)


def test_set_interface_creates_default_alias(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    aliases = client.get("/v1/networking/config/aliases").json()["aliases"]
    assert aliases.get("eth0") == "eth0"


def test_set_interface_default_alias_not_overwritten_by_second_put(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    client.put("/v1/networking/config/aliases/eth0", json={"interface": "br0"})
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "down"}})
    assert client.get("/v1/networking/config/aliases").json()["aliases"]["eth0"] == "br0"


def test_import_interfaces_creates_default_aliases(plugin, client):
    plugin._ip_addr_show = MagicMock(return_value=_make_ip_addr_list({
        "eth0": {}, "eth1": {"addresses": ["10.0.0.1/24"]},
    }))
    client.post("/v1/networking/config/interfaces/import", json={})
    aliases = client.get("/v1/networking/config/aliases").json()["aliases"]
    assert aliases.get("eth0") == "eth0"
    assert aliases.get("eth1") == "eth1"


def test_boot_import_creates_default_aliases(tmp_path):
    addr_data = _make_ip_addr_list({"eth0": {"addresses": ["10.0.0.1/24"]}})
    plugin = _make_plugin_boot_import(tmp_path, ip_addr_data=addr_data)
    assert plugin._aliases.get("eth0") == "eth0"


def test_load_state_creates_default_aliases_for_existing_interfaces(tmp_path):
    state = {
        "desired_state": {
            "interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}},
            "routes": {},
        },
        "current_state": {
            "interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}},
            "routes": {},
        },
    }
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "networking_state.json").write_text(json.dumps(state))
    plugin = _make_plugin(tmp_path)
    assert plugin._aliases.get("eth0") == "eth0"


def test_boot_emits_aliases_updated_when_aliases_exist(tmp_path):
    state = {
        "desired_state": {
            "interfaces": {},
            "routes": {},
            "aliases": {"LAN1": "eth0"},
        },
        "current_state": {
            "interfaces": {},
            "routes": {},
            "aliases": {"LAN1": "eth0"},
        },
    }
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "networking_state.json").write_text(json.dumps(state))

    received: list = []
    global_bus.subscribe("networking.aliases_updated", received.append)
    try:
        _make_plugin(tmp_path, config={"ignore_state_on_boot": True})
        assert len(received) == 0
        _make_plugin(tmp_path)
        assert len(received) == 1
        assert received[0].payload["aliases"] == {"LAN1": "eth0", "lo": "lo"}
    finally:
        global_bus.unsubscribe("networking.aliases_updated", received.append)


# ── GET /config/diff ───────────────────────────────────────────────────────────

def test_diff_empty_when_no_pending_changes(client):
    r = client.get("/v1/networking/config/diff")
    assert r.status_code == 200
    body = r.json()
    assert body["pending_changes"] is False
    assert body["diff"] == {}


def test_diff_shows_added_interface(plugin, client):
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is True
    assert "eth0" in body["diff"]["interfaces"]["added"]


def test_diff_shows_removed_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.delete("/v1/networking/config/interfaces/eth0")
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is True
    assert "eth0" in body["diff"]["interfaces"]["removed"]


def test_diff_shows_modified_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.2/24"]})
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is True
    modified = body["diff"]["interfaces"]["modified"]["eth0"]
    assert modified["from"]["addresses"] == ["10.0.0.1/24"]
    assert modified["to"]["addresses"] == ["10.0.0.2/24"]


def test_diff_pending_false_after_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is False
    assert body["diff"] == {}


# ── interface macro resolver ───────────────────────────────────────────────────

def test_interface_macro_name_resolves_to_device(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    assert plugin._resolve_interface_macro("lan", "name") == "eth0"


def test_interface_macro_address_resolves_to_ip_list(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    plugin._interfaces["eth0"] = {"addresses": ["192.168.1.1/24"]}
    assert plugin._resolve_interface_macro("lan", "address") == ["192.168.1.1"]


def test_interface_macro_address_empty_when_no_addresses(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    plugin._interfaces["eth0"] = {}
    assert plugin._resolve_interface_macro("lan", "address") == []


def test_interface_macro_unknown_alias_returns_none(tmp_path):
    plugin = _make_plugin(tmp_path)
    assert plugin._resolve_interface_macro("missing", "name") is None


def test_interface_macro_unknown_field_returns_none(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    assert plugin._resolve_interface_macro("lan", "other") is None


def test_interface_macro_missing_field_returns_none(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    assert plugin._resolve_interface_macro("lan") is None


def test_interface_macro_no_args_returns_none(tmp_path):
    plugin = _make_plugin(tmp_path)
    assert plugin._resolve_interface_macro() is None


def test_macro_snapshot_includes_name_and_address(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    plugin._interfaces["eth0"] = {"addresses": ["10.0.0.1/24"]}
    snap = plugin.macro_snapshot()
    assert snap["interface"]["lan.name"] == "eth0"
    assert snap["interface"]["lan.address"] == ["10.0.0.1"]


def test_macro_snapshot_omits_address_when_none(tmp_path):
    plugin = _make_plugin(tmp_path)
    plugin._aliases["lan"] = "eth0"
    plugin._interfaces["eth0"] = {}
    snap = plugin.macro_snapshot()
    assert "lan.address" not in snap["interface"]
    assert snap["interface"]["lan.name"] == "eth0"


# ── os boot service ────────────────────────────────────────────────────────────

def test_use_systemd_networkd_emits_service_start_for_networkd(tmp_path):
    received = []
    global_bus.subscribe("initsys.service.start", received.append)
    try:
        _make_plugin(tmp_path, config={"use_systemd_networkd": True})
        start_names = [e.payload["service_name"] for e in received]
        assert "systemd-networkd.service" in start_names
    finally:
        global_bus.unsubscribe("initsys.service.start", received.append)


def test_use_systemd_networkd_true_does_not_emit_service_add(tmp_path):
    received = []
    global_bus.subscribe("initsys.service.add", received.append)
    try:
        _make_plugin(tmp_path, config={"use_systemd_networkd": True})
        assert received == []
    finally:
        global_bus.unsubscribe("initsys.service.add", received.append)


def test_use_systemd_networkd_disables_configured_managers(tmp_path):
    disable_events = []
    global_bus.subscribe("initsys.service.disable", disable_events.append)
    try:
        _make_plugin(tmp_path, config={
            "use_systemd_networkd": True,
            "disable_os_managers": ["NetworkManager", "networking"],
        })
        names = [e.payload["service_name"] for e in disable_events]
        assert "NetworkManager" in names
        assert "networking" in names
    finally:
        global_bus.unsubscribe("initsys.service.disable", disable_events.append)


def test_use_systemd_networkd_false_emits_no_disable_events(tmp_path):
    disable_events = []
    global_bus.subscribe("initsys.service.disable", disable_events.append)
    try:
        _make_plugin(tmp_path, config={"use_systemd_networkd": False, "disable_os_managers": ["NetworkManager"]})
        assert disable_events == []
    finally:
        global_bus.unsubscribe("initsys.service.disable", disable_events.append)


def test_use_systemd_networkd_empty_managers_list_emits_no_disable_events(tmp_path):
    disable_events = []
    global_bus.subscribe("initsys.service.disable", disable_events.append)
    try:
        _make_plugin(tmp_path, config={"use_systemd_networkd": True, "disable_os_managers": []})
        assert disable_events == []
    finally:
        global_bus.unsubscribe("initsys.service.disable", disable_events.append)


def test_use_systemd_networkd_false_emits_service_remove(tmp_path):
    received = []
    global_bus.subscribe("initsys.service.remove", received.append)
    try:
        _make_plugin(tmp_path, config={"use_systemd_networkd": False})
        assert len(received) == 1
        assert received[0].payload["service_name"] == "fastfirewall-networking"
    finally:
        global_bus.unsubscribe("initsys.service.remove", received.append)


def test_use_systemd_networkd_default_false_emits_service_remove(tmp_path):
    received = []
    global_bus.subscribe("initsys.service.remove", received.append)
    try:
        _make_plugin(tmp_path)
        assert len(received) == 1
        assert received[0].payload["service_name"] == "fastfirewall-networking"
    finally:
        global_bus.unsubscribe("initsys.service.remove", received.append)


# ── DHCP interfaces ────────────────────────────────────────────────────────────

def test_dhcp4_true_stored_on_interface(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True, "link": {"state": "up"}})
    assert r.status_code == 200
    assert r.json()["dhcp4"] is True


def test_dhcp6_true_stored_on_interface(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"dhcp6": True, "link": {"state": "up"}})
    assert r.status_code == 200
    assert r.json()["dhcp6"] is True


def test_dhcp4_false_stored_explicitly(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True})
    r = client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": False})
    assert r.status_code == 200
    assert r.json()["dhcp4"] is False


def test_dhcp6_false_stored_explicitly(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp6": True})
    r = client.put("/v1/networking/config/interfaces/eth0", json={"dhcp6": False})
    assert r.status_code == 200
    assert r.json()["dhcp6"] is False


def test_new_interface_always_has_explicit_dhcp_defaults(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    assert r.status_code == 200
    assert r.json()["dhcp4"] is False
    assert r.json()["dhcp6"] is False


def test_dhcp4_not_sent_preserves_existing_flag(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True})
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    r = client.get("/v1/networking/config/interfaces/eth0")
    assert r.json()["dhcp4"] is True


def test_dhcp4_and_static_addresses_coexist(client):
    r = client.put("/v1/networking/config/interfaces/eth0", json={
        "dhcp4": True,
        "addresses": ["192.168.1.1/24"],
    })
    assert r.status_code == 200
    assert r.json()["dhcp4"] is True
    assert r.json()["addresses"] == ["192.168.1.1/24"]


def test_dhcp4_networkd_file_has_dhcp_ipv4(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True})
    r = client.get("/v1/networking/config")
    content = r.json()["10-ff-eth0.network"]
    assert "DHCP=ipv4" in content


def test_dhcp6_networkd_file_has_dhcp_ipv6(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp6": True})
    r = client.get("/v1/networking/config")
    content = r.json()["10-ff-eth0.network"]
    assert "DHCP=ipv6" in content


def test_both_dhcp_networkd_file_has_dhcp_yes(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True, "dhcp6": True})
    r = client.get("/v1/networking/config")
    content = r.json()["10-ff-eth0.network"]
    assert "DHCP=yes" in content


def test_no_dhcp_networkd_file_has_dhcp_no(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.get("/v1/networking/config")
    content = r.json()["10-ff-eth0.network"]
    assert "DHCP=no" in content


def test_dhcp4_interface_event_includes_flag(plugin, client):
    received = []
    global_bus.subscribe("networking.interface.configured", received.append)
    try:
        client.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True})
        assert received[0].payload["dhcp4"] is True
    finally:
        global_bus.unsubscribe("networking.interface.configured", received.append)


def test_dhcp4_persists_across_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/networking/config/interfaces/eth0", json={"dhcp4": True})
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    r = c2.get("/v1/networking/config/interfaces/eth0")
    assert r.json()["dhcp4"] is True


# ── bonding ────────────────────────────────────────────────────────────────────

def test_create_bond_returns_201(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    r = client.post("/v1/networking/config/bonds", json={
        "name": "bond0", "mode": "802.3ad", "members": ["eth0", "eth1"]
    })
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "bond0"
    assert data["link"]["kind"] == "bond"


def test_create_bond_409_if_name_exists(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0", "eth1"]})
    r = client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    assert r.status_code == 409


def test_create_bond_409_if_member_already_bonded(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.put("/v1/networking/config/interfaces/eth2", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    r = client.post("/v1/networking/config/bonds", json={"name": "bond1", "members": ["eth0", "eth2"]})
    assert r.status_code == 409


def test_create_bond_sets_master_on_members(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0", "eth1"]})
    eth0 = client.get("/v1/networking/config/interfaces/eth0").json()
    assert eth0["link"]["master"] == "bond0"


def test_list_bonds(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    r = client.get("/v1/networking/config/bonds")
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["bonds"][0]["name"] == "bond0"


def test_get_bond(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    r = client.get("/v1/networking/config/bonds/bond0")
    assert r.status_code == 200
    assert r.json()["name"] == "bond0"


def test_get_bond_404(client):
    r = client.get("/v1/networking/config/bonds/nonexistent")
    assert r.status_code == 404


def test_delete_bond_removes_members(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0", "eth1"]})
    r = client.delete("/v1/networking/config/bonds/bond0")
    assert r.status_code == 200
    assert r.json()["deleted"] == "bond0"
    assert client.get("/v1/networking/config/interfaces/eth0").status_code == 404
    assert client.get("/v1/networking/config/interfaces/eth1").status_code == 404


def test_delete_bond_emits_event(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    received = []
    global_bus.subscribe("networking.interface.removed", received.append)
    try:
        client.delete("/v1/networking/config/bonds/bond0")
        names = [e.payload["name"] for e in received]
        assert "bond0" in names
    finally:
        global_bus.unsubscribe("networking.interface.removed", received.append)


def test_add_bond_member(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    r = client.post("/v1/networking/config/bonds/bond0/members", json={"interface": "eth1"})
    assert r.status_code == 201
    assert r.json()["member"] == "eth1"
    eth1 = client.get("/v1/networking/config/interfaces/eth1").json()
    assert eth1["link"]["master"] == "bond0"


def test_delete_bond_member(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0", "eth1"]})
    r = client.delete("/v1/networking/config/bonds/bond0/members/eth1")
    assert r.status_code == 200
    assert r.json()["removed_member"] == "eth1"
    eth1 = client.get("/v1/networking/config/interfaces/eth1").json()
    assert "master" not in (eth1.get("link") or {})


def test_bond_netdev_file_generated(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    r = client.get("/v1/networking/config")
    data = r.json()
    assert "10-ff-bond0.netdev" in data
    assert "Kind=bond" in data["10-ff-bond0.netdev"]


def test_bond_member_network_file_has_bond_directive(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0"]})
    r = client.get("/v1/networking/config")
    content = r.json()["10-ff-eth0.network"]
    assert "Bond=bond0" in content


def test_bond_netdev_contains_mode(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bonds", json={
        "name": "bond0", "members": ["eth0"], "mode": "active-backup"
    })
    content = client.get("/v1/networking/config").json()["10-ff-bond0.netdev"]
    assert "Mode=active-backup" in content


def test_bond_alias_redirect_on_create(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/aliases/LAN", json={"interface": "eth0"})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bonds", json={"name": "bond0", "members": ["eth0", "eth1"]})
    aliases = client.get("/v1/networking/config/aliases").json()["aliases"]
    assert aliases.get("LAN") == "bond0"


# ── bridging ───────────────────────────────────────────────────────────────────

def test_create_bridge_returns_201(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    r = client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "br0"
    assert data["link"]["kind"] == "bridge"


def test_create_bridge_409_if_name_exists(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    r = client.post("/v1/networking/config/bridges", json={"name": "br0", "members": []})
    assert r.status_code == 409


def test_list_bridges(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    r = client.get("/v1/networking/config/bridges")
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_delete_bridge_removes_members(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    r = client.delete("/v1/networking/config/bridges/br0")
    assert r.status_code == 200
    assert client.get("/v1/networking/config/interfaces/eth0").status_code == 404


def test_bridge_netdev_file_generated(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    r = client.get("/v1/networking/config")
    data = r.json()
    assert "10-ff-br0.netdev" in data
    assert "Kind=bridge" in data["10-ff-br0.netdev"]


def test_bridge_member_network_file_has_bridge_directive(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    content = client.get("/v1/networking/config").json()["10-ff-eth0.network"]
    assert "Bridge=br0" in content


def test_bridge_netdev_contains_stp(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.post("/v1/networking/config/bridges", json={
        "name": "br0", "members": ["eth0"], "stp": True
    })
    content = client.get("/v1/networking/config").json()["10-ff-br0.netdev"]
    assert "STP=yes" in content


def test_add_bridge_member(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0"]})
    r = client.post("/v1/networking/config/bridges/br0/members", json={"interface": "eth1"})
    assert r.status_code == 201
    assert r.json()["member"] == "eth1"


def test_delete_bridge_member(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    client.put("/v1/networking/config/interfaces/eth1", json={})
    client.post("/v1/networking/config/bridges", json={"name": "br0", "members": ["eth0", "eth1"]})
    r = client.delete("/v1/networking/config/bridges/br0/members/eth1")
    assert r.status_code == 200
    assert r.json()["removed_member"] == "eth1"


# ── WiFi ───────────────────────────────────────────────────────────────────────

def test_wifi_interface_sets_kind_wifi(client):
    r = client.put("/v1/networking/config/interfaces/wlan0", json={
        "link": {"kind": "wifi", "state": "up"},
        "dhcp4": True,
        "wifi": {"ssid": "MyNetwork", "psk": "password123"},
    })
    assert r.status_code == 200
    assert r.json()["link"]["kind"] == "wifi"
    assert r.json()["wifi"]["ssid"] == "MyNetwork"


def test_wifi_networkd_file_has_ignore_carrier_loss(client):
    client.put("/v1/networking/config/interfaces/wlan0", json={
        "link": {"kind": "wifi"},
        "dhcp4": True,
        "wifi": {"ssid": "MyNetwork", "psk": "pass"},
    })
    content = client.get("/v1/networking/config").json()["10-ff-wlan0.network"]
    assert "IgnoreCarrierLoss=3s" in content


def test_wifi_no_netdev_file_generated(client):
    client.put("/v1/networking/config/interfaces/wlan0", json={
        "link": {"kind": "wifi"},
        "wifi": {"ssid": "MyNetwork", "psk": "pass"},
    })
    files = client.get("/v1/networking/config").json()
    assert "10-ff-wlan0.netdev" not in files
    assert "10-ff-wlan0.network" in files


def test_wifi_apply_writes_wpa_supplicant_config(plugin, client):
    client.put("/v1/networking/config/interfaces/wlan0", json={
        "link": {"kind": "wifi"},
        "dhcp4": True,
        "wifi": {"ssid": "MyNet", "psk": "secret"},
    })
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    wpa_calls = [
        c for c in plugin._pyinfra_run.call_args_list
        if "/etc/wpa_supplicant/" in str(c.kwargs.get("dest", ""))
    ]
    assert len(wpa_calls) == 1
    assert "wpa_supplicant-wlan0.conf" in wpa_calls[0].kwargs["dest"]


def test_wifi_apply_enables_wpa_supplicant_service(plugin, client):
    client.put("/v1/networking/config/interfaces/wlan0", json={
        "link": {"kind": "wifi"},
        "wifi": {"ssid": "MyNet", "psk": "secret"},
    })
    received = []
    global_bus.subscribe("initsys.service.start", received.append)
    try:
        with patch("subprocess.run", side_effect=_subprocess_run_ok):
            client.post("/v1/networking/apply")
        service_names = [e.payload["service_name"] for e in received]
        assert "wpa_supplicant@wlan0.service" in service_names
    finally:
        global_bus.unsubscribe("initsys.service.start", received.append)


def test_wifi_psk_written_with_mode_600(plugin, client):
    client.put("/v1/networking/config/interfaces/wlan0", json={
        "link": {"kind": "wifi"},
        "wifi": {"ssid": "MyNet", "psk": "secret"},
    })
    with patch("subprocess.run", side_effect=_subprocess_run_ok):
        client.post("/v1/networking/apply")
    wpa_calls = [
        c for c in plugin._pyinfra_run.call_args_list
        if "/etc/wpa_supplicant/" in str(c.kwargs.get("dest", ""))
    ]
    assert wpa_calls[0].kwargs["mode"] == "600"


# ── WireGuard ──────────────────────────────────────────────────────────────────

def test_wg_interface_creates_netdev_file(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "addresses": ["10.0.0.1/24"],
        "wireguard": {"private_key": "A" * 44, "listen_port": 51820},
    })
    files = client.get("/v1/networking/config").json()
    assert "10-ff-wg0.netdev" in files
    assert "10-ff-wg0.network" in files


def test_wg_netdev_contains_private_key(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "B" * 44},
    })
    content = client.get("/v1/networking/config").json()["10-ff-wg0.netdev"]
    assert "PrivateKey=" + "B" * 44 in content


def test_wg_add_peer_returns_201(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    r = client.post("/v1/networking/config/interfaces/wg0/peers", json={
        "public_key": "C" * 44,
        "allowed_ips": ["10.0.0.2/32"],
    })
    assert r.status_code == 201
    data = r.json()
    assert "id" in data
    assert data["public_key"] == "C" * 44


def test_wg_peer_id_is_pubkey_hash(client):
    import hashlib as _hashlib
    pubkey = "D" * 44
    expected_id = _hashlib.sha256(pubkey.encode()).hexdigest()[:8]
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    r = client.post("/v1/networking/config/interfaces/wg0/peers", json={"public_key": pubkey})
    assert r.json()["id"] == expected_id


def test_wg_duplicate_peer_409(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    client.post("/v1/networking/config/interfaces/wg0/peers", json={"public_key": "E" * 44})
    r = client.post("/v1/networking/config/interfaces/wg0/peers", json={"public_key": "E" * 44})
    assert r.status_code == 409


def test_wg_list_peers(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    client.post("/v1/networking/config/interfaces/wg0/peers", json={"public_key": "F" * 44})
    r = client.get("/v1/networking/config/interfaces/wg0/peers")
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_wg_delete_peer(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    r = client.post("/v1/networking/config/interfaces/wg0/peers", json={"public_key": "G" * 44})
    peer_id = r.json()["id"]
    del_r = client.delete(f"/v1/networking/config/interfaces/wg0/peers/{peer_id}")
    assert del_r.status_code == 200
    assert del_r.json()["deleted"] == peer_id
    assert client.get("/v1/networking/config/interfaces/wg0/peers").json()["count"] == 0


def test_wg_update_peer(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    r = client.post("/v1/networking/config/interfaces/wg0/peers", json={
        "public_key": "H" * 44,
        "allowed_ips": ["10.0.0.2/32"],
    })
    peer_id = r.json()["id"]
    up_r = client.put(f"/v1/networking/config/interfaces/wg0/peers/{peer_id}", json={
        "persistent_keepalive": 25,
    })
    assert up_r.status_code == 200
    assert up_r.json()["persistent_keepalive"] == 25
    assert up_r.json()["allowed_ips"] == ["10.0.0.2/32"]


def test_wg_peer_on_nonwireguard_interface_422(client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    r = client.post("/v1/networking/config/interfaces/eth0/peers", json={"public_key": "I" * 44})
    assert r.status_code == 404


def test_wg_netdev_contains_peer_section(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    client.post("/v1/networking/config/interfaces/wg0/peers", json={
        "public_key": "J" * 44,
        "allowed_ips": ["10.0.0.2/32"],
        "endpoint": "peer.example.com:51820",
    })
    content = client.get("/v1/networking/config").json()["10-ff-wg0.netdev"]
    assert "[WireGuardPeer]" in content
    assert "PublicKey=" + "J" * 44 in content
    assert "AllowedIPs=10.0.0.2/32" in content
    assert "Endpoint=peer.example.com:51820" in content


def test_wg_netdev_omits_optional_peer_fields_when_none(client):
    client.put("/v1/networking/config/interfaces/wg0", json={
        "link": {"kind": "wireguard"},
        "wireguard": {"private_key": "A" * 44},
    })
    client.post("/v1/networking/config/interfaces/wg0/peers", json={
        "public_key": "K" * 44,
    })
    content = client.get("/v1/networking/config").json()["10-ff-wg0.netdev"]
    assert "Endpoint=" not in content
    assert "PresharedKey=" not in content
    assert "PersistentKeepalive=" not in content
