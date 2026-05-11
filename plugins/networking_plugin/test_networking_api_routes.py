"""
Tests for networking_plugin routes (/v1/networking/*).

ifstatecli subprocess calls are mocked via plugin._run_ifstate so no actual
system changes are made.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure /app is importable when this file is run in isolation
_REPO_ROOT = str(Path(__file__).parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plugin_system.core.events import bus as global_bus

PLUGIN_PY = Path(__file__).parent / "plugin.py"
_REPO_ROOT = str(Path(__file__).parents[2])


# ── helpers ────────────────────────────────────────────────────────────────────

def _load_module():
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    name = "_test_networking_plugin"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_PY)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _ifstate_ok(stdout="", stderr="") -> MagicMock:
    return MagicMock(returncode=0, stdout=stdout, stderr=stderr)


def _ifstate_err(stderr="error") -> MagicMock:
    return MagicMock(returncode=1, stdout="", stderr=stderr)


def _make_plugin(tmp_path, config=None):
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking_plugin"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking_plugin")
    plugin._run_ifstate = MagicMock(return_value=_ifstate_ok())
    plugin.setup()
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
    managed = client.get("/v1/networking/status").json()["managed"]
    assert managed == {"interfaces": 0, "routes": 0, "sysctl": 0}


def test_status_counts_reflect_additions(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1"})
    client.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    managed = client.get("/v1/networking/status").json()["managed"]
    assert managed == {"interfaces": 1, "routes": 1, "sysctl": 1}


# ── live state (ifstatecli show) ───────────────────────────────────────────────

def test_show_interfaces_parses_ifstate_output(plugin, client):
    show_yaml = yaml.dump({"interfaces": {"eth0": {"addresses": ["192.168.1.100/24"]}}})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=show_yaml)
    r = client.get("/v1/networking/interfaces")
    assert r.status_code == 200
    assert "eth0" in r.json()["interfaces"]
    assert r.json()["source"] == "running"


def test_show_interfaces_calls_show_subcommand(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.get("/v1/networking/interfaces")
    plugin._run_ifstate.assert_called_once_with("show")


def test_show_interfaces_500_on_ifstate_error(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_err(stderr="permission denied")
    r = client.get("/v1/networking/interfaces")
    assert r.status_code == 500


def test_show_single_interface_found(plugin, client):
    show_yaml = yaml.dump({"interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}, "eth1": {}}})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=show_yaml)
    r = client.get("/v1/networking/interfaces/eth0")
    assert r.status_code == 200
    assert r.json()["name"] == "eth0"
    assert "addresses" in r.json()


def test_show_single_interface_404_when_not_present(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=yaml.dump({"interfaces": {}}))
    r = client.get("/v1/networking/interfaces/eth99")
    assert r.status_code == 404


def test_identify_returns_output(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="eth0:\n  perm_address: aa:bb:cc:dd:ee:ff\n")
    r = client.get("/v1/networking/identify")
    assert r.status_code == 200
    assert "output" in r.json()


def test_identify_calls_identify_subcommand(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok()
    client.get("/v1/networking/identify")
    plugin._run_ifstate.assert_called_once_with("identify")


def test_identify_500_on_error(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_err()
    r = client.get("/v1/networking/identify")
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


def test_add_route_with_dev_and_metric(client):
    r = client.post("/v1/networking/config/routes", json={"to": "10.0.0.0/8", "dev": "eth1", "metric": 100})
    assert r.status_code == 201
    assert r.json()["dev"] == "eth1"
    assert r.json()["metric"] == 100


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


# ── config — sysctl ────────────────────────────────────────────────────────────

def test_list_sysctl_empty(client):
    assert client.get("/v1/networking/config/sysctl").json() == {"sysctl": {}}


def test_set_sysctl_creates_entry(client):
    r = client.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    assert r.status_code == 200
    assert r.json() == {"key": "net.ipv4.ip_forward", "value": "1"}


def test_set_sysctl_updates_value(client):
    client.put("/v1/networking/config/sysctl/vm.swappiness", json={"value": "60"})
    client.put("/v1/networking/config/sysctl/vm.swappiness", json={"value": "10"})
    assert client.get("/v1/networking/config/sysctl").json()["sysctl"]["vm.swappiness"] == "10"


def test_list_sysctl_shows_added(client):
    client.put("/v1/networking/config/sysctl/net.ipv6.conf.all.forwarding", json={"value": "1"})
    sysctl = client.get("/v1/networking/config/sysctl").json()["sysctl"]
    assert "net.ipv6.conf.all.forwarding" in sysctl


def test_delete_sysctl_removes_entry(client):
    client.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    r = client.delete("/v1/networking/config/sysctl/net.ipv4.ip_forward")
    assert r.status_code == 200
    assert r.json() == {"deleted": "net.ipv4.ip_forward"}
    assert "net.ipv4.ip_forward" not in client.get("/v1/networking/config/sysctl").json()["sysctl"]


def test_delete_sysctl_not_managed_returns_404(client):
    assert client.delete("/v1/networking/config/sysctl/nonexistent.key").status_code == 404


def test_set_sysctl_emits_event(plugin, client):
    received = []
    global_bus.subscribe("networking.sysctl.changed", received.append)
    try:
        client.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
        assert received[0].payload == {"key": "net.ipv4.ip_forward", "value": "1"}
    finally:
        global_bus.unsubscribe("networking.sysctl.changed", received.append)


def test_delete_sysctl_emits_event(plugin, client):
    client.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    received = []
    global_bus.subscribe("networking.sysctl.removed", received.append)
    try:
        client.delete("/v1/networking/config/sysctl/net.ipv4.ip_forward")
        assert received[0].payload["key"] == "net.ipv4.ip_forward"
    finally:
        global_bus.unsubscribe("networking.sysctl.removed", received.append)


# ── full config YAML ───────────────────────────────────────────────────────────

def test_get_config_yaml_content_type(client):
    r = client.get("/v1/networking/config")
    assert "yaml" in r.headers["content-type"]


def test_get_config_json_format(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.get("/v1/networking/config?format=json")
    assert r.status_code == 200
    data = r.json()
    assert "interfaces" in data
    assert "eth0" in data["interfaces"]


def test_get_config_yaml_includes_interfaces_and_routes(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["192.168.1.1/24"]})
    client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.254"})
    r = client.get("/v1/networking/config")
    config = yaml.safe_load(r.text)
    assert "eth0" in config["interfaces"]
    assert config["routing"]["routes"][0]["to"] == "default"


def test_get_config_yaml_includes_sysctl(client):
    client.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    config = yaml.safe_load(client.get("/v1/networking/config").text)
    assert config["sysctl"]["net.ipv4.ip_forward"] == "1"


def test_get_config_empty_state_is_valid_yaml(client):
    r = client.get("/v1/networking/config")
    assert yaml.safe_load(r.text) is not None


# ── apply & check ──────────────────────────────────────────────────────────────

def test_apply_calls_ifstatecli_apply(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="applied")
    r = client.post("/v1/networking/apply")
    assert r.status_code == 200
    args = plugin._run_ifstate.call_args[0]
    assert args[-1] == "apply"
    assert args[0] == "-c"


def test_apply_returns_success_true_on_zero_exit(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="ok")
    r = client.post("/v1/networking/apply")
    assert r.json()["success"] is True
    assert r.json()["returncode"] == 0


def test_apply_returns_success_false_on_nonzero_exit(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_err(stderr="failed")
    r = client.post("/v1/networking/apply")
    assert r.status_code == 200
    assert r.json()["success"] is False
    assert r.json()["returncode"] == 1


def test_apply_emits_event(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok()
    received = []
    global_bus.subscribe("networking.applied", received.append)
    try:
        client.post("/v1/networking/apply")
        assert len(received) == 1
        assert received[0].payload["success"] is True
    finally:
        global_bus.unsubscribe("networking.applied", received.append)


def test_check_calls_ifstatecli_check(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok()
    client.post("/v1/networking/check")
    args = plugin._run_ifstate.call_args[0]
    assert args[-1] == "check"


def test_check_returns_valid_true_on_success(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="ok")
    r = client.post("/v1/networking/check")
    assert r.status_code == 200
    assert r.json()["success"] is True


def test_check_returns_valid_false_on_failure(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_err(stderr="parse error")
    r = client.post("/v1/networking/check")
    assert r.json()["success"] is False


def test_apply_passes_config_yaml_via_temp_file(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok()
    plugin._run_ifstate.reset_mock()
    client.post("/v1/networking/apply")
    args = plugin._run_ifstate.call_args[0]
    # -c <tmpfile> apply
    assert len(args) == 3
    assert args[0] == "-c"
    assert args[2] == "apply"


# ── state persistence ──────────────────────────────────────────────────────────

def test_state_persists_across_plugin_restart(tmp_path):
    p1 = _make_plugin(tmp_path)
    c1 = _make_client(p1)
    c1.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    c1.post("/v1/networking/config/routes", json={"to": "default", "via": "10.0.0.254"})
    c1.put("/v1/networking/config/sysctl/net.ipv4.ip_forward", json={"value": "1"})
    p1.teardown()

    p2 = _make_plugin(tmp_path)
    c2 = _make_client(p2)
    names = [i["name"] for i in c2.get("/v1/networking/config/interfaces").json()["interfaces"]]
    assert "eth0" in names
    assert c2.get("/v1/networking/config/routes").json()["count"] == 1
    assert "net.ipv4.ip_forward" in c2.get("/v1/networking/config/sysctl").json()["sysctl"]


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
