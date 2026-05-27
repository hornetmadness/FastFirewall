"""
Tests for networking_plugin routes (/v1/networking/*).

ifstatecli subprocess calls are mocked via plugin._run_ifstate so no actual
system changes are made.
"""
from __future__ import annotations

import importlib.util
import json
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
    name = "_test_networking"
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
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._run_ifstate = MagicMock(return_value=_ifstate_ok())
    plugin.setup()
    plugin._run_ifstate.reset_mock()
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
    # lo alias is always auto-registered at startup
    assert data["ff_managed"] == {"interfaces": 0, "routes": 0, "aliases": 1}
    assert data["pending_changes"] is False


def test_status_counts_reflect_additions(client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    client.post("/v1/networking/config/routes", json={"to": "default", "via": "192.168.1.1"})
    # eth0 interface auto-creates alias "eth0", LAN1 is explicit, lo is always present → 3 total
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    managed = client.get("/v1/networking/status").json()["ff_managed"]
    assert managed == {"interfaces": 1, "routes": 1, "aliases": 3}


# ── live state (ifstatecli show) ───────────────────────────────────────────────

def test_show_interfaces_parses_ifstate_output(plugin, client):
    show_yaml = yaml.dump({"interfaces": {"eth0": {"addresses": ["192.168.1.100/24"]}}})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=show_yaml)
    r = client.get("/v1/networking/interfaces")
    assert r.status_code == 200
    assert "eth0" in r.json()["interfaces"]
    assert r.json()["source"] == "running"


def test_show_interfaces_managed_false_when_not_in_config(plugin, client):
    show_yaml = yaml.dump({"interfaces": {"eth0": {}}})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=show_yaml)
    r = client.get("/v1/networking/interfaces")
    assert r.json()["interfaces"]["eth0"]["ff_managed"] is False


def test_show_interfaces_managed_true_when_in_config(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    show_yaml = yaml.dump({"interfaces": {"eth0": {}}})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=show_yaml)
    r = client.get("/v1/networking/interfaces")
    assert r.json()["interfaces"]["eth0"]["ff_managed"] is True


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


def test_show_single_interface_managed_false(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=yaml.dump({"interfaces": {"eth0": {}}}))
    r = client.get("/v1/networking/interfaces/eth0")
    assert r.json()["ff_managed"] is False


def test_show_single_interface_managed_true(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=yaml.dump({"interfaces": {"eth0": {}}}))
    r = client.get("/v1/networking/interfaces/eth0")
    assert r.json()["ff_managed"] is True


def test_show_single_interface_404_when_not_present(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=yaml.dump({"interfaces": {}}))
    r = client.get("/v1/networking/interfaces/eth99")
    assert r.status_code == 404


def test_identify_returns_output(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="eth0:\n  perm_address: aa:bb:cc:dd:ee:ff\n")
    r = client.get("/v1/networking/identify")
    assert r.status_code == 200
    assert r.json() == {"eth0": {"perm_address": "aa:bb:cc:dd:ee:ff"}}


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


def test_get_config_yaml_link_defaults_to_physical(client):
    # ifstate requires 'link' with 'kind' on every interface.
    # When the API caller omits 'kind' (e.g. bootstrap sends {link: {state: up}}),
    # _build_ifstate_yaml must default kind to "physical" to pass schema validation.
    client.put("/v1/networking/config/interfaces/eth0", json={"link": {"state": "up"}})
    config = yaml.safe_load(client.get("/v1/networking/config").text)
    assert config["interfaces"]["eth0"]["link"]["kind"] == "physical"
    assert config["interfaces"]["eth0"]["link"]["state"] == "up"


def test_get_config_empty_state_is_valid_yaml(client):
    r = client.get("/v1/networking/config")
    assert yaml.safe_load(r.text) is not None


# ── apply & check ──────────────────────────────────────────────────────────────

def test_apply_calls_ifstatecli_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    r = client.post("/v1/networking/apply")
    assert r.status_code == 200
    args = plugin._run_ifstate.call_args[0]
    assert args[-1] == "apply"
    assert args[0] == "-c"


def test_apply_returns_success_true_on_zero_exit(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    r = client.post("/v1/networking/apply")
    assert r.json()["success"] is True
    assert r.json()["returncode"] == 0


def test_apply_returns_success_false_on_nonzero_exit(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_err(stderr="failed")
    r = client.post("/v1/networking/apply")
    assert r.status_code == 200
    assert r.json()["success"] is False
    assert r.json()["returncode"] == 1


def test_apply_changes_shows_added_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    r = client.post("/v1/networking/apply")
    assert r.json()["changes"]["interfaces"]["added"]["eth0"]["addresses"] == ["10.0.0.1/24"]


def test_apply_changes_empty_when_nothing_pending(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    plugin._run_ifstate.reset_mock()
    r = client.post("/v1/networking/apply")
    assert r.json()["changes"] == {}


def test_apply_updates_current_state_on_success(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    assert plugin._state_file.current_snapshot is not None
    assert "eth0" in plugin._state_file.current_snapshot["interfaces"]


def test_apply_does_not_update_current_state_on_failure(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_err()
    client.post("/v1/networking/apply")
    assert plugin._state_file.current_snapshot is None


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


def test_check_shows_deleted_route_when_ifstatecli_has_no_routing_section(plugin, client):
    # Add a route and apply it so current_state captures it
    r = client.post("/v1/networking/config/routes", json={"to": "default", "via": "10.0.0.1"})
    route_id = r.json()["id"]
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    # Now delete the route — routing section disappears from ifstate YAML
    client.delete(f"/v1/networking/config/routes/{route_id}")
    # /check should still surface the pending removal even though ifstatecli sees no routing section
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    r = client.post("/v1/networking/check")
    assert r.status_code == 200
    assert route_id in r.json()["changes"]["routes"]["removed"]


def test_apply_passes_config_yaml_via_temp_file(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    plugin._run_ifstate.reset_mock()
    client.post("/v1/networking/apply")
    args = plugin._run_ifstate.call_args[0]
    # -c <tmpfile> apply
    assert len(args) == 3
    assert args[0] == "-c"
    assert args[2] == "apply"


# ── discard ────────────────────────────────────────────────────────────────────

def test_discard_409_when_no_snapshot(client):
    r = client.post("/v1/networking/discard")
    assert r.status_code == 409


def test_discard_restores_current_state(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    # add a pending change
    client.put("/v1/networking/config/interfaces/eth1", json={})
    assert client.get("/v1/networking/config/interfaces").json()["count"] == 2
    client.post("/v1/networking/discard")
    assert client.get("/v1/networking/config/interfaces").json()["count"] == 1
    names = [i["name"] for i in client.get("/v1/networking/config/interfaces").json()["interfaces"]]
    assert "eth1" not in names


def test_discard_returns_diff_of_what_was_reverted(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={})
    r = client.post("/v1/networking/discard")
    assert r.status_code == 200
    assert r.json()["discarded"] is True
    assert "eth1" in r.json()["changes"]["interfaces"]["removed"]


def test_discard_empty_changes_when_nothing_pending(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    r = client.post("/v1/networking/discard")
    assert r.json()["changes"] == {}


# ── pending_changes in status ──────────────────────────────────────────────────

def test_status_pending_false_initially(client):
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


def test_status_pending_true_after_mutation_before_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={})
    assert client.get("/v1/networking/status").json()["pending_changes"] is True


def test_status_pending_false_after_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


def test_status_pending_false_after_discard(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
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

def _show_yaml(interfaces: dict) -> str:
    return yaml.dump({"interfaces": interfaces})


def test_import_all_interfaces(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(
        stdout=_show_yaml({"eth0": {"addresses": ["10.0.0.1/24"]}, "eth1": {"link": {"state": "up"}}})
    )
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.status_code == 200
    data = r.json()
    assert set(data["imported"]) == {"eth0", "eth1"}
    assert data["skipped"] == []
    assert data["not_found"] == []


def test_import_specific_interfaces(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(
        stdout=_show_yaml({"eth0": {"addresses": ["10.0.0.1/24"]}, "eth1": {}, "eth2": {}})
    )
    r = client.post("/v1/networking/config/interfaces/import", json={"names": ["eth0", "eth2"]})
    assert r.status_code == 200
    data = r.json()
    assert set(data["imported"]) == {"eth0", "eth2"}
    assert "eth1" not in data["imported"]


def test_import_not_found_interface(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=_show_yaml({"eth0": {}}))
    r = client.post("/v1/networking/config/interfaces/import", json={"names": ["eth0", "eth99"]})
    assert r.status_code == 200
    data = r.json()
    assert "eth0" in data["imported"]
    assert "eth99" in data["not_found"]


def test_import_skips_already_managed_without_overwrite(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["1.2.3.4/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(
        stdout=_show_yaml({"eth0": {"addresses": ["10.0.0.1/24"]}})
    )
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.status_code == 200
    data = r.json()
    assert "eth0" in data["skipped"]
    assert "eth0" not in data["imported"]
    # original config untouched
    cfg = client.get("/v1/networking/config/interfaces/eth0").json()
    assert cfg["addresses"] == ["1.2.3.4/24"]


def test_import_overwrites_managed_when_flag_set(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["1.2.3.4/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(
        stdout=_show_yaml({"eth0": {"addresses": ["10.0.0.1/24"]}})
    )
    r = client.post("/v1/networking/config/interfaces/import", json={"overwrite": True})
    assert r.status_code == 200
    assert "eth0" in r.json()["imported"]
    cfg = client.get("/v1/networking/config/interfaces/eth0").json()
    assert cfg["addresses"] == ["10.0.0.1/24"]


def test_import_500_on_ifstate_failure(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_err(stderr="permission denied")
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.status_code == 500


def test_import_calls_show_subcommand(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=_show_yaml({}))
    plugin._run_ifstate.reset_mock()
    client.post("/v1/networking/config/interfaces/import", json={})
    plugin._run_ifstate.assert_called_once_with("show")


def test_import_emits_event_per_interface(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(
        stdout=_show_yaml({"eth0": {"addresses": ["10.0.0.1/24"]}, "eth1": {}})
    )
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
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=_show_yaml({}))
    received = []
    global_bus.subscribe("networking.interface.configured", received.append)
    try:
        client.post("/v1/networking/config/interfaces/import", json={})
        assert received == []
    finally:
        global_bus.unsubscribe("networking.interface.configured", received.append)


def test_import_saves_state(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(
        stdout=_show_yaml({"eth0": {"addresses": ["10.0.0.1/24"]}})
    )
    client.post("/v1/networking/config/interfaces/import", json={})
    assert (plugin.plugin_dir / "data" / "networking_state.json").exists()


def test_import_does_not_save_state_when_nothing_imported(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=_show_yaml({}))
    r = client.post("/v1/networking/config/interfaces/import", json={})
    assert r.json()["imported"] == []


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
    plugin._run_ifstate = MagicMock(return_value=_ifstate_ok())
    plugin.setup()
    return plugin


def test_ifstate_apply_called_on_boot_when_state_exists(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path)
    apply_calls = [c for c in plugin._run_ifstate.call_args_list if c[0][-1] == "apply"]
    assert len(apply_calls) == 1


def test_ignore_state_on_boot_skips_load_and_apply(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path, config={"ignore_state_on_boot": True})
    apply_calls = [c for c in plugin._run_ifstate.call_args_list if c[0][-1] == "apply"]
    assert len(apply_calls) == 0
    assert plugin._interfaces == {}


def test_apply_skipped_when_state_is_empty(tmp_path):
    plugin = _make_plugin_raw(tmp_path)  # no pre-existing state file — boot import runs show, not apply
    apply_calls = [c for c in plugin._run_ifstate.call_args_list if c[0][-1] == "apply"]
    assert len(apply_calls) == 0


def test_apply_state_does_not_crash_on_ifstate_failure(tmp_path):
    _write_boot_state(tmp_path)
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._run_ifstate = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="permission denied"))
    plugin.setup()  # must not raise
    assert plugin._interfaces == {"eth0": {"addresses": ["10.0.0.1/24"]}}


def test_boot_apply_does_not_commit_current_state(tmp_path):
    # Boot-time apply re-asserts the kernel config but does NOT auto-commit current_state —
    # only an explicit POST /apply should clear pending_changes.
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path)
    assert plugin._state_file.current_snapshot is None


def test_boot_apply_does_not_set_current_state_on_failure(tmp_path):
    _write_boot_state(tmp_path)
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._run_ifstate = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="failed"))
    plugin.setup()
    assert plugin._state_file.current_snapshot is None


def test_boot_apply_clears_pending_changes(tmp_path):
    # Simulates the reported bug: state exists, no current_state, reboot should leave pending_changes=False
    _write_boot_state(tmp_path)
    plugin = _make_plugin_raw(tmp_path)
    client = _make_client(plugin)
    assert client.get("/v1/networking/status").json()["pending_changes"] is False


# ── boot-time auto-import ──────────────────────────────────────────────────────

def _make_plugin_boot_import(tmp_path, show_stdout="", config=None):
    """Create a plugin with a custom ifstatecli show response for boot-import tests."""
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = config or {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._run_ifstate = MagicMock(return_value=_ifstate_ok(stdout=show_stdout))
    plugin.setup()
    return plugin


def test_boot_import_interfaces_when_state_empty(tmp_path):
    show = yaml.dump({"interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}, "eth1": {"link": {"state": "up"}}}})
    plugin = _make_plugin_boot_import(tmp_path, show_stdout=show)
    assert "eth0" in plugin._interfaces
    assert "eth1" in plugin._interfaces
    assert plugin._interfaces["eth0"]["addresses"] == ["10.0.0.1/24"]


def test_boot_import_routes_when_state_empty(tmp_path):
    show = yaml.dump({
        "interfaces": {},
        "routing": {"routes": [
            {"to": "default", "via": "192.168.1.1", "dev": "eth0"},
            {"to": "10.0.0.0/8", "dev": "eth0"},
        ]},
    })
    plugin = _make_plugin_boot_import(tmp_path, show_stdout=show)
    destinations = {r["to"] for r in plugin._routes.values()}
    assert "default" in destinations
    assert "10.0.0.0/8" in destinations


def test_boot_import_route_fields_preserved(tmp_path):
    show = yaml.dump({
        "interfaces": {},
        "routing": {"routes": [{"to": "default", "via": "10.0.0.1", "dev": "eth0", "preference": 100}]},
    })
    plugin = _make_plugin_boot_import(tmp_path, show_stdout=show)
    route = next(iter(plugin._routes.values()))
    assert route["via"] == "10.0.0.1"
    assert route["dev"] == "eth0"
    assert route["preference"] == 100


def test_boot_import_saves_state_file(tmp_path):
    show = yaml.dump({"interfaces": {"eth0": {}}})
    _make_plugin_boot_import(tmp_path, show_stdout=show)
    assert (tmp_path / "data" / "networking_state.json").exists()


def test_boot_import_does_not_save_when_nothing_found(tmp_path):
    plugin = _make_plugin_boot_import(tmp_path, show_stdout="{}")
    assert plugin._interfaces == {}
    assert plugin._routes == {}


def test_boot_import_skipped_when_state_has_data(tmp_path):
    _write_boot_state(tmp_path)
    plugin = _make_plugin(tmp_path)
    show_calls = [c for c in plugin._run_ifstate.call_args_list if c[0] == ("show",)]
    assert len(show_calls) == 0


def test_boot_import_skipped_with_ignore_state_on_boot(tmp_path):
    show = yaml.dump({"interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}}})
    plugin = _make_plugin_boot_import(tmp_path, show_stdout=show, config={"ignore_state_on_boot": True})
    assert plugin._interfaces == {}
    plugin._run_ifstate.assert_not_called()


def test_boot_import_calls_show_subcommand(tmp_path):
    plugin = _make_plugin_boot_import(tmp_path, show_stdout="{}")
    plugin._run_ifstate.assert_called_once_with("show")


def test_boot_import_does_not_crash_on_ifstate_failure(tmp_path):
    mod = _load_module()
    plugin = mod.NetworkingPlugin()
    plugin.plugin_id = "networking"
    plugin.meta = {"name": "Networking Plugin", "version": "1.0.0"}
    plugin.config = {}
    plugin.plugin_dir = tmp_path
    plugin.logger = logging.getLogger("test.networking")
    plugin._run_ifstate = MagicMock(return_value=_ifstate_err(stderr="permission denied"))
    plugin.setup()  # must not raise
    assert plugin._interfaces == {}
    assert plugin._routes == {}


# ── interface aliases ──────────────────────────────────────────────────────────

def test_list_aliases_empty(client):
    r = client.get("/v1/networking/config/aliases")
    assert r.status_code == 200
    # lo is always auto-registered at startup
    assert r.json() == {"aliases": {"lo": "lo"}, "count": 1}


def test_set_alias_creates_entry(client):
    r = client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    assert r.status_code == 200
    assert r.json() == {"name": "LAN1", "interface": "eth0"}


def test_set_alias_appears_in_list(client):
    client.put("/v1/networking/config/aliases/LAN1", json={"interface": "eth0"})
    client.put("/v1/networking/config/aliases/WAN", json={"interface": "eth1"})
    data = client.get("/v1/networking/config/aliases").json()
    assert data["count"] == 3  # lo + LAN1 + WAN
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
    # Manual alias must not be clobbered by the setdefault on re-configure
    assert client.get("/v1/networking/config/aliases").json()["aliases"]["eth0"] == "br0"


def test_import_interfaces_creates_default_aliases(plugin, client):
    show_yaml = yaml.dump({"interfaces": {"eth0": {}, "eth1": {"addresses": ["10.0.0.1/24"]}}})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout=show_yaml)
    client.post("/v1/networking/config/interfaces/import", json={})
    aliases = client.get("/v1/networking/config/aliases").json()["aliases"]
    assert aliases.get("eth0") == "eth0"
    assert aliases.get("eth1") == "eth1"


def test_boot_import_creates_default_aliases(tmp_path):
    show_yaml = yaml.dump({"interfaces": {"eth0": {"addresses": ["10.0.0.1/24"]}}})
    plugin = _make_plugin_boot_import(tmp_path, show_stdout=show_yaml)
    assert plugin._aliases.get("eth0") == "eth0"


def test_load_state_creates_default_aliases_for_existing_interfaces(tmp_path):
    # State file has no aliases key — simulates a state file written before the alias feature.
    # After loading, each managed interface should automatically get an identity alias.
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
    plugin = _make_plugin(tmp_path)  # loads state → _ensure_default_aliases() adds eth0→eth0
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
        # ignore_state_on_boot skips _load_state, so no aliases loaded → no event
        assert len(received) == 0
        plugin = _make_plugin(tmp_path)
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
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    r = client.get("/v1/networking/config/diff")
    assert r.status_code == 200
    body = r.json()
    assert body["pending_changes"] is True
    assert "eth0" in body["diff"]["interfaces"]["added"]


def test_diff_shows_removed_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    client.delete("/v1/networking/config/interfaces/eth0")
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is True
    assert "eth0" in body["diff"]["interfaces"]["removed"]


def test_diff_shows_modified_interface(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.1/24"]})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth0", json={"addresses": ["10.0.0.2/24"]})
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is True
    modified = body["diff"]["interfaces"]["modified"]["eth0"]
    assert modified["from"]["addresses"] == ["10.0.0.1/24"]
    assert modified["to"]["addresses"] == ["10.0.0.2/24"]


def test_diff_shows_added_interface(plugin, client):
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    client.put("/v1/networking/config/interfaces/eth1", json={"link": {"state": "up"}})
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is True
    assert "eth1" in body["diff"]["interfaces"]["added"]


def test_diff_pending_false_after_apply(plugin, client):
    client.put("/v1/networking/config/interfaces/eth0", json={})
    plugin._run_ifstate.return_value = _ifstate_ok(stdout="{}")
    client.post("/v1/networking/apply")
    r = client.get("/v1/networking/config/diff")
    body = r.json()
    assert body["pending_changes"] is False
    assert body["diff"] == {}


def test_diff_no_current_snapshot_returns_empty_diff(client):
    # With ignore_state_on_boot the plugin has no current snapshot yet
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
