"""
Tests for the Firewall plugin routes (/v1/firewall/*).

The plugin is loaded via importlib the same way PluginLoader does, bypassing
py_requirements installation while still exercising the real production code.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugin_system.core.events import bus as global_bus

PLUGIN_PY = Path(__file__).parent / "plugin.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_module():
    name = "_test_firewall_plugin"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_PY)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_app(tmp_path):
    mod = _load_module()
    inst = mod.FirewallPlugin()
    inst.plugin_id = "firewall_plugin"
    inst.meta = {"name": "Firewall Plugin", "version": "1.0.0", "description": "", "author": ""}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.firewall_plugin")
    inst.config = {
        "rules_file": "rules.json",
        "default_platform": "iptables",
        "default_filter_name": "test-fw",
    }
    inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    return app


def _create_rule(client, **kwargs):
    payload = {"name": "test-rule", **kwargs}
    r = client.post("/v1/firewall/rules", json=payload)
    assert r.status_code == 201
    return r.json()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    return TestClient(_make_app(tmp_path))


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def test_status_returns_plugin_metadata(client):
    r = client.get("/v1/firewall/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "Firewall Plugin"
    assert data["version"] == "1.0.0"


def test_status_rule_counts_start_at_zero(client):
    counts = client.get("/v1/firewall/status").json()["rules"]
    assert counts == {"total": 0, "enabled": 0, "disabled": 0}


def test_status_counts_update_after_create(client):
    _create_rule(client, name="on",  enabled=True)
    _create_rule(client, name="off", enabled=False)
    counts = client.get("/v1/firewall/status").json()["rules"]
    assert counts == {"total": 2, "enabled": 1, "disabled": 1}


# ---------------------------------------------------------------------------
# List rules
# ---------------------------------------------------------------------------

def test_list_rules_empty(client):
    r = client.get("/v1/firewall/rules")
    assert r.status_code == 200
    assert r.json() == {"rules": [], "count": 0}


def test_list_rules_returns_all(client):
    _create_rule(client, name="rule-a")
    _create_rule(client, name="rule-b")
    assert client.get("/v1/firewall/rules").json()["count"] == 2


def test_list_rules_sorted_by_priority(client):
    _create_rule(client, name="low",  priority=200)
    _create_rule(client, name="high", priority=10)
    _create_rule(client, name="mid",  priority=100)
    names = [r["name"] for r in client.get("/v1/firewall/rules").json()["rules"]]
    assert names == ["high", "mid", "low"]


def test_list_rules_enabled_only_filter(client):
    _create_rule(client, name="active",   enabled=True)
    _create_rule(client, name="inactive", enabled=False)
    names = [r["name"] for r in client.get("/v1/firewall/rules?enabled_only=true").json()["rules"]]
    assert "active" in names
    assert "inactive" not in names


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def test_create_rule_returns_201(client):
    assert client.post("/v1/firewall/rules", json={"name": "my-rule"}).status_code == 201


def test_create_rule_response_contains_id(client):
    assert "id" in _create_rule(client)


def test_create_rule_defaults(client):
    data = _create_rule(client, name="default-rule")
    assert data["action"] == "deny"
    assert data["src_address"] == "any"
    assert data["dst_address"] == "any"
    assert data["enabled"] is True
    assert data["priority"] == 100


def test_create_rule_custom_fields(client):
    data = _create_rule(client,
        name="allow-ssh",
        action="accept",
        protocol="tcp",
        dst_port=22,
        src_address="10.0.0.0/8",
        comment="internal SSH",
        priority=5,
    )
    assert data["action"] == "accept"
    assert data["protocol"] == "tcp"
    assert data["dst_port"] == 22
    assert data["src_address"] == "10.0.0.0/8"
    assert data["priority"] == 5


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------

def test_get_rule_by_id(client):
    rule = _create_rule(client, name="findme")
    r = client.get(f"/v1/firewall/rules/{rule['id']}")
    assert r.status_code == 200
    assert r.json()["name"] == "findme"


def test_get_rule_404_for_unknown_id(client):
    assert client.get("/v1/firewall/rules/does-not-exist").status_code == 404


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

def test_update_rule_changes_fields(client):
    rule = _create_rule(client, name="old-name", priority=50)
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"name": "new-name", "priority": 99}).json()
    assert data["name"] == "new-name"
    assert data["priority"] == 99


def test_update_rule_partial_preserves_other_fields(client):
    rule = _create_rule(client, name="keep-me", action="accept", priority=5)
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"priority": 10}).json()
    assert data["name"] == "keep-me"
    assert data["action"] == "accept"
    assert data["priority"] == 10


def test_update_rule_can_disable(client):
    rule = _create_rule(client, name="disable-me", enabled=True)
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"enabled": False}).json()
    assert data["enabled"] is False


def test_update_rule_404_for_unknown_id(client):
    assert client.put("/v1/firewall/rules/ghost", json={"name": "x"}).status_code == 404


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def test_delete_rule_returns_200(client):
    rule = _create_rule(client)
    r = client.delete(f"/v1/firewall/rules/{rule['id']}")
    assert r.status_code == 200
    assert r.json()["deleted"] is True


def test_delete_rule_removes_from_list(client):
    rule = _create_rule(client)
    client.delete(f"/v1/firewall/rules/{rule['id']}")
    ids = [x["id"] for x in client.get("/v1/firewall/rules").json()["rules"]]
    assert rule["id"] not in ids


def test_delete_rule_404_for_unknown_id(client):
    assert client.delete("/v1/firewall/rules/ghost").status_code == 404


# ---------------------------------------------------------------------------
# Platforms
# ---------------------------------------------------------------------------

def test_list_platforms_returns_known_platforms(client):
    platforms = client.get("/v1/firewall/platforms").json()["platforms"]
    for expected in ("cisco", "juniper", "iptables"):
        assert expected in platforms


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def test_compile_returns_correct_shape(client):
    _create_rule(client, name="allow-https", action="accept", protocol="tcp", dst_port=443)
    r = client.post("/v1/firewall/compile", json={"platform": "iptables", "filter_name": "test-fw"})
    assert r.status_code == 200
    data = r.json()
    assert data["platform"] == "iptables"
    assert data["filter_name"] == "test-fw"
    assert data["rule_count"] == 1
    assert data["output"] != ""


def test_compile_counts_only_enabled_rules(client):
    _create_rule(client, name="on",  enabled=True)
    _create_rule(client, name="off", enabled=False)
    assert client.post("/v1/firewall/compile", json={"platform": "cisco", "filter_name": "fw"}).json()["rule_count"] == 1


def test_compile_with_no_rules_still_responds(client):
    r = client.post("/v1/firewall/compile", json={"platform": "cisco", "filter_name": "fw"})
    assert r.status_code == 200
    assert r.json()["rule_count"] == 0


# ---------------------------------------------------------------------------
# Policy YAML
# ---------------------------------------------------------------------------

def test_policy_json_contains_rule_name(client):
    _create_rule(client, name="ssh-rule", action="accept", protocol="tcp", dst_port=22)
    r = client.get("/v1/firewall/policy?platform=cisco&filter_name=test")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "ssh-rule" in r.text


def test_policy_json_default_platform_is_iptables(client):
    r = client.get("/v1/firewall/policy")
    targets = r.json()["filters"][0]["header"]["targets"]
    assert "iptables" in targets


def test_policy_default_format_is_json(client):
    r = client.get("/v1/firewall/policy")
    assert r.headers["content-type"].startswith("application/json")


def test_policy_yaml_format(client):
    r = client.get("/v1/firewall/policy?format=yaml")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/yaml")


def test_policy_always_includes_default_deny(client):
    assert "default-deny" in client.get("/v1/firewall/policy").text


def test_policy_yaml_always_includes_default_deny(client):
    assert "default-deny" in client.get("/v1/firewall/policy?format=yaml").text


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_corrupt_rules_file_starts_empty(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text("this is not valid json {{{")
    client = TestClient(_make_app(tmp_path))
    assert client.get("/v1/firewall/rules").json() == {"rules": [], "count": 0}


def test_missing_rules_file_starts_empty(tmp_path):
    client = TestClient(_make_app(tmp_path))
    assert client.get("/v1/firewall/rules").json() == {"rules": [], "count": 0}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_rules_survive_across_plugin_instances(tmp_path):
    rule = _create_rule(TestClient(_make_app(tmp_path)), name="persistent-rule")
    r = TestClient(_make_app(tmp_path)).get(f"/v1/firewall/rules/{rule['id']}")
    assert r.status_code == 200
    assert r.json()["name"] == "persistent-rule"


def _make_inst(tmp_path, config=None):
    """Return a bare plugin instance with attributes set but setup() not called."""
    mod = _load_module()
    inst = mod.FirewallPlugin()
    inst.plugin_id = "firewall_plugin"
    inst.meta = {"name": "Firewall Plugin", "version": "1.0.0", "description": "", "author": ""}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.firewall_plugin")
    inst.config = {
        "rules_file": "rules.json",
        "default_platform": "iptables",
        "default_filter_name": "test-fw",
        **(config or {}),
    }
    return inst, mod


# ---------------------------------------------------------------------------
# Boot-time state apply
# ---------------------------------------------------------------------------

_BOOT_RULE = [{"id": "r1", "name": "allow-http", "action": "accept"}]
_CLEAN_OUTPUT = "*filter\n-P INPUT ACCEPT\nCOMMIT\n"


def test_rules_applied_to_iptables_on_boot(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps(_BOOT_RULE))
    inst, mod = _make_inst(tmp_path)
    inst._execute_compiled_rules = MagicMock()
    with patch.object(mod, "_compile_rules", return_value=_CLEAN_OUTPUT):
        inst.setup()
    inst._execute_compiled_rules.assert_called_once_with(_CLEAN_OUTPUT)


def test_ignore_state_on_boot_skips_load_and_apply(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps(_BOOT_RULE))
    inst, _ = _make_inst(tmp_path, config={"ignore_state_on_boot": True})
    inst._execute_compiled_rules = MagicMock()
    inst.setup()
    inst._execute_compiled_rules.assert_not_called()
    assert inst._rules == {}


def test_apply_state_skips_when_aerleon_unavailable(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps(_BOOT_RULE))
    inst, _ = _make_inst(tmp_path)
    inst._execute_compiled_rules = MagicMock()
    inst.setup()  # aerleon not installed → _compile_rules returns "# ..." → skips apply
    inst._execute_compiled_rules.assert_not_called()
    assert "r1" in inst._rules  # rules still loaded


def test_apply_state_does_not_crash_on_iptables_failure(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps(_BOOT_RULE))
    inst, mod = _make_inst(tmp_path)
    inst._execute_compiled_rules = MagicMock(side_effect=RuntimeError("iptables-restore failed: permission denied"))
    with patch.object(mod, "_compile_rules", return_value=_CLEAN_OUTPUT):
        inst.setup()  # must not raise
    assert "r1" in inst._rules


def test_deleted_rule_not_present_after_reload(tmp_path):
    client1 = TestClient(_make_app(tmp_path))
    rule = _create_rule(client1, name="gone-after-reload")
    client1.delete(f"/v1/firewall/rules/{rule['id']}")
    assert TestClient(_make_app(tmp_path)).get(f"/v1/firewall/rules/{rule['id']}").status_code == 404


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def test_create_rule_emits_added_event(tmp_path):
    received: list = []
    global_bus.subscribe("firewall.rule.added", received.append)
    try:
        rule = _create_rule(TestClient(_make_app(tmp_path)), name="event-rule")
        assert len(received) == 1
        assert received[0].payload["name"] == "event-rule"
        assert received[0].payload["rule_id"] == rule["id"]
    finally:
        global_bus.unsubscribe("firewall.rule.added", received.append)


def test_update_rule_emits_updated_event(tmp_path):
    received: list = []
    global_bus.subscribe("firewall.rule.updated", received.append)
    try:
        client = TestClient(_make_app(tmp_path))
        rule = _create_rule(client)
        client.put(f"/v1/firewall/rules/{rule['id']}", json={"priority": 1})
        assert len(received) == 1
        assert "priority" in received[0].payload["changes"]
    finally:
        global_bus.unsubscribe("firewall.rule.updated", received.append)


def test_delete_rule_emits_deleted_event(tmp_path):
    received: list = []
    global_bus.subscribe("firewall.rule.deleted", received.append)
    try:
        client = TestClient(_make_app(tmp_path))
        rule = _create_rule(client, name="byebye")
        client.delete(f"/v1/firewall/rules/{rule['id']}")
        assert len(received) == 1
        assert received[0].payload["rule_id"] == rule["id"]
    finally:
        global_bus.unsubscribe("firewall.rule.deleted", received.append)
