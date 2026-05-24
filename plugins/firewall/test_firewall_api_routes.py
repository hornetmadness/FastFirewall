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

from plugin_system.core.events import Event, bus as global_bus

PLUGIN_PY = Path(__file__).parent / "plugin.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_module():
    name = "_test_firewall"
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
    inst.plugin_id = "firewall"
    inst.meta = {"name": "Firewall Plugin", "version": "1.0.0", "description": "", "author": ""}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.firewall")
    inst.config = {
        "state_file": "rules.json",
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


def test_status_rule_counts_start_at_defaults(client):
    counts = client.get("/v1/firewall/status").json()["rules"]
    assert counts == {"total": 2, "enabled": 2, "disabled": 0}


def test_status_counts_update_after_create(client):
    _create_rule(client, name="on",  enabled=True)
    _create_rule(client, name="off", enabled=False)
    counts = client.get("/v1/firewall/status").json()["rules"]
    assert counts == {"total": 4, "enabled": 3, "disabled": 1}


def test_status_pending_changes_true_after_create(tmp_path):
    # Write a state that has both desired and current set (simulates a prior successful apply)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(
        json.dumps({"desired_state": _BOOT_STATE, "current_state": _BOOT_STATE})
    )
    client = TestClient(_make_app(tmp_path))
    # Adding a rule diverges desired from the committed current
    _create_rule(client, name="new-rule")
    assert client.get("/v1/firewall/status").json()["pending_changes"] is True


def test_status_pending_changes_false_after_boot_apply(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps({"desired_state": _BOOT_STATE}))
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    assert TestClient(app).get("/v1/firewall/status").json()["pending_changes"] is False


# ---------------------------------------------------------------------------
# List rules
# ---------------------------------------------------------------------------

def test_list_rules_starts_with_defaults(client):
    r = client.get("/v1/firewall/rules")
    assert r.status_code == 200
    names = {rule["name"] for rule in r.json()["rules"]}
    assert "allow-ssh" in names
    assert "allow-fastfirewall-api" in names


def test_list_rules_returns_all(client):
    _create_rule(client, name="rule-a")
    _create_rule(client, name="rule-b")
    assert client.get("/v1/firewall/rules").json()["count"] == 4  # 2 defaults + 2 added


def test_list_rules_sorted_by_priority(client):
    _create_rule(client, name="low",  priority=200)
    _create_rule(client, name="high", priority=5)   # below default priorities (10, 11)
    _create_rule(client, name="mid",  priority=100)
    names = [r["name"] for r in client.get("/v1/firewall/rules").json()["rules"]]
    assert names.index("high") < names.index("mid") < names.index("low")


def test_list_rules_applied_false_before_apply(client):
    # Fresh install — nftables stub always fails, so no committed snapshot exists
    rules = client.get("/v1/firewall/rules").json()["rules"]
    assert all(r["applied"] is False for r in rules)


def test_list_rules_applied_true_after_apply(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    rules = client.get("/v1/firewall/rules").json()["rules"]
    assert all(r["applied"] is True for r in rules)


def test_list_rules_new_rule_applied_false_until_apply(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    new = _create_rule(client, name="pending-rule")
    rules_by_id = {r["id"]: r for r in client.get("/v1/firewall/rules").json()["rules"]}
    assert rules_by_id[new["id"]]["applied"] is False
    for rule_id, rule in rules_by_id.items():
        if rule_id != new["id"]:
            assert rule["applied"] is True


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


def test_create_rule_response_applied_false(client):
    data = _create_rule(client, name="new-rule")
    assert data["applied"] is False


def test_create_rule_defaults(client):
    data = _create_rule(client, name="default-rule")
    assert data["chain"] == "input"
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


def test_get_rule_includes_applied_field(client):
    rule = _create_rule(client, name="check-applied")
    data = client.get(f"/v1/firewall/rules/{rule['id']}").json()
    assert "applied" in data
    assert data["applied"] is False


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


def test_update_rule_includes_applied_field(client):
    rule = _create_rule(client, name="update-applied")
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"priority": 50}).json()
    assert "applied" in data
    assert data["applied"] is False


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
# Check (dry-run validate)
# ---------------------------------------------------------------------------

def test_check_returns_success_true_on_valid_script(tmp_path):
    inst, _ = _make_inst(tmp_path)
    inst._validate_nft_script = MagicMock(return_value=(True, ""))
    inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    r = TestClient(app).post("/v1/firewall/check")
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert data["output"] == ""
    assert data["rule_count"] == 2  # 2 defaults


def test_check_returns_success_false_on_validation_error(tmp_path):
    inst, _ = _make_inst(tmp_path)
    inst._validate_nft_script = MagicMock(return_value=(False, "Error: table not found"))
    inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    r = TestClient(app).post("/v1/firewall/check")
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is False
    assert "Error" in data["output"]


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def test_apply_calls_apply_nft_script(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    _create_rule(TestClient(app), name="allow-ssh")
    inst._apply_nft_script.reset_mock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        r = TestClient(app).post("/v1/firewall/apply")
    assert r.status_code == 200
    inst._apply_nft_script.assert_called_once_with(_CLEAN_SCRIPT)


def test_apply_commits_state(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    _create_rule(client, name="rule")
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    assert client.get("/v1/firewall/status").json()["pending_changes"] is False


def test_apply_returns_rule_count(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    _create_rule(client, name="r1", enabled=True)
    _create_rule(client, name="r2", enabled=False)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        data = client.post("/v1/firewall/apply").json()
    assert data["rule_count"] == 3  # 2 defaults (enabled) + r1 (enabled)
    assert data["success"] is True


def test_apply_returns_500_on_nft_failure(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock(side_effect=RuntimeError("nft failed"))
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    _create_rule(TestClient(app), name="r")
    inst._apply_nft_script.side_effect = RuntimeError("nft failed")
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        r = TestClient(app).post("/v1/firewall/apply")
    assert r.status_code == 500


def test_apply_emits_event(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    _create_rule(TestClient(app), name="r")
    received: list = []
    global_bus.subscribe("firewall.applied", received.append)
    try:
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            TestClient(app).post("/v1/firewall/apply")
        assert len(received) == 1
        assert received[0].payload["success"] is True
    finally:
        global_bus.unsubscribe("firewall.applied", received.append)


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def test_compile_returns_correct_shape(client):
    _create_rule(client, name="allow-https", action="accept", protocol="tcp", dst_port=443)
    r = client.post("/v1/firewall/compile", json={"filter_name": "test-fw"})
    assert r.status_code == 200
    data = r.json()
    assert data["filter_name"] == "test-fw"
    assert data["rule_count"] == 3  # 2 defaults + 1 added
    assert data["output"] != ""


def test_compile_output_contains_nft_syntax(client):
    r = client.post("/v1/firewall/compile", json={"filter_name": "myfirewall"})
    assert r.status_code == 200
    output = r.json()["output"]
    assert any("table inet myfirewall" in line for line in output)
    assert any("add chain inet myfirewall input" in line for line in output)
    assert any("add chain inet myfirewall forward" in line for line in output)
    assert any("add chain inet myfirewall output" in line for line in output)


def test_compile_counts_only_enabled_rules(client):
    _create_rule(client, name="on",  enabled=True)
    _create_rule(client, name="off", enabled=False)
    # 2 defaults (enabled) + "on" (enabled) = 3; "off" (disabled) excluded
    assert client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["rule_count"] == 3


def test_compile_with_no_rules_still_responds(client):
    r = client.post("/v1/firewall/compile", json={"filter_name": "fw"})
    assert r.status_code == 200
    assert r.json()["rule_count"] == 2  # 2 defaults


# ---------------------------------------------------------------------------
# Discard
# ---------------------------------------------------------------------------

def test_discard_returns_409_when_no_snapshot(tmp_path):
    # Fresh install — no committed snapshot yet
    r = TestClient(_make_app(tmp_path)).post("/v1/firewall/discard")
    assert r.status_code == 409


def test_discard_reverts_pending_rule_additions(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(
        json.dumps({"desired_state": _BOOT_STATE, "current_state": _BOOT_STATE})
    )
    client = TestClient(_make_app(tmp_path))
    # Add an extra rule (makes desired != current)
    extra = _create_rule(client, name="should-disappear")
    assert client.get("/v1/firewall/rules").json()["count"] == 2
    # Discard reverts to the committed snapshot
    r = client.post("/v1/firewall/discard")
    assert r.status_code == 200
    assert r.json()["discarded"] is True
    ids = [x["id"] for x in client.get("/v1/firewall/rules").json()["rules"]]
    assert extra["id"] not in ids


def test_discard_clears_pending_changes(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    _create_rule(client, name="pending-rule")
    assert client.get("/v1/firewall/status").json()["pending_changes"] is True
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/status").json()["pending_changes"] is False


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_corrupt_rules_file_starts_empty(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text("this is not valid json {{{")
    client = TestClient(_make_app(tmp_path))
    assert client.get("/v1/firewall/rules").json() == {"rules": [], "count": 0}


def test_missing_rules_file_seeds_defaults(tmp_path):
    client = TestClient(_make_app(tmp_path))
    rules = client.get("/v1/firewall/rules").json()
    assert rules["count"] == 2
    names = {r["name"] for r in rules["rules"]}
    assert "allow-ssh" in names
    assert "allow-fastfirewall-api" in names


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
    inst.plugin_id = "firewall"
    inst.meta = {"name": "Firewall Plugin", "version": "1.0.0", "description": "", "author": ""}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.firewall")
    inst.config = {
        "state_file": "rules.json",
        "default_filter_name": "test-fw",
        **(config or {}),
    }
    return inst, mod


# ---------------------------------------------------------------------------
# Boot-time state apply
# ---------------------------------------------------------------------------

_BOOT_RULE = [{"id": "r1", "name": "allow-http", "action": "accept"}]
_BOOT_CHAINS = {"input": {"policy": "drop", "priority": 0}, "forward": {"policy": "drop", "priority": 0}, "output": {"policy": "accept", "priority": 0}}
_BOOT_STATE = {"rules": _BOOT_RULE, "chains": _BOOT_CHAINS}
_CLEAN_SCRIPT = (
    "add table inet test-fw\n"
    "flush table inet test-fw\n"
    "add chain inet test-fw input { type filter hook input priority 0; policy drop; }\n"
    "add chain inet test-fw forward { type filter hook forward priority 0; policy drop; }\n"
    "add chain inet test-fw output { type filter hook output priority 0; policy accept; }\n"
    "add rule inet test-fw input iif lo accept\n"
    "add rule inet test-fw input ct state established,related accept\n"
    "add rule inet test-fw forward ct state established,related accept"
)


def test_rules_applied_to_nft_on_boot(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps({"desired_state": _BOOT_STATE}))
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    inst._apply_nft_script.assert_called_once_with(_CLEAN_SCRIPT)


def test_ignore_state_on_boot_skips_apply(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(
        json.dumps({"desired_state": {"rules": _BOOT_RULE, "chains": _BOOT_CHAINS}})
    )
    inst, _ = _make_inst(tmp_path, config={"ignore_state_on_boot": True})
    inst._apply_nft_script = MagicMock()
    inst.setup()
    inst._apply_nft_script.assert_not_called()
    assert "r1" in inst._rules


def test_ignore_state_on_boot_still_creates_state_file(tmp_path):
    inst, _ = _make_inst(tmp_path, config={"ignore_state_on_boot": True})
    inst.setup()
    assert (tmp_path / "data" / "rules.json").exists()


def test_apply_state_does_not_crash_on_nft_failure(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps({"desired_state": _BOOT_STATE}))
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock(side_effect=RuntimeError("nft failed"))
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
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


# ---------------------------------------------------------------------------
# Macros
# ---------------------------------------------------------------------------

def test_create_rule_integer_port_still_accepted(client):
    data = _create_rule(client, name="ssh", dst_port=22)
    assert data["dst_port"] == 22


def test_create_rule_macro_dst_port_stored_verbatim(client):
    data = _create_rule(client, name="allow-dns", protocol="udp", dst_port="$service_port.dns.udp")
    assert data["dst_port"] == "$service_port.dns.udp"


def test_create_rule_macro_src_port_stored_verbatim(client):
    data = _create_rule(client, name="allow-dns-src", protocol="udp", src_port="$service_port.dns.udp")
    assert data["src_port"] == "$service_port.dns.udp"


def test_create_rule_rejects_macro_without_segment(client):
    r = client.post("/v1/firewall/rules", json={"name": "bad", "dst_port": "$service_port"})
    assert r.status_code == 422


def test_create_rule_rejects_malformed_macro(client):
    r = client.post("/v1/firewall/rules", json={"name": "bad", "dst_port": "$"})
    assert r.status_code == 422


def test_create_rule_rejects_duplicate_content(client):
    body = {"name": "allow-ssh", "action": "accept", "protocol": "tcp", "dst_port": 22}
    assert client.post("/v1/firewall/rules", json=body).status_code == 201
    r = client.post("/v1/firewall/rules", json=body)
    assert r.status_code == 409


def test_create_rule_allows_same_name_different_content(client):
    client.post("/v1/firewall/rules", json={"name": "allow-ssh", "action": "accept", "protocol": "tcp", "dst_port": 22})
    r = client.post("/v1/firewall/rules", json={"name": "allow-ssh", "action": "accept", "protocol": "tcp", "dst_port": 2222})
    assert r.status_code == 201


def test_fresh_install_seeds_default_rules(tmp_path):
    client = TestClient(_make_app(tmp_path))
    rules = client.get("/v1/firewall/rules").json()["rules"]
    names = {r["name"] for r in rules}
    assert "allow-ssh" in names
    assert "allow-fastfirewall-api" in names


def test_fresh_install_persists_state_file(tmp_path):
    _make_app(tmp_path)
    state_file = tmp_path / "data" / "rules.json"
    assert state_file.exists()
    data = json.loads(state_file.read_text())
    assert len(data["desired_state"]["rules"]) == 2
    assert "chains" in data["desired_state"]


def test_existing_state_file_not_reseeded(tmp_path):
    _make_app(tmp_path)
    # second boot with an existing state file should not add duplicates
    app2 = _make_app(tmp_path)
    client = TestClient(app2)
    rules = client.get("/v1/firewall/rules").json()["rules"]
    names = [r["name"] for r in rules]
    assert names.count("allow-ssh") == 1
    assert names.count("allow-fastfirewall-api") == 1


def test_update_rule_accepts_macro_port(client):
    rule = _create_rule(client, name="upgrade-to-macro", dst_port=22)
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"dst_port": "$service_port.smtp.tcp"}).json()
    assert data["dst_port"] == "$service_port.smtp.tcp"


def test_update_rule_rejects_malformed_macro(client):
    rule = _create_rule(client, name="bad-update")
    r = client.put(f"/v1/firewall/rules/{rule['id']}", json={"dst_port": "$bad"})
    assert r.status_code == 422


def _default_chains(mod):
    return {name: mod.ChainConfig(**cfg) for name, cfg in mod._DEFAULT_CHAINS.items()}


def test_macro_resolved_to_port_in_script():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.set_service_ports({"dns": {"udp": [53]}})
    try:
        rule = mod.FirewallRule(name="allow-dns", action="accept", protocol="udp", dst_port="$service_port.dns.udp")
        script = mod._compile_to_script([rule], "test", _default_chains(mod), logging.getLogger("test"))
        assert "udp dport 53" in script
    finally:
        macro_registry.set_service_ports({})


def test_macro_multi_port_all_appear_in_script():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.set_service_ports({"smtp": {"tcp": [25, 587, 465]}})
    try:
        rule = mod.FirewallRule(name="allow-smtp", action="accept", protocol="tcp", dst_port="$service_port.smtp.tcp")
        script = mod._compile_to_script([rule], "test", _default_chains(mod), logging.getLogger("test"))
        # All three ports should appear as a set expression
        assert "25" in script
        assert "465" in script
        assert "587" in script
    finally:
        macro_registry.set_service_ports({})


def test_macro_rule_skipped_when_registry_empty():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.set_service_ports({})
    # protocol="udp" required so port resolution is attempted; without protocol, ports are skipped
    rule = mod.FirewallRule(name="needs-dns", action="accept", protocol="udp", dst_port="$service_port.dns.udp")
    script = mod._compile_to_script([rule], "test", _default_chains(mod), logging.getLogger("test"))
    # Rule is skipped — no dport statement for the rule, but script still has the table/chain
    assert "needs-dns" not in script
    assert "table inet test" in script


def test_status_includes_macros(tmp_path):
    from plugin_system.core.macros import macro_registry
    macro_registry.set_service_ports({"dns": {"udp": [53]}, "dhcp": {"udp": [67]}})
    try:
        inst, _ = _make_inst(tmp_path)
        inst.setup()
        app = FastAPI()
        app.include_router(inst.router, prefix="/v1/firewall")
        status = TestClient(app).get("/v1/firewall/status").json()
        assert "service_port" in status["macros"]
    finally:
        macro_registry.set_service_ports({})


def test_macro_rule_survives_reload(tmp_path):
    rule = _create_rule(TestClient(_make_app(tmp_path)), name="persistent-macro", dst_port="$service_port.dns.udp")
    r = TestClient(_make_app(tmp_path)).get(f"/v1/firewall/rules/{rule['id']}")
    assert r.status_code == 200
    assert r.json()["dst_port"] == "$service_port.dns.udp"


# ---------------------------------------------------------------------------
# Interface alias macros
# ---------------------------------------------------------------------------

def test_create_rule_uppercase_alias_macro_accepted(client):
    data = _create_rule(client, name="alias-rule", dst_port="$service_port.dns.udp")
    assert data["dst_port"] == "$service_port.dns.udp"


def test_interface_macro_syntax_accepted(client):
    # $interface.LAN1 is valid macro syntax (uppercase segment allowed)
    from plugin_system.core.macros import is_macro, validate_macro_syntax
    assert is_macro("$interface.LAN1")
    assert is_macro("$interface.WAN")
    assert validate_macro_syntax("$interface.LAN1") == "$interface.LAN1"


def test_status_includes_interface_macro_namespace(tmp_path):
    from plugin_system.core.macros import macro_registry
    _aliases: dict[str, str] = {"LAN1": "eth0", "WAN": "eth1"}
    macro_registry.register_namespace("interface", lambda *s: _aliases.get(s[0]) if s else None)
    try:
        inst, _ = _make_inst(tmp_path)
        inst.setup()
        app = FastAPI()
        app.include_router(inst.router, prefix="/v1/firewall")
        status = TestClient(app).get("/v1/firewall/status").json()
        assert "interface" in status["macros"]
    finally:
        macro_registry.unregister_namespace("interface")


def test_interface_macro_resolve_string():
    from plugin_system.core.macros import macro_registry
    _aliases: dict[str, str] = {"LAN1": "eth0", "WAN": "eth1"}
    macro_registry.register_namespace("interface", lambda *s: _aliases.get(s[0]) if s else None)
    try:
        assert macro_registry.resolve_string("$interface.LAN1") == "eth0"
        assert macro_registry.resolve_string("$interface.WAN") == "eth1"
        assert macro_registry.resolve_string("$interface.MISSING") is None
        assert macro_registry.resolve_string("$service_port.dns.udp") is None
    finally:
        macro_registry.unregister_namespace("interface")


def test_interface_macro_unknown_namespace_returns_none():
    from plugin_system.core.macros import macro_registry
    assert macro_registry.resolve_string("$unknown.FOO") is None


# ---------------------------------------------------------------------------
# Multi-chain support
# ---------------------------------------------------------------------------

def test_create_rule_with_forward_chain(client):
    data = _create_rule(client, name="fwd-rule", chain="forward")
    assert data["chain"] == "forward"


def test_create_rule_with_output_chain(client):
    data = _create_rule(client, name="out-rule", chain="output")
    assert data["chain"] == "output"


def test_forward_rule_appears_in_forward_chain(client):
    _create_rule(client, name="allow-fwd", chain="forward", action="accept", protocol="tcp", dst_port=443)
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("fw forward" in line for line in output)
    assert any("allow-fwd" in line for line in output)


def test_update_rule_chain(client):
    rule = _create_rule(client, name="move-me", chain="input")
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"chain": "forward"}).json()
    assert data["chain"] == "forward"


# ---------------------------------------------------------------------------
# reject action
# ---------------------------------------------------------------------------

def test_create_rule_reject_action(client):
    data = _create_rule(client, name="reject-rule", action="reject")
    assert data["action"] == "reject"


def test_reject_rule_compiles_to_reject_verdict():
    mod = _load_module()
    rule = mod.FirewallRule(name="block-telnet", action="reject", protocol="tcp", dst_port=23)
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert expr.endswith("reject")


# ---------------------------------------------------------------------------
# IPv6 address matching
# ---------------------------------------------------------------------------

def test_ipv6_src_address_uses_ip6_saddr():
    mod = _load_module()
    rule = mod.FirewallRule(name="v6-rule", action="accept", src_address="2001:db8::/32")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "ip6 saddr 2001:db8::/32" in expr
    assert "ip saddr" not in expr


def test_ipv4_src_address_uses_ip_saddr():
    mod = _load_module()
    rule = mod.FirewallRule(name="v4-rule", action="accept", src_address="10.0.0.0/8")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "ip saddr 10.0.0.0/8" in expr


def test_ipv6_dst_address_uses_ip6_daddr():
    mod = _load_module()
    rule = mod.FirewallRule(name="v6-dst", action="accept", dst_address="fd00::1")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "ip6 daddr fd00::1" in expr


# ---------------------------------------------------------------------------
# Stateful connection tracking
# ---------------------------------------------------------------------------

def test_compile_output_contains_iif_lo_accept_in_input(client):
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("fw input iif lo accept" in line for line in output)


def test_compile_iif_lo_not_in_forward_chain(client):
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert not any("fw forward iif lo accept" in line for line in output)


def test_compile_output_contains_ct_state_input(client):
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("fw input ct state established,related accept" in line for line in output)


def test_compile_output_contains_ct_state_forward(client):
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("fw forward ct state established,related accept" in line for line in output)


# ---------------------------------------------------------------------------
# Protocol matching — meta l4proto
# ---------------------------------------------------------------------------

def test_icmp_protocol_uses_meta_l4proto():
    mod = _load_module()
    rule = mod.FirewallRule(name="allow-icmp", action="accept", protocol="icmp")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "meta l4proto icmp" in expr
    assert "ip protocol" not in expr


def test_icmpv6_protocol_compiles_to_ipv6_icmp():
    mod = _load_module()
    rule = mod.FirewallRule(name="allow-icmpv6", action="accept", protocol="icmpv6")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "meta l4proto ipv6-icmp" in expr


# ---------------------------------------------------------------------------
# Chain management endpoints
# ---------------------------------------------------------------------------

def test_list_chains_returns_three_chains(client):
    r = client.get("/v1/firewall/chains")
    assert r.status_code == 200
    data = r.json()
    assert set(data["chains"].keys()) == {"input", "forward", "output"}


def test_list_chains_includes_table(client):
    data = client.get("/v1/firewall/chains").json()
    assert "inet" in data["table"]
    assert "test-fw" in data["table"]


def test_get_chain_returns_policy(client):
    data = client.get("/v1/firewall/chains/input").json()
    assert data["name"] == "input"
    assert data["policy"] == "drop"


def test_get_chain_output_defaults_accept(client):
    data = client.get("/v1/firewall/chains/output").json()
    assert data["policy"] == "accept"


def test_list_chains_applied_false_before_apply(client):
    chains = client.get("/v1/firewall/chains").json()["chains"]
    assert all(cfg["applied"] is False for cfg in chains.values())


def test_get_chain_applied_false_before_apply(client):
    data = client.get("/v1/firewall/chains/input").json()
    assert data["applied"] is False


def test_update_chain_applied_false_after_policy_change(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    # All chains applied=True after apply
    chains = client.get("/v1/firewall/chains").json()["chains"]
    assert all(cfg["applied"] is True for cfg in chains.values())
    # Changing a chain policy makes it applied=False
    data = client.put("/v1/firewall/chains/forward", json={"policy": "accept"}).json()
    assert data["applied"] is False
    # Other chains remain applied=True
    chains = client.get("/v1/firewall/chains").json()["chains"]
    assert chains["input"]["applied"] is True
    assert chains["forward"]["applied"] is False


def test_get_chain_404_for_unknown(client):
    assert client.get("/v1/firewall/chains/nonexistent").status_code == 404


def test_update_chain_policy(client):
    data = client.put("/v1/firewall/chains/forward", json={"policy": "accept"}).json()
    assert data["name"] == "forward"
    assert data["policy"] == "accept"


def test_update_chain_policy_roundtrips(client):
    client.put("/v1/firewall/chains/output", json={"policy": "drop"})
    data = client.get("/v1/firewall/chains/output").json()
    assert data["policy"] == "drop"


def test_update_chain_policy_affects_compiled_output(client):
    client.put("/v1/firewall/chains/forward", json={"policy": "accept"})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("forward" in line for line in output)
    assert any("policy accept" in line for line in output)


def test_chain_response_includes_preamble(client):
    data = client.get("/v1/firewall/chains/input").json()
    assert "preamble" in data
    assert "iif lo accept" in data["preamble"]
    assert "ct state established,related accept" in data["preamble"]


def test_update_chain_preamble(client):
    data = client.put("/v1/firewall/chains/forward", json={"preamble": []}).json()
    assert data["preamble"] == []
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert not any("fw forward ct state" in line for line in output)


def test_update_chain_policy_leaves_preamble_unchanged(client):
    # Changing policy does not automatically modify the preamble
    original = client.get("/v1/firewall/chains/forward").json()["preamble"]
    client.put("/v1/firewall/chains/forward", json={"policy": "accept"})
    updated = client.get("/v1/firewall/chains/forward").json()["preamble"]
    assert updated == original


def test_update_chain_404_for_unknown(client):
    assert client.put("/v1/firewall/chains/ghost", json={"policy": "drop"}).status_code == 404


def test_update_chain_priority(client):
    data = client.put("/v1/firewall/chains/input", json={"priority": 10}).json()
    assert data["priority"] == 10


# ---------------------------------------------------------------------------
# Table endpoint
# ---------------------------------------------------------------------------

def test_get_table_returns_name_and_family(client):
    data = client.get("/v1/firewall/table").json()
    assert data["name"] == "test-fw"
    assert data["family"] == "inet"


def test_get_table_lists_chains(client):
    data = client.get("/v1/firewall/table").json()
    assert set(data["chains"]) == {"input", "forward", "output"}
