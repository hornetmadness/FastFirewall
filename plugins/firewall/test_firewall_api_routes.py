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
_PLUGIN_DIR = str(Path(__file__).parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from models import LogConfig, RateLimit  # noqa: E402


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
    assert client.get("/v1/firewall/status").json()["pending_changes"]["any"] is True


def test_status_pending_changes_false_after_boot_apply(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "rules.json").write_text(json.dumps({"desired_state": _BOOT_STATE}))
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    assert TestClient(app).get("/v1/firewall/status").json()["pending_changes"]["any"] is False


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
    assert client.get("/v1/firewall/status").json()["pending_changes"]["any"] is False


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
    assert data["output_path"].endswith("test-fw.nft")


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
    assert client.get("/v1/firewall/status").json()["pending_changes"]["any"] is True
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/status").json()["pending_changes"]["any"] is False


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


# ---------------------------------------------------------------------------
# Interface matching (§2)
# ---------------------------------------------------------------------------

def test_create_rule_src_interface_stored(client):
    data = _create_rule(client, name="lan-ssh", src_interface="eth0")
    assert data["src_interface"] == "eth0"


def test_create_rule_dst_interface_stored(client):
    data = _create_rule(client, name="wan-out", dst_interface="eth1")
    assert data["dst_interface"] == "eth1"


def test_create_rule_interface_defaults_none(client):
    data = _create_rule(client, name="no-iface")
    assert data["src_interface"] is None
    assert data["dst_interface"] is None


def test_update_rule_can_set_src_interface(client):
    rule = _create_rule(client, name="add-iface")
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"src_interface": "eth0"}).json()
    assert data["src_interface"] == "eth0"


def test_update_rule_can_clear_interface(client):
    rule = _create_rule(client, name="clear-iface", src_interface="eth0")
    data = client.put(f"/v1/firewall/rules/{rule['id']}", json={"src_interface": None}).json()
    assert data["src_interface"] is None


def test_src_interface_compiles_to_iif():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", src_interface="eth0")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert 'iif "eth0"' in expr


def test_dst_interface_compiles_to_oif():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", dst_interface="eth1")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert 'oif "eth1"' in expr


def test_interface_comes_before_address_in_expr():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", src_interface="eth0", src_address="10.0.0.0/8")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert expr.index('iif "eth0"') < expr.index("ip saddr")


def test_both_interfaces_compile_together():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", src_interface="eth0", dst_interface="eth1")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert 'iif "eth0"' in expr
    assert 'oif "eth1"' in expr


def test_interface_rule_in_compiled_script(client):
    _create_rule(client, name="lan-fwd", chain="forward", action="accept",
                 src_interface="eth0", dst_interface="eth1")
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any('iif "eth0"' in line for line in output)
    assert any('oif "eth1"' in line for line in output)


def test_interface_survives_reload(tmp_path):
    rule = _create_rule(TestClient(_make_app(tmp_path)), name="iface-persist", src_interface="eth0")
    r = TestClient(_make_app(tmp_path)).get(f"/v1/firewall/rules/{rule['id']}")
    assert r.status_code == 200
    assert r.json()["src_interface"] == "eth0"


# ---------------------------------------------------------------------------
# .nft file annotations (§15)
# ---------------------------------------------------------------------------

def test_compiled_script_contains_rule_id_comment():
    mod = _load_module()
    rule = mod.FirewallRule(name="annotated", action="accept", protocol="tcp", dst_port=80)
    chains = _default_chains(mod)
    script = mod._compile_to_script([rule], "fw", chains, logging.getLogger("test"))
    assert f"# rule_id: {rule.id}" in script


def test_compiled_script_rule_id_in_nft_comment():
    mod = _load_module()
    rule = mod.FirewallRule(name="annotated", action="accept", protocol="tcp", dst_port=80)
    chains = _default_chains(mod)
    script = mod._compile_to_script([rule], "fw", chains, logging.getLogger("test"))
    assert f"[id:{rule.id}]" in script


def test_compiled_script_contains_chain_comment():
    mod = _load_module()
    chains = _default_chains(mod)
    script = mod._compile_to_script([], "fw", chains, logging.getLogger("test"))
    assert "# chain: input" in script
    assert "# chain: forward" in script
    assert "# chain: output" in script


def test_compiled_script_contains_generated_timestamp():
    mod = _load_module()
    script = mod._compile_to_script([], "fw", _default_chains(mod), logging.getLogger("test"))
    assert "# generated:" in script


# ---------------------------------------------------------------------------
# Rate limiting (§5)
# ---------------------------------------------------------------------------

def test_create_rule_with_rate_limit(client):
    data = _create_rule(client, name="ssh-guard", protocol="tcp", dst_port=22,
                        action="accept", ct_state=["new"],
                        rate_limit={"rate": 3, "unit": "minute"})
    assert data["rate_limit"]["rate"] == 3
    assert data["rate_limit"]["unit"] == "minute"


def test_rate_limit_compiles_to_limit_expr():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="tcp", dst_port=22,
                            rate_limit=RateLimit(rate=10, unit="second"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "limit rate 10/second" in expr


def test_rate_limit_over_flag():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny",
                            rate_limit=RateLimit(rate=100, unit="second", over=True))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "limit rate over 100/second" in expr


def test_rate_limit_with_burst():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept",
                            rate_limit=RateLimit(rate=10, unit="second", burst=20, burst_unit="packets"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "burst 20 packets" in expr


def test_rate_limit_byte_unit():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept",
                            rate_limit=RateLimit(rate=10, unit="mbytes"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "limit rate 10 mbytes/second" in expr


def test_rate_limit_comes_before_verdict():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept",
                            rate_limit=RateLimit(rate=5, unit="second"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert expr.index("limit rate") < expr.index("accept")


# ---------------------------------------------------------------------------
# Logging (§6)
# ---------------------------------------------------------------------------

def test_create_rule_with_log_config(client):
    data = _create_rule(client, name="log-ssh", protocol="tcp", dst_port=22, action="accept",
                        log={"prefix": "SSH: ", "level": "info"})
    assert data["log"]["prefix"] == "SSH: "
    assert data["log"]["level"] == "info"


def test_log_compiles_to_log_statement():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny",
                            log=LogConfig(prefix="DROP: ", level="warn"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert 'log prefix "DROP: " level warn' in expr


def test_log_comes_before_verdict():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny",
                            log=LogConfig(prefix="X: ", level="warn"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert expr.index("log prefix") < expr.index("drop")


def test_log_with_nflog_group():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept",
                            log=LogConfig(prefix="FWD: ", level="info", group=1))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "group 1" in expr


def test_log_with_flags():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept",
                            log=LogConfig(prefix="X: ", level="warn", flags="all"))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "flags all" in expr


def test_log_with_snaplen():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny",
                            log=LogConfig(prefix="X: ", level="warn", snaplen=256))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "snaplen 256" in expr


# ---------------------------------------------------------------------------
# TCP flags (§9a)
# ---------------------------------------------------------------------------

def test_tcp_flags_compiles_to_flags_set():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny", protocol="tcp",
                            tcp_flags=["syn", "rst"])
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "tcp flags { syn, rst }" in expr


def test_tcp_flags_with_mask():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="tcp",
                            tcp_flags=["syn"], tcp_flags_mask=["syn", "ack"])
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "tcp flags & (syn|ack) == (syn)" in expr


def test_tcp_flags_mask_zero_match():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny", protocol="tcp",
                            tcp_flags=[], tcp_flags_mask=["fin", "syn", "rst"])
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "== 0" in expr


def test_tcp_flags_stored_and_reloaded(client):
    data = _create_rule(client, name="syn-guard", protocol="tcp",
                        action="deny", tcp_flags=["syn", "fin"])
    assert set(data["tcp_flags"]) == {"syn", "fin"}


# ---------------------------------------------------------------------------
# ICMP type (§9b)
# ---------------------------------------------------------------------------

def test_icmp_type_string_compiles():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="icmp",
                            icmp_type="echo-request")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "icmp type echo-request" in expr


def test_icmp_type_int_compiles():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="icmp", icmp_type=8)
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "icmp type 8" in expr


def test_icmpv6_type_uses_icmpv6_keyword():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="icmpv6",
                            icmp_type="echo-request")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "icmpv6 type echo-request" in expr


# ---------------------------------------------------------------------------
# CT state on rules (§9c)
# ---------------------------------------------------------------------------

def test_ct_state_single_compiles():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", ct_state=["new"])
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "ct state new" in expr


def test_ct_state_multiple_compiles():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="deny", ct_state=["invalid", "untracked"])
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "ct state {" in expr
    assert "invalid" in expr
    assert "untracked" in expr


def test_ct_state_stored_and_reloaded(client):
    data = _create_rule(client, name="new-only", ct_state=["new"])
    assert data["ct_state"] == ["new"]


# ---------------------------------------------------------------------------
# Port ranges (§9d)
# ---------------------------------------------------------------------------

def test_dst_port_range_compiles():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="tcp",
                            dst_port_range=(1024, 65535))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "tcp dport 1024-65535" in expr


def test_src_port_range_compiles():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="udp",
                            src_port_range=(32768, 60999))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "udp sport 32768-60999" in expr


def test_port_range_stored_and_reloaded(client):
    data = _create_rule(client, name="ephemeral", protocol="tcp",
                        dst_port_range=[1024, 65535])
    assert data["dst_port_range"] == [1024, 65535]


def test_port_range_and_exact_port_are_exclusive():
    mod = _load_module()
    # When src_port is set, src_port_range is ignored (exact port wins)
    rule = mod.FirewallRule(name="r", action="accept", protocol="tcp",
                            src_port=22, src_port_range=(20, 30))
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "sport 22" in expr
    assert "20-30" not in expr


# ---------------------------------------------------------------------------
# Live kernel state (§14)
# ---------------------------------------------------------------------------

def test_live_state_returns_500_when_nft_fails(tmp_path):
    inst, _ = _make_inst(tmp_path)
    inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    # nft_cmd will fail since we're not root — expect a 500
    r = client.get("/v1/firewall/live-state")
    assert r.status_code == 500


# ---------------------------------------------------------------------------
# Named sets — CRUD (§3)
# ---------------------------------------------------------------------------

def test_list_sets_empty_initially(client):
    r = client.get("/v1/firewall/sets")
    assert r.status_code == 200
    data = r.json()
    assert data["sets"] == []
    assert data["count"] == 0


def test_create_set_returns_201(client):
    r = client.post("/v1/firewall/sets", json={"name": "blocklist", "type": "ipv4_addr"})
    assert r.status_code == 201


def test_create_set_stores_fields(client):
    data = client.post("/v1/firewall/sets", json={
        "name": "my-set",
        "type": "ipv6_addr",
        "flags": ["interval"],
        "auto_merge": True,
        "timeout": 300,
        "comment": "test set",
    }).json()
    assert data["name"] == "my-set"
    assert data["type"] == "ipv6_addr"
    assert "interval" in data["flags"]
    assert data["auto_merge"] is True
    assert data["timeout"] == 300
    assert data["comment"] == "test set"


def test_create_set_duplicate_returns_409(client):
    client.post("/v1/firewall/sets", json={"name": "dup", "type": "ipv4_addr"})
    r = client.post("/v1/firewall/sets", json={"name": "dup", "type": "ipv4_addr"})
    assert r.status_code == 409


def test_get_set_by_name(client):
    client.post("/v1/firewall/sets", json={"name": "findme", "type": "ipv4_addr"})
    r = client.get("/v1/firewall/sets/findme")
    assert r.status_code == 200
    assert r.json()["name"] == "findme"


def test_get_set_404_unknown(client):
    assert client.get("/v1/firewall/sets/ghost").status_code == 404


def test_delete_set_removes_it(client):
    client.post("/v1/firewall/sets", json={"name": "gone", "type": "ipv4_addr"})
    r = client.delete("/v1/firewall/sets/gone")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get("/v1/firewall/sets/gone").status_code == 404


def test_delete_set_404_unknown(client):
    assert client.delete("/v1/firewall/sets/ghost").status_code == 404


def test_add_elements_to_set(client):
    client.post("/v1/firewall/sets", json={"name": "ips", "type": "ipv4_addr"})
    data = client.post("/v1/firewall/sets/ips/elements",
                       json={"elements": ["10.0.0.1", "10.0.0.2"]}).json()
    assert "10.0.0.1" in data["elements"]
    assert "10.0.0.2" in data["elements"]


def test_add_elements_deduplicates(client):
    client.post("/v1/firewall/sets", json={"name": "ips", "type": "ipv4_addr"})
    client.post("/v1/firewall/sets/ips/elements", json={"elements": ["10.0.0.1"]})
    data = client.post("/v1/firewall/sets/ips/elements",
                       json={"elements": ["10.0.0.1", "10.0.0.3"]}).json()
    assert data["elements"].count("10.0.0.1") == 1
    assert "10.0.0.3" in data["elements"]


def test_remove_elements_from_set(client):
    client.post("/v1/firewall/sets", json={"name": "ips", "type": "ipv4_addr",
                                            "elements": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]})
    data = client.request("DELETE", "/v1/firewall/sets/ips/elements",
                          json={"elements": ["10.0.0.2"]}).json()
    assert "10.0.0.1" in data["elements"]
    assert "10.0.0.2" not in data["elements"]
    assert "10.0.0.3" in data["elements"]


def test_add_elements_404_unknown_set(client):
    r = client.post("/v1/firewall/sets/ghost/elements", json={"elements": ["1.2.3.4"]})
    assert r.status_code == 404


def test_remove_elements_404_unknown_set(client):
    r = client.request("DELETE", "/v1/firewall/sets/ghost/elements", json={"elements": ["1.2.3.4"]})
    assert r.status_code == 404


def test_set_count_in_list(client):
    client.post("/v1/firewall/sets", json={"name": "a", "type": "ipv4_addr"})
    client.post("/v1/firewall/sets", json={"name": "b", "type": "ipv6_addr"})
    data = client.get("/v1/firewall/sets").json()
    assert data["count"] == 2


def test_set_survives_reload(tmp_path):
    client1 = TestClient(_make_app(tmp_path))
    client1.post("/v1/firewall/sets", json={"name": "persist", "type": "ipv4_addr",
                                             "elements": ["192.168.1.0/24"]})
    r = TestClient(_make_app(tmp_path)).get("/v1/firewall/sets/persist")
    assert r.status_code == 200
    assert "192.168.1.0/24" in r.json()["elements"]


def test_status_includes_set_count(client):
    client.post("/v1/firewall/sets", json={"name": "s1", "type": "ipv4_addr"})
    status = client.get("/v1/firewall/status").json()
    assert status["sets"] == 1


def test_set_compiled_to_add_set_statement(client):
    client.post("/v1/firewall/sets", json={"name": "blocklist", "type": "ipv4_addr",
                                            "elements": ["1.2.3.4"]})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add set inet fw blocklist" in line for line in output)
    assert any("add element inet fw blocklist" in line for line in output)


def test_set_with_flags_in_compiled_output(client):
    client.post("/v1/firewall/sets", json={"name": "timed", "type": "ipv4_addr",
                                            "flags": ["timeout"], "timeout": 60})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("timeout" in line and "timed" in line for line in output)


# ── rule src/dst_address_set fields ──

def test_create_rule_with_src_address_set(client):
    client.post("/v1/firewall/sets", json={"name": "trusted", "type": "ipv4_addr"})
    data = _create_rule(client, name="allow-trusted", action="accept", src_address_set="trusted")
    assert data["src_address_set"] == "trusted"


def test_create_rule_with_dst_address_set(client):
    client.post("/v1/firewall/sets", json={"name": "servers", "type": "ipv4_addr"})
    data = _create_rule(client, name="allow-servers", action="accept", dst_address_set="servers")
    assert data["dst_address_set"] == "servers"


def test_src_address_set_compiles_to_saddr_ref():
    mod = _load_module()
    fw_set = mod.FirewallSet(name="blocklist", type="ipv4_addr")
    rule = mod.FirewallRule(name="r", action="deny", src_address_set="blocklist")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"), sets={"blocklist": fw_set})
    assert expr is not None
    assert "ip saddr @blocklist" in expr


def test_dst_address_set_compiles_to_daddr_ref():
    mod = _load_module()
    fw_set = mod.FirewallSet(name="servers", type="ipv4_addr")
    rule = mod.FirewallRule(name="r", action="accept", dst_address_set="servers")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"), sets={"servers": fw_set})
    assert expr is not None
    assert "ip daddr @servers" in expr


def test_ipv6_set_compiles_to_ip6_saddr():
    mod = _load_module()
    fw_set = mod.FirewallSet(name="v6block", type="ipv6_addr")
    rule = mod.FirewallRule(name="r", action="deny", src_address_set="v6block")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"), sets={"v6block": fw_set})
    assert expr is not None
    assert "ip6 saddr @v6block" in expr


def test_set_ref_in_full_compiled_script(client):
    client.post("/v1/firewall/sets", json={"name": "trusted", "type": "ipv4_addr",
                                            "elements": ["10.0.0.0/8"]})
    _create_rule(client, name="allow-trusted", action="accept", src_address_set="trusted")
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("ip saddr @trusted" in line for line in output)


def test_discard_restores_sets(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    # Add a set after apply
    client.post("/v1/firewall/sets", json={"name": "pending-set", "type": "ipv4_addr"})
    assert client.get("/v1/firewall/sets").json()["count"] == 1
    # Discard should remove the pending set
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/sets").json()["count"] == 0


# ---------------------------------------------------------------------------
# NAT rules — CRUD (§4)
# ---------------------------------------------------------------------------

def test_list_nat_rules_empty_initially(client):
    r = client.get("/v1/firewall/nat/rules")
    assert r.status_code == 200
    data = r.json()
    assert data["nat_rules"] == []
    assert data["count"] == 0


def test_create_nat_rule_returns_201(client):
    r = client.post("/v1/firewall/nat/rules", json={
        "name": "masq-wan",
        "type": "masquerade",
        "chain": "postrouting",
        "out_interface": "eth0",
    })
    assert r.status_code == 201


def test_create_nat_rule_stores_fields(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "masq-wan",
        "type": "masquerade",
        "chain": "postrouting",
        "out_interface": "eth0",
        "comment": "WAN masquerade",
        "priority": 50,
    }).json()
    assert data["name"] == "masq-wan"
    assert data["type"] == "masquerade"
    assert data["chain"] == "postrouting"
    assert data["out_interface"] == "eth0"
    assert data["comment"] == "WAN masquerade"
    assert data["priority"] == 50
    assert "id" in data


def test_create_nat_rule_applied_false(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "masq", "type": "masquerade", "chain": "postrouting"
    }).json()
    assert data["applied"] is False


def test_create_nat_rule_duplicate_returns_409(client):
    body = {"name": "masq", "type": "masquerade", "chain": "postrouting"}
    client.post("/v1/firewall/nat/rules", json=body)
    r = client.post("/v1/firewall/nat/rules", json=body)
    assert r.status_code == 409


def test_get_nat_rule_by_id(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "findme", "type": "masquerade", "chain": "postrouting"
    }).json()
    r = client.get(f"/v1/firewall/nat/rules/{data['id']}")
    assert r.status_code == 200
    assert r.json()["name"] == "findme"


def test_get_nat_rule_404_unknown(client):
    assert client.get("/v1/firewall/nat/rules/ghost").status_code == 404


def test_update_nat_rule_changes_fields(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "old-name", "type": "masquerade", "chain": "postrouting"
    }).json()
    updated = client.put(f"/v1/firewall/nat/rules/{data['id']}",
                         json={"name": "new-name", "priority": 200}).json()
    assert updated["name"] == "new-name"
    assert updated["priority"] == 200


def test_update_nat_rule_partial_preserves_fields(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "keep-name", "type": "masquerade", "chain": "postrouting", "priority": 10
    }).json()
    updated = client.put(f"/v1/firewall/nat/rules/{data['id']}", json={"priority": 20}).json()
    assert updated["name"] == "keep-name"
    assert updated["priority"] == 20


def test_update_nat_rule_404_unknown(client):
    assert client.put("/v1/firewall/nat/rules/ghost", json={"name": "x"}).status_code == 404


def test_delete_nat_rule(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "gone", "type": "masquerade", "chain": "postrouting"
    }).json()
    r = client.delete(f"/v1/firewall/nat/rules/{data['id']}")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get(f"/v1/firewall/nat/rules/{data['id']}").status_code == 404


def test_delete_nat_rule_404_unknown(client):
    assert client.delete("/v1/firewall/nat/rules/ghost").status_code == 404


def test_status_includes_nat_rule_count(client):
    client.post("/v1/firewall/nat/rules", json={
        "name": "masq", "type": "masquerade", "chain": "postrouting"
    })
    status = client.get("/v1/firewall/status").json()
    assert status["nat_rules"] == 1


def test_nat_rule_survives_reload(tmp_path):
    client1 = TestClient(_make_app(tmp_path))
    data = client1.post("/v1/firewall/nat/rules", json={
        "name": "persist-nat", "type": "masquerade", "chain": "postrouting", "out_interface": "eth0"
    }).json()
    r = TestClient(_make_app(tmp_path)).get(f"/v1/firewall/nat/rules/{data['id']}")
    assert r.status_code == 200
    assert r.json()["out_interface"] == "eth0"


# ── NAT compiler expressions ──

def test_masquerade_compiles():
    mod = _load_module()
    from _nft.compiler import _nat_rule_to_nft_expr
    rule = mod.NatRule(name="masq", type="masquerade", chain="postrouting", out_interface="eth0")
    expr = _nat_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "masquerade" in expr
    assert 'oif "eth0"' in expr


def test_snat_compiles_to_address():
    mod = _load_module()
    from _nft.compiler import _nat_rule_to_nft_expr
    rule = mod.NatRule(name="snat-out", type="snat", chain="postrouting",
                       to_address="203.0.113.1")
    expr = _nat_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "snat to 203.0.113.1" in expr


def test_dnat_compiles_to_address_port():
    mod = _load_module()
    from _nft.compiler import _nat_rule_to_nft_expr
    rule = mod.NatRule(name="dnat-http", type="dnat", chain="prerouting",
                       to_address="192.168.1.10", to_port=8080, protocol="tcp", dst_port=80)
    expr = _nat_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "dnat to 192.168.1.10:8080" in expr


def test_redirect_to_port_compiles():
    mod = _load_module()
    from _nft.compiler import _nat_rule_to_nft_expr
    rule = mod.NatRule(name="redir", type="redirect", chain="prerouting",
                       protocol="tcp", dst_port=80, to_port=3128)
    expr = _nat_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "redirect to 3128" in expr


def test_snat_without_to_address_skipped():
    mod = _load_module()
    from _nft.compiler import _nat_rule_to_nft_expr
    rule = mod.NatRule(name="bad-snat", type="snat", chain="postrouting")
    expr = _nat_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is None


def test_dnat_without_to_address_skipped():
    mod = _load_module()
    from _nft.compiler import _nat_rule_to_nft_expr
    rule = mod.NatRule(name="bad-dnat", type="dnat", chain="prerouting")
    expr = _nat_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is None


def test_nat_rule_in_compiled_script(client):
    client.post("/v1/firewall/nat/rules", json={
        "name": "masq-wan", "type": "masquerade", "chain": "postrouting",
        "out_interface": "eth0", "enabled": True
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    # postrouting chain emitted
    assert any("postrouting" in line for line in output)
    # masquerade rule present
    assert any("masquerade" in line and "oif" in line for line in output)


def test_nat_rule_nat_rule_id_comment_in_script(client):
    data = client.post("/v1/firewall/nat/rules", json={
        "name": "nat-annotated", "type": "masquerade", "chain": "postrouting"
    }).json()
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any(f"nat_rule_id: {data['id']}" in line for line in output)


def test_nat_prerouting_chain_emitted_for_dnat(client):
    client.post("/v1/firewall/nat/rules", json={
        "name": "dnat-http", "type": "dnat", "chain": "prerouting",
        "protocol": "tcp", "dst_port": 80,
        "to_address": "192.168.1.10", "to_port": 8080
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("prerouting" in line for line in output)


def test_disabled_nat_rule_not_in_script(client):
    client.post("/v1/firewall/nat/rules", json={
        "name": "off-masq", "type": "masquerade", "chain": "postrouting",
        "out_interface": "eth0", "enabled": False
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert not any("postrouting" in line and "type nat" in line for line in output)


def test_nat_rule_flags_compiled(client):
    client.post("/v1/firewall/nat/rules", json={
        "name": "masq-rand", "type": "masquerade", "chain": "postrouting",
        "flags": ["random"]
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("random" in line for line in output)


# ---------------------------------------------------------------------------
# Ingress rules — netdev family (§11)
# ---------------------------------------------------------------------------

def test_list_ingress_rules_empty_initially(client):
    r = client.get("/v1/firewall/ingress/rules")
    assert r.status_code == 200
    data = r.json()
    assert data["ingress_rules"] == []
    assert data["count"] == 0


def test_create_ingress_rule_returns_201(client):
    r = client.post("/v1/firewall/ingress/rules", json={
        "name": "block-bogons", "device": "eth0", "action": "deny",
        "src_address": "192.168.0.0/16"
    })
    assert r.status_code == 201


def test_create_ingress_rule_stores_fields(client):
    data = client.post("/v1/firewall/ingress/rules", json={
        "name": "block-bogons", "device": "eth0", "action": "deny",
        "src_address": "10.0.0.0/8", "priority": 5, "comment": "RFC1918 block",
    }).json()
    assert data["name"] == "block-bogons"
    assert data["device"] == "eth0"
    assert data["action"] == "deny"
    assert data["src_address"] == "10.0.0.0/8"
    assert data["priority"] == 5
    assert "id" in data


def test_create_ingress_rule_applied_false(client):
    data = client.post("/v1/firewall/ingress/rules", json={
        "name": "r", "device": "eth0"
    }).json()
    assert data["applied"] is False


def test_create_ingress_rule_duplicate_returns_409(client):
    body = {"name": "r", "device": "eth0", "action": "deny"}
    client.post("/v1/firewall/ingress/rules", json=body)
    r = client.post("/v1/firewall/ingress/rules", json=body)
    assert r.status_code == 409


def test_get_ingress_rule_by_id(client):
    data = client.post("/v1/firewall/ingress/rules", json={"name": "findme", "device": "eth0"}).json()
    r = client.get(f"/v1/firewall/ingress/rules/{data['id']}")
    assert r.status_code == 200
    assert r.json()["name"] == "findme"


def test_get_ingress_rule_404_unknown(client):
    assert client.get("/v1/firewall/ingress/rules/ghost").status_code == 404


def test_update_ingress_rule(client):
    data = client.post("/v1/firewall/ingress/rules", json={"name": "old", "device": "eth0"}).json()
    updated = client.put(f"/v1/firewall/ingress/rules/{data['id']}", json={"name": "new"}).json()
    assert updated["name"] == "new"


def test_delete_ingress_rule(client):
    data = client.post("/v1/firewall/ingress/rules", json={"name": "gone", "device": "eth0"}).json()
    r = client.delete(f"/v1/firewall/ingress/rules/{data['id']}")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get(f"/v1/firewall/ingress/rules/{data['id']}").status_code == 404


def test_delete_ingress_rule_404_unknown(client):
    assert client.delete("/v1/firewall/ingress/rules/ghost").status_code == 404


def test_status_includes_ingress_rule_count(client):
    client.post("/v1/firewall/ingress/rules", json={"name": "r1", "device": "eth0"})
    assert client.get("/v1/firewall/status").json()["ingress_rules"] == 1


def test_ingress_rule_survives_reload(tmp_path):
    client1 = TestClient(_make_app(tmp_path))
    data = client1.post("/v1/firewall/ingress/rules", json={
        "name": "persist-ingress", "device": "eth0", "src_address": "1.2.3.4"
    }).json()
    r = TestClient(_make_app(tmp_path)).get(f"/v1/firewall/ingress/rules/{data['id']}")
    assert r.status_code == 200
    assert r.json()["src_address"] == "1.2.3.4"


def test_ingress_rule_in_compiled_script(client):
    client.post("/v1/firewall/ingress/rules", json={
        "name": "block-bogons", "device": "eth0", "action": "deny",
        "src_address": "10.0.0.0/8"
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add table netdev" in line for line in output)
    assert any("ff_ingress" in line for line in output)
    assert any("eth0_in" in line for line in output)
    assert any("ip saddr 10.0.0.0/8" in line for line in output)


def test_ingress_rule_separate_from_inet_table(client):
    client.post("/v1/firewall/ingress/rules", json={"name": "r", "device": "eth0"})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    # netdev table is separate from inet table
    assert any("add table inet fw" in line for line in output)
    assert any("add table netdev ff_ingress" in line for line in output)


def test_ingress_netdev_chain_has_ingress_hook(client):
    client.post("/v1/firewall/ingress/rules", json={"name": "r", "device": "eth0"})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("hook ingress device eth0" in line for line in output)


def test_ingress_rules_per_device(client):
    client.post("/v1/firewall/ingress/rules", json={"name": "r1", "device": "eth0", "action": "deny"})
    client.post("/v1/firewall/ingress/rules", json={"name": "r2", "device": "eth1", "action": "deny"})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("eth0_in" in line for line in output)
    assert any("eth1_in" in line for line in output)


def test_ingress_rule_id_in_compiled_script(client):
    data = client.post("/v1/firewall/ingress/rules", json={
        "name": "annotated-ingress", "device": "eth0"
    }).json()
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any(f"ingress_rule_id: {data['id']}" in line for line in output)


def test_disabled_ingress_rule_not_in_script(client):
    client.post("/v1/firewall/ingress/rules", json={
        "name": "off", "device": "eth0", "enabled": False
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert not any("add table netdev" in line for line in output)


def test_discard_restores_ingress_rules(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    client.post("/v1/firewall/ingress/rules", json={"name": "pending-ingress", "device": "eth0"})
    assert client.get("/v1/firewall/ingress/rules").json()["count"] == 1
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/ingress/rules").json()["count"] == 0


# ── ingress compiler expression ──

def test_ingress_rule_compiles_address_match():
    mod = _load_module()
    from _nft.compiler import _ingress_rule_to_nft_expr
    rule = mod.IngressRule(name="r", device="eth0", action="deny", src_address="1.2.3.0/24")
    expr = _ingress_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "ip saddr 1.2.3.0/24" in expr
    assert "drop" in expr


def test_ingress_rule_compiles_rate_limit():
    mod = _load_module()
    from _nft.compiler import _ingress_rule_to_nft_expr
    rule = mod.IngressRule(name="r", device="eth0", action="deny",
                           rate_limit=RateLimit(rate=100, unit="second", over=True))
    expr = _ingress_rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "limit rate over 100/second" in expr


# ---------------------------------------------------------------------------
# Custom chains and jump targets (§10)
# ---------------------------------------------------------------------------

def test_list_custom_chains_empty_initially(client):
    r = client.get("/v1/firewall/custom-chains")
    assert r.status_code == 200
    data = r.json()
    assert data["custom_chains"] == []
    assert data["count"] == 0


def test_create_custom_chain_returns_201(client):
    r = client.post("/v1/firewall/custom-chains", json={"name": "validate_tcp"})
    assert r.status_code == 201


def test_create_custom_chain_stores_fields(client):
    data = client.post("/v1/firewall/custom-chains", json={
        "name": "validate_tcp",
        "comment": "TCP validity checks",
    }).json()
    assert data["name"] == "validate_tcp"
    assert data["comment"] == "TCP validity checks"


def test_create_custom_chain_duplicate_returns_409(client):
    client.post("/v1/firewall/custom-chains", json={"name": "dup"})
    r = client.post("/v1/firewall/custom-chains", json={"name": "dup"})
    assert r.status_code == 409


def test_create_custom_chain_conflicts_with_hook_chain_returns_409(client):
    r = client.post("/v1/firewall/custom-chains", json={"name": "input"})
    assert r.status_code == 409


def test_get_custom_chain_by_name(client):
    client.post("/v1/firewall/custom-chains", json={"name": "findme"})
    r = client.get("/v1/firewall/custom-chains/findme")
    assert r.status_code == 200
    assert r.json()["name"] == "findme"


def test_get_custom_chain_404_unknown(client):
    assert client.get("/v1/firewall/custom-chains/ghost").status_code == 404


def test_delete_custom_chain(client):
    client.post("/v1/firewall/custom-chains", json={"name": "gone"})
    r = client.delete("/v1/firewall/custom-chains/gone")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get("/v1/firewall/custom-chains/gone").status_code == 404


def test_delete_custom_chain_404_unknown(client):
    assert client.delete("/v1/firewall/custom-chains/ghost").status_code == 404


def test_status_includes_custom_chain_count(client):
    client.post("/v1/firewall/custom-chains", json={"name": "cc1"})
    assert client.get("/v1/firewall/status").json()["custom_chains"] == 1


def test_custom_chain_compiled_to_add_chain(client):
    client.post("/v1/firewall/custom-chains", json={"name": "validate_tcp"})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add chain inet fw validate_tcp" in line for line in output)


def test_custom_chain_has_no_hook_in_declaration(client):
    client.post("/v1/firewall/custom-chains", json={"name": "validate_tcp"})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    chain_lines = [l for l in output if "add chain inet fw validate_tcp" in l]
    assert len(chain_lines) == 1
    assert "hook" not in chain_lines[0]


def test_jump_action_compiles_to_jump_target():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", chain="input", action="jump", jump_target="validate_tcp")
    chains = _default_chains(mod)
    custom = {"validate_tcp": mod.CustomChain(name="validate_tcp")}
    script = mod._compile_to_script([rule], "fw", chains, logging.getLogger("test"),
                                    custom_chains=custom)
    assert "jump validate_tcp" in script


def test_return_action_compiles_to_return():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", chain="input", action="return")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert expr.endswith("return")


def test_jump_without_target_skips_rule():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", chain="input", action="jump")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is None


def test_rule_targeting_custom_chain_compiled():
    mod = _load_module()
    chains = _default_chains(mod)
    custom = {"validate_tcp": mod.CustomChain(name="validate_tcp")}
    # A rule placed inside the custom chain
    rule = mod.FirewallRule(name="drop-invalid-tcp", chain="validate_tcp", action="deny",
                            protocol="tcp", tcp_flags=["syn", "fin"])
    script = mod._compile_to_script([rule], "fw", chains, logging.getLogger("test"),
                                    custom_chains=custom)
    assert "fw validate_tcp" in script


def test_rule_targeting_unknown_chain_skipped():
    mod = _load_module()
    chains = _default_chains(mod)
    rule = mod.FirewallRule(name="r", chain="nonexistent", action="accept")
    script = mod._compile_to_script([rule], "fw", chains, logging.getLogger("test"))
    assert "nonexistent" not in script


def test_custom_chain_survives_reload(tmp_path):
    client1 = TestClient(_make_app(tmp_path))
    client1.post("/v1/firewall/custom-chains", json={"name": "persist_chain"})
    r = TestClient(_make_app(tmp_path)).get("/v1/firewall/custom-chains/persist_chain")
    assert r.status_code == 200


def test_discard_restores_custom_chains(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    client.post("/v1/firewall/custom-chains", json={"name": "pending_chain"})
    assert client.get("/v1/firewall/custom-chains").json()["count"] == 1
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/custom-chains").json()["count"] == 0


def test_rule_chain_field_accepts_custom_chain_name(client):
    client.post("/v1/firewall/custom-chains", json={"name": "validate_tcp"})
    data = _create_rule(client, name="check-tcp", chain="validate_tcp", action="deny",
                        protocol="tcp")
    assert data["chain"] == "validate_tcp"


# ---------------------------------------------------------------------------
# Counters (§8)
# ---------------------------------------------------------------------------

def test_create_rule_with_counter_name(client):
    data = _create_rule(client, name="counted-ssh", protocol="tcp", dst_port=22,
                        action="accept", counter_name="ssh_counter")
    assert data["counter_name"] == "ssh_counter"


def test_counter_name_defaults_none(client):
    data = _create_rule(client, name="uncounted")
    assert data["counter_name"] is None


def test_counter_compiles_to_counter_name_expr():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", protocol="tcp", dst_port=22,
                            counter_name="ssh_counter")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert "counter name ssh_counter" in expr


def test_counter_comes_before_verdict():
    mod = _load_module()
    rule = mod.FirewallRule(name="r", action="accept", counter_name="my_counter")
    expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr is not None
    assert expr.index("counter name") < expr.index("accept")


def test_counter_declaration_in_compiled_script(client):
    _create_rule(client, name="counted", action="accept", protocol="tcp", dst_port=80,
                 counter_name="http_traffic")
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add counter inet fw http_traffic" in line for line in output)


def test_counter_declaration_appears_before_chains(client):
    _create_rule(client, name="counted", action="accept", protocol="tcp", dst_port=80,
                 counter_name="http_traffic")
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    counter_idx = next(i for i, l in enumerate(output) if "add counter inet fw http_traffic" in l)
    chain_idx = next(i for i, l in enumerate(output) if "add chain inet fw input" in l)
    assert counter_idx < chain_idx


def test_multiple_rules_same_counter_declared_once(client):
    _create_rule(client, name="r1", action="accept", protocol="tcp", dst_port=80,
                 counter_name="web_traffic")
    _create_rule(client, name="r2", action="accept", protocol="tcp", dst_port=443,
                 counter_name="web_traffic")
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    counter_lines = [l for l in output if "add counter inet fw web_traffic" in l]
    assert len(counter_lines) == 1


def test_counter_survives_reload(tmp_path):
    rule = _create_rule(TestClient(_make_app(tmp_path)), name="counted-reload",
                        counter_name="persist_counter")
    r = TestClient(_make_app(tmp_path)).get(f"/v1/firewall/rules/{rule['id']}")
    assert r.status_code == 200
    assert r.json()["counter_name"] == "persist_counter"


def test_list_counters_returns_500_without_root(tmp_path):
    inst, _ = _make_inst(tmp_path)
    inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    r = TestClient(app).get("/v1/firewall/counters")
    assert r.status_code == 500


def test_reset_counter_returns_500_without_root(tmp_path):
    inst, _ = _make_inst(tmp_path)
    inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    r = TestClient(app).post("/v1/firewall/counters/ssh_counter/reset")
    assert r.status_code == 500


# ---------------------------------------------------------------------------
# Flowtables (§7)
# ---------------------------------------------------------------------------

def test_list_flowtables_empty_initially(client):
    r = client.get("/v1/firewall/flowtables")
    assert r.status_code == 200
    data = r.json()
    assert data["flowtables"] == []
    assert data["count"] == 0


def test_create_flowtable_returns_201(client):
    r = client.post("/v1/firewall/flowtables", json={
        "name": "forward_fast",
        "devices": ["eth0", "eth1"],
    })
    assert r.status_code == 201


def test_create_flowtable_stores_fields(client):
    data = client.post("/v1/firewall/flowtables", json={
        "name": "forward_fast",
        "priority": 5,
        "devices": ["eth0", "eth1"],
        "offload_forward": True,
        "comment": "WAN+LAN fastpath",
    }).json()
    assert data["name"] == "forward_fast"
    assert data["priority"] == 5
    assert "eth0" in data["devices"]
    assert "eth1" in data["devices"]
    assert data["offload_forward"] is True
    assert data["comment"] == "WAN+LAN fastpath"


def test_create_flowtable_duplicate_returns_409(client):
    client.post("/v1/firewall/flowtables", json={"name": "dup", "devices": ["eth0"]})
    r = client.post("/v1/firewall/flowtables", json={"name": "dup", "devices": ["eth0"]})
    assert r.status_code == 409


def test_get_flowtable_by_name(client):
    client.post("/v1/firewall/flowtables", json={"name": "ft1", "devices": ["eth0"]})
    r = client.get("/v1/firewall/flowtables/ft1")
    assert r.status_code == 200
    assert r.json()["name"] == "ft1"


def test_get_flowtable_404_unknown(client):
    assert client.get("/v1/firewall/flowtables/ghost").status_code == 404


def test_delete_flowtable(client):
    client.post("/v1/firewall/flowtables", json={"name": "gone", "devices": ["eth0"]})
    r = client.delete("/v1/firewall/flowtables/gone")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get("/v1/firewall/flowtables/gone").status_code == 404


def test_delete_flowtable_404_unknown(client):
    assert client.delete("/v1/firewall/flowtables/ghost").status_code == 404


def test_status_includes_flowtable_count(client):
    client.post("/v1/firewall/flowtables", json={"name": "ft1", "devices": ["eth0"]})
    assert client.get("/v1/firewall/status").json()["flowtables"] == 1


def test_flowtable_survives_reload(tmp_path):
    client1 = TestClient(_make_app(tmp_path))
    client1.post("/v1/firewall/flowtables", json={"name": "persist_ft", "devices": ["eth0", "eth1"]})
    r = TestClient(_make_app(tmp_path)).get("/v1/firewall/flowtables/persist_ft")
    assert r.status_code == 200
    assert "eth0" in r.json()["devices"]


def test_flowtable_compiled_to_add_flowtable_statement(client):
    client.post("/v1/firewall/flowtables", json={"name": "forward_fast", "devices": ["eth0", "eth1"]})
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add flowtable inet fw forward_fast" in line for line in output)
    assert any("eth0" in line and "eth1" in line for line in output)


def test_flowtable_offload_injects_flow_rule(client):
    client.post("/v1/firewall/flowtables", json={
        "name": "forward_fast", "devices": ["eth0"], "offload_forward": True
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("fw forward flow add @forward_fast" in line for line in output)


def test_flowtable_no_offload_does_not_inject_flow_rule(client):
    client.post("/v1/firewall/flowtables", json={
        "name": "manual_ft", "devices": ["eth0"], "offload_forward": False
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert not any("flow add @manual_ft" in line for line in output)


def test_flowtable_flow_rule_before_preamble(client):
    client.post("/v1/firewall/flowtables", json={
        "name": "forward_fast", "devices": ["eth0"], "offload_forward": True
    })
    output = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    flow_idx = next(i for i, l in enumerate(output) if "flow add @forward_fast" in l)
    ct_idx = next(i for i, l in enumerate(output) if "fw forward ct state" in l)
    assert flow_idx < ct_idx


def test_discard_restores_flowtables(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    client.post("/v1/firewall/flowtables", json={"name": "pending_ft", "devices": ["eth0"]})
    assert client.get("/v1/firewall/flowtables").json()["count"] == 1
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/flowtables").json()["count"] == 0


def test_discard_restores_nat_rules(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    client = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        client.post("/v1/firewall/apply")
    # Add a NAT rule after apply
    client.post("/v1/firewall/nat/rules", json={
        "name": "pending-nat", "type": "masquerade", "chain": "postrouting"
    })
    assert client.get("/v1/firewall/nat/rules").json()["count"] == 1
    # Discard should remove the pending NAT rule
    client.post("/v1/firewall/discard")
    assert client.get("/v1/firewall/nat/rules").json()["count"] == 0


# ---------------------------------------------------------------------------
# §12 Verdict maps
# ---------------------------------------------------------------------------

def test_list_verdict_maps_empty_initially(client):
    r = client.get("/v1/firewall/maps")
    assert r.status_code == 200
    assert r.json() == {"verdict_maps": [], "count": 0}


def test_create_verdict_map_returns_201(client):
    r = client.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "dispatch"
    assert data["key_type"] == "inet_service"
    assert data["entries"] == []


def test_create_verdict_map_stores_fields(client):
    client.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service",
        "flags": ["interval"],
        "comment": "port dispatch map",
        "entries": [
            {"key": "22", "verdict": "accept"},
            {"key": "80", "verdict": "jump", "jump_target": "http_chain"},
        ],
    })
    r = client.get("/v1/firewall/maps/dispatch")
    assert r.status_code == 200
    data = r.json()
    assert data["flags"] == ["interval"]
    assert data["comment"] == "port dispatch map"
    assert len(data["entries"]) == 2
    assert data["entries"][0] == {"key": "22", "verdict": "accept", "jump_target": None}
    assert data["entries"][1] == {"key": "80", "verdict": "jump", "jump_target": "http_chain"}


def test_create_verdict_map_duplicate_returns_409(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    r = client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    assert r.status_code == 409


def test_get_verdict_map_404_unknown(client):
    r = client.get("/v1/firewall/maps/nonexistent")
    assert r.status_code == 404


def test_delete_verdict_map(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    r = client.delete("/v1/firewall/maps/dispatch")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get("/v1/firewall/maps/dispatch").status_code == 404


def test_delete_verdict_map_404_unknown(client):
    r = client.delete("/v1/firewall/maps/nonexistent")
    assert r.status_code == 404


def test_add_verdict_map_entries(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    r = client.post("/v1/firewall/maps/dispatch/entries", json={
        "entries": [
            {"key": "80", "verdict": "jump", "jump_target": "http_chain"},
            {"key": "443", "verdict": "jump", "jump_target": "https_chain"},
        ]
    })
    assert r.status_code == 200
    data = r.json()
    assert len(data["entries"]) == 2


def test_add_verdict_map_entries_deduplicates_by_key(client):
    client.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service",
        "entries": [{"key": "80", "verdict": "accept"}],
    })
    r = client.post("/v1/firewall/maps/dispatch/entries", json={
        "entries": [{"key": "80", "verdict": "drop"}]  # same key, different verdict
    })
    assert r.status_code == 200
    # original entry is kept because key already exists
    assert len(r.json()["entries"]) == 1
    assert r.json()["entries"][0]["verdict"] == "accept"


def test_remove_verdict_map_entries(client):
    client.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service",
        "entries": [
            {"key": "80", "verdict": "accept"},
            {"key": "443", "verdict": "drop"},
        ],
    })
    r = client.request("DELETE", "/v1/firewall/maps/dispatch/entries", json={"keys": ["80"]})
    assert r.status_code == 200
    data = r.json()
    assert len(data["entries"]) == 1
    assert data["entries"][0]["key"] == "443"


def test_verdict_map_entries_404_on_unknown_map(client):
    r = client.post("/v1/firewall/maps/nomap/entries", json={"entries": []})
    assert r.status_code == 404
    r2 = client.request("DELETE", "/v1/firewall/maps/nomap/entries", json={"keys": []})
    assert r2.status_code == 404


def test_status_includes_verdict_maps_count(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    s = client.get("/v1/firewall/status").json()
    assert s["verdict_maps"] == 1


def test_verdict_map_survives_reload(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    c.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service",
        "entries": [{"key": "80", "verdict": "accept"}],
    })
    # Reload from disk
    inst2, mod2 = _make_inst(tmp_path)
    inst2._apply_nft_script = MagicMock()
    with patch.object(mod2, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst2.setup()
    app2 = FastAPI()
    app2.include_router(inst2.router, prefix="/v1/firewall")
    c2 = TestClient(app2)
    r = c2.get("/v1/firewall/maps/dispatch")
    assert r.status_code == 200
    assert r.json()["entries"][0]["key"] == "80"


def test_discard_restores_verdict_maps(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        c.post("/v1/firewall/apply")
    # Add a verdict map after apply
    c.post("/v1/firewall/maps", json={"name": "pending-map", "key_type": "inet_service"})
    assert c.get("/v1/firewall/maps").json()["count"] == 1
    # Discard should remove the pending verdict map
    c.post("/v1/firewall/discard")
    assert c.get("/v1/firewall/maps").json()["count"] == 0


def test_verdict_map_compiled_to_add_map_statement(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    r = client.post("/v1/firewall/compile", json={"filter_name": "fw"})
    lines = r.json()["output"]
    assert any("add map inet fw dispatch" in l for l in lines)
    assert any("inet_service : verdict" in l for l in lines)


def test_verdict_map_elements_emitted_in_compiled_script(client):
    client.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service",
        "entries": [
            {"key": "80", "verdict": "jump", "jump_target": "http_chain"},
            {"key": "22", "verdict": "accept"},
        ],
    })
    r = client.post("/v1/firewall/compile", json={"filter_name": "fw"})
    lines = r.json()["output"]
    element_line = next((l for l in lines if "add element inet fw dispatch" in l), None)
    assert element_line is not None
    assert "80 : jump http_chain" in element_line
    assert "22 : accept" in element_line


def test_verdict_map_flags_included_in_map_declaration(client):
    client.post("/v1/firewall/maps", json={
        "name": "dispatch", "key_type": "inet_service", "flags": ["interval"],
    })
    r = client.post("/v1/firewall/compile", json={"filter_name": "fw"})
    lines = r.json()["output"]
    map_line = next((l for l in lines if "add map inet fw dispatch" in l), None)
    assert map_line is not None
    assert "flags interval" in map_line


def test_verdict_map_declared_before_chains_in_script(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    r = client.post("/v1/firewall/compile", json={"filter_name": "fw"})
    lines = r.json()["output"]
    map_idx = next(i for i, l in enumerate(lines) if "add map" in l)
    chain_idx = next(i for i, l in enumerate(lines) if "add chain" in l)
    assert map_idx < chain_idx


def test_rule_with_dst_port_vmap_field(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    r = client.post("/v1/firewall/rules", json={
        "name": "vmap-dispatch",
        "chain": "input",
        "action": "accept",
        "protocol": "tcp",
        "dst_port_vmap": "dispatch",
    })
    assert r.status_code == 201
    assert r.json()["dst_port_vmap"] == "dispatch"


def test_dst_port_vmap_in_compiled_rule():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(
        name="port-dispatch", chain="input", action="accept",
        protocol="tcp", dst_port_vmap="dispatch",
    )
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr == "tcp dport vmap @dispatch"


def test_src_port_vmap_in_compiled_rule():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(
        name="sport-dispatch", chain="input", action="accept",
        protocol="udp", src_port_vmap="clients",
    )
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr == "udp sport vmap @clients"


def test_vmap_suppresses_normal_dst_port_match():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    # dst_port and dst_port_vmap both set — vmap wins, no literal port in expr
    rule = mod.FirewallRule(
        name="r", chain="input", action="accept",
        protocol="tcp", dst_port=80, dst_port_vmap="dispatch",
    )
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert "80" not in expr
    assert "vmap @dispatch" in expr


def test_vmap_with_address_match_in_compiled_rule():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(
        name="r", chain="input", action="accept",
        protocol="tcp", src_address="192.168.1.0/24", dst_port_vmap="dispatch",
    )
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr == "ip saddr 192.168.1.0/24 tcp dport vmap @dispatch"


def test_vmap_rule_in_compiled_script(client):
    client.post("/v1/firewall/maps", json={"name": "dispatch", "key_type": "inet_service"})
    client.post("/v1/firewall/rules", json={
        "name": "port-dispatch", "chain": "input",
        "action": "accept", "protocol": "tcp", "dst_port_vmap": "dispatch",
    })
    r = client.post("/v1/firewall/compile", json={})
    lines = r.json()["output"]
    assert any("tcp dport vmap @dispatch" in l for l in lines)


# ---------------------------------------------------------------------------
# §9e Meta expressions (mark, dscp, pkttype)
# ---------------------------------------------------------------------------

def test_rule_with_mark_field(client):
    r = client.post("/v1/firewall/rules", json={"name": "mark-rule", "action": "accept", "mark": 42})
    assert r.status_code == 201
    assert r.json()["mark"] == 42


def test_mark_compiles_to_meta_mark():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(name="r", action="accept", mark=42)
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert "meta mark 42" in expr
    assert "accept" in expr


def test_dscp_compiles_to_ip_dscp():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(name="r", action="deny", dscp=16)
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert "ip dscp 16" in expr


def test_dscp_named_value():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(name="r", action="accept", dscp="ef")
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert "ip dscp ef" in expr


def test_pkttype_compiles_to_meta_pkttype():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(name="r", action="deny", pkttype="broadcast")
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert "meta pkttype broadcast" in expr


def test_meta_fields_default_to_none(client):
    r = client.post("/v1/firewall/rules", json={"name": "plain", "action": "accept"})
    data = r.json()
    assert data["mark"] is None
    assert data["dscp"] is None
    assert data["pkttype"] is None


def test_meta_fields_ordering_before_rate_limit():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(
        name="r", action="accept", mark=5,
        rate_limit=RateLimit(rate=10, unit="second"),
    )
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert expr.index("meta mark") < expr.index("limit rate")


# ---------------------------------------------------------------------------
# §8 Quotas
# ---------------------------------------------------------------------------

def test_list_quotas_empty_initially(client):
    r = client.get("/v1/firewall/quotas")
    assert r.status_code == 200
    assert r.json() == {"quotas": [], "count": 0}


def test_create_quota_returns_201(client):
    r = client.post("/v1/firewall/quotas", json={
        "name": "daily_cap", "amount": 1, "unit": "gbytes",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "daily_cap"
    assert data["amount"] == 1
    assert data["unit"] == "gbytes"
    assert data["over"] is False


def test_create_quota_over_flag(client):
    r = client.post("/v1/firewall/quotas", json={
        "name": "cap", "amount": 500, "unit": "mbytes", "over": True,
    })
    assert r.status_code == 201
    assert r.json()["over"] is True


def test_create_quota_duplicate_returns_409(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    r = client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    assert r.status_code == 409


def test_get_quota_by_name(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 100, "unit": "mbytes"})
    r = client.get("/v1/firewall/quotas/cap")
    assert r.status_code == 200
    assert r.json()["amount"] == 100


def test_get_quota_404_unknown(client):
    assert client.get("/v1/firewall/quotas/nope").status_code == 404


def test_delete_quota(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    r = client.delete("/v1/firewall/quotas/cap")
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    assert client.get("/v1/firewall/quotas/cap").status_code == 404


def test_delete_quota_404_unknown(client):
    assert client.delete("/v1/firewall/quotas/nope").status_code == 404


def test_status_includes_quota_count(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    assert client.get("/v1/firewall/status").json()["quotas"] == 1


def test_quota_survives_reload(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    c.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    inst2, mod2 = _make_inst(tmp_path)
    inst2._apply_nft_script = MagicMock()
    with patch.object(mod2, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst2.setup()
    app2 = FastAPI()
    app2.include_router(inst2.router, prefix="/v1/firewall")
    r = TestClient(app2).get("/v1/firewall/quotas/cap")
    assert r.status_code == 200
    assert r.json()["unit"] == "gbytes"


def test_quota_compiled_to_add_quota_statement(client):
    client.post("/v1/firewall/quotas", json={"name": "daily_cap", "amount": 1, "unit": "gbytes"})
    lines = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add quota inet fw daily_cap" in l for l in lines)
    assert any("1 gbytes" in l for l in lines)


def test_quota_over_flag_in_compiled_script(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 500, "unit": "mbytes", "over": True})
    lines = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    assert any("add quota over inet fw cap" in l for l in lines)


def test_quota_declared_before_chains_in_script(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    lines = client.post("/v1/firewall/compile", json={"filter_name": "fw"}).json()["output"]
    quota_idx = next(i for i, l in enumerate(lines) if "add quota" in l)
    chain_idx = next(i for i, l in enumerate(lines) if "add chain" in l)
    assert quota_idx < chain_idx


def test_rule_with_quota_name_field(client):
    client.post("/v1/firewall/quotas", json={"name": "cap", "amount": 1, "unit": "gbytes"})
    r = client.post("/v1/firewall/rules", json={
        "name": "quota-rule", "action": "accept", "quota_name": "cap",
    })
    assert r.status_code == 201
    assert r.json()["quota_name"] == "cap"


def test_quota_name_compiles_to_quota_name_expr():
    mod = _load_module()
    from _nft.compiler import _rule_to_nft_expr
    rule = mod.FirewallRule(name="r", action="accept", quota_name="daily_cap")
    expr = _rule_to_nft_expr(rule, logging.getLogger("test"))
    assert "quota name daily_cap" in expr
    assert "accept" in expr


def test_discard_restores_quotas(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        c.post("/v1/firewall/apply")
    c.post("/v1/firewall/quotas", json={"name": "pending", "amount": 1, "unit": "gbytes"})
    assert c.get("/v1/firewall/quotas").json()["count"] == 1
    c.post("/v1/firewall/discard")
    assert c.get("/v1/firewall/quotas").json()["count"] == 0


# ---------------------------------------------------------------------------
# §13 Per-type pending_changes
# ---------------------------------------------------------------------------

def test_pending_changes_is_dict(client):
    pc = client.get("/v1/firewall/status").json()["pending_changes"]
    assert isinstance(pc, dict)
    assert "any" in pc


def test_pending_changes_keys_present(client):
    pc = client.get("/v1/firewall/status").json()["pending_changes"]
    for key in ["any", "rules", "chains", "sets", "nat_rules", "flowtables",
                "custom_chains", "ingress_rules", "verdict_maps", "quotas"]:
        assert key in pc, f"missing key: {key}"


def test_pending_changes_any_false_when_all_false(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        c.post("/v1/firewall/apply")
    pc = c.get("/v1/firewall/status").json()["pending_changes"]
    assert pc["any"] is False
    assert all(pc[k] is False for k in pc if k != "any")


def test_pending_changes_rules_true_after_rule_add(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        c.post("/v1/firewall/apply")
    c.post("/v1/firewall/rules", json={"name": "new-rule", "action": "accept"})
    pc = c.get("/v1/firewall/status").json()["pending_changes"]
    assert pc["rules"] is True
    assert pc["any"] is True
    # non-dirty types stay False
    assert pc["nat_rules"] is False
    assert pc["sets"] is False


def test_pending_changes_nat_rules_true_after_nat_add(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        c.post("/v1/firewall/apply")
    c.post("/v1/firewall/nat/rules", json={"name": "masq", "type": "masquerade", "chain": "postrouting"})
    pc = c.get("/v1/firewall/status").json()["pending_changes"]
    assert pc["nat_rules"] is True
    assert pc["rules"] is False
    assert pc["any"] is True


def test_pending_changes_in_apply_response(tmp_path):
    inst, mod = _make_inst(tmp_path)
    inst._apply_nft_script = MagicMock()
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        inst.setup()
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/firewall")
    c = TestClient(app)
    with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
        r = c.post("/v1/firewall/apply")
    pc = r.json()["pending_changes"]
    assert isinstance(pc, dict)
    assert pc["any"] is False


# ---------------------------------------------------------------------------
# Macro snapshot
# ---------------------------------------------------------------------------

def test_macro_snapshot_saved_after_apply(tmp_path):
    from plugin_system.core.macros import macro_registry
    macro_registry.set_service_ports({"dns": {"udp": [53]}})
    try:
        inst, mod = _make_inst(tmp_path)
        inst._apply_nft_script = MagicMock()
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst.setup()
        app = FastAPI()
        app.include_router(inst.router, prefix="/v1/firewall")
        c = TestClient(app)
        c.post("/v1/firewall/rules", json={"name": "allow-dns", "protocol": "udp", "dst_port": "$service_port.dns.udp", "action": "accept"})
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            c.post("/v1/firewall/apply")
        snapshot = inst._state_file.get_macro_snapshot()
        assert snapshot is not None
        assert "$service_port.dns.udp" in snapshot
        assert snapshot["$service_port.dns.udp"] == [53]
    finally:
        macro_registry.set_service_ports({})


def test_macro_snapshot_persists_across_reload(tmp_path):
    from plugin_system.core.macros import macro_registry
    macro_registry.set_service_ports({"dns": {"udp": [53]}})
    try:
        inst, mod = _make_inst(tmp_path)
        inst._apply_nft_script = MagicMock()
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst.setup()
        app = FastAPI()
        app.include_router(inst.router, prefix="/v1/firewall")
        c = TestClient(app)
        c.post("/v1/firewall/rules", json={"name": "allow-dns", "protocol": "udp", "dst_port": "$service_port.dns.udp", "action": "accept"})
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            c.post("/v1/firewall/apply")
        # Reload plugin from the same tmp_path
        inst2, mod2 = _make_inst(tmp_path)
        inst2._apply_nft_script = MagicMock()
        with patch.object(mod2, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst2.setup()
        snapshot = inst2._state_file.get_macro_snapshot()
        assert snapshot is not None
        assert snapshot.get("$service_port.dns.udp") == [53]
    finally:
        macro_registry.set_service_ports({})


def test_plugins_all_loaded_reapplies_when_macro_changed(tmp_path):
    from plugin_system.core.macros import macro_registry
    # service_port macros are NOT populated during setup() — this mirrors real boot order,
    # where the loader sets service_ports only after all plugins finish loading.
    macro_registry.set_service_ports({})
    try:
        (tmp_path / "data").mkdir()
        state = {
            "desired_state": {
                "rules": [{"id": "m1", "name": "allow-dns", "action": "accept", "protocol": "udp", "dst_port": "$service_port.dns.udp"}],
                "chains": _BOOT_CHAINS,
                "sets": {}, "nat_rules": [], "flowtables": {}, "custom_chains": {}, "ingress_rules": [], "verdict_maps": {}, "quotas": {},
            },
        }
        (tmp_path / "data" / "rules.json").write_text(json.dumps(state))
        inst, mod = _make_inst(tmp_path)
        inst._apply_nft_script = MagicMock()
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst.setup()
        # After setup, snapshot has [] for the dns macro (service_port not populated)
        assert inst._state_file.get_macro_snapshot() == {"$service_port.dns.udp": []}
        call_count_after_setup = inst._apply_nft_script.call_count
        # Now service_ports are populated — as plugins.all_loaded timing implies
        macro_registry.set_service_ports({"dns": {"udp": [53]}})
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst._on_plugins_loaded(Event("plugins.all_loaded", payload={}))
        # Snapshot changed [] → [53] so a re-apply must have occurred
        assert inst._apply_nft_script.call_count > call_count_after_setup
    finally:
        macro_registry.set_service_ports({})


def test_plugins_all_loaded_skips_reapply_when_macro_unchanged(tmp_path):
    from plugin_system.core.macros import macro_registry
    # service_port macros populated before setup — snapshot saved as [53]
    macro_registry.set_service_ports({"dns": {"udp": [53]}})
    try:
        (tmp_path / "data").mkdir()
        state = {
            "desired_state": {
                "rules": [{"id": "m1", "name": "allow-dns", "action": "accept", "protocol": "udp", "dst_port": "$service_port.dns.udp"}],
                "chains": _BOOT_CHAINS,
                "sets": {}, "nat_rules": [], "flowtables": {}, "custom_chains": {}, "ingress_rules": [], "verdict_maps": {}, "quotas": {},
            },
        }
        (tmp_path / "data" / "rules.json").write_text(json.dumps(state))
        inst, mod = _make_inst(tmp_path)
        inst._apply_nft_script = MagicMock()
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst.setup()
        # Snapshot now holds [53] — matches current registry
        assert inst._state_file.get_macro_snapshot() == {"$service_port.dns.udp": [53]}
        call_count_after_setup = inst._apply_nft_script.call_count
        # Macros unchanged — no re-apply expected
        with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
            inst._on_plugins_loaded(Event("plugins.all_loaded", payload={}))
        assert inst._apply_nft_script.call_count == call_count_after_setup
    finally:
        macro_registry.set_service_ports({})


# ---------------------------------------------------------------------------
# Address macro resolution in compiler
# ---------------------------------------------------------------------------

def test_src_address_macro_resolves_to_ip_saddr():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.register_namespace("interface", lambda *s: ["192.168.1.0/24"] if s == ("lan", "net_addr") else None)
    try:
        rule = mod.FirewallRule(name="lan-ssh", action="accept", protocol="tcp",
                                src_address="$interface.lan.net_addr", dst_port=22)
        expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
        assert expr is not None
        assert "ip saddr 192.168.1.0/24" in expr
    finally:
        macro_registry.unregister_namespace("interface")


def test_dst_address_macro_resolves_to_ip_daddr():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.register_namespace("interface", lambda *s: ["10.0.0.0/8"] if s == ("wan", "net_addr") else None)
    try:
        rule = mod.FirewallRule(name="fwd-to-wan", action="accept",
                                dst_address="$interface.wan.net_addr")
        expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
        assert expr is not None
        assert "ip daddr 10.0.0.0/8" in expr
    finally:
        macro_registry.unregister_namespace("interface")


def test_src_address_macro_multiple_addrs_produces_inline_set():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.register_namespace("interface", lambda *s: ["192.168.1.0/24", "10.0.0.0/8"] if s == ("lan", "net_addr") else None)
    try:
        rule = mod.FirewallRule(name="multi-lan", action="accept",
                                src_address="$interface.lan.net_addr")
        expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
        assert expr is not None
        assert "ip saddr { 192.168.1.0/24, 10.0.0.0/8 }" in expr
    finally:
        macro_registry.unregister_namespace("interface")


def test_src_address_macro_unresolved_skips_rule():
    from plugin_system.core.macros import macro_registry
    mod = _load_module()
    macro_registry.register_namespace("interface", lambda *s: None)
    try:
        rule = mod.FirewallRule(name="missing-iface", action="accept",
                                src_address="$interface.lan.net_addr")
        expr = mod._rule_to_nft_expr(rule, logging.getLogger("test"))
        assert expr is None
    finally:
        macro_registry.unregister_namespace("interface")
