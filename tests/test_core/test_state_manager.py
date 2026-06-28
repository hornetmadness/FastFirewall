import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from infra.state_manager import PluginStateFile


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_state(tmp_path: Path, **kwargs) -> PluginStateFile:
    return PluginStateFile(
        tmp_path / "state.json",
        plugin_version="1.0.0",
        **kwargs,
    )


# ── desired_meta written on save_desired ──────────────────────────────────────

def test_save_desired_writes_desired_meta(tmp_path):
    sf = _make_state(tmp_path, mutation_model="deferred")
    sf.load_desired(default={})

    fixed_ts = 1750000000
    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = fixed_ts
        sf.save_desired({"x": 1})

    raw = json.loads((tmp_path / "state.json").read_text())
    assert raw["desired_meta"]["version"] == fixed_ts
    assert raw["desired_meta"]["plugin_version"] == "1.0.0"
    assert raw["desired_meta"]["updated_at"] == _iso(fixed_ts)


def test_save_desired_version_persists_across_reload(tmp_path):
    sf = _make_state(tmp_path, mutation_model="deferred")
    sf.load_desired(default={})

    fixed_ts = 1750000000
    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = fixed_ts
        sf.save_desired({"x": 1})

    sf2 = _make_state(tmp_path, mutation_model="deferred")
    sf2.load_desired(default={})
    assert sf2._desired_version == fixed_ts
    assert sf2._desired_updated_at == _iso(fixed_ts)


# ── current_meta written on commit ───────────────────────────────────────────

def test_commit_writes_current_meta(tmp_path):
    sf = _make_state(tmp_path, mutation_model="deferred")
    sf.load_desired(default={})

    desired_ts = 1750000000
    commit_ts = 1750000010
    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = desired_ts
        sf.save_desired({"x": 1})
        mock_time.time.return_value = commit_ts
        sf.commit()

    raw = json.loads((tmp_path / "state.json").read_text())
    assert raw["current_meta"]["version"] == commit_ts
    assert raw["current_meta"]["plugin_version"] == "1.0.0"
    assert raw["current_meta"]["applied_at"] == _iso(commit_ts)


def test_commit_version_persists_across_reload(tmp_path):
    sf = _make_state(tmp_path, mutation_model="deferred")
    sf.load_desired(default={})

    commit_ts = 1750000010
    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = 1750000000
        sf.save_desired({"x": 1})
        mock_time.time.return_value = commit_ts
        sf.commit()

    sf2 = _make_state(tmp_path, mutation_model="deferred")
    sf2.load_desired(default={})
    assert sf2._current_version == commit_ts


# ── save_and_commit uses one timestamp for both ───────────────────────────────

def test_save_and_commit_sets_both_versions(tmp_path):
    sf = _make_state(tmp_path, mutation_model="deferred")
    sf.load_desired(default={})

    fixed_ts = 1750000000
    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = fixed_ts
        sf.save_and_commit({"x": 1})

    raw = json.loads((tmp_path / "state.json").read_text())
    assert raw["desired_meta"]["version"] == fixed_ts
    assert raw["current_meta"]["version"] == fixed_ts
    assert raw["desired_meta"]["updated_at"] == raw["current_meta"]["applied_at"]


# ── immediate model auto-commits version into current_meta ────────────────────

def test_immediate_model_auto_commits_version(tmp_path):
    sf = _make_state(tmp_path, mutation_model="immediate")
    sf.load_desired(default={})

    fixed_ts = 1750000000
    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = fixed_ts
        sf.save_desired({"x": 1})

    raw = json.loads((tmp_path / "state.json").read_text())
    assert raw["desired_meta"]["version"] == fixed_ts
    assert raw["current_meta"]["version"] == fixed_ts
    assert raw["desired_meta"]["updated_at"] == raw["current_meta"]["applied_at"]


# ── fresh file defaults to version=0 ─────────────────────────────────────────

def test_fresh_file_versions_default_to_zero(tmp_path):
    sf = _make_state(tmp_path, mutation_model="deferred")
    sf.load_desired(default={})

    raw = json.loads((tmp_path / "state.json").read_text())
    assert raw["desired_meta"]["version"] == 0
    assert raw["current_meta"]["version"] == 0
    assert sf._desired_version == 0
    assert sf._current_version == 0


# ── backward compat: legacy file with no meta loads cleanly ──────────────────

def test_legacy_file_without_meta_loads_cleanly(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "desired_state": {"rules": []},
        "current_state": {"rules": []},
    }))

    sf = _make_state(tmp_path, mutation_model="deferred")
    desired = sf.load_desired(default={})

    assert desired == {"rules": []}
    assert sf._desired_version == 0
    assert sf._current_version == 0
    assert sf._desired_updated_at is None
    assert sf._current_applied_at is None


# ── meta does not leak into desired_state or current_state ───────────────────

def test_meta_not_inside_desired_or_current_state(tmp_path):
    sf = _make_state(tmp_path, mutation_model="immediate")
    sf.load_desired(default={"rules": []})

    with patch("infra.state_manager.time") as mock_time:
        mock_time.time.return_value = 1750000000
        sf.save_desired({"rules": [{"id": "abc"}]})

    raw = json.loads((tmp_path / "state.json").read_text())
    assert "version" not in raw["desired_state"]
    assert "plugin_version" not in raw["desired_state"]
    assert "version" not in raw["current_state"]
    assert "plugin_version" not in raw["current_state"]
