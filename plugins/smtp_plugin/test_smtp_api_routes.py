"""
Tests for the SMTP plugin routes (/v1/smtp/*).

The plugin is loaded via importlib (same as PluginLoader) with subprocess and
smtplib interactions replaced by mocks so Postfix does not need to be installed.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugin_system.core.events import Event, bus as global_bus

PLUGIN_PY = Path(__file__).parent / "plugin.py"


# ── helpers ─────────────────────────────────────────────────────────────────────

def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


_POSTFIX_RUNNING = _proc(0, "postfix/postfix-script: the Postfix mail system is running", "")
_POSTFIX_STOPPED = _proc(1, "", "postfix/postfix-script: the Postfix mail system is not running")
_MAILQ_EMPTY = _proc(0, "Mail queue is empty", "")
_MAILQ_ONE = _proc(
    0,
    "ABC123456789     1234 Mon May 11 10:00:00  sender@example.com\n"
    "                                          recipient@example.com\n\n"
    "-- 1 Kbytes in 1 Request.\n",
    "",
)


def _load_module():
    name = "_test_smtp_plugin"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_PY)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_inst(tmp_path, run_cmd_rv=None):
    mod = _load_module()
    inst = mod.SmtpPlugin()
    inst.plugin_id = "smtp_plugin"
    inst.meta = {"name": "SMTP Plugin", "version": "1.0.0", "description": "", "author": ""}
    inst.plugin_dir = tmp_path
    inst.logger = logging.getLogger("test.smtp_plugin")
    inst.config = {
        "state_file": "smtp_state.json",
        "smtp_host": "127.0.0.1",
        "smtp_port": 25,
        "default_from": "noreply@localhost",
    }
    inst._run_cmd = MagicMock(return_value=run_cmd_rv or _proc(0))
    inst._smtp_send = MagicMock()
    inst._which = MagicMock(return_value="/usr/sbin/postconf")
    inst._postfix_running = MagicMock(return_value=True)
    inst.setup()
    return inst


def _make_client(tmp_path, run_cmd_rv=None) -> tuple[TestClient, MagicMock]:
    inst = _make_inst(tmp_path, run_cmd_rv)
    app = FastAPI()
    app.include_router(inst.router, prefix="/v1/smtp")
    return TestClient(app), inst


# ── fixtures ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def ctx(tmp_path):
    """Returns (TestClient, plugin_instance)."""
    return _make_client(tmp_path)


@pytest.fixture
def client(ctx):
    return ctx[0]


# ── status ───────────────────────────────────────────────────────────────────────

def test_status_returns_plugin_metadata(client):
    r = client.get("/v1/smtp/status")
    assert r.status_code == 200
    data = r.json()
    assert data["plugin"] == "SMTP Plugin"
    assert data["version"] == "1.0.0"


def test_status_reflects_postfix_running(ctx):
    client, inst = ctx
    inst._postfix_running.return_value = True
    assert client.get("/v1/smtp/status").json()["postfix_running"] is True


def test_status_reflects_postfix_stopped(ctx):
    client, inst = ctx
    inst._postfix_running.return_value = False
    assert client.get("/v1/smtp/status").json()["postfix_running"] is False


def test_status_shows_postfix_installed(ctx):
    client, inst = ctx
    inst._which.return_value = "/usr/sbin/postconf"
    assert client.get("/v1/smtp/status").json()["postfix_installed"] is True


def test_status_shows_postfix_not_installed(ctx):
    client, inst = ctx
    inst._which.return_value = None
    assert client.get("/v1/smtp/status").json()["postfix_installed"] is False


def test_status_shows_smtp_connection_info(client):
    data = client.get("/v1/smtp/status").json()
    assert data["smtp_host"] == "127.0.0.1"
    assert data["smtp_port"] == 25


def test_status_managed_settings_starts_at_zero(client):
    assert client.get("/v1/smtp/status").json()["managed_settings"] == 0


# ── config GET ───────────────────────────────────────────────────────────────────

def test_get_config_reads_live_postconf(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0, "myhostname = mail.example.com\nrelayhost = \n", "")
    data = client.get("/v1/smtp/config").json()
    assert data["postfix_installed"] is True
    assert data["settings"]["myhostname"]["value"] == "mail.example.com"


def test_get_config_marks_managed_keys(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0, "relayhost = [smtp.example.com]:587\n", "")
    inst._state["postfix_settings"] = {"relayhost": "[smtp.example.com]:587"}
    data = client.get("/v1/smtp/config").json()
    assert data["settings"]["relayhost"]["managed"] is True


def test_get_config_marks_unmanaged_keys(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0, "myhostname = mail.example.com\n", "")
    data = client.get("/v1/smtp/config").json()
    assert data["settings"]["myhostname"]["managed"] is False


def test_get_config_falls_back_when_postfix_not_installed(ctx):
    client, inst = ctx
    inst._which.return_value = None
    inst._state["postfix_settings"] = {"relayhost": "[smtp.example.com]:587"}
    data = client.get("/v1/smtp/config").json()
    assert data["postfix_installed"] is False
    assert data["settings"]["relayhost"]["value"] == "[smtp.example.com]:587"


# ── config PUT ───────────────────────────────────────────────────────────────────

def test_update_config_calls_postconf(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    inst._which.return_value = "/usr/sbin/postconf"
    r = client.put("/v1/smtp/config", json={"myhostname": "mail.example.com"})
    assert r.status_code == 200
    args_used = inst._run_cmd.call_args[0][0]
    assert "/usr/sbin/postconf" in args_used
    assert "-e" in args_used
    assert any("myhostname=mail.example.com" in a for a in args_used)


def test_update_config_not_installed_returns_503(ctx):
    client, inst = ctx
    inst._which.return_value = None
    assert client.put("/v1/smtp/config", json={"myhostname": "x"}).status_code == 503


def test_update_config_persists_to_state(ctx, tmp_path):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    client.put("/v1/smtp/config", json={"relayhost": "[relay.example.com]:25"})
    assert inst._state["postfix_settings"]["relayhost"] == "[relay.example.com]:25"


def test_update_config_response_lists_updated_keys(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    r = client.put("/v1/smtp/config", json={"mydomain": "example.com", "myorigin": "example.com"})
    updated = r.json()["updated"]
    assert "mydomain" in updated
    assert "myorigin" in updated


def test_update_config_response_contains_diff(ctx):
    client, inst = ctx
    # first call: _postconf_get returns old value; second call (_postconf_set): success
    inst._run_cmd.side_effect = [
        _proc(0, "myhostname = old.example.com\n", ""),  # _postconf_get (before)
        _proc(0),                                          # _postconf_set
    ]
    r = client.put("/v1/smtp/config", json={"myhostname": "new.example.com"})
    diff = r.json()["diff"]
    assert diff["myhostname"]["before"] == "old.example.com"
    assert diff["myhostname"]["after"] == "new.example.com"


def test_update_config_diff_before_empty_when_postfix_not_readable(ctx):
    client, inst = ctx
    # _postconf_get fails (returncode != 0), _postconf_set succeeds
    inst._run_cmd.side_effect = [
        _proc(1, "", "postconf: error"),
        _proc(0),
    ]
    r = client.put("/v1/smtp/config", json={"relayhost": "[relay.example.com]:25"})
    assert r.json()["diff"]["relayhost"]["before"] == ""
    assert r.json()["diff"]["relayhost"]["after"] == "[relay.example.com]:25"


def test_update_config_bool_converted_to_yes_no(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    client.put("/v1/smtp/config", json={"smtp_sasl_auth_enable": True})
    args = inst._run_cmd.call_args[0][0]
    assert any("smtp_sasl_auth_enable=yes" in a for a in args)


def test_update_config_empty_body_returns_400(client):
    assert client.put("/v1/smtp/config", json={}).status_code == 400


def test_update_config_postconf_failure_returns_500(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(1, "", "postconf: fatal: configuration error")
    r = client.put("/v1/smtp/config", json={"myhostname": "bad"})
    assert r.status_code == 500


def test_update_config_emits_event(ctx, tmp_path):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    received: list = []
    global_bus.subscribe("smtp.config.updated", received.append)
    try:
        client.put("/v1/smtp/config", json={"myhostname": "mail.example.com"})
        assert len(received) == 1
        assert "myhostname" in received[0].payload["keys"]
    finally:
        global_bus.unsubscribe("smtp.config.updated", received.append)


def test_config_survives_reload(tmp_path):
    client1, inst1 = _make_client(tmp_path)
    inst1._run_cmd.return_value = _proc(0)
    client1.put("/v1/smtp/config", json={"relayhost": "[smtp.example.com]:587"})

    # second instance: postfix not available, so falls back to stored state
    client2, inst2 = _make_client(tmp_path)
    inst2._which.return_value = None
    entry = client2.get("/v1/smtp/config").json()["settings"]["relayhost"]
    assert entry["value"] == "[smtp.example.com]:587"
    assert entry["managed"] is True


# ── queue ────────────────────────────────────────────────────────────────────────

def test_queue_empty(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _MAILQ_EMPTY
    data = client.get("/v1/smtp/queue").json()
    assert data["empty"] is True
    assert data["count"] == 0
    assert data["entries"] == []


def test_queue_with_message(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _MAILQ_ONE
    data = client.get("/v1/smtp/queue").json()
    assert data["empty"] is False
    assert data["count"] == 1
    entry = data["entries"][0]
    assert entry["id"] == "ABC123456789"
    assert entry["arrival"] == "Mon May 11 10:00:00"
    assert entry["sender"] == "sender@example.com"
    assert "recipient@example.com" in entry["recipients"]


def test_queue_uses_mailq_command(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _MAILQ_EMPTY
    inst._which.return_value = "/usr/sbin/mailq"
    client.get("/v1/smtp/queue")
    inst._run_cmd.assert_called_with(["/usr/sbin/mailq"], timeout=15)


def test_flush_queue_success(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    r = client.delete("/v1/smtp/queue")
    assert r.status_code == 200
    assert r.json()["flushed"] is True


def test_flush_queue_uses_postqueue(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    inst._which.return_value = "/usr/sbin/postqueue"
    client.delete("/v1/smtp/queue")
    inst._run_cmd.assert_called_with(["/usr/sbin/postqueue", "-f"], timeout=30)


def test_flush_queue_not_installed_returns_503(ctx):
    client, inst = ctx
    inst._which.return_value = None
    assert client.delete("/v1/smtp/queue").status_code == 503


def test_flush_queue_failure_returns_500(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(1, "", "postqueue: Cannot flush mail queue!")
    assert client.delete("/v1/smtp/queue").status_code == 500


def test_flush_queue_emits_event(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    received: list = []
    global_bus.subscribe("smtp.queue.flushed", received.append)
    try:
        client.delete("/v1/smtp/queue")
        assert len(received) == 1
    finally:
        global_bus.unsubscribe("smtp.queue.flushed", received.append)


# ── send ─────────────────────────────────────────────────────────────────────────

def test_send_returns_202(client):
    r = client.post("/v1/smtp/send", json={
        "to": "user@example.com",
        "subject": "Hello",
        "body": "World",
    })
    assert r.status_code == 202


def test_send_calls_smtp_send(ctx):
    client, inst = ctx
    client.post("/v1/smtp/send", json={
        "to": "user@example.com",
        "subject": "Hello",
        "body": "World",
    })
    inst._smtp_send.assert_called_once()
    from_arg, recipients_arg, _ = inst._smtp_send.call_args[0]
    assert from_arg == "noreply@localhost"
    assert recipients_arg == ["user@example.com"]


def test_send_uses_custom_from_addr(ctx):
    client, inst = ctx
    client.post("/v1/smtp/send", json={
        "to": "user@example.com",
        "subject": "Hi",
        "body": "Body",
        "from_addr": "custom@example.com",
    })
    from_arg = inst._smtp_send.call_args[0][0]
    assert from_arg == "custom@example.com"


def test_send_multiple_recipients(ctx):
    client, inst = ctx
    client.post("/v1/smtp/send", json={
        "to": ["a@example.com", "b@example.com"],
        "subject": "Multi",
        "body": "Body",
    })
    _, recipients, _ = inst._smtp_send.call_args[0]
    assert recipients == ["a@example.com", "b@example.com"]


def test_send_smtp_error_returns_502(ctx):
    import smtplib
    client, inst = ctx
    inst._smtp_send.side_effect = smtplib.SMTPException("connection refused")
    r = client.post("/v1/smtp/send", json={"to": "x@y.com", "subject": "s", "body": "b"})
    assert r.status_code == 502


def test_send_os_error_returns_503(ctx):
    client, inst = ctx
    inst._smtp_send.side_effect = OSError("connection refused")
    r = client.post("/v1/smtp/send", json={"to": "x@y.com", "subject": "s", "body": "b"})
    assert r.status_code == 503


def test_send_emits_event(ctx):
    client, inst = ctx
    received: list = []
    global_bus.subscribe("smtp.email.sent", received.append)
    try:
        client.post("/v1/smtp/send", json={"to": "user@example.com", "subject": "Ev", "body": "B"})
        assert len(received) == 1
        assert received[0].payload["to"] == ["user@example.com"]
        assert received[0].payload["subject"] == "Ev"
    finally:
        global_bus.unsubscribe("smtp.email.sent", received.append)


# ── test email ───────────────────────────────────────────────────────────────────

def test_test_email_returns_202(client):
    r = client.post("/v1/smtp/test", json={"to": "admin@example.com"})
    assert r.status_code == 202


def test_test_email_response_shape(client):
    data = client.post("/v1/smtp/test", json={"to": "admin@example.com"}).json()
    assert data["sent"] is True
    assert data["to"] == "admin@example.com"
    assert data["from"] == "noreply@localhost"


def test_test_email_uses_default_subject(ctx):
    client, inst = ctx
    client.post("/v1/smtp/test", json={"to": "admin@example.com"})
    _, _, msg_str = inst._smtp_send.call_args[0]
    assert "FastFirewall Test Email" in msg_str


def test_test_email_custom_subject_and_body(ctx):
    client, inst = ctx
    client.post("/v1/smtp/test", json={
        "to": "admin@example.com",
        "subject": "Custom Subject",
        "body": "Custom body text",
    })
    _, _, msg_str = inst._smtp_send.call_args[0]
    assert "Custom Subject" in msg_str
    assert "Custom body text" in msg_str


def test_test_email_default_body_mentions_fastfirewall(ctx):
    client, inst = ctx
    client.post("/v1/smtp/test", json={"to": "admin@example.com"})
    _, _, msg_str = inst._smtp_send.call_args[0]
    assert "FastFirewall" in msg_str


def test_test_email_smtp_error_returns_502(ctx):
    import smtplib
    client, inst = ctx
    inst._smtp_send.side_effect = smtplib.SMTPException("relay denied")
    assert client.post("/v1/smtp/test", json={"to": "x@y.com"}).status_code == 502


def test_test_email_emits_event(ctx):
    client, inst = ctx
    received: list = []
    global_bus.subscribe("smtp.email.sent", received.append)
    try:
        client.post("/v1/smtp/test", json={"to": "admin@example.com", "subject": "T"})
        assert len(received) == 1
        assert received[0].payload["to"] == ["admin@example.com"]
    finally:
        global_bus.unsubscribe("smtp.email.sent", received.append)


# ── reload ───────────────────────────────────────────────────────────────────────

def test_reload_returns_200(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    r = client.post("/v1/smtp/reload")
    assert r.status_code == 200
    assert r.json()["reloaded"] is True


def test_reload_calls_postfix_reload(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    inst._which.return_value = "/usr/sbin/postfix"
    inst._sudo_prefix = MagicMock(return_value=[])  # simulate running as root
    client.post("/v1/smtp/reload")
    inst._run_cmd.assert_called_with(["/usr/sbin/postfix", "reload"], timeout=30)


def test_reload_not_installed_returns_503(ctx):
    client, inst = ctx
    inst._which.return_value = None
    assert client.post("/v1/smtp/reload").status_code == 503


def test_reload_failure_returns_500(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(1, "", "postfix: permission denied")
    assert client.post("/v1/smtp/reload").status_code == 500


def test_reload_emits_event(ctx):
    client, inst = ctx
    inst._run_cmd.return_value = _proc(0)
    received: list = []
    global_bus.subscribe("smtp.postfix.reloaded", received.append)
    try:
        client.post("/v1/smtp/reload")
        assert len(received) == 1
    finally:
        global_bus.unsubscribe("smtp.postfix.reloaded", received.append)


# ── event handler ────────────────────────────────────────────────────────────────

def test_smtp_test_event_sends_email(tmp_path):
    inst = _make_inst(tmp_path)
    global_bus.subscribe("smtp.test", inst.on_smtp_test)
    try:
        global_bus.emit(Event("smtp.test", source="test", payload={
            "to": "alert@example.com",
            "subject": "Alert",
        }))
        inst._smtp_send.assert_called_once()
        _, recipients, _ = inst._smtp_send.call_args[0]
        assert recipients == ["alert@example.com"]
    finally:
        global_bus.unsubscribe("smtp.test", inst.on_smtp_test)


def test_smtp_test_event_missing_to_is_a_noop(tmp_path):
    inst = _make_inst(tmp_path)
    global_bus.subscribe("smtp.test", inst.on_smtp_test)
    try:
        global_bus.emit(Event("smtp.test", source="test", payload={}))
        inst._smtp_send.assert_not_called()
    finally:
        global_bus.unsubscribe("smtp.test", inst.on_smtp_test)

