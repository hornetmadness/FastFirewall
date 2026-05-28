"""
SMTP Plugin
───────────
Manages Postfix SMTP server configuration and provides email sending and
test-mail endpoints. Routes mount at /v1/smtp/.

Events emitted:
  smtp.config.updated   – payload: {keys: [list of changed setting names]}
  smtp.email.sent       – payload: {to, subject, from_addr}
  smtp.queue.flushed    – payload: {}
  smtp.postfix.reloaded – payload: {}

Events consumed:
  smtp.test             – payload: {to, subject?, body?}
    Sends a test email to the given address out-of-band.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import smtplib
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, List, Optional, Union

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator

from plugin_system.core import PluginBase, PluginStateFile, ApiRouterPlugin, Service, on
from plugin_system.core.events import Event, bus
from plugin_system.core.macros import macro_registry


# ── Pydantic schemas ────────────────────────────────────────────────────────────

# Matches $interface.<alias>.address macro tokens (e.g. $interface.lan.address)
_INET_MACRO_RE = re.compile(r'^\$interface\.[A-Za-z][A-Za-z0-9_]*\.address$')


def _validate_inet_interfaces(value: str) -> str:
    """Accept 'all', 'loopback-only', 'localhost', macro refs, or a CSV of IP addresses."""
    v = value.strip()
    if v in ("all", "loopback-only", "localhost"):
        return v
    for part in v.split(","):
        token = part.strip()
        if _INET_MACRO_RE.match(token):
            continue
        addr = token.strip("[]")
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError(
                f"{token!r} is not a valid inet_interfaces token; expected 'all', "
                "'loopback-only', a macro like '$interface.lan.address', "
                "or a comma-separated list of IP addresses"
            )
    return v


def _resolve_inet_interfaces(value: str) -> str:
    """Expand $interface.*.address macros to IPs; wrap IPv6 in brackets for Postfix."""
    if value in ("all", "loopback-only", "localhost"):
        return value
    parts: list[str] = []
    for token in (t.strip() for t in value.split(",")):
        if _INET_MACRO_RE.match(token):
            raw = macro_registry.resolve(token)
            ips: list[str] = raw if isinstance(raw, list) else ([raw] if raw else [])
            for ip_str in ips:
                try:
                    addr = ipaddress.ip_address(str(ip_str))
                    parts.append(f"[{ip_str}]" if addr.version == 6 else str(ip_str))
                except ValueError:
                    parts.append(str(ip_str))
        else:
            parts.append(token)
    return ", ".join(parts)


class PostfixSettingsUpdate(BaseModel):
    myhostname: Optional[str] = Field(default=None, max_length=253)
    mydomain: Optional[str] = Field(default=None, max_length=253)
    myorigin: Optional[str] = Field(default=None, max_length=253)
    mynetworks: Optional[str] = Field(default=None, max_length=1024)
    inet_interfaces: Optional[str] = Field(default=None, max_length=256)
    relayhost: Optional[str] = Field(default=None, max_length=253)

    @field_validator("inet_interfaces")
    @classmethod
    def validate_inet_interfaces(cls, v: object) -> object:
        if v is None:
            return v
        return _validate_inet_interfaces(str(v))
    smtp_tls_security_level: Optional[str] = Field(default=None, max_length=32)
    smtp_sasl_auth_enable: Optional[bool] = None
    smtp_sasl_password_maps: Optional[str] = Field(default=None, max_length=512)
    message_size_limit: Optional[int] = None
    mailbox_size_limit: Optional[int] = None


class SendEmailRequest(BaseModel):
    to: Union[str, List[str]]
    subject: str = Field(max_length=998)
    body: str = Field(max_length=65536)
    from_addr: Optional[str] = Field(default=None, max_length=254)
    html: bool = False


class TestEmailRequest(BaseModel):
    to: str = Field(max_length=254)
    subject: str = Field(default="FastFirewall Test Email", max_length=998)
    body: Optional[str] = Field(default=None, max_length=65536)


# ── Plugin ──────────────────────────────────────────────────────────────────────

class SmtpPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.SMTP]

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "smtp_state.json", self.logger,
            mutation_model="immediate",
        )
        self._smtp_host: str = self.config.get("smtp_host", "127.0.0.1")
        self._smtp_port: int = int(self.config.get("smtp_port", 25))
        self._default_from: str = self.config.get("default_from", "fastfirewall@localhost")
        self._state: dict[str, Any] = self._state_file.load_desired(default={"postfix_settings": {}})
        if not self.config.get("ignore_state_on_boot", False):
            self._apply_state()
        self._register_routes()
        self.logger.info("SMTP plugin loaded (postfix at %s:%d)", self._smtp_host, self._smtp_port)

    def teardown(self) -> None:
        self._save_state()

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _apply_state(self) -> None:
        settings = self._state.get("postfix_settings", {})
        if not settings:
            return
        postconf_args = self._build_postconf_args(settings)
        try:
            self._postconf_set(postconf_args)
            self.logger.info("Re-applied %d postfix setting(s) from state on boot", len(settings))
        except HTTPException as exc:
            self.logger.warning("Could not re-apply postfix settings on boot: %s", exc.detail)

    def _build_postconf_args(self, settings: dict[str, Any]) -> dict[str, str]:
        result: dict[str, str] = {}
        for k, v in settings.items():
            if isinstance(v, bool):
                result[k] = "yes" if v else "no"
            else:
                s = str(v)
                if k == "inet_interfaces":
                    s = _resolve_inet_interfaces(s)
                result[k] = s
        return result

    # ── system helpers (mockable) ────────────────────────────────────────────────

    def _run_cmd(self, args: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

    def _smtp_send(self, from_addr: str, recipients: list[str], msg_str: str) -> None:
        with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as smtp:
            smtp.sendmail(from_addr, recipients, msg_str)

    # ── postfix helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _which(cmd: str) -> Optional[str]:
        """Find a binary, checking /usr/sbin first since that's where postfix tools live."""
        return shutil.which(cmd) or shutil.which(cmd, path="/usr/sbin:/usr/bin:/sbin:/bin")

    # Keys exposed by the config API — used for both reads and writes.
    _MANAGED_KEYS = [
        "myhostname", "mydomain", "myorigin", "mynetworks", "inet_interfaces",
        "relayhost", "smtp_tls_security_level", "smtp_sasl_auth_enable",
        "smtp_sasl_password_maps", "message_size_limit", "mailbox_size_limit",
    ]

    def _postconf_get(self, keys: list[str]) -> dict[str, str]:
        """Read current live values from postconf; returns {} if postfix not installed."""
        postconf = self._which("postconf")
        if not postconf:
            return {}
        result = self._run_cmd([postconf] + keys)
        if result.returncode != 0:
            return {}
        out: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _sudo_prefix() -> list[str]:
        """Return ['sudo'] when not already root, so postconf can write main.cf."""
        return [] if os.getuid() == 0 else ["sudo"]

    def _postconf_set(self, settings: dict[str, str]) -> None:
        postconf = self._which("postconf")
        if not postconf:
            raise HTTPException(503, "postconf not found — is Postfix installed?")
        args = self._sudo_prefix() + [postconf, "-e"] + [f"{k}={v}" for k, v in settings.items()]
        result = self._run_cmd(args)
        if result.returncode != 0:
            self.logger.error("postconf -e failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to apply Postfix settings; check server logs")

    def _postfix_running(self) -> bool:
        """Check the Postfix master PID file — no subprocess needed."""
        return (
            Path("/var/spool/postfix/pid/master.pid").exists()
            or Path("/var/run/postfix.pid").exists()
        )

    def _mailq_parse(self) -> dict[str, Any]:
        mailq = self._which("mailq") or "mailq"
        result = self._run_cmd([mailq], timeout=15)
        output = result.stdout.strip()
        queue_empty = "Mail queue is empty" in output
        entries: list[dict[str, Any]] = []
        lines = output.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            parts = line.split()
            # Queue entry lines: ID size DOW Mon DD HH:MM:SS sender (≥7 fields, ID ≥6 chars)
            if line and not line.startswith((" ", "-")) and len(parts) >= 6 and len(parts[0]) >= 6:
                entry: dict[str, Any] = {
                    "id": parts[0].rstrip("*!"),
                    "size": parts[1],
                    "arrival": f"{parts[2]} {parts[3]} {parts[4]} {parts[5]}",
                    "sender": parts[6] if len(parts) > 6 else "",
                    "recipients": [],
                }
                i += 1
                while i < len(lines) and lines[i].startswith(" "):
                    entry["recipients"].append(lines[i].strip())
                    i += 1
                entries.append(entry)
            else:
                i += 1
        return {"empty": queue_empty, "count": len(entries), "entries": entries}

    def _build_message(
        self, recipients: list[str], subject: str, body: str, from_addr: str, html: bool
    ) -> str:
        msg = MIMEMultipart("alternative" if html else "mixed")
        msg["From"] = from_addr
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html" if html else "plain"))
        return msg.as_string()

    # ── route registration ───────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        add("/status",  self._status,        methods=["GET"],    summary="Plugin and Postfix service status")
        add("/config",  self._get_config,    methods=["GET"],    summary="Get managed Postfix settings")
        add("/config",  self._update_config, methods=["PUT"],    summary="Apply Postfix settings via postconf")
        add("/queue",   self._get_queue,     methods=["GET"],    summary="Show the Postfix mail queue")
        add("/queue",   self._flush_queue,   methods=["DELETE"], summary="Flush the mail queue (postqueue -f)")
        add("/send",    self._send,          methods=["POST"],   summary="Send an email via Postfix",          status_code=202)
        add("/test",    self._test_email,    methods=["POST"],   summary="Send a test email via local SMTP",   status_code=202)
        add("/reload",  self._reload,        methods=["POST"],   summary="Reload Postfix configuration")

    # ── route handlers ───────────────────────────────────────────────────────────

    def _status(self) -> dict:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "postfix_running": self._postfix_running(),
            "postfix_installed": self._which("postconf") is not None,
            "smtp_host": self._smtp_host,
            "smtp_port": self._smtp_port,
            "default_from": self._default_from,
            "managed_settings": len(self._state.get("postfix_settings", {})),
            "pending_changes": self._state_file.pending_changes,
        }

    def _get_config(self) -> dict:
        live = self._postconf_get(self._MANAGED_KEYS)
        managed_keys = set(self._state.get("postfix_settings", {}).keys())
        settings = {
            k: {"value": v, "managed": k in managed_keys}
            for k, v in live.items()
        }
        if not live:
            # postfix not installed — fall back to stored state
            settings = {
                k: {"value": str(v), "managed": True}
                for k, v in self._state.get("postfix_settings", {}).items()
            }
        return {"settings": settings, "postfix_installed": live != {}}

    def _update_config(self, body: PostfixSettingsUpdate) -> dict:
        updates = body.model_dump(exclude_none=True)
        if not updates:
            raise HTTPException(400, "No settings provided")
        postconf_args = self._build_postconf_args(updates)
        before = self._postconf_get(list(updates.keys()))
        self._postconf_set(postconf_args)
        self._state.setdefault("postfix_settings", {}).update(updates)
        self._save_state()
        diff = {
            k: {"before": before.get(k, ""), "after": postconf_args[k]}
            for k in updates
        }
        bus.emit(Event("smtp.config.updated", payload={"keys": list(updates.keys())}))
        return {"updated": list(updates.keys()), "diff": diff}

    def _get_queue(self) -> dict:
        return self._mailq_parse()

    def _flush_queue(self) -> dict:
        postqueue = self._which("postqueue")
        if not postqueue:
            raise HTTPException(503, "postqueue not found — is Postfix installed?")
        result = self._run_cmd([postqueue, "-f"], timeout=30)
        if result.returncode != 0:
            self.logger.error("postqueue -f failed: %s", result.stderr.strip())
            raise HTTPException(500, "Failed to flush mail queue; check server logs")
        bus.emit(Event("smtp.queue.flushed", payload={}))
        return {"flushed": True}

    def _send(self, body: SendEmailRequest) -> dict:
        from_addr = body.from_addr or self._default_from
        recipients = body.to if isinstance(body.to, list) else [body.to]
        msg_str = self._build_message(recipients, body.subject, body.body, from_addr, body.html)
        try:
            self._smtp_send(from_addr, recipients, msg_str)
        except smtplib.SMTPException as exc:
            self.logger.error("SMTP send failed: %s", exc)
            raise HTTPException(502, "SMTP error while sending; check server logs") from exc
        except OSError as exc:
            self.logger.error("Cannot reach Postfix at %s:%d: %s", self._smtp_host, self._smtp_port, exc)
            raise HTTPException(503, "Cannot reach Postfix SMTP server; check server logs") from exc
        bus.emit(Event(
            "smtp.email.sent",
            payload={"to": recipients, "subject": body.subject, "from_addr": from_addr},
        ))
        return {"sent": True, "to": recipients, "subject": body.subject, "from": from_addr}

    def _test_email(self, body: TestEmailRequest) -> dict:
        test_body = body.body or (
            "This is a test email from FastFirewall SMTP plugin.\n\n"
            "If you received this, your Postfix configuration is working correctly."
        )
        from_addr = self._default_from
        msg_str = self._build_message([body.to], body.subject, test_body, from_addr, False)
        try:
            self._smtp_send(from_addr, [body.to], msg_str)
        except smtplib.SMTPException as exc:
            self.logger.error("SMTP test send failed: %s", exc)
            raise HTTPException(502, "SMTP error while sending; check server logs") from exc
        except OSError as exc:
            self.logger.error("Cannot reach Postfix at %s:%d: %s", self._smtp_host, self._smtp_port, exc)
            raise HTTPException(503, "Cannot reach Postfix SMTP server; check server logs") from exc
        bus.emit(Event(
            "smtp.email.sent",
            payload={"to": [body.to], "subject": body.subject, "from_addr": from_addr},
        ))
        return {"sent": True, "to": body.to, "subject": body.subject, "from": from_addr}

    def _reload(self) -> dict:
        postfix = self._which("postfix")
        if not postfix:
            raise HTTPException(503, "postfix not found — is Postfix installed?")
        result = self._run_cmd(self._sudo_prefix() + [postfix, "reload"], timeout=30)
        if result.returncode != 0:
            self.logger.error("postfix reload failed: %s", result.stderr.strip())
            raise HTTPException(500, "Postfix reload failed; check server logs")
        bus.emit(Event("smtp.postfix.reloaded", payload={}))
        return {"reloaded": True}

    # ── event handler ────────────────────────────────────────────────────────────

    @on("smtp.send")
    def on_smtp_send(self, event: Event) -> None:
        to = event.payload.get("to")
        if not to:
            self.logger.warning("smtp.send event missing 'to' field")
            return
        req = SendEmailRequest(
            to=to,
            subject=event.payload.get("subject", "(no subject)"),
            body=event.payload.get("body", ""),
            from_addr=event.payload.get("from_addr"),
            html=bool(event.payload.get("html", False)),
        )
        try:
            self._send(req)
        except Exception as exc:
            self.logger.error("smtp.send event handler failed for %r: %s", to, exc)

    @on("smtp.test")
    def on_smtp_test(self, event: Event) -> None:
        to = event.payload.get("to")
        if not to:
            self.logger.warning("smtp.test event missing 'to' field")
            return
        req = TestEmailRequest(
            to=to,
            subject=event.payload.get("subject", "FastFirewall Test Email"),
            body=event.payload.get("body"),
        )
        try:
            self._test_email(req)
            self.logger.info("Test email sent to %r via smtp.test event", to)
        except Exception as exc:
            self.logger.error("smtp.test event handler failed: %s", exc)
