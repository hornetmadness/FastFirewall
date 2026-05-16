# SMTP Plugin

Manages Postfix SMTP server configuration and provides email sending and test-mail endpoints. Routes mount at `/v1/smtp/`.

**Mutation model: immediate apply.** Every `PUT` mutation calls `postconf -e` inline and applies the change to Postfix before returning. Uses `PluginStateFile` with `mutation_model="immediate"`, so `_save_state()` / `save_desired()` automatically commits `current = desired` and `pending_changes` stays `False` after every mutation.

## Routes

| Method | Path | Summary |
|---|---|---|
| `GET` | `/status` | Plugin and Postfix service status |
| `GET` | `/config` | Get managed Postfix settings (live postconf + ff_managed flag) |
| `PUT` | `/config` | Apply Postfix settings via `postconf -e` |
| `GET` | `/queue` | Show the Postfix mail queue (`mailq`) |
| `DELETE` | `/queue` | Flush the mail queue (`postqueue -f`) |
| `POST` | `/send` | Send an email via Postfix (202) |
| `POST` | `/test` | Send a test email via local SMTP (202) |
| `POST` | `/reload` | Reload Postfix configuration (`postfix reload`) |

`GET /config` returns all settings from live `postconf` output, each annotated with `managed: bool`. Falls back to stored state when Postfix is not installed.

## State file

`data/smtp_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "postfix_settings": {}
  },
  "current_state": {
    "postfix_settings": {}
  }
}
```

`postfix_settings` maps setting name → value (as originally submitted, before `yes`/`no` conversion). `current_state` is committed automatically on every `_save_state()` call because `mutation_model="immediate"`.

## Key methods

**`_desired_snapshot()`** — returns `json.loads(json.dumps(self._state))`: a normalized deep copy used as the argument to `save_desired()`.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Because the mutation model is `"immediate"`, this also auto-commits `current = desired` — no separate `commit()` call is needed.

**`_apply_state()`** — re-applies `postfix_settings` on boot via `_postconf_set`. Errors are logged as warnings; the plugin continues loading.

**`_postconf_get(keys)`** — reads live values from `postconf`; returns `{}` if Postfix is not installed.

**`_postconf_set(settings)`** — runs `postconf -e key=value ...`; raises `HTTPException(503)` if `postconf` is not found, `HTTPException(500)` on non-zero exit.

**`_postfix_running()`** — checks for the Postfix master PID file; no subprocess needed.

**`_build_message(...)`** — constructs a `MIMEMultipart` message string ready for `smtplib`.

## System helpers (mockable in tests)

- `_run_cmd(args, timeout)` — wraps `subprocess.run`
- `_smtp_send(from_addr, recipients, msg_str)` — wraps `smtplib.SMTP.sendmail`
- `_which(cmd)` — wraps `shutil.which`, checks `/usr/sbin` first

## Events emitted

| Event | Payload |
|---|---|
| `smtp.config.updated` | `{keys: [changed setting names]}` |
| `smtp.email.sent` | `{to, subject, from_addr}` |
| `smtp.queue.flushed` | `{}` |
| `smtp.postfix.reloaded` | `{}` |

## Events consumed

| Event | Behaviour |
|---|---|
| `smtp.test` | Sends a test email to `payload.to` out-of-band (errors are logged, not raised) |
| `smtp.send` | Sends a full email from `payload` fields out-of-band |

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `smtp_state.json` | filename inside `data/` |
| `smtp_host` | `127.0.0.1` | SMTP host for sending |
| `smtp_port` | `25` | SMTP port for sending |
| `default_from` | `fastfirewall@localhost` | Default sender address |
| `ignore_state_on_boot` | `false` | Skip `_apply_state()` on startup |

## Testing

Tests in `test_smtp_api_routes.py`. No real Postfix needed — `_run_cmd`, `_smtp_send`, `_which`, and `_postfix_running` are all replaced with `MagicMock` before `setup()` is called.

```python
inst._run_cmd = MagicMock(return_value=_proc(0))
inst._smtp_send = MagicMock()
inst._which = MagicMock(return_value="/usr/sbin/postconf")
inst._postfix_running = MagicMock(return_value=True)
inst.setup()
```

Use `tmp_path` for `plugin_dir` so state files are isolated per test. The `_proc(returncode, stdout, stderr)` helper builds a mock `CompletedProcess`. Two fixture tiers: `ctx` returns `(TestClient, instance)` for tests that need to inspect instance state; `client` returns just the `TestClient`.
