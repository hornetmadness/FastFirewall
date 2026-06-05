# Plan: Caddy HTTPS Reverse-Proxy Plugin

## Context

FastFirewall needs a managed HTTPS reverse proxy so the management UI (and any future plugin-provided service) can be reached over TLS without configuring Caddy manually. Other plugins register their upstream address by emitting `app_proxy.register` on the event bus; the Caddy plugin accumulates those entries in desired state and pushes a Caddy JSON config on explicit `POST /apply`.

---

## Files to create

| Path | Purpose |
|---|---|
| `plugins/caddy/__init__.py` | Package marker (empty) |
| `plugins/caddy/plugin.yaml` | Metadata, `APP_PROXY` service, ports 80/443, Caddy apt repo |
| `plugins/caddy/plugin.py` | `CaddyPlugin` implementation |
| `plugins/caddy/pyproject.toml` | Package definition + entry point |
| `plugins/caddy/test_caddy_api_routes.py` | Route tests |

`Service.APP_PROXY` already exists in `plugin_system/core/services.py` (line 52).

---

## plugin.yaml

- `id: caddy`
- `service_ports.app_proxy: tcp: [80, 443]`
- `skip_host_os_port_check: true` (Caddy may already run)
- `os_requirements: [caddy]`
- `repos:` Cloudsmith Caddy stable apt repo (key + source override using `src:` field so the `any-version main` dist is used)
- `config` defaults: `state_file: caddy_state.json`, `config_file: caddy.json` (staging copy in data dir), `system_conf_file: /etc/caddy/caddy.json` (system location), `admin_port: 2019`, `http_port: 80`, `https_port: 443`, `auto_https: "off"`, `tls_email: ""`

---

## State structure

```json
{
  "apps": {
    "fastfirewall": {
      "upstream": "http://127.0.0.1:8000",
      "path_prefix": "/",
      "description": "FastFirewall management UI",
      "source": "fastfirewall_app.registered"
    }
  },
  "settings": {
    "http_port": 80,
    "https_port": 443,
    "admin_port": 2019,
    "tls_email": "",
    "auto_https": "off"
  }
}
```

`source` records who registered the entry (`"api"` or the event `source` string), purely informational.

---

## Mutation model: deferred

`PluginStateFile.from_config(..., mutation_model="deferred")` — every CRUD operation and event registration calls `save_desired()` only. Config is not pushed to Caddy until `POST /apply`.

---

## API routes (mounted at `/v1/caddy/`)

| Method | Path | Description |
|---|---|---|
| GET | `/status` | Pending-changes flag, app count, conf_file path |
| GET | `/config/apps` | List all registered proxy apps |
| POST | `/config/apps` | Add an app (body: `AppEntry`) |
| GET | `/config/apps/{name}` | Get one app |
| PUT | `/config/apps/{name}` | Replace an app |
| DELETE | `/config/apps/{name}` | Remove an app (204) |
| GET | `/config/settings` | Global settings (ports, TLS) |
| PATCH | `/config/settings` | Update settings |
| POST | `/apply` | Build config → write file → `caddy reload` → `commit()` |
| POST | `/discard` | Restore desired from `current_snapshot` |

---

## Pydantic models

```python
class AppEntry(BaseModel):
    name: str = Field(..., max_length=100)
    upstream: str = Field(..., max_length=2048)   # e.g. "http://127.0.0.1:8000"
    path_prefix: str = Field("/", max_length=255)
    description: str = Field("", max_length=255)

class AppUpdate(BaseModel):
    upstream: Optional[str] = Field(None, max_length=2048)
    path_prefix: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=255)

class CaddySettings(BaseModel):
    http_port: Optional[int] = Field(None, ge=1, le=65535)
    https_port: Optional[int] = Field(None, ge=1, le=65535)
    admin_port: Optional[int] = Field(None, ge=1, le=65535)
    tls_email: Optional[str] = Field(None, max_length=254)
    auto_https: Optional[str] = Field(None, max_length=32)  # "off" | "" | "disable_redirects"
```

---

## Event bus interface

### Incoming (listened to by `@on`)

| Event | Payload fields | Behavior |
|---|---|---|
| `app_proxy.register` | `name`, `upstream`, `path_prefix?`, `description?` | Upsert into `apps`, `save_desired()` |
| `app_proxy.unregister` | `name` | Remove from `apps`, `save_desired()` |

### Outgoing (emitted after apply/discard)

| Event | Payload |
|---|---|
| `caddy.config.applied` | `{"success": bool}` |
| `caddy.config.discarded` | `{}` |

---

## Caddy JSON config generation (`_build_caddy_config`)

Produces Caddy's native JSON format:

```json
{
  "admin": {"listen": "localhost:2019"},
  "apps": {
    "http": {
      "servers": {
        "main": {
          "listen": [":80", ":443"],
          "automatic_https": {"disable": true},
          "routes": [
            {
              "match": [{"path": ["/prefix/*"]}],
              "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "127.0.0.1:8000"}],
                "headers": {
                  "request": {
                    "set": {
                      "X-Forwarded-Proto": ["{http.request.scheme}"],
                      "X-Forwarded-Host": ["{http.request.host}"]
                    }
                  }
                }
              }]
            }
          ]
        }
      }
    }
  }
}
```

- Root-path apps (`path_prefix == "/"`) get no `match` block (catch-all, appended last).
- Path-prefix routes are sorted longest-first so more specific prefixes match first.
- When `tls_email` is non-empty, a `tls.automation` block is included; otherwise `automatic_https.disable: true`.

---

## Config file persistence

The plugin maintains its own staging copy at `plugin_dir / "data" / "caddy.json"` (the data dir, consistent with other plugins). On apply this file is written first, then copied to the system location (`/etc/caddy/caddy.json`).

---

## Apply flow (`POST /apply`)

**First apply** (no `current_snapshot` — fresh state file, Caddy not yet configured):
1. `_build_caddy_config(desired_snapshot)` → JSON string
2. Write JSON to `data/caddy.json` via plain `Path.write_text` (data dir is plugin-owned)
3. `_pyinfra_run(files_ops.put, src=io.StringIO(json_str), dest="/etc/caddy/caddy.json", mode="644", _sudo=True)` — copy to system location
4. `_pyinfra_run(server_ops.service, service="caddy", running=True, enabled=True, _sudo=True)` — start service
5. On success: `commit()` + emit `caddy.config.applied`

**Subsequent applies** (`current_snapshot` exists — Caddy is running):
1. `_build_caddy_config(desired_snapshot)` → JSON string
2. Write to `data/caddy.json` (data dir staging copy)
3. `_pyinfra_run(files_ops.put, ...)` — copy to system location for persistence across Caddy restarts
4. `POST http://localhost:{admin_port}/load` with JSON body — Caddy admin API hot-reload (no restart, no dropped connections); uses Python `urllib.request`
5. On success: `commit()` + emit `caddy.config.applied`
6. On any failure: log error, emit `{success: false}`, raise `HTTPException(500, ...)`

## Discard flow (`POST /discard`)

1. Get `current_snapshot`; 409 if None
2. Restore `self._state = current_snapshot`
3. Call `_save_state()` (updates desired on disk)
4. Emit `caddy.config.discarded`
5. Return `{"discarded": True}`

---

## Helper pattern (testability)

```python
def _pyinfra_run(self, op, **kwargs):
    norm_kwargs = {
        k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
        for k, v in kwargs.items()
    }
    success, err = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])[0]
    if not success:
        raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")
```

Tests mock both `plugin._pyinfra_run = MagicMock()` and `subprocess.run`.

---

## Tests (`test_caddy_api_routes.py`)

Follow the direct-load pattern (no PluginLoader). Key test cases:

- CRUD: add/get/update/delete apps, 409 on duplicate, 404 on missing
- Settings patch and persistence
- `pending_changes` is `False` initially, `True` after mutation, `False` after apply
- Apply: asserts `_pyinfra_run` called with correct dest/mode, `subprocess.run` called with `["caddy", "reload", ...]`, `current_snapshot` updated after apply
- Apply failure (pyinfra raises): returns 500, `current_snapshot` unchanged
- Discard: restores state, 409 if no snapshot
- Event registration: emit `app_proxy.register` → app appears in state; emit `app_proxy.unregister` → removed
- Config generation: `_build_caddy_config` unit tests covering path ordering, no-match for root prefix, TLS block when email set

---

## Verification

```bash
uv run --extra dev pytest plugins/caddy/test_caddy_api_routes.py -v
uv run --with pyright pyright plugins/caddy/plugin.py
# Optional: start server and hit the API
uv run python fastfirewall_app.py --plugin caddy
curl http://localhost:8000/v1/caddy/status
```
