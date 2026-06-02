# Apt-Cacher-NG Plugin

Installs and manages apt-cacher-ng, a caching proxy for Debian/Ubuntu package downloads. Writes `/etc/apt-cacher-ng/acng.conf` and controls the service via `systemctl`. Routes mount at `/v1/apt_cacher_ng/`.

**Mutation model: immediate apply.** Every config mutation writes state and applies the conf file before returning. Uses `PluginStateFile` with `mutation_model="immediate"`, so `_save_state()` / `save_desired()` automatically commits `current = desired` and `pending_changes` stays `False` after every mutation.

## Routes

| Method | Path | Summary |
|---|---|---|
| `GET` | `/status` | Plugin and service status, proxy URL, and apt proxy.conf string |
| `GET` | `/config` | Get managed acng settings (live conf + ff_managed flag) |
| `PATCH` | `/config` | Update acng settings and reload the service |
| `POST` | `/config/reload` | Reload apt-cacher-ng without a config change |
| `GET` | `/config/raw` | Read raw acng.conf from disk |
| `GET` | `/proxy-url` | Get proxy URL and host resolution info |
| `PUT` | `/proxy-url` | Set a static host override for the proxy URL |
| `DELETE` | `/proxy-url` | Clear the static host override |
| `GET` | `/cache` | Cache disk usage and file count |
| `DELETE` | `/cache` | Delete all cached packages |
| `GET` | `/logs` | Recent apt-cacher-ng journal entries |

`GET /status` includes both `proxy_url` (e.g. `http://192.168.1.1:3142/`) and `apt_proxy_conf` (the line to drop into `/etc/apt/apt.conf.d/`).

## State file

`data/apt_cacher_ng_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "acng_settings": {},
    "proxy_host": null
  },
  "current_state": {
    "acng_settings": {},
    "proxy_host": null
  }
}
```

`acng_settings` maps field names (see table below) → values as originally submitted. `proxy_host` is `null` when no override is set. `current_state` is committed automatically on every `_save_state()` call because `mutation_model="immediate"`.

## acng.conf field mapping

`_FIELD_TO_KEY` maps Python field names → acng.conf key names. Note apt-cacher-ng spells the threshold key `ExTreshold` (one 'h') — that is intentional.

| Field name | acng.conf key | Type |
|---|---|---|
| `port` | `Port` | int |
| `bind_address` | `BindAddress` | str |
| `ex_threshold` | `ExTreshold` | int |
| `max_dl_speed_kb` | `MaxDlSpeed` | int |
| `fetch_timeout` | `FetchTimeout` | int |
| `tunnel_timeout` | `TunnelTimeout` | int |
| `force_managed` | `ForceManaged` | bool → `"1"`/`"0"` |
| `allow_user_ports` | `AllowUserPorts` | bool → `"1"`/`"0"` |

## Proxy URL resolution

`_resolve_proxy_host()` returns `(host, source)` using a three-step priority chain:

1. **`"override"`** — `self._state["proxy_host"]` if set (PUT `/proxy-url`)
2. **`"macro"`** — last address from `macro_registry.resolve("$interface.lan.address")` (networking plugin must be loaded)
3. **`"fqdn"`** — `socket.getfqdn()` as a last resort

## Key methods

**`_desired_snapshot()`** — returns `json.loads(json.dumps(self._state))`: a normalized deep copy used as the argument to `save_desired()`.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Because `mutation_model="immediate"`, this also auto-commits `current = desired`.

**`_apply_state()`** — re-applies `acng_settings` from state on boot by calling `_render_acng_conf` + `_write_conf_file`. Errors are logged as warnings; the plugin continues loading.

**`_resolve_proxy_host()`** — returns `(host, source)` tuple; see priority chain above.

**`_write_conf_file(content)`** — writes the conf file via `_pyinfra_run` (requires `sudo`). Uses `files_ops.put` from `pyinfra.operations`.

**`_reload_service()`** — emits `initsys.service.restart` on the bus and inspects `results[0].get("success")`; raises `RuntimeError` if the host plugin reports failure.

**`_pyinfra_run(op, **kwargs)`** — spawns `infra/pyinfra_worker.py` in a subprocess to avoid gevent/anyio event-loop conflicts with pyinfra. Shared with host and syslog plugins.

## acng.conf helpers

**`_parse_acng_conf(path)`** — reads an acng.conf and returns `{key: value}` for all non-comment `Key: Value` lines. Returns `{}` if the file doesn't exist.

**`_settings_to_acng(settings)`** — converts `{field: value}` → `{acng_key: str_value}`. Booleans become `"1"`/`"0"`.

**`_render_acng_conf(path, updates)`** — merges `updates` into an existing acng.conf, preserving comments and unmanaged keys. Appends any keys not already present. Creates a minimal file from scratch when none exists.

## Events emitted

| Event | Payload |
|---|---|
| `apt_cacher_ng.config.updated` | `{keys: [changed field names]}` |
| `apt_cacher_ng.cache.flushed` | `{cache_dir}` |
| `apt_cacher_ng.service.reloaded` | `{}` |
| `initsys.service.restart` | `{service_name: "apt-cacher-ng"}` — emitted by `_reload_service()` |
| `initsys.service.add` | emitted at `setup()` when `enable_os_boot: true` |
| `initsys.service.disable` | emitted at `setup()` when `enable_os_boot: false` |

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `apt_cacher_ng_state.json` | filename inside `data/` |
| `conf_file` | `/etc/apt-cacher-ng/acng.conf` | acng.conf path on disk |
| `cache_dir` | `/var/cache/apt-cacher-ng` | package cache directory |
| `log_dir` | `/var/log/apt-cacher-ng` | log directory |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` on startup |
| `enable_os_boot` | `false` | register (or disable) apt-cacher-ng as a boot-time managed service via `initsys.service.add` / `initsys.service.disable` |

`skip_host_os_port_check: true` is set in `plugin.yaml` because apt-cacher-ng may already be running on port 3142 when the plugin loads.

## Testing

Tests in `test_apt_cacher_ng_plugin.py`. No real apt-cacher-ng needed — `_pyinfra_run` is replaced with `MagicMock` before `setup()` is called, and `ignore_state_on_boot: True` is set so no boot apply runs. Service status is now fetched via `bus.emit(initsys.service.status)`, so tests that exercise `GET /status` should also mock the bus or patch `bus.emit` to return the expected status dict.

```python
inst._pyinfra_run = MagicMock()
inst.config["ignore_state_on_boot"] = True
inst.setup()
```

Use `tmp_path` for `plugin_dir` so state files are isolated per test. The `_proc(returncode, stdout, stderr)` helper builds a mock `CompletedProcess`. Two fixture tiers: `ctx` returns `(TestClient, instance)` for tests that need to inspect instance state; `client` returns just the `TestClient`.

To test proxy URL resolution with the networking macro, register and clean up the `interface` namespace:

```python
macro_registry.register_namespace(
    "interface",
    lambda *s: ["192.168.1.1"] if s == ("lan", "address") else None,
)
try:
    # ... test
finally:
    macro_registry.unregister_namespace("interface")
```
