# Networking Plugin

Manages network interfaces and routes declaratively via **ifstate** (`ifstatecli`). Desired state is stored in a JSON file; call `POST /apply` to push it to the running kernel. Routes mount at `/v1/networking/`.

Sysctl management is delegated to the host plugin. To set a sysctl from this plugin emit `host.sysctl.set` instead of calling `sysctl` directly — the host plugin will apply, persist, and track it.

**Mutation model: deferred apply.** Every `PUT`/`POST`/`DELETE` mutation only updates the desired-state dict and saves it to disk — nothing is applied to the kernel until `POST /apply` is called. Uses `PluginStateFile` with `mutation_model="deferred"`, so `save_desired()` only writes desired state; `commit()` is called explicitly after a successful apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

Depends on: `host` plugin.

## Resources

Two managed resource types:

| Resource | List | Mutate | Delete | Import |
|---|---|---|---|---|
| interfaces | `GET /config/interfaces` | `PUT /config/interfaces/{name}` | `DELETE /config/interfaces/{name}` | `POST /config/interfaces/import` |
| routes | `GET /config/routes` | `POST /config/routes` | `DELETE /config/routes/{route_id}` | `POST /config/routes/import` |

Additional routes: `GET /status`, `GET /interfaces`, `GET /interfaces/{name}`, `GET /identify`, `GET /config`, `GET /config/diff`, `POST /apply`, `POST /check`, `POST /discard`, `POST /ping`, `POST /mtr`.

## Route prefixes: live vs config

- `/interfaces` — reads live running state via `ifstatecli show` (no config side-effects)
- `/config/interfaces` — reads/writes the managed desired-state dict
- `/config` — returns the full ifstate YAML (or JSON with `?format=json`) built from desired state

## State file

`data/networking_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "interfaces": {},
    "routes": {},
    "aliases": {}
  },
  "current_state": {
    "interfaces": {},
    "routes": {},
    "aliases": {}
  }
}
```

`desired_state` holds what FF should enforce. `current_state` is committed only after a successful `POST /apply` or boot-time apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Key methods

**`_load_state()`** — calls `self._state_file.load_desired(default={})`, then reads `interfaces`, `routes`, `aliases` from the result into `self._interfaces`, `self._routes`, `self._aliases`. `current_snapshot` is restored automatically from the on-disk `current_state`.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Does **not** update `current_state` — that only happens via `commit()`.

**`_desired_snapshot()`** — returns `json.loads(json.dumps({interfaces, routes, aliases}))`: a normalized deep copy used for diffing and snapshotting.

**`_apply_state()`** — re-applies desired state on boot by writing `_ifstate_config_path` and running `ifstate apply`. Calls `self._state_file.commit(self._desired_snapshot())` on success.

**`_import_state_from_system()`** — called at boot when the state file is empty; seeds `_interfaces` and `_routes` from `ifstate show` output, then calls `self._state_file.save_and_commit(self._desired_snapshot())` so desired and current start identical.

**`_build_ifstate_yaml()`** — serializes `_interfaces` and `_routes` into the YAML format expected by ifstate.

**`_ifstate_config_path`** (property) — `Path` to `data/ifstate.yaml`, the persistent ifstate config written on every apply. The path is exposed in `GET /status` as `config_file`.

**`_run_ifstate(*args)`** — runs `sudo sys.executable -m ifstate.ifstate <args>` as a subprocess (uses the same Python interpreter that is running FastFirewall, avoiding `uv` path lookup issues).

**`_sync_os_boot_service()`** — called from `setup()`; emits `initsys.service.add` (oneshot) when `enable_os_boot` is `true`, or `initsys.service.remove` when `false`. The registered service runs `sudo python -m ifstate.ifstate -c <config_path> apply` at OS boot.

**`_resolve_interface_macro(*segments)`** — resolver for the `interface` macro namespace. `segments[0]` is the alias name, `segments[1]` is the field:

| Field | Returns |
|---|---|
| `name` | OS interface name string (e.g. `"enp0s25"`) |
| `address` | List of host IPs without prefix length (e.g. `["192.168.1.1"]`) |
| `net_addr` | List of network addresses with prefix length (e.g. `["192.168.1.0/24"]`) |

Example: `$interface.lan.net_addr` → `["192.168.1.0/24"]`

## `GET /config/diff`

Returns a structured diff between the last applied state (`current_snapshot`) and the current desired state. Response: `{pending_changes: bool, diff: {...}}`. The `diff` is computed by `_diff_state(current, desired)`. If nothing has ever been applied (`current_snapshot` is `None`), treats current as `{}`.

## `POST /discard`

Reverts `_interfaces`, `_routes`, `_aliases` back to `self._state_file.current_snapshot`. If `current_snapshot` is `None` (never applied), raises 409.

## Route IDs

Routes are keyed by a 16-character SHA-256 prefix of the serialized route dict (`to`, `via`, `dev`, `preference`, `table` — `None` fields excluded). The same route submitted twice produces the same id and gets a 409.

## Import endpoints

`POST /config/interfaces/import` reads `ifstatecli show` output and upserts the named (or all) interfaces into desired state. `POST /config/routes/import` does the same for routes. Both accept `overwrite: bool` (default `false`) to skip already-managed entries.

## Diagnostics

`POST /ping` — runs `ping -c <count> <host>`. Input validated by Pydantic (`PingRequest`) to reject shell metacharacters.  
`POST /mtr` — runs `mtr --report --json --report-cycles <count> <host>` and formats the hub list into a tabular string array.

## Alias mutations and `pending_changes`

Interface alias `PUT`/`DELETE` mutations call `self._state_file.commit(self._desired_snapshot())` immediately after `_save_state()`. This means alias changes do **not** leave `pending_changes: true` — they are treated as instant (no external apply step is needed to commit an alias change, since aliases are local to the FF macro system and don't touch the kernel).

## Events emitted

| Event | Payload |
|---|---|
| `networking.interface.configured` | `{name, addresses?, link?}` |
| `networking.interface.removed` | `{name}` |
| `networking.route.added` | `{route_id, to}` |
| `networking.route.removed` | `{route_id, to}` |
| `networking.applied` | `{success, returncode}` |

## Events emitted to init system

At `setup()` time the plugin emits one of these to the host plugin's `initsys` handlers:

| Event | When |
|---|---|
| `initsys.service.add` | `enable_os_boot: true` — registers `fastfirewall-networking` as a oneshot systemd service |
| `initsys.service.remove` | `enable_os_boot: false` — removes the service if it exists |

## Events consumed

| Event | Payload | Action |
|---|---|---|
| _(none)_ | — | Emit `host.sysctl.set` when sysctl changes are needed; the host plugin handles apply and persistence. |

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `networking_state.json` | filename inside `data/` |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` / `_import_state_from_system()` on startup |
| `enable_os_boot` | `false` | register (or remove) a oneshot systemd service that applies networking config at OS boot, before FastFirewall starts |
| `debug` | `false` | log the config path and command; include `debug` key in `POST /apply` response |

## Testing

Tests in `test_networking_api_routes.py`. `ifstatecli` subprocess calls are mocked via `plugin._run_ifstate` — no real system changes are made.

- **`_make_plugin(tmp_path, config=None)` / `_make_client(plugin)`** — creates a fresh isolated instance per test. All tests use this pattern (no shared session fixture).
- Mock `plugin._run_ifstate` with `MagicMock(return_value=_ifstate_ok(...))` before calling `plugin.setup()` to control what `ifstatecli show` returns during boot-time import.
- `_ifstate_ok(stdout, stderr)` and `_ifstate_err(stderr)` are helpers that return `MagicMock` objects with the appropriate `returncode`.
- Boot-state tests write a state JSON file into `tmp_path / "data" / "networking_state.json"` before calling `_make_plugin(tmp_path)`.
