# Networking Plugin

Manages network interfaces, routes, and kernel sysctl settings declaratively via **ifstate** (`ifstatecli`). Desired state is stored in a JSON file; call `POST /apply` to push it to the running kernel. Routes mount at `/v1/networking/`.

**Mutation model: deferred apply.** Every `PUT`/`POST`/`DELETE` mutation only updates the desired-state dict and saves it to disk — nothing is applied to the kernel until `POST /apply` is called. Uses `PluginStateFile` with `mutation_model="deferred"`, so `save_desired()` only writes desired state; `commit()` is called explicitly after a successful apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

Depends on: `host` plugin.

## Resources

Three managed resource types:

| Resource | List | Mutate | Delete | Import |
|---|---|---|---|---|
| interfaces | `GET /config/interfaces` | `PUT /config/interfaces/{name}` | `DELETE /config/interfaces/{name}` | `POST /config/interfaces/import` |
| routes | `GET /config/routes` | `POST /config/routes` | `DELETE /config/routes/{route_id}` | `POST /config/routes/import` |
| sysctl | `GET /config/sysctl` | `PUT /config/sysctl/{key}` | `DELETE /config/sysctl/{key}` | — |

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
    "sysctl": {}
  },
  "current_state": {
    "interfaces": {},
    "routes": {},
    "sysctl": {}
  }
}
```

`desired_state` holds what FF should enforce. `current_state` is committed only after a successful `POST /apply` or boot-time apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Key methods

**`_load_state()`** — calls `self._state_file.load_desired(default={})`, then reads `interfaces`, `routes`, `sysctl` from the result into `self._interfaces`, `self._routes`, `self._sysctl`. `current_snapshot` is restored automatically from the on-disk `current_state`.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Does **not** update `current_state` — that only happens via `commit()`.

**`_desired_snapshot()`** — returns `json.loads(json.dumps({interfaces, routes, sysctl}))`: a normalized deep copy used for diffing and snapshotting.

**`_apply_state()`** — re-applies desired state on boot via `ifstatecli apply`. Calls `self._state_file.commit(self._desired_snapshot())` on success.

**`_import_state_from_system()`** — called at boot when the state file is empty; seeds `_interfaces` and `_routes` from `ifstatecli show` output, then calls `self._state_file.save_and_commit(self._desired_snapshot())` so desired and current start identical.

**`_build_ifstate_yaml()`** — serializes `_interfaces`, `_routes`, and `_sysctl` into the YAML format expected by ifstatecli.

**`_run_ifstate(*args)`** — runs `sudo uv run ifstatecli <args>` as a subprocess.

## `GET /config/diff`

Returns a structured diff between the last applied state (`current_snapshot`) and the current desired state. Response: `{pending_changes: bool, diff: {...}}`. The `diff` is computed by `_diff_state(current, desired)`. If nothing has ever been applied (`current_snapshot` is `None`), treats current as `{}`.

## `POST /discard`

Reverts `_interfaces`, `_routes`, `_sysctl` back to `self._state_file.current_snapshot`. If `current_snapshot` is `None` (never applied), raises 409.

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
| `networking.sysctl.changed` | `{key, value}` |
| `networking.sysctl.removed` | `{key}` |
| `networking.applied` | `{success, returncode}` |

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `networking_state.json` | filename inside `data/` |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` / `_import_state_from_system()` on startup |
| `debug` | `false` | log the temp config path and command; include `debug` key in `POST /apply` response |

## Testing

Tests in `test_networking_api_routes.py`. `ifstatecli` subprocess calls are mocked via `plugin._run_ifstate` — no real system changes are made.

- **`_make_plugin(tmp_path, config=None)` / `_make_client(plugin)`** — creates a fresh isolated instance per test. All tests use this pattern (no shared session fixture).
- Mock `plugin._run_ifstate` with `MagicMock(return_value=_ifstate_ok(...))` before calling `plugin.setup()` to control what `ifstatecli show` returns during boot-time import.
- `_ifstate_ok(stdout, stderr)` and `_ifstate_err(stderr)` are helpers that return `MagicMock` objects with the appropriate `returncode`.
- Boot-state tests write a state JSON file into `tmp_path / "data" / "networking_state.json"` before calling `_make_plugin(tmp_path)`.
