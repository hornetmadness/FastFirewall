# Host Plugin

Manages basic host system configuration via pyinfra `server.*` operations. Routes mount at `/v1/host/`.

**Mutation model: immediate apply.** Every `PUT`/`POST`/`DELETE` mutation calls pyinfra inline and applies the change to the system before returning. There is no `/apply` endpoint — state is always current. Uses `PluginStateFile` with `mutation_model="immediate"`, so `save_desired()` automatically commits `current = desired` and `pending_changes` stays `False` after every mutation.

## Resources

Seven managed resource types, each following the same three-endpoint pattern:

| Resource | List | Mutate | Delete | Import |
|---|---|---|---|---|
| services | `GET /services` | `PUT /services/{name}` | `DELETE /services/{name}` | `POST /services/{name}/import` |
| sysctl | `GET /sysctl` | `PUT /sysctl/{key}` | `DELETE /sysctl/{key}` | `POST /sysctl/{key}/import` |
| users | `GET /users` | `POST /users/{name}` | `DELETE /users/{name}` | `POST /users/{name}/import` |
| groups | `GET /groups` | `POST /groups/{name}` | `DELETE /groups/{name}` | `POST /groups/{name}/import` |
| group members | `GET /groups/{name}/members` | `POST /groups/{name}/members` | `DELETE /groups/{name}/members/{username}` | — |
| cron | `GET /cron` | `POST /cron/{name}` | `DELETE /cron/{name}` | `POST /cron/{name}/import` |
| packages | `GET /packages` | `POST /packages/{name}` | `DELETE /packages/{name}` | `POST /packages/{name}/import` |
| repos | `GET /repos` | `POST /repos/{name}` | `DELETE /repos/{name}` | `POST /repos/import` |

Additional routes: `GET /status`, `GET /tasks`, `GET /hostname`, `PUT /hostname`, `GET /sysctl-all`, `GET /packages/search`, `POST /packages/upgrade-system`.

### Group member management

`GET /groups/{name}/members` — returns all members of the OS group (live read via `grp.getgrnam`), merged with the FF-managed member list. Each entry includes `ff_managed: bool`. Non-existent groups return 404.

`POST /groups/{name}/members` — adds a user to a group via `gpasswd -a`. Requires the group to be FF-managed (imported or created via FF) — returns 404 otherwise. Body: `{"username": "..."}`. Username is validated against `^[a-z_][a-z0-9_-]{0,31}$`.

`DELETE /groups/{name}/members/{username}` — removes a user from a group via `gpasswd -d`. Only removes FF-managed members (tracked in the state file); returns 404 if the username is not in the managed member list.

Groups store their member list in the state file:
```json
"groups": {
  "mygroup": {"system": false, "gid": 1001, "members": ["alice", "bob"]}
}
```

`GET /services`, `GET /sysctl`, `GET /users`, `GET /groups`, `GET /cron`, `GET /repos` all read live system state and merge it with the managed dict, annotating each entry with `ff_managed: bool`. `GET /packages` returns only FF-managed packages (no live system merge).

## State file

`data/host_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "services": {}, "sysctl": {}, "users": {}, "groups": {},
    "cron": {}, "packages": {}, "repos": {}
  },
  "current_state": { ... }
}
```

`desired_state` holds what FF should enforce. `current_state` is committed automatically on every `_save_state()` call (because `mutation_model="immediate"`). `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Key methods

**`_load_state()`** — calls `self._state_file.load_desired(default={})`, then merges the result with `_EMPTY_STATE` defaults. `current_snapshot` is restored automatically so `pending_changes` is accurate immediately.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Because the mutation model is `"immediate"`, this also auto-commits `current = desired` — no separate `commit()` call is needed.

**`_desired_snapshot()`** — returns `json.loads(json.dumps(self._state))`: a normalized deep copy used as the argument to `save_desired()`.

**`_apply_state()`** — re-applies `self._state` on boot via pyinfra. Tracks per-resource success into a local `applied` dict; calls `self._state_file.commit(applied)` at the end so only successfully applied resources appear in `current_state`.

**`_read_system_services()`** — reads live running service state via `systemctl`/`initctl`/`/etc/init.d` depending on the detected init system. Returns `{name: {running, enabled}}`.

## Import endpoints

`POST /{resource}/{name}/import` reads the current system state for that entry, writes it into `self._state`, and calls `_save_state()`. No pyinfra call is made.

Cron import (`POST /cron/{name}/import`) requires a `{"source_key": "..."}` body because cron entries are keyed by a generated path+index string (e.g. `"cron.d/myfile/0"`). Repo import (`POST /repos/import`) requires `{"id": "...", "alias": "..."}`.

## pyinfra

All system mutations go through `self._pyinfra_run(op, **kwargs)`, which serializes the call, runs it in a subprocess via `_pyinfra_worker.py`, and raises `RuntimeError` on non-zero exit. In tests, replace this with `MagicMock` before calling `setup()`.

## `_pkg_manager.py`

`PackageManager` wraps apt/yum/dnf/apk/pacman via pyinfra. `detect_package_manager()` inspects `PATH` to pick the platform. Key methods: `install`, `update`, `remove`, `list_system_packages`, `list_available_packages`, `search_packages`, `apply_repo`, `list_system_repos`, `repo_system_id`, `upgrade_system`.

The package index is cached for `os_pkgmgr_max_cache_ttl_secs` seconds (default 300).

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `host_state.json` | filename inside `data/` |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` on startup |
| `os_pkgmgr_max_cache_ttl_secs` | `300` | package index cache TTL |
| `init.enable_init_script` | `false` | register and enable a service on startup |
| `init.service_name` | `ff-claude` | service name for the init script |
| `init.command` | `uv run /app/app.py` | command to run |
| `init.working_dir` | `null` | working directory |

## Testing

Tests in `test_host_api_routes.py`. Two fixture tiers:

- **`client` / `plugin`** (session fixtures) — a single plugin instance with `_pyinfra_run` mocked, shared across most tests. Fast but stateful; tests that add resources see each other's state.
- **`_make_plugin(tmp_path)` / `_make_client(plugin)`** — creates a fresh isolated instance per test. Use this for persistence, restart, and boot-apply tests.

Boot-state tests write a `_BOOT_STATE` dict (with `desired_state` wrapper) via `_write_boot_state(tmp_path)`, then call `_make_inst(tmp_path)` to get a plugin that hasn't called `setup()` yet, so pyinfra call assertions can be made against `_pyinfra_run.call_args_list` after `plugin.setup()`.
