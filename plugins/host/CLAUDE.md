# Host Plugin

Manages basic host system configuration via pyinfra `server.*` operations. Routes mount at `/v1/host/`.

**Mutation model: immediate apply.** Every `PUT`/`POST`/`DELETE` mutation calls pyinfra inline and applies the change to the system before returning. There is no `/apply` endpoint — state is always current. Uses `PluginStateFile` with `mutation_model="immediate"`, so `save_desired()` automatically commits `current = desired` and `pending_changes` stays `False` after every mutation.

## Resources

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

Additional routes: `GET /status`, `GET /tasks`, `GET /hostname`, `PUT /hostname`, `GET /domainname`, `PUT /domainname`, `DELETE /domainname`, `GET /sysctl-all`, `GET /packages/search`, `POST /packages/upgrade-system`.

### Hostname and domain name

`GET /hostname` — returns `{"hostname": "<short hostname>"}` read live from `socket.gethostname()`.

`PUT /hostname` — sets the system hostname via `server_ops.hostname`. Body: `{"hostname": "..."}` (max 253 chars). Emits `host.hostname.changed`.

`GET /domainname` — returns `{"domainname": "<ff-managed>", "system_domain": "<os-derived>"}`. `domainname` is the FF-managed value (or `null`); `system_domain` is parsed live from `socket.getfqdn()` by stripping the short hostname prefix.

`PUT /domainname` — stores the domain in FF state and applies the full FQDN (`hostname.domainname`) via `server_ops.hostname`. Body: `{"domainname": "..."}` (max 253 chars). Emits `host.domainname.changed` with `{domainname, fqdn}`.

`DELETE /domainname` — clears the managed domain name from state. Returns 404 if none is set. Emits `host.domainname.deleted`.

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

## Macro namespace — `$host`

`HostPlugin` is a `MacroProviderPlugin`. It registers the `host` namespace with three keys:

| Macro | Resolves to |
|---|---|
| `$host.hostname` | `socket.gethostname()` — the short hostname, read live |
| `$host.domainname` | FF-managed domain, falling back to the OS FQDN-derived domain |
| `$host.fqdn` | `hostname.domainname` (or just `hostname` if no domain is set) |

`domainname` appears in `macro_snapshot()` only when a domain is known (FF-managed or OS-detectable). `fqdn` is always present.

## State file

`data/host_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "domainname": "example.com",
    "services": {}, "sysctl": {}, "users": {}, "groups": {},
    "cron": {}, "packages": {}, "repos": {}
  },
  "current_state": { ... }
}
```

`domainname` is a top-level string (not a dict). On first boot (state file absent), `_load_state()` seeds `domainname` from `socket.getfqdn()` so the macro resolves correctly without manual configuration. `desired_state` holds what FF should enforce. `current_state` is committed automatically on every `_save_state()` call (because `mutation_model="immediate"`). `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Key methods

**`_load_state()`** — on first run (file absent), seeds `domainname` from the OS FQDN via `_get_system_domain()` and passes it as the `default` to `load_desired()`, which writes it to disk immediately. On subsequent runs, restores `domainname` from `desired.get("domainname")`. Also merges dict-keyed resources with `_EMPTY_STATE` defaults.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Because the mutation model is `"immediate"`, this also auto-commits `current = desired` — no separate `commit()` call is needed.

**`_desired_snapshot()`** — returns `json.loads(json.dumps(self._state))`: a normalized deep copy used as the argument to `save_desired()`.

**`_apply_state()`** — re-applies `self._state` on boot via pyinfra. Collects all pyinfra-backed resource types (services, sysctl, users, groups, cron) into a single batch and calls `_pyinfra_run_many` once. Each operation's result is tracked individually; `self._state_file.commit(applied)` is called at the end — `applied` includes `domainname` so `pending_changes` stays `False` after boot.

**`_get_system_domain()`** — static; parses `socket.getfqdn()` and strips the leading `hostname.` prefix. Returns `None` if the FQDN equals the short hostname (no domain detectable).

**`_resolve_host_macro(*segments)`** — the `$host` namespace resolver. Dispatches on `segments[0]` to return `hostname`, `domainname`, or `fqdn`.

**`macro_snapshot()`** — returns `{"host": {"hostname": ..., "domainname": ..., "fqdn": ...}}` for `--show-macros` / `GET /v1/macros`. `domainname` is only included when a domain is known.

**`_pyinfra_run_many(ops)`** — runs a batch of `(op, kwargs)` pairs in a single worker subprocess via `pyinfra_run_batch`. Returns `list[(success, error_or_None)]`, one entry per input operation.

**`_read_system_services()`** — reads live running service state via `systemctl`/`initctl`/`/etc/init.d` depending on the detected init system. Returns `{name: {running, enabled}}`.

## Import endpoints

`POST /{resource}/{name}/import` reads the current system state for that entry, writes it into `self._state`, and calls `_save_state()`. No pyinfra call is made.

Cron import (`POST /cron/{name}/import`) requires a `{"source_key": "..."}` body because cron entries are keyed by a generated path+index string (e.g. `"cron.d/myfile/0"`). Repo import (`POST /repos/import`) requires `{"id": "...", "alias": "..."}`.

## pyinfra

All single-operation mutations go through `self._pyinfra_run(op, **kwargs)`, which delegates to `pyinfra_run_batch` with a one-item list and raises `RuntimeError` if the operation fails.

Boot-time batch operations go through `self._pyinfra_run_many(ops)`, which takes a list of `(op, kwargs)` pairs, serializes them all, and dispatches a single `pyinfra_run_batch` call so Python startup and pyinfra import cost is paid once. Returns `list[(success, error_or_None)]`.

In tests, replace both with `MagicMock` before calling `setup()`:
```python
plugin._pyinfra_run = MagicMock()
plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
```

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

## Events emitted

| Event | Payload |
|---|---|
| `host.hostname.changed` | `{hostname}` |
| `host.domainname.changed` | `{domainname, fqdn}` |
| `host.domainname.deleted` | `{domainname}` |
| `host.sysctl.changed` | `{key, value, persist}` |
| `host.sysctl.deleted` | `{key}` |
| `host.user.changed` | `{user, shell, home_dir, system, comment}` |
| `host.user.deleted` | `{user}` |
| `host.group.changed` | `{group, system, gid}` |
| `host.group.deleted` | `{group}` |
| `host.cron.changed` | `{name, command, minute, hour, ...}` |
| `host.cron.deleted` | `{name}` |

## Events consumed

| Event | Payload | Action |
|---|---|---|
| `host.sysctl.set` | `{key, value, persist=true}` | Applies the sysctl via pyinfra (`server_ops.sysctl`), saves it to managed state, and emits `host.sysctl.changed`. Any plugin may emit this instead of calling `sysctl` directly. On failure, logs the error and leaves state unchanged. |

## Testing

Tests in `test_host_api_routes.py`. Two fixture tiers:

- **`client` / `plugin`** (session fixtures) — a single plugin instance with `_pyinfra_run` mocked, shared across most tests. Fast but stateful; tests that add resources see each other's state.
- **`_make_plugin(tmp_path)` / `_make_client(plugin)`** — creates a fresh isolated instance per test. Use this for persistence, restart, and boot-apply tests.

Boot-state tests write a `_BOOT_STATE` dict (with `desired_state` wrapper) via `_write_boot_state(tmp_path)`, then call `_make_inst(tmp_path)` to get a plugin that hasn't called `setup()` yet. `_make_inst` mocks both `_pyinfra_run` and `_pyinfra_run_many`. Since `_apply_state` batches all ops into one `_pyinfra_run_many` call, boot-time assertions inspect `_pyinfra_run_many.call_args[0][0]` (the batch list) rather than `_pyinfra_run.call_args_list`.
