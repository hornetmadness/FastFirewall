# Package Management Plugin

Manages OS packages, repositories, and system services via pyinfra. Routes mount at `/v1/pkg_management/`.

**Mutation model: immediate apply.** Every `POST`/`PUT`/`DELETE` mutation calls pyinfra inline and applies the change before returning. There is no `/apply` endpoint. Uses `PluginStateFile` with `mutation_model="immediate"`, so `save_desired()` automatically commits `current = desired` and `pending_changes` stays `False` after every mutation.

`PkgManagementPlugin` composes a `PkgManagementAPI(ApiRouterAspect)` aspect (`api = PkgManagementAPI`, taking over what was `_register_routes()`), instantiated by the loader after `configure()` runs. `configure()` builds the state file, `_bg_tasks`, and `_pkg_mgr`, and loads `_state` (or resets it to empty when `ignore_state_on_boot`). `setup()` only runs `_apply_state()` (when not `ignore_state_on_boot`) and subscribes the `pkg_management.add.*` event handlers; `teardown()` unsubscribes them and saves state, unchanged from before.

## Resources

Three managed resource types, each following the same three-endpoint pattern:

| Resource | List | Mutate | Delete | Import |
|---|---|---|---|---|
| services | `GET /services` | `PUT /services/{name}` | `DELETE /services/{name}` | `POST /services/{name}/import` |
| packages | `GET /packages` | `POST /packages/{name}` | `DELETE /packages/{name}` | `POST /packages/{name}/import` |
| repos | `GET /repos` | `POST /repos/{name}` | `DELETE /repos/{name}` | `POST /repos/import` |

Additional routes: `GET /status`, `GET /tasks`, `GET /packages/search`, `POST /packages/upgrade-system`.

`GET /services` and `GET /repos` read live system state and merge it with the managed dict, annotating each entry with `ff_managed: bool`. `GET /packages` returns only FF-managed packages by default; pass `?mode=installed` or `?mode=available` for broader views.

## Events consumed

Other plugins trigger actions by emitting these events. The plugin subscribes at `setup()` and unsubscribes at `teardown()` using stable bound-method references (`self._handler_*`) to satisfy the bus's `is`-identity check on unsubscribe.

| Event | Required payload | Optional payload |
|---|---|---|
| `pkg_management.add.package` | `name` | `present` (default `true`), `latest` (default `false`) |
| `pkg_management.add.repo` | `name` + any `RepoBody` fields | — |
| `pkg_management.add.service` | `service` | `running` (default `true`), `enabled` (default `true`) |

Errors (missing fields, pyinfra failures) are logged and swallowed — they never propagate to the emitter.

## Events emitted

| Event | Payload |
|---|---|
| `pkg_management.service.changed` | `{service, running, enabled}` |
| `pkg_management.service.deleted` | `{service}` |
| `pkg_management.package.changed` | `{package, present, latest, platform}` |
| `pkg_management.package.updated` | `{package, platform}` |
| `pkg_management.package.deleted` | `{package, platform}` |
| `pkg_management.repo.changed` | `{repo, platform, ...RepoBody fields}` |
| `pkg_management.repo.deleted` | `{repo, platform}` |
| `pkg_management.package.upgrade-system.started` | `{task_id, email, platform}` |
| `pkg_management.package.upgrade-system.done` | `{platform, returncode, email}` |
| `smtp.send` | `{to, subject, body}` — consumed by the smtp plugin |

## State file

`data/pkg_management_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "services": {}, "packages": {}, "repos": {}
  },
  "current_state": { ... }
}
```

`desired_state` is what FF should enforce. `current_state` is committed automatically on every `_save_state()` call (immediate model). `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Key methods

**`_load_state()`** — calls `self._state_file.load_desired(default={})`, merges the result with `_EMPTY_STATE` defaults. `current_snapshot` is restored automatically so `pending_changes` is accurate immediately.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Because the mutation model is `"immediate"`, this also auto-commits `current = desired`.

**`_desired_snapshot()`** — returns `json.loads(json.dumps(self._state))`: a normalized deep copy used as the argument to `save_desired()`.

**`_apply_state()`** — re-applies state on boot. Services are batched into a single `_pyinfra_run_many` call; packages and repos are applied individually via `_pkg_mgr` (which has its own pyinfra subprocess per call). Only successfully applied resources are written to `current_state` via `self._state_file.commit(applied)`.

**`_read_system_services()`** — detects the init system (systemd / upstart / sysvinit) and returns `{name: {running, enabled}}` from live OS state.

**`_repo_id(sys_key)`** — SHA-256 (first 8 hex chars) of a repo's system key; used as a stable identifier in the import endpoint.

## `_pkg_manager.py`

`PackageManager` wraps apt/yum/dnf/apk/pacman via pyinfra. `detect_package_manager()` inspects `PATH` to pick the platform. Key methods: `install`, `update`, `remove`, `list_system_packages`, `list_available_packages`, `search_packages`, `apply_repo`, `list_system_repos`, `repo_system_id`, `upgrade_system`, `assert_supported`.

The package index is cached for `os_pkgmgr_max_cache_ttl_secs` seconds (default 300). `assert_supported()` raises HTTP 501 on unsupported platforms.

**`RepoBody` fields relevant to apt:**

| Field | Type | Purpose |
|---|---|---|
| `src` | `str` | Full `deb [...]` line for `sources.list.d` |
| `filename` | `str` | Filename (without `.list`) under `/etc/apt/sources.list.d/` |
| `key_url` | `str` | URL of the GPG key to import via `apt_ops.key` |
| `key_dest` | `str \| None` | Destination path for the dearmored key (e.g. `/usr/share/keyrings/vendor.gpg`). Passed as `dest` to `apt_ops.key`; requires `gpg` to be installed. If `None`, pyinfra uses its default key location. |

`apply_repo` for apt: imports the GPG key (`apt_ops.key`) if `key_url` is set, adds/removes the repo (`apt_ops.repo`), then refreshes the cache (`apt_ops.update`) if `body.present` is true.

## Import endpoints

`POST /services/{name}/import` — reads live system state for the service, writes it to `self._state`, calls `_save_state()`. No pyinfra call.

`POST /packages/{name}/import` — confirms the package is installed via `list_system_packages()`, records `{present: true, latest: false}` in state. No pyinfra call.

`POST /repos/import` — body: `{"id": "<8-char sha>", "alias": "<name>"}`. Matches the id against `list_system_repos()`, records state under `alias`. No pyinfra call.

## pyinfra

All single-operation mutations go through `self._pyinfra_run(op, **kwargs)`, which delegates to `pyinfra_run_batch` with a one-item list and raises `RuntimeError` on failure.

Boot-time service ops go through `self._pyinfra_run_many(ops)`, which batches all `(op, kwargs)` pairs into a single subprocess call. Returns `list[(success, error_or_None)]`.

In tests, replace both with `MagicMock` before calling `setup()`:
```python
plugin._pyinfra_run = MagicMock()
plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
```

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `pkg_management_state.json` | filename inside `data/` |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` on startup |
| `os_pkgmgr_max_cache_ttl_secs` | `300` | package index cache TTL (0 = always refresh) |

`plugin_requirements: ["smtp", "audit"]` — smtp is recommended so `smtp.send` events from `POST /packages/upgrade-system` are delivered; audit provides audit logging.

## Testing

Tests in `test_pkg_management_api_routes.py`. Two fixture tiers:

- **`client` / `plugin`** (session fixtures) — a single plugin instance with `_pyinfra_run` mocked, shared across most tests. Fast but stateful.
- **`_make_plugin(tmp_path, config=None, system_repos=None)`** — creates a fresh isolated instance per test. Use for persistence, restart, boot-apply, and event-handler tests.

Each `_make_plugin` call uses a unique logger (`logging.getLogger(f"test.pkg_management.{id(plugin)}")`) so `patch.object(plugin.logger, "error")` doesn't bleed across tests when multiple plugin instances remain subscribed to the global bus.

`_make_plugin` calls `plugin.configure()`, sets `plugin.api = mod.PkgManagementAPI(plugin)`, then `plugin.setup()` — mirroring `PluginLoader._instantiate_aspects`. `_make_client` mounts `plugin.api.router` (not `plugin.router`).

Boot-state tests write a `_BOOT_STATE` dict via `_write_boot_state(tmp_path)`, then call `_make_inst(tmp_path)` to get a plugin that hasn't called `configure()`/`setup()` yet — tests call `plugin.configure()` then `plugin.setup()` explicitly. Since `_apply_state` batches service ops into one `_pyinfra_run_many` call, boot-time assertions inspect `_pyinfra_run_many.call_args[0][0]` (the batch list) for services, and `_pyinfra_run.call_args_list` for packages/repos.

Event-handler tests call `plugin.teardown()` in a `finally` block to unsubscribe from the global bus and prevent cross-test leakage.
