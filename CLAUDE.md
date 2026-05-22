# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Coding conventions

- All imports go at the module level — never inside functions or methods.

### Error handling in plugins

Never put internal details into `HTTPException` response bodies. Subprocess stderr, exception messages, and internal file paths must stay server-side.

**Correct pattern — subprocess failure:**
```python
if result.returncode != 0:
    self.logger.error("nft apply failed: %s", result.stderr.strip())
    raise HTTPException(500, "Failed to apply firewall rules; check server logs")
```

**Correct pattern — caught exception:**
```python
except Exception as exc:
    self.logger.error("Config reload failed", exc_info=True)
    raise HTTPException(500, "Config reload failed; check server logs") from exc
```

**Wrong — leaks internals to the caller:**
```python
raise HTTPException(500, str(exc))                          # exception message
raise HTTPException(500, f"nft failed: {result.stderr}")    # subprocess stderr
```

`4xx` errors (Not Found, Conflict, Validation) may and should include the specific reason — those describe a client mistake, not a server-side failure. Only `5xx` responses need sanitizing.

### Pydantic model conventions

Every request body field must have a `max_length` constraint. Use `Field(max_length=N)` — never leave a bare `str` without a bound. Standard limits:

| Field type | Limit |
|---|---|
| Names, labels | `max_length=100` |
| Comments, GECOS | `max_length=255` |
| Hostnames / DNS names | `max_length=253` |
| IP addresses | `max_length=39` |
| CIDR ranges | `max_length=43` |
| Linux interface names | `max_length=15` |
| File / socket paths | `max_length=4096` |
| URLs | `max_length=2048` |
| Email addresses | `max_length=254` |
| Sysctl values | `max_length=64` |
| Short enum-like strings (modes, frequencies) | `max_length=8`–`32` |

For `list[str]` fields, constrain the element type with `Annotated`:
```python
from typing import Annotated
from pydantic import Field

addresses: list[Annotated[str, Field(max_length=39)]] | None = None
```

Response-only models (never received as input) do not need `max_length`.

### Plugin dependency installation

Plugins declare OS packages in `os_requirements` in `plugin.yaml`. The loader installs them automatically via pyinfra before calling `setup()`. **Never emit `pkg_management.add.package` to install a plugin's own dependencies.** That event is for runtime package management requested by users or other plugins — not for bootstrapping a plugin's own packages.

```yaml
# Correct — loader installs these before setup() is called
os_requirements:
  - fluent-bit
  - logrotate
```

```python
# Wrong — do not emit this event to install your own package
bus.emit(Event("pkg_management.add.package", source=self.plugin_id, payload={"name": "fluent-bit"}))
```

**Third-party repos** are a different matter. If a plugin's `os_requirements` package lives in a repo that is not in the default apt/yum/dnf sources, the plugin must register that repo *before* the loader installs `os_requirements`. Do this by emitting `pkg_management.add.repo` from `__init__` (not `setup()`), so the repo is added before the loader proceeds to package installation:

```python
def __init__(self) -> None:
    super().__init__()
    # repo must exist before the loader installs os_requirements
    bus.emit(Event("pkg_management.add.repo", source="myplugin", payload={
        "name": "vendor-repo",
        "key_url": "https://vendor.example.com/gpg.key",
        "key_dest": "/usr/share/keyrings/vendor.gpg",
        "src": "deb [signed-by=/usr/share/keyrings/vendor.gpg] https://vendor.example.com/apt stable main",
        "filename": "vendor",
    }))
```

Do **not** also emit the repo event from `setup()` — `__init__` already covered it and a second emission causes `apt update` to run again unnecessarily.

## Working style

- Never ask the user to edit `test_*` files — make all test changes directly.
- When committing, never silently exclude modified files. If there are changed files beyond what was directly touched, ask the user whether to include them in the same commit, a separate one, or leave them unstaged.

## Commands

```bash
# Run the dev server (reload enabled by default in app_config.yaml)
uv run python app.py

# Run with only specific plugins loaded
uv run python app.py --plugin firewall --plugin dns

# List all plugins and their enabled state
uv run python app.py --list-plugins

# Show all macro namespaces and their current resolved values, then exit
uv run python app.py --show-macros

# Enable or disable a plugin (edits plugin.yaml, then exits)
uv run python app.py --enable-plugin syslog
uv run python app.py --disable-plugin syslog

# Show all CLI options
uv run python app.py --help

# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_core/test_events.py

# Run a single test by name
uv run pytest tests/test_core/test_events.py::test_subscribe_and_emit

# Run plugin-local tests (also collected automatically by pytest)
uv run pytest plugins/firewall/test_firewall_api_routes.py

# Run pyright type checking
uv run --with pyright pyright

# Install dependencies (uses uv.lock)
uv sync

# Install with dev extras
uv sync --extra dev
```

The OpenAPI docs are available at `http://localhost:8000/docs` when the server is running.

CLI argument parsing and all management commands (`--list-plugins`, `--show-macros`, `--enable-plugin`, `--disable-plugin`, `--help`) are handled by `plugin_system/manager_cli.py`. `app.py` calls `manager_cli.run(loader, plugins_dir)` which either exits after handling a pre-load command or returns `(only, ignore_states, show_macros)` for normal startup. `--show-macros` is a post-load command: `run()` signals it via the third return value, `app.py` calls `load_directory(skip_requirements=True)` to populate the macro registry without installing packages, then calls `manager_cli.print_macros(loader)` and exits. `manager_cli.get_macros(loader)` returns the same data as a plain dict and is used by `GET /v1/macros`.

## Architecture

This is a **FastAPI application driven entirely by plugins**. The app itself (`app.py`) has no routes of its own — all API surface comes from plugins loaded at startup.

### Boot sequence

1. `AppConfig.load()` reads `app_config.yaml` into typed dataclasses. `configure_state()` is called immediately after to apply backup settings before any plugin runs.
2. `manager_cli.run(loader, plugins_dir)` parses CLI args; exits early for management commands, otherwise returns an optional plugin allow-list.
3. `PluginLoader.load_directory()` scans the configured `plugins/` directory and derives load order via topological sort of `plugin_requirements` (dependencies before dependents; alphabetical tiebreaker). Pass `only=[...]` to restrict which plugins are loaded; transitive dependencies are included automatically. If a plugin fails to load, all plugins that depend on it (directly or transitively) are skipped rather than erroring out.
4. For each plugin directory with a `plugin.yaml` + `plugin.py`: the loader imports the module, instantiates any `PluginBase` subclass, wires up event handlers, calls `setup()`, then mounts FastAPI routes if the plugin is an `ApiRouterPlugin` and registers macro namespaces if the plugin is a `MacroProviderPlugin`. **Instantiation (calling `__init__`) happens before `os_requirements` are installed** — plugins that need a third-party apt/yum/dnf repo for their `os_requirements` package must emit `pkg_management.add.repo` from `__init__` so the repo exists when the loader proceeds to install packages.
5. After all plugins are loaded, the loader populates `macro_registry` with the aggregated `service_port` data (ports with `-1`-only entries are omitted), then emits `plugins.all_loaded` on the bus.
6. A `plugin.loaded` event is emitted on the bus after each individual plugin loads.

### Plugin anatomy

Every plugin is a directory under `plugins/` with two required files:

**`plugin.yaml`** — metadata and config:
- `id`, `name`, `version`, `author`, `description`
- `enabled` (default `true`)
- `plugin_requirements` — list of other plugin ids this depends on; determines load order
- `py_requirements` / `os_requirements` — installed at load time via pyinfra
- `service_ports` **(required)** — declares which ports the plugin listens on. Must be `-1` (no ports) or a dict keyed by service name matching the plugin's declared `services`:
  ```yaml
  service_ports:
    smtp:
      tcp: [25, 587, 465]   # use -1 as the port value when the service has no real ports
  ```
  Keys must exactly match the `Service` enum values the plugin claims. The loader validates this at load time, checks for conflicts with other loaded plugins, and checks the OS isn't already using the port (reads `/proc/net/tcp`, `/proc/net/udp`).
- `skip_host_os_port_check` (default `false`) — set to `true` for plugins that manage a service already running on the host (e.g. Postfix, rsyslog). Skips the OS port-in-use check; inter-plugin port conflict check still runs.
- `config` — arbitrary dict passed to the plugin instance as `self.config`

**`plugin.py`** — must contain either a `PluginBase` subclass or decorated module-level functions (or both).

### Plugin base classes

`PluginBase` (`plugin_system/core/plugin_base.py`) — inherit to get lifecycle hooks:
- `setup()` — called once after loading; use it to read config, register routes, open resources
- `teardown()` — called on unload; persist state, close connections
- Instance attributes set by the loader before `setup()`: `self.config`, `self.meta`, `self.plugin_id`, `self.plugin_dir`, `self.logger`

`ApiRouterPlugin` (`plugin_system/core/api_router_plugin.py`) — mixin for plugins that contribute API routes. Must also inherit `PluginBase`:
```python
class MyPlugin(PluginBase, ApiRouterPlugin):
    services = [Service.DNS]     # exclusive ownership claim
```
The loader mounts `self.router` at `/v1/<plugin_id>/`. Add routes to `self.router` inside `setup()`.

`MacroProviderPlugin` (`plugin_system/core/macro_provider_plugin.py`) — mixin for plugins that expose one or more macro namespaces. Must also inherit `PluginBase`. Call `self.add_macro_namespace(name, resolver)` inside `setup()` for each namespace the plugin owns — analogous to adding routes to `self.router`:
```python
class NetworkingPlugin(PluginBase, ApiRouterPlugin, MacroProviderPlugin):
    services = [Service.NETWORKING]

    def setup(self):
        self.add_macro_namespace("interface", self._resolve_interface_macro)
        # a plugin can register multiple namespaces

    def _resolve_interface_macro(self, *segments: str) -> Any:
        # segments[0] = alias name, segments[1] = "name" | "address" | "net_addr"
        if len(segments) < 2:
            return None
        device = self._aliases.get(segments[0])
        if device is None:
            return None
        if segments[1] == "name":
            return device
        if segments[1] == "address":
            return [str(ipaddress.ip_interface(a).ip)
                    for a in self._interfaces.get(device, {}).get("addresses", [])]
        if segments[1] == "net_addr":
            return [str(ipaddress.ip_interface(a).network)
                    for a in self._interfaces.get(device, {}).get("addresses", [])]
        return None

    def macro_snapshot(self) -> dict[str, dict[str, Any]]:
        # optional — override to expose current entries for --show-macros / GET /v1/macros
        entries: dict[str, Any] = {}
        for alias, device in self._aliases.items():
            entries[f"{alias}.name"] = device
            addrs = [str(ipaddress.ip_interface(a).ip)
                     for a in self._interfaces.get(device, {}).get("addresses", [])]
            if addrs:
                entries[f"{alias}.address"] = addrs
            nets = [str(ipaddress.ip_interface(a).network)
                    for a in self._interfaces.get(device, {}).get("addresses", [])]
            if nets:
                entries[f"{alias}.net_addr"] = nets
        return {"interface": entries}
```
After `setup()` the loader calls `macro_registry.register_namespace(name, resolver)` for every namespace the plugin declared. On unload each namespace is unregistered. Both `ApiRouterPlugin` and `MacroProviderPlugin` use cooperative `__init__` (`super().__init__()`), so multiple mixins compose correctly.

### Service exclusivity

`Service` (`plugin_system/core/services.py`) is a `str` enum of well-known network-appliance services (`FIREWALL`, `DNS`, `DHCP`, `HOST`, `NETWORKING`, `PKG_MANAGEMENT`, `PKG_CACHE`, `MONITORING`, etc.). Only one plugin may claim a given `Service` at a time; the loader raises `PluginError` if a second plugin tries to claim an already-owned service.

### Event bus

The module-level singleton `bus` (`plugin_system/core/events.py`) is the shared channel. Plugins import it directly:

```python
from plugin_system.core.events import bus, Event
```

**Subscribing** — use decorators in `plugin.py` (wired up automatically by the loader):
```python
from plugin_system.core.decorators import on, on_any

@on("firewall.rule.added")
def handle(event: Event): ...

@on("order.placed", "order.updated")   # multiple events
async def handle(event: Event): ...

@on_any
def log_everything(event: Event): ...  # wildcard
```

Decorators also work on `PluginBase` instance methods.

**Emitting:**
```python
bus.emit(Event("firewall.rule.added", source=self.plugin_id, payload={"rule_id": rule.id}))
await bus.emit_async(event)   # awaits async handlers; prefer in async contexts
```

`emit()` is fire-and-forget for async handlers (scheduled as a task on the running loop, or run via `asyncio.run` if no loop exists). `emit_async()` awaits each handler.

The bus auto-injects the emitting plugin's `services` list into `event.payload` unless the caller already set a `"services"` key.

### Macro system

`macro_registry` (`plugin_system/core/macros.py`) is the module-level singleton that stores all macro namespaces. Plugins and rules reference macros with `$namespace.segment[.segment...]` syntax (e.g. `$service_port.dns.udp`, `$interface.lan.name`, `$interface.lan.address`, `$interface.lan.net_addr`).

**Built-in namespace — `service_port`**

Populated by the loader after all plugins finish loading. Keys come from each plugin's `service_ports` in `plugin.yaml`; protocols with all-`-1` port values are omitted. Example: `$service_port.dns.udp` → `[53]`.

**Plugin-defined namespaces**

Populated by `MacroProviderPlugin` subclasses (see Plugin base classes above). The loader calls `macro_registry.register_namespace(name, resolver)` after `setup()` for each namespace the plugin declared. On unload, each namespace is unregistered.

**Resolution API**

```python
from plugin_system.core.macros import macro_registry

# Resolve to a list of port integers (also accepts a bare int)
ports: list[int] = macro_registry.resolve_ports("$service_port.dns.udp")   # → [53]

# Resolve to a string (string-valued macros only)
name: str | None = macro_registry.resolve_string("$interface.lan.name")    # → "enp0s25"

# Resolve without type coercion — returns the raw value from the resolver
raw: Any = macro_registry.resolve("$interface.lan.address")                # → ["192.168.0.1"]

# All currently registered namespaces
namespaces: list[str] = macro_registry.namespaces   # e.g. ["service_port", "interface"]
```

`resolve_ports` returns `[]` and `resolve_string` / `resolve` return `None` for unknown macros or malformed syntax — callers should treat these as "unresolvable" rather than errors.

`resolve_ports` caches results for the `service_port` namespace (the hot path in firewall rule compilation) in an internal dict and invalidates it on `register_namespace`, `unregister_namespace`, and `set_service_ports`. Plugin-defined namespace results (e.g. `$interface.*`) are **not** cached because their resolvers read live plugin state that can change without a `register_namespace` call.

**Testing with macros**

Tests that exercise port-based rules must seed the registry before the call and clean up after:

```python
from plugin_system.core.macros import macro_registry

macro_registry.set_service_ports({"dns": {"udp": [53]}})
try:
    # ... test code
finally:
    macro_registry.set_service_ports({})
```

For plugin-defined namespaces, use `register_namespace` / `unregister_namespace`:

```python
macro_registry.register_namespace(
    "interface",
    lambda *s: "enp0s25" if s == ("lan", "name") else
               ["192.168.0.1"] if s == ("lan", "address") else None,
)
try:
    # ... test code
finally:
    macro_registry.unregister_namespace("interface")
```

### PluginLoader management API

Beyond `load_plugin` / `unload_plugin`, `PluginLoader` exposes two read/write helpers that do not load or execute any plugin code:

- `list_plugins(directory)` — scans `directory` and returns a list of dicts with `id`, `name`, `version`, `description`, `author`, `enabled`, `plugin_requirements`, `service_ports` for every discovered plugin, sorted in topological load order.
- `set_plugin_enabled(directory, plugin_id, enabled)` — finds the plugin by id, sets the `enabled` field in its `plugin.yaml`, and writes it back. Raises `PluginError` if the plugin is not found.

`load_directory(directory, only=None, skip_requirements=False)` and `load_plugin(path, skip_requirements=False)` accept a `skip_requirements` flag. When `True`, the loader skips pyinfra `py_requirements` / `os_requirements` installation. Use this for CLI-only loads (e.g. `--show-macros`) where populating runtime state is needed but installing packages is a side-effect you want to avoid.

`load_plugin(path)` auto-loads any missing `plugin_requirements` it finds as sibling directories before loading the requested plugin. Circular dependencies are detected via `_loading: set[str]` (plugin ids currently mid-load) and raise `PluginError` immediately.

`load_directory` tracks which plugins failed to load in a `failed` set and silently skips any plugin whose dependency is in that set, logging a warning rather than propagating the error.

`PluginLoader` maintains two runtime registries updated on every load/unload:
- `service_registry` — `{Service → plugin_id}`: which plugin owns each service
- `_port_registry` — `{(proto, port) → plugin_id}`: which plugin has claimed each port; port `-1` is never registered

### Dependency installation

Plugins can declare `py_requirements` (pip packages) and `os_requirements` (system packages) in `plugin.yaml`. The loader installs them at load time using **pyinfra** running against `@local`.

**Pyinfra worker subprocess**

Plugins that write privileged files via pyinfra (e.g. host, syslog, apt_cacher_ng) must not call pyinfra directly from the FastAPI process — pyinfra's gevent monkey-patching conflicts with anyio. Instead they call `pyinfra_run_batch`, which serializes one or more operations and sends them to a single worker subprocess:

```python
from infra import pyinfra_run_batch

norm_kwargs = {
    k: ("__stringio__", v.getvalue()) if isinstance(v, io.StringIO) else v
    for k, v in kwargs.items()
}
results = pyinfra_run_batch([(op.__module__, op.__name__, norm_kwargs)])
success, err = results[0]
if not success:
    raise RuntimeError(f"pyinfra '{op.__name__}' failed:\n{err}")
```

`infra/pyinfra_worker.py` is the single canonical worker. It reads a **list** of `(op_module, op_name, norm_kwargs)` tuples from stdin, runs each operation independently (a failure in one does not abort the rest), and writes a list of `(success, error_or_None)` results to stdout. The worker always exits 0; per-operation errors are reported in the result list, not via exit code. When an exception has an empty `str()`, the error falls back to `type(exc).__name__` so callers always get a non-empty error string.

`pyinfra_run_batch(ops)` in `infra/__init__.py` is the shared entry point. It spawns the worker, handles catastrophic startup failure (non-zero exit → all ops failed), and returns the result list. When the worker exits 0 but any operation failed, any stderr the worker emitted is appended to the error strings of the failed operations — so pyinfra's own diagnostic output (e.g. `gpg: not found`) surfaces to the caller. Never create per-plugin subprocess logic — use `pyinfra_run_batch` directly.

Plugins that apply many operations at boot (e.g. `HostPlugin._apply_state`) build a single batch list and call `_pyinfra_run_many`, so Python startup and the full pyinfra import happen once per boot cycle instead of once per operation.

### Testing

Tests live in two places and are both collected by pytest automatically (see `testpaths` in `pyproject.toml`):

- `tests/` — core unit tests (`test_events`, `test_decorators`, `test_loader`) and integration tests (`test_api/test_routes.py`)
- `plugins/<name>/test_*.py` — plugin-local route and behaviour tests (currently `firewall` and `host`)

**Plugin test pattern — direct load (firewall)**

Plugin route tests do *not* go through `PluginLoader`. They import the plugin module directly via `importlib`, instantiate the plugin class, set the loader-injected attributes (`plugin_id`, `meta`, `config`, `plugin_dir`, `logger`) by hand, call `setup()`, then mount `instance.router` onto a fresh `FastAPI()` and wrap it in `TestClient`. This sidesteps pyinfra dependency installation while still running real production code.

```python
inst = mod.FirewallPlugin()
inst.plugin_id = "firewall"
inst.meta = {...}
inst.config = {"rules_file": "rules.json", ...}
inst.plugin_dir = tmp_path
inst.logger = logging.getLogger("test")
inst.setup()
app = FastAPI()
app.include_router(inst.router, prefix="/v1/firewall")
client = TestClient(app)
```

Use `tmp_path` for any file-backed state (e.g. `rules_file`, `state_file`) so tests are isolated. Plugins that persist state write into a `data/` subdirectory of `plugin_dir` (e.g. `tmp_path / "data" / "rules.json"`); the subdirectory is created automatically on first save.

**Plugin test pattern — pyinfra mocking (host, syslog, apt_cacher_ng)**

For plugins that call `_pyinfra_run`, replace it with `MagicMock` after instantiation and before `setup()`. For the host plugin also mock `_pyinfra_run_many` (used by `_apply_state` to batch boot-time ops). Then assert on `call_args` to verify the correct pyinfra op and kwargs were used without touching the real system:

```python
plugin._pyinfra_run = MagicMock()
# host plugin only — _apply_state uses _pyinfra_run_many for batch boot ops
plugin._pyinfra_run_many = MagicMock(side_effect=lambda ops: [(True, None)] * len(ops))
plugin.setup()
# ...
args, kwargs = plugin._pyinfra_run.call_args
assert args[0] is server_ops.hostname
assert kwargs["hostname"] == "mybox.example.com"
```

**PluginLoader integration tests (`tests/test_api/test_routes.py`)**

These write `plugin.yaml` and `plugin.py` content into `tmp_path` at test time, then call `PluginLoader.load_plugin()` with a fresh `EventBus` and `FastAPI` instance. Use this pattern when testing loader-level behaviour (service exclusivity, route mounting, `plugin.loaded` events, dependency checks).

**Event testing**

Subscribe to `global_bus` directly, run the operation, assert on received events, and always clean up with `unsubscribe` in a `finally` block:

```python
from plugin_system.core.events import bus as global_bus

received = []
global_bus.subscribe("firewall.rule.added", received.append)
try:
    # ... trigger the operation
    assert received[0].payload["rule_id"] == rule["id"]
finally:
    global_bus.unsubscribe("firewall.rule.added", received.append)
```

Async tests are automatically discovered because `asyncio_mode = auto` is set; no `@pytest.mark.asyncio` is required (though it is accepted).

### Plugin state files

`PluginStateFile` (`infra/state_manager.py`) is a shared primitive for JSON-backed state with built-in `desired_state` / `current_state` envelope and `pending_changes` tracking. Plugins should use it instead of writing their own load/save boilerplate.

Two mutation models control when `current_state` is updated:

- `"immediate"` — `save_desired()` auto-commits `current = desired` on every write (no separate apply step; used by the host plugin)
- `"deferred"` — `save_desired()` only writes `desired`; call `commit()` explicitly after a successful external apply (used by the networking plugin)

```python
from infra.state_manager import PluginStateFile

# In setup():
self._state_file = PluginStateFile.from_config(
    self.plugin_dir, self.config, "state_file", "my_state.json", self.logger,
    mutation_model="immediate",   # or "deferred"
)
desired = self._state_file.load_desired(default={"key": {}})
# current_snapshot is automatically restored from disk — pending_changes is accurate immediately

# On every mutation (immediate model):
self._state_file.save_desired(snapshot)

# After a successful external apply (deferred model):
self._state_file.commit(snapshot)          # snapshot defaults to current desired if omitted

# When importing live state (desired == current):
self._state_file.save_and_commit(snapshot)
```

**Envelope API:**
- `load_desired(default)` — reads `desired_state` from disk, restores `current_snapshot` from `current_state`, returns `desired_state` (or `default` if missing). **On first load (file absent), writes `default` to disk immediately so every plugin starts with a state file rather than creating it lazily.**
- `save_desired(snapshot)` — writes `snapshot` as `desired_state`. For `"immediate"` model, also sets `current = snapshot`.
- `commit(snapshot=None)` — sets `current_state` to `snapshot` (or current desired if omitted) and flushes to disk. Use in deferred plugins after a successful apply.
- `save_and_commit(snapshot)` — writes `snapshot` as both `desired_state` and `current_state` in one disk write. Use for import endpoints where desired and current are identical.
- `pending_changes` (property) — `True` when `desired != current`. Returns `False` if `current` was never set (fresh install).
- `current_snapshot` (property) — the last committed `current_state`, or `None`.

The raw `load(default)` / `save(data)` methods are still available for backward compatibility but plugins should prefer the envelope API.

`from_config` resolves `plugin_dir / "data" / config.get(key, default_filename)`.

**Backups** — when `state.backup.enabled` is `true` in `app_config.yaml`, `save()` snapshots the existing file to `state.backup.directory` (default `/var/tmp/ff-backups/states`) before overwriting. Backup filenames include a timestamp: `<stem>_<YYYYMMDD_HHMMSS>.json`. The backup path is global (not inside the plugin's own `data/` dir) so backups survive plugin removal.

```yaml
state:
  backup:
    enabled: true
    directory: /var/tmp/ff-backups/states
```

`configure_state()` is called once at startup in `app.py` to apply the `app_config.yaml` settings before any plugin `setup()` runs.

**Testing** — in plugin tests, `state_manager._backup_enabled` is `False` by default (module default), so no backup directory is created. If a test exercises the backup path, patch `plugin_system.core.state_manager._backup_enabled` and `_backup_directory` directly.

### Plugin resource conventions

Plugins that manage system resources (users, packages, services, etc.) follow three conventions:

**`ff_managed` flag on list endpoints**

`GET /{resource}` must return *all* system entries, not only FF-managed ones. Each entry includes `ff_managed: bool` to distinguish managed from unmanaged resources. The pattern is to read the live system state, then overlay the managed dict:

```python
def _list_services(self) -> list[dict[str, Any]]:
    system = _read_system_services()          # live OS read
    managed = self._state.get("services", {})
    merged: dict[str, Any] = {}
    for name, info in system.items():
        merged[name] = {**info, "ff_managed": False}
    for name, cfg in managed.items():
        merged[name] = {**cfg, "ff_managed": True}
    return list(merged.values())
```

**Import endpoints**

`POST /{resource}/{id}/import` lets an admin claim an existing system resource into FF management without running pyinfra. The handler reads the current system state for that entry, writes it into `self._state`, calls `_save_state()`, and returns 201. No pyinfra call is made.

```python
@router.post("/services/{name}/import", status_code=201)
def _import_service(self, name: str) -> dict[str, Any]:
    system = _read_system_services()
    if name not in system:
        raise HTTPException(404, detail="Service not found")
    self._state["services"][name] = system[name]
    self._save_state()
    return {**self._state["services"][name], "ff_managed": True}
```

**`current_state` / `pending_changes` tracking**

`PluginStateFile` handles this automatically via its envelope API. Plugins don't need to manage a `_current_state` field directly.

Key plugin-side helpers (see `plugins/host/plugin.py` for the canonical immediate-model implementation):

- `_desired_snapshot()` — `json.loads(json.dumps(self._state))`: normalized deep copy of current desired state, used as the argument to `save_desired()` and `commit()`.
- `_save_state()` — calls `self._state_file.save_desired(self._desired_snapshot())`. In the immediate model, this also auto-commits current.
- In `_apply_state()` (boot-time re-apply for deferred plugins), track per-resource success and call `self._state_file.commit(applied_snapshot)` at the end.
- `pending_changes` in status: use `self._state_file.pending_changes` — no manual comparison needed.

The state file on disk has two top-level keys — `desired_state` (the resource dicts) and `current_state` (the snapshot taken at the last successful apply):

```json
{
  "desired_state": {
    "services": {},
    "sysctl": { "vm.swappiness": { "value": "10", "persist": true } },
    "users": {}, "groups": {}, "cron": {}, "packages": {}, "repos": {}
  },
  "current_state": {
    "services": {},
    "sysctl": { "vm.swappiness": { "value": "10", "persist": true } },
    "users": {}, "groups": {}, "cron": {}, "packages": {}, "repos": {}
  }
}
```

When adding `current_state` to an existing state file, set it to a copy of `desired_state` so the plugin boots with `pending_changes: false`.

### Authentication

Authentication is handled in `ff_auth/auth.py` and configured via the `auth:` section of `app_config.yaml`. Both **HTTP Basic** and **OAuth2 Bearer JWT** are accepted on every protected route — clients may use either.

Enforcement is a middleware in `app.py` (`enforce_auth`). Routes listed in `auth.exempt_paths` bypass it; defaults are `/token`, `/docs`, `/openapi.json`, `/redoc`.

**Endpoints added by `app.py`:**
- `POST /token` — OAuth2 password flow; accepts `username` + `password` form fields, returns `{"access_token": "...", "token_type": "bearer"}`. Rate-limited per client IP (see below).
- `GET /auth/me` — returns `{"username": "...", "roles": [...]}` for the authenticated caller; also registers both security schemes in the OpenAPI `/docs` "Authorize" dialog
- `GET /v1/macros` — returns all macro namespaces and their current resolved values as a structured dict; delegates to `manager_cli.get_macros(loader)` (same data as `--show-macros`)

**Using Basic Auth:**
```
Authorization: Basic base64("username:password")
```

**Using Bearer JWT:**
```bash
# 1. Obtain a token
curl -X POST http://localhost:8000/token \
  -d "username=admin&password=admin"

# 2. Use the token
curl -H "Authorization: Bearer <token>" http://localhost:8000/auth/me
```

**Brute-force protection on `POST /token`:**

Failed login attempts are tracked per client IP using an in-memory sliding window. After `rate_limit.max_attempts` failures within `rate_limit.window_seconds` seconds, the endpoint returns `429 Too Many Requests` with a `Retry-After` header. The counter clears on a successful login or when the window expires. State is held in `_rl_attempts` (module-level dict in `ff_auth/auth.py`); it does not persist across restarts.

**`app_config.yaml` auth options:**
```yaml
auth:
  enabled: true
  secret_key: "..."          # signs JWTs — change before deploying
  algorithm: HS256
  token_expire_minutes: 60
  exempt_paths: [/token, /docs, /openapi.json, /redoc]
  rate_limit:
    max_attempts: 5          # failures before 429
    window_seconds: 300      # sliding window length
  users:
    - username: admin
      password: "admin"      # plaintext auto-hashed at startup
      roles: [admin]
```

Plaintext passwords in `app_config.yaml` are bcrypt-hashed at startup. To store a pre-hashed password instead:
```bash
uv run python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```
Paste the `$2b$…` output as the `password` value — the loader detects the prefix and skips re-hashing.

**Key module:** `ff_auth/auth.py` — `setup(cfg)`, `enforce_auth` (middleware), `get_current_user` (FastAPI dependency), `create_token`, `authenticate_for_token`, `is_rate_limited`, `record_login_failure`, `record_login_success`. The package `ff_auth/__init__.py` re-exports all public symbols so `app.py` imports from `ff_auth` directly.

> Note: the directory on disk is `ff_auth` (underscore) — Python package names cannot contain hyphens.

### Docker

The `Dockerfile` uses Python 3.14-slim + uv. The image grants `cap_net_admin` and `cap_net_raw` to the Python binary (required for iptables) and runs as root. Entry point: `uv run python app.py`.
