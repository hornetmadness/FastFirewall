# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the dev server (reload enabled by default in app_config.yaml)
uv run python app.py

# Run with only specific plugins loaded
uv run python app.py --plugin firewall_plugin --plugin dns_plugin

# List all plugins and their enabled state
uv run python app.py --list-plugins

# Enable or disable a plugin (edits plugin.yaml, then exits)
uv run python app.py --enable-plugin syslog_plugin
uv run python app.py --disable-plugin syslog_plugin

# Show all CLI options
uv run python app.py --help

# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_core/test_events.py

# Run a single test by name
uv run pytest tests/test_core/test_events.py::test_subscribe_and_emit

# Run plugin-local tests (also collected automatically by pytest)
uv run pytest plugins/firewall_plugin/test_firewall_api_routes.py

# Run pyright type checking
uv run --with pyright pyright

# Install dependencies (uses uv.lock)
uv sync

# Install with dev extras
uv sync --extra dev
```

The OpenAPI docs are available at `http://localhost:8000/docs` when the server is running.

CLI argument parsing and all management commands (`--list-plugins`, `--enable-plugin`, `--disable-plugin`, `--help`) are handled by `plugin_system/manager_cli.py`. `app.py` calls `manager_cli.run(loader, plugins_dir)` which either exits after handling a management command or returns the plugin allow-list for normal startup.

## Architecture

This is a **FastAPI application driven entirely by plugins**. The app itself (`app.py`) has no routes of its own — all API surface comes from plugins loaded at startup.

### Boot sequence

1. `AppConfig.load()` reads `app_config.yaml` into typed dataclasses.
2. `manager_cli.run(loader, plugins_dir)` parses CLI args; exits early for management commands, otherwise returns an optional plugin allow-list.
3. `PluginLoader.load_directory()` scans the configured `plugins/` directory and derives load order via topological sort of `plugin_requirements` (dependencies before dependents; alphabetical tiebreaker). Pass `only=[...]` to restrict which plugins are loaded; transitive dependencies are included automatically.
4. For each plugin directory with a `plugin.yaml` + `plugin.py`: the loader imports the module, instantiates any `PluginBase` subclass, wires up event handlers, calls `setup()`, then mounts FastAPI routes if the plugin is a `RoutedPlugin`.
5. After loading, a `plugin.loaded` event is emitted on the bus.

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

`RoutedPlugin` (`plugin_system/core/routed_plugin.py`) — mixin for plugins that contribute API routes. Must also inherit `PluginBase`:
```python
class MyPlugin(PluginBase, RoutedPlugin):
    service_name = Service.DNS   # required — determines mount path
    services = [Service.DNS]     # exclusive ownership claim
```
The loader mounts `self.router` at `/v1/<service_name.value>/`. Add routes to `self.router` inside `setup()`.

### Service exclusivity

`Service` (`plugin_system/core/services.py`) is a `str` enum of well-known network-appliance services (`FIREWALL`, `DNS`, `DHCP`, etc.). Only one plugin may claim a given `Service` at a time; the loader raises `PluginError` if a second plugin tries to claim an already-owned service.

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

### PluginLoader management API

Beyond `load_plugin` / `unload_plugin`, `PluginLoader` exposes two read/write helpers that do not load or execute any plugin code:

- `list_plugins(directory)` — scans `directory` and returns a list of dicts with `id`, `name`, `version`, `description`, `author`, `enabled`, `plugin_requirements`, `service_ports` for every discovered plugin, sorted in topological load order.
- `set_plugin_enabled(directory, plugin_id, enabled)` — finds the plugin by id, sets the `enabled` field in its `plugin.yaml`, and writes it back. Raises `PluginError` if the plugin is not found.

`PluginLoader` maintains two runtime registries updated on every load/unload:
- `service_registry` — `{Service → plugin_id}`: which plugin owns each service
- `_port_registry` — `{(proto, port) → plugin_id}`: which plugin has claimed each port; port `-1` is never registered

### Dependency installation

Plugins can declare `py_requirements` (pip packages) and `os_requirements` (system packages) in `plugin.yaml`. The loader installs them at load time using **pyinfra** running against `@local`. If `PluginLoader` is constructed with `pipx_app="<name>"`, Python packages are injected into that pipx environment instead of the current one.

### Testing

Tests live in two places and are both collected by pytest automatically (see `testpaths` in `pyproject.toml`):

- `tests/` — core unit tests (`test_events`, `test_decorators`, `test_loader`) and integration tests (`test_api/test_routes.py`)
- `plugins/<name>/test_*.py` — plugin-local route and behaviour tests (currently `firewall_plugin` and `host_plugin`)

**Plugin test pattern — direct load (firewall_plugin)**

Plugin route tests do *not* go through `PluginLoader`. They import the plugin module directly via `importlib`, instantiate the plugin class, set the loader-injected attributes (`plugin_id`, `meta`, `config`, `plugin_dir`, `logger`) by hand, call `setup()`, then mount `instance.router` onto a fresh `FastAPI()` and wrap it in `TestClient`. This sidesteps pyinfra dependency installation while still running real production code.

```python
inst = mod.FirewallPlugin()
inst.plugin_id = "firewall_plugin"
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

**Plugin test pattern — pyinfra mocking (host_plugin)**

For plugins that call `_pyinfra_run`, replace it with `MagicMock` after instantiation and before `setup()`. Then assert on `call_args` to verify the correct pyinfra op and kwargs were used without touching the real system:

```python
plugin._pyinfra_run = MagicMock()
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

### Authentication

Authentication is handled in `plugin_system/core/auth.py` and configured via the `auth:` section of `app_config.yaml`. Both **HTTP Basic** and **OAuth2 Bearer JWT** are accepted on every protected route — clients may use either.

Enforcement is a middleware in `app.py` (`enforce_auth`). Routes listed in `auth.exempt_paths` bypass it; defaults are `/token`, `/docs`, `/openapi.json`, `/redoc`.

**Endpoints added by `app.py`:**
- `POST /token` — OAuth2 password flow; accepts `username` + `password` form fields, returns `{"access_token": "...", "token_type": "bearer"}`
- `GET /auth/me` — returns `{"username": "...", "roles": [...]}` for the authenticated caller; also registers both security schemes in the OpenAPI `/docs` "Authorize" dialog

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

**`app_config.yaml` auth options:**
```yaml
auth:
  enabled: true
  secret_key: "..."          # signs JWTs — change before deploying
  algorithm: HS256
  token_expire_minutes: 60
  exempt_paths: [/token, /docs, /openapi.json, /redoc]
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

**Key module:** `ff_auth/auth.py` — `setup(cfg)`, `enforce_auth` (middleware), `get_current_user` (FastAPI dependency), `create_token`, `authenticate_for_token`. The package `ff_auth/__init__.py` re-exports all public symbols so `app.py` imports from `ff_auth` directly.

> Note: the directory on disk is `ff_auth` (underscore) — Python package names cannot contain hyphens.

### Docker

The `Dockerfile` uses Python 3.14-slim + uv. The image grants `cap_net_admin` and `cap_net_raw` to the Python binary (required for iptables) and runs as root. Entry point: `uv run python app.py`.
