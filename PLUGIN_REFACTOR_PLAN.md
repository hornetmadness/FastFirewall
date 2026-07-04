# Refactor plugin composition — repo-wide rollout (v1 plan)

## Context

Plugin authoring has grown complex: a plugin needing both API routes and macros must
inherit multiple mixins (`class Foo(PluginBase, ApiRouterPlugin, MacroProviderPlugin)`)
with cooperative-`__init__`/MRO plumbing enforced by `__init_subclass__` guards. Separately,
two plugins (`firewall`, `caddy`) special-case their boot-time "apply state to the OS" step
behind a `@on("plugins.all_loaded")` handler, because `setup()` runs one plugin at a time in
topological load order — a plugin's own `setup()` can't safely assume every other plugin's
macros/routes are registered yet.

The goal: split each concern into its own class (composition instead of multiple
inheritance), and make `setup()` run only after **every** plugin has finished registering
itself — for **every** plugin in the repo, not just Caddy, giving one uniform way to build a
plugin. No backward-compatibility shim: all 10 plugins migrate together. `plugins.all_loaded`
keeps being emitted (for future extensibility), even though after this change nothing needs
to listen to it anymore.

Chosen design: **declarative composition**. A core `PluginBase` subclass declares aspect
classes as class attributes (e.g. `api = CaddyAPI`, `macros = HostMacros`); the loader
instantiates each declared aspect, wired to the core instance, instead of using multiple
inheritance.

## Current mechanics that constrain the design (verified in code)

- Every plugin except `caddy` follows the same "boot-apply-inline" shape today: `setup()`
  builds config-derived paths, loads a `PluginStateFile`, calls `_apply_state()` (or an
  equivalent, e.g. syslog's `_configure_services()`) inline unless `ignore_state_on_boot`,
  then calls `_register_routes()` (and, for `host`/`networking`, a macro-registration
  helper). `caddy` alone defers the apply step to `@on("plugins.all_loaded")`; `firewall`
  does both — applies inline in `setup()` *and* re-applies via `plugins.all_loaded` if a
  macro snapshot changed, because at `firewall`'s own `setup()` time some macros from later
  in the topological load order may not exist yet.
- Only `dnsmasq` and `networking` have `libs/` mixin subpackages; in both, the mixins provide
  handler methods and config/apply builders but **never** call `self.router` or
  `self.register_macro` directly — all route/macro registration is centralized in each
  plugin's own `plugin.py` (`_register_routes()`, and for `networking`,
  `_register_interface_macros()`). So converting these plugins only touches their top-level
  `plugin.py`, not the `libs/` files.
- `plugin.loaded` (emitted after each individual plugin's old setup()+route-mount) has **zero
  production consumers** — only a test subscribes to it. Safe to re-time.
- `plugins.all_loaded` has exactly two consumers today (`caddy`, `firewall`), both of which
  become unnecessary once `setup()` is uniformly deferred (see below) — both handlers can be
  deleted as a direct simplification this refactor unlocks.
- The loader's recursive dependency auto-load (`plugin_requirements`) inserts a dependency
  into `self._plugins` (a regular dict) before its dependent — so iterating `self._plugins`
  in natural insertion order for a later "run every setup()" pass automatically preserves
  today's dependency ordering guarantee, with no changes needed to the recursion itself.
- Service/port claiming and conflict-checking depend only on `plugin.yaml`-declared,
  static `service_ports`/`services` — zero dependency on `setup()` timing. Likewise, the
  loader's batch OS/Python package installation (`_load_discovered`, before the per-plugin
  loop) and the per-plugin OS-requirement fallback (inside `load_plugin()`, before
  instantiate/configure/setup) both already run **before** any plugin is instantiated —
  this ordering is untouched by this refactor, so packages are still guaranteed installed
  before any `setup()` call.
- `manager_cli.py`'s `get_macros()`/`print_macros()` (used by `--show-macros` and
  `GET /v1/macros`) currently does
  `isinstance(loaded.instance, MacroProviderPlugin)` then calls `loaded.instance.macro_snapshot()`
  directly on the core — this needs updating once macros move onto a separate aspect object.
- **Ordering constraint this design must get right:** aspects (particularly macro aspects)
  need the plugin's state already loaded to register correct values (e.g. `host`'s hostname
  macro, `networking`'s interface macros both read from state loaded via `PluginStateFile`).
  So the loader must call `instance.configure()` (which loads state) **before** instantiating
  that plugin's aspects — not after.

## Approach

### 1. New aspect base — `plugin_system/core/plugin_aspect.py` (new file)

```python
class PluginAspect:
    """Composed onto a PluginBase core via a declared class attribute
    (e.g. `api = FooAPI`), instead of multiple inheritance."""
    def __init__(self, core: PluginBase) -> None:
        self.core = core
```

### 2. Replace the mixins with aspects

- `plugin_system/core/api_router_plugin.py`: **delete** the `ApiRouterPlugin` mixin and its
  `__init_subclass__` guard; replace with:
  ```python
  class ApiRouterAspect(PluginAspect):
      def __init__(self, core: PluginBase) -> None:
          super().__init__(core)
          self.router: APIRouter = APIRouter()
  ```
- `plugin_system/core/macro_provider_plugin.py`: **delete** the `MacroProviderPlugin` mixin;
  replace with:
  ```python
  class MacroProviderAspect(PluginAspect):
      def __init__(self, core: PluginBase) -> None:
          super().__init__(core)
          self._macro_keys: list[str] = []

      def register_macro(self, key: str, value: Any) -> None: ...   # same body as today
      def unregister_macro(self, key: str) -> None: ...              # same body as today
      def macro_snapshot(self) -> dict[str, dict[str, Any]]:
          return {}
  ```
  `macro_snapshot()` moves here (was on the core plugin class via the old mixin); each
  plugin's macro aspect subclass overrides it, reading from `self.core._state`/`self.core.config`.

### 3. New `configure()` lifecycle hook — `plugin_system/core/plugin_base.py`

```python
def configure(self) -> None:
    """Called once after the loader injects plugin_id/meta/config/plugin_dir/logger/
    data_dir, but before this plugin's aspects are instantiated and before setup()
    (which the loader defers until every plugin has been configured — see
    PluginLoader.finished()). Load state and config-derived values here. Default: no-op."""
```
`__init__` stays the zero-arg no-op it already is (inherited from `PluginBase`) for every
plugin — none of them need a custom `__init__` after this change (today's `syslog` no-op
`__init__` gets deleted, since the explanatory comment it existed for no longer applies).

### 4. `LoadedPlugin` gains an `aspects` field

`aspects: list[tuple[str, PluginAspect]]`, populated at load time — the generic list of every
declared aspect instance for that plugin, in declaration order. Used for route mounting,
macro cleanup on unload, and macro-snapshot introspection (replacing the old
`isinstance(instance, ApiRouterPlugin)`/`isinstance(instance, MacroProviderPlugin)` checks
against the core).

### 5. Loader changes — `plugin_system/core/loader.py`

- `__init__`: add `self._deferred_setups: list[tuple[str, PluginBase]] = []` and
  `self._booted: bool = False`.
- New method `_instantiate_aspects(instance) -> list[tuple[str, PluginAspect]]`: scans
  `type(instance)` for class attributes that are `PluginAspect` subclasses
  (`inspect.getmembers(type(instance), ...)`), instantiates each as `cls(instance)`, and
  `setattr(instance, name, aspect_instance)` (shadows the class attribute at the instance
  level without mutating the class attribute itself).
- New method `_mount_aspect_routers(aspects, plugin_id)`: for each aspect that's an
  `ApiRouterAspect`, mounts `aspect.router` onto the FastAPI app at `/v1/<plugin_id>` (same
  prefix/tags convention as today's `_register_api_routes`).
- Replace the current end-of-`load_plugin()` block (today: `instance.setup();
  self._register_api_routes(...); self._register_macro_provider(...)`) with:
  ```python
  if instance is not None:
      instance.configure()                              # state/config first
      aspects = self._instantiate_aspects(instance)      # then routes/macros, which may read that state
      self._mount_aspect_routers(aspects, plugin_id)
      loaded.aspects = aspects
      if self._booted:
          instance.setup()      # plugin loaded after initial boot — no barrier to wait for
      else:
          self._deferred_setups.append((plugin_id, instance))
  ```
  Delete `_register_api_routes`/`_register_macro_provider` as separate loader methods — their
  jobs are now `_mount_aspect_routers` (routes) and "a side effect of aspect `__init__`"
  (macros), respectively.
- `finished()`: drain deferred setups, mark booted, log pending changes, *then* emit
  `plugins.all_loaded` (kept exactly as an event — for future use — even though no plugin
  will subscribe to it after this refactor):
  ```python
  def finished(self) -> None:
      for plugin_id, instance in self._deferred_setups:
          try:
              instance.setup()
          except Exception:
              self.logger.exception("setup() failed for plugin %r", plugin_id)
      self._deferred_setups.clear()
      self._booted = True
      self._log_pending_changes()
      loaded = sorted(self._loaded)
      all_service_ports = self._all_service_ports
      self._bus.emit(Event("plugins.all_loaded", payload={"service_ports": all_service_ports, "loaded": loaded}))
  ```
- `_load_discovered()`: remove its own call to `self._log_pending_changes()` (line ~717) —
  it's now called once, globally, from `finished()`, *after* every plugin's `setup()`/apply
  has actually run, which is when "pending changes" is a meaningful signal (today it's called
  before any real plugin's `setup()` even exists to set `_state_file`, so moving it later is
  a correctness fix, not just a reshuffle).
- `unload_plugin()`: replace `if loaded.instance is not None and isinstance(loaded.instance, MacroProviderPlugin): for key in loaded.instance._macro_keys: ...`
  with iterating `loaded.aspects` and unregistering keys for any `MacroProviderAspect` found.
- Service/port claim-and-commit (today's lines ~939-944) stays exactly where it is, before
  `configure()`/aspects/setup — unaffected by any of this.

### 6. `plugin_system/core/__init__.py`

Remove `ApiRouterPlugin`, `MacroProviderPlugin` from exports; add `PluginAspect`,
`ApiRouterAspect`, `MacroProviderAspect`.

### 7. `plugin_system/manager_cli.py`

`get_macros()`/`print_macros()` (~line 101-108): replace
`isinstance(loaded.instance, MacroProviderPlugin)` + `loaded.instance.macro_snapshot()` with
iterating `loaded.aspects`, checking `isinstance(aspect, MacroProviderAspect)`, and calling
`aspect.macro_snapshot()`.

## Per-plugin migration recipe (applies uniformly to all 10 plugins)

**General pattern**, moving from:
```python
class FooPlugin(PluginBase, ApiRouterPlugin[, MacroProviderPlugin][, libs/ mixins]):
    services = [...]
    def setup(self):
        self._state_file = PluginStateFile.from_config(...)
        self._state = self._state_file.load_desired(default=...)
        if not self.config.get("ignore_state_on_boot"):
            self._apply_state()
        self._register_routes()
        [self._register_<x>_macros()]
```
to:
```python
class FooPlugin(PluginBase[, libs/ mixins unchanged]):
    services = [...]
    api = FooAPI                  # was ApiRouterPlugin
    macros = FooMacros            # only where a macro provider exists — was MacroProviderPlugin

    def configure(self):
        self._state_file = PluginStateFile.from_config(...)
        self._state = self._state_file.load_desired(default=...)

    def setup(self):
        if not self.config.get("ignore_state_on_boot"):
            self._apply_state()

class FooAPI(ApiRouterAspect):
    def __init__(self, core):
        super().__init__(core)
        add = self.router.add_api_route
        add("/status", core._status, methods=["GET"], ...)
        ...   # exact body of today's _register_routes(), bound to core.<handler>

class FooMacros(MacroProviderAspect):     # only for host, networking
    def __init__(self, core):
        super().__init__(core)
        self.register_macro("$foo.bar", core._state[...])
        ...   # exact body of today's _register_<x>_macros()

    def macro_snapshot(self):
        ...   # moved from core, reads self.core._state
```
`libs/` mixin files (`dnsmasq`, `networking`) need **no changes** — their handler/config-builder
methods never touch `self.router`/`register_macro` today, so nothing there references the old
mixin APIs.

### Representative conversions

- **`caddy`** (API only, no macros): as designed and reviewed earlier — `CaddyAPI(ApiRouterAspect)`
  takes over `_register_routes()`; `configure()` takes over state loading; `setup()` shrinks to
  the apply-only body, folding in today's `_on_plugins_loaded` logic (delete the
  `@on("plugins.all_loaded")` handler entirely — the loader's global deferred pass replaces it).
- **`host`** (API + Macros): `HostAPI(ApiRouterAspect)` takes over `_register_routes()`;
  `HostMacros(MacroProviderAspect)` takes over `_register_host_macros()` and the existing
  `macro_snapshot()` override; `configure()` takes over state loading; `setup()` keeps just the
  inline `_apply_state()` call (plus the optional init-script run, if that's apply-adjacent).
- **`networking`** (API + Macros + `libs/`): same shape as `host`; `libs/` mixins
  (`LiveMixin`, `BuilderMixin`, `BondsMixin`, `BridgesMixin`, `WireguardMixin`) stay mixed
  into `NetworkingPlugin` unchanged. Note the first-boot "import live state" branch
  (`_import_state_from_system()`) is a read-only OS query, not a mutation — keep it in
  `configure()` alongside state loading, not in `setup()`.
- **`dnsmasq`** (API + many `libs/` mixins, no macros): easiest conversion — only
  `_register_routes()` moves into `DnsmasqAPI(ApiRouterAspect)`; every `libs/` mixin file is
  untouched.
- **`firewall`** (API only): converts like `dnsmasq`. Additionally, **delete**
  `@on("plugins.all_loaded") _on_plugins_loaded` and its supporting
  `_collect_macro_snapshot()`/`set_macro_snapshot()`/`get_macro_snapshot()` call sites — once
  every plugin's `setup()` is deferred until all plugins are configured, firewall's `setup()`
  always sees fully-registered macros on its first (and only) apply, so the "did macros change,
  re-apply" workaround is no longer needed. (`PluginStateFile.set_macro_snapshot`/
  `get_macro_snapshot` become unused as a result — leave them in `infra/state_manager.py`
  as harmless, generic API; not in scope to remove.)
- **`apt_cacher_ng`, `smtp`, `syslog`, `pkg_management`** (API only): same mechanical
  conversion as `dnsmasq`/`firewall` — `_register_routes()` → `<Foo>API(ApiRouterAspect)`,
  state loading → `configure()`, apply call → `setup()`. `pkg_management`'s bus-event
  subscriptions (`pkg_management.add.package/repo/service`) and `syslog`'s no-op `__init__`
  (delete it) are otherwise untouched.
- **`audit`** (no API, no macros): no aspects declared at all — `class AuditPlugin(PluginBase):`
  stays as-is. It has no state file/apply step, so there's nothing to split between
  `configure()`/`setup()`; leave its current `setup()` body where it is (optionally rename to
  `configure()` for consistency, but functionally inert either way).

## Test changes

**General pattern** for every plugin's `test_*.py` (mirrors the Caddy-specific plan already
reviewed): in the shared "build a configured plugin" fixture, after setting loader-injected
attributes, replace the single `plugin.setup()` call with:
```python
plugin.configure()
plugin.api = mod.FooAPI(plugin)              # mirrors loader._instantiate_aspects
plugin.macros = mod.FooMacros(plugin)        # only where applicable
plugin.setup()                                # only if the test wants the apply step to run too
```
and mount `plugin.api.router` (not `plugin.router`) in whatever builds the `TestClient`. Any
test asserting on `_apply_state()` behavior calls `plugin.setup()` explicitly, same as today.

Apply this to all 10 plugin test files. `plugins/caddy/test_caddy_api_routes.py` and
`plugins/firewall/test_firewall_api_routes.py` additionally need their
`plugins.all_loaded`/`_on_plugins_loaded` boot-apply tests changed to call `plugin.setup()`
directly (the event handler no longer exists).

### `tests/test_core/test_loader.py`

- Two existing tests break because `setup()` no longer runs synchronously inside
  `load_plugin()`: `test_load_plugin_with_pluginbase_instance` and
  `test_plugin_instance_has_plugin_dir_before_setup` — both assert on attributes only set
  inside `setup()`, right after `load_plugin()` returns. Fix: call `loader.finished()` before
  those assertions.
- New coverage needed (no existing test touches this machinery):
  - `test_configure_called_before_aspects_and_setup` — dummy plugin recording call order
    across `configure()`/aspect `__init__`/`setup()`.
  - `test_setup_deferred_until_finished` — assert `setup()` hasn't run right after
    `load_plugin()`, but has after `loader.finished()`.
  - `test_aspect_class_attribute_replaced_with_instance` — assert `type(instance).<attr>` is
    still the class while `instance.<attr>` is the instance.
  - `test_aspect_router_mounted_before_setup` — dummy plugin with an `ApiRouterAspect`-based
    aspect exposing one route; assert it's reachable immediately after `load_plugin()`, before
    `finished()` runs.
  - `test_deferred_setup_failure_is_logged_not_raised` — dummy plugin's `setup()` raises;
    assert `loader.finished()` doesn't propagate, and other plugins' `setup()` still run.
  - `test_setup_called_immediately_after_finished_already_ran` — call `finished()` once, then
    `load_plugin()` a new plugin (simulates `reload_plugin`/a dynamic post-boot load); assert
    its `setup()` ran immediately rather than being silently stranded in
    `_deferred_setups` forever.
  - `test_macro_aspect_cleanup_on_unload` — dummy `MacroProviderAspect`-based plugin;
    `unload_plugin()` removes its registered macro keys.
  - Update `test_reload_plugin` if needed so reload after `finished()` still results in
    `setup()` running (covers the fix above end-to-end).

## Verification

1. `uv run --extra dev pytest` — full suite must pass across all 10 plugins plus updated/new
   core loader tests.
2. `uv run --with pyright pyright` — must be clean. Aspect `__init__` methods should type
   `core` as the plugin's concrete class (e.g. `core: "CaddyPlugin"`), not the generic
   `PluginBase`, since aspects reference plugin-specific handler methods/state.
3. Manual boot check: run the full app (`uv run python fastfirewall_app.py`) and confirm via
   logs that every plugin's "configured" log line appears during normal topological load,
   while every plugin's apply-state log now appears only after all plugins have been
   configured — right before `plugins.all_loaded` fires at the very end.
4. Hit a route from a plugin near the end of the dependency graph (e.g.
   `GET /v1/caddy/status`) and one near the start (e.g. `GET /v1/host/status`) to confirm
   routes are live regardless of position in the deferred-setup ordering.
5. Run `uv run python fastfirewall_app.py --show-macros` and `GET /v1/macros` to confirm the
   `manager_cli.py` aspect-based rewrite still surfaces `host`/`networking` macros correctly.
