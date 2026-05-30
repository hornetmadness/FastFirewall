# Plan: Optimize Plugin Loader Boot Sequence

## Context

The loader installs Python and OS packages one plugin at a time inside `load_plugin()`. With 9 plugins, that can mean up to 9 separate `apt-get update && apt-get install` calls and N separate `uv pip install` calls — all sequential, all blocking the next plugin from starting. The user wants to batch these into a single pass before any `setup()` runs, and replace the per-plugin `py_requirements` mechanic with a single `uv sync` (since every plugin is already a uv workspace member with its own `pyproject.toml`).

---

## Critical files

- [plugin_system/core/loader.py](plugin_system/core/loader.py) — all changes; key methods at lines 469 (`load_directory`), 507 (`load_installed`), 563 (`_load_discovered`), 843 (`load_plugin` requirements block), 970–1031 (install helpers)
- [plugins/syslog/plugin.py](plugins/syslog/plugin.py) — `__init__` at line 77 emits `pkg_management.add.repo` before loader installs its `os_requirements`; this is the one ordering edge case
- [plugins/syslog/plugin.yaml](plugins/syslog/plugin.yaml) — replace `__init__` repo emission with static `repos:` entry; remove `defer_os_install` flag (no longer needed)
- [infra/__init__.py](infra/__init__.py) — `pyinfra_run_batch` used by OS install helpers

---

## Change 1: Replace py_requirements with `uv sync`

**Why:** Every plugin has a `pyproject.toml` and is a uv workspace member. `py_requirements` in `plugin.yaml` duplicates what `pyproject.toml` already declares. `uv sync --no-dev --frozen` installs all workspace dependencies in one shot from the existing lockfile — no re-resolve, no per-plugin subprocesses.

**How:**
1. Add `_install_py_requirements_uv_sync()` to `PluginLoader`:
   - Runs `subprocess.run(["uv", "sync", "--no-dev", "--frozen"])` with `cwd` set to the workspace root (3 parents up from `loader.py`).
   - If `uv` is not on PATH, log a warning and return (pip-installed deployments have dependencies pre-installed; `load_installed()` already sets `skip_py_requirements=True`).
   - Raise `PluginError` on non-zero exit.

2. Call it **once** in `_load_discovered()`, **after** the OS package batch install, guarded by `if not skip_requirements and not skip_py_requirements:`. OS packages must be installed first — Python packages may need system libraries or binaries (e.g. compiled C extensions, CLI tools) that OS packages provide.

3. Remove the per-plugin block from `load_plugin()` (lines 843–850):
   ```python
   if py_requirements and not skip_requirements and not skip_py_requirements:
       self._install_py_requirements(plugin_id, py_requirements)
   ```
   Keep the old `_install_py_requirements()` helper intact but no longer call it from the main load path (it can serve as a fallback for direct `load_plugin()` calls outside of `_load_discovered`).

**Result:** `uv sync` runs once at boot instead of N `uv pip install` processes.

---

## Change 2: Batch all OS requirements

**Why:** Currently each plugin with `os_requirements` triggers a full `apt-get update && apt-get install` cycle. With 6 plugins that declare OS packages, that's 6 `apt-get update` runs. A single pre-load batch reduces this to 1.

**Edge case — syslog / fluent-bit:** `SyslogPlugin.__init__` emits `pkg_management.add.repo` to register the fluent-bit apt repo. If we batch everything before any `__init__` runs, the fluent-bit repo is not yet in sources and `apt-get install fluent-bit` fails. Fix: move repo registration out of `__init__` entirely and into a static `repos:` section in `plugin.yaml`. The loader reads and registers repos at parse time — before any module is imported.

**How:**

**Step 2a — Add `repos:` to `plugin.yaml` schema.**

A `repos` list in `plugin.yaml` declares third-party apt repos the plugin needs. The loader registers these before the batch package install. `plugins/syslog/plugin.yaml`:

```yaml
repos:
  - name: fluent-bit
    key_url: "https://packages.fluentbit.io/fluentbit.key"
    key_dest: "/usr/share/keyrings/fluentbit-keyring.gpg"
    repo_url: "https://packages.fluentbit.io/debian"
    filename: "fluent-bit"
```

The loader detects the OS codename via `platform.freedesktop_os_release()` and constructs the full `src` string (`deb [signed-by=...] <repo_url>/<codename> <codename> main`) — same logic currently in `SyslogPlugin.__init__`. Remove the `bus.emit(pkg_management.add.repo)` call from `SyslogPlugin.__init__` entirely; its body becomes just `super().__init__()`.

**Step 2b — Carry `os_requirements` and `repos` through discovery.**

`load_directory()` and `load_installed()` both build a `discovered` dict with only `{path, enabled, requirements}`. Extend to include:

```python
discovered[pid] = {
    "path": child,
    "enabled": bool(raw.get("enabled", True)),
    "requirements": list(raw.get("plugin_requirements") or []),
    "os_requirements": list(raw.get("os_requirements") or []),
    "repos": list(raw.get("repos") or []),
}
```

**Step 2c — Add `_register_repos(active, discovered)` to `PluginLoader`.**

Collects all `repos` entries from active plugins, deduplicates by `name`, and calls `pyinfra_run_batch` with apt key + repo source operations for each. Called before the batch OS install in `_load_discovered()`. The pkg_management plugin's `_on_add_repo` handler is bypassed here (it hasn't loaded yet) — the loader calls pyinfra directly, same as it does for `os_requirements`.

**Step 2d — Add `_collect_os_requirements(active, discovered)` to `PluginLoader`.**

Returns a deduplicated sorted list of all OS packages from all active plugins.

**Step 2e — Batch install before the load loop in `_load_discovered()`.**

After topological sort, before `for pid in load_order:`:

```python
if not skip_requirements:
    self._register_repos(active, discovered)       # register custom apt repos
    batch_pkgs = self._collect_os_requirements(active, discovered)
    if batch_pkgs:
        self._install_os_requirements("<batch>", batch_pkgs)
```

**Step 2f — Remove per-plugin OS install from `load_plugin()`.**

Delete the `if os_requirements and not skip_requirements:` block (lines 852–859). For `load_plugin()` called directly (outside `_load_discovered`), keep the block as a fallback with a comment noting it is not batch-optimized.

**Result:** All 9 plugins' packages install in one `apt-get update` + one `apt-get install`. No exceptions, no deferred paths. `SyslogPlugin.__init__` no longer has side effects.

---

## Change 3: Deferred pyinfra imports

**Why:** Lines 67–79 of `loader.py` import every pyinfra package-manager module at module load time. This triggers gevent initialization on every boot, even when `--show-macros` or `--list-plugins` is used and no packages will ever be installed. Moving these imports inside `_install_os_requirements()` and `_detect_os_pkg_op()` makes them lazy.

**How:** Move the 12 pyinfra `from pyinfra.operations import ...` lines from the module top into the body of `_install_os_requirements()` / `_detect_os_pkg_op()`. Python caches module imports so subsequent calls don't re-import.

---

## Change 4: Cache OS package manager detection

**Why:** `_detect_os_pkg_op` calls `shutil.which(...)` on each plugin. Minor free win.

**How:** Add `_detected_pkg_manager: str | None = None` to `PluginLoader.__init__`. In `_detect_os_pkg_op`, check the cached value first; set it on first detection.

---

## Boot sequence after changes

```
_load_discovered():
  ① register repos from plugin.yaml    # apt key + source list entries via pyinfra_run_batch
  ② apt-get update + apt-get install   # once, ALL os_requirements across all plugins
  ③ uv sync --no-dev --frozen          # once, ALL python deps (after OS bins/libs available)
  ④ for pid in topo order:
       load_plugin(pid)
         __init__()                     # no more side effects in syslog
         wire event handlers
         setup()
         mount routes / macros
         emit plugin.loaded
```

---

## What stays the same

- `load_plugin()` called directly (outside `_load_discovered`) keeps the full existing per-plugin install behavior as a safe fallback.
- `skip_requirements=True` path (`--show-macros`, tests) is unchanged — both new batch calls are guarded by `if not skip_requirements`.
- `load_installed()` path sets `skip_py_requirements=True`; the `uv sync` step is skipped. OS batch still runs for installed plugins.
- Topological ordering and dependency failure propagation are unchanged.
- `py_requirements` field remains in `plugin.yaml` for documentation but is no longer used by the loader for workspace installs.

---

## Verification

```bash
# Cold boot — watch for single apt-get update in logs
uv run python fastfirewall_app.py 2>&1 | grep -E "(apt|uv sync|Loaded plugin)"

# Skip-requirements path unchanged
uv run python fastfirewall_app.py --show-macros

# All tests pass
uv run pytest

# Single-plugin filter still works
uv run python fastfirewall_app.py --plugin firewall --plugin networking

# Type check
uv run --with pyright pyright plugin_system/core/loader.py
```
