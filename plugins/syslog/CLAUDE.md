# Syslog Plugin

Installs and configures **fluent-bit** as a standalone syslog server. Listens on UDP/TCP 514 for incoming syslog messages, optionally reads the systemd journal, and writes everything to `/var/log/fastfirewall/`. Routes mount at `/v1/syslog/`.

**Mutation model: immediate apply.** Every `PATCH` mutation updates the in-memory scalars, persists them via `_save_overrides()`, then calls `_apply_config()` or `_apply_logrotate_config()` to write the rendered config to disk and restart fluent-bit. Uses `PluginStateFile` with `mutation_model="immediate"`, so `save_desired()` auto-commits `current = desired` on every write.

Unlike the host/smtp plugins, this plugin stores individual scalar fields (`_syslog_port`, `_syslog_mode`, etc.) rather than a single `_state` dict. `_save_overrides()` builds the snapshot dict inline and calls `save_desired()` directly.

## Routes

| Method | Path | Summary |
|---|---|---|
| `GET` | `/status` | Plugin status, service health, and `pending_changes` |
| `GET` | `/config` | Get effective fluent-bit config settings |
| `PATCH` | `/config` | Update fluent-bit config settings and reload |
| `POST` | `/config/reload` | Reload fluent-bit without changing config |
| `GET` | `/config/raw` | Read raw fluent-bit config file from disk |
| `GET` | `/config/diagnose` | Diagnose fluent-bit setup and journal access |
| `GET` | `/config/logrotate` | Get logrotate settings |
| `PATCH` | `/config/logrotate` | Update logrotate settings |
| `POST` | `/config/logrotate/run` | Manually trigger log rotation |
| `GET` | `/files` | List log files in `log_dir` |
| `GET` | `/logs/{filename}` | Read last N lines of a log file |
| `GET` | `/tail/{filename}` | Tail a log file (alias for `/logs` with smaller default) |
| `GET` | `/journal` | Read systemd journal entries |

## State file

`data/syslog_overrides.json` — stores runtime overrides that supersede `plugin.yaml` config values. Two top-level keys (envelope API):

```json
{
  "desired_state": {
    "syslog_port": 514,
    "syslog_mode": "udp",
    "syslog_unix_path": null,
    "syslog_unix_mode": "unix_udp",
    "enable_systemd_input": true,
    "logrotate": {
      "rotate": 7,
      "frequency": "daily",
      "compress": true,
      "max_size": null
    }
  },
  "current_state": { ... }
}
```

On boot: `load_desired(default={})` returns the overrides dict, which is merged with `self.config` (`{**self.config, **overrides}`) to produce the effective configuration.

## Bootstrap — fluent-bit repo

The fluent-bit apt repo is declared as a `repos:` entry in `plugin.yaml`. The loader reads it at parse time — before any module is imported — and registers the GPG key and apt source list entry via `pyinfra_run_batch`. It then runs a single `apt-get install fluent-bit logrotate` for all plugins together. `plugin.py` has no repo registration code in `__init__`.

`fluent-bit` and `logrotate` are declared in `os_requirements`; the loader installs them as part of the batch OS install before any `setup()` runs.

## Key methods

**`_save_overrides()`** — builds a snapshot dict from the current scalar fields and calls `self._state_file.save_desired(...)`. Because the mutation model is `"immediate"`, this also auto-commits `current = desired`.

**`_configure_services()`** — called during `setup()`; creates the log directory via pyinfra, ensures fluent-bit's main config includes `conf.d/`, enables and starts fluent-bit, and calls `_apply_config()` + `_apply_logrotate_config()`.

**`_apply_config()`** — renders the fluent-bit config via `_build_fastfirewall_conf_classic()`, writes it to `fastfirewall_conf` via pyinfra, and restarts fluent-bit if the content hash changed.

**`_apply_logrotate_config()`** — renders and writes the logrotate config via pyinfra.

**`_ensure_main_conf_includes_confd()`** — checks fluent-bit's main config for a `conf.d` include; creates or appends the include line if missing.

**`_pyinfra_run(op, **kwargs)`** — serializes and executes a pyinfra operation in a subprocess via `_pyinfra_worker.py`. Raises `RuntimeError` on non-zero exit.

## Config scalars

| Field | Default | Source |
|---|---|---|
| `_syslog_port` | `514` | `plugin.yaml` / override |
| `_syslog_mode` | `udp` | `plugin.yaml` / override (`udp`, `tcp`, `tcp+udp`) |
| `_syslog_unix_path` | `None` | `plugin.yaml` / override |
| `_syslog_unix_mode` | `unix_udp` | `plugin.yaml` / override (`unix_udp`, `unix_tcp`) |
| `_enable_systemd` | `True` | `plugin.yaml` / override |
| `_log_rotate_count` | `7` | `plugin.yaml.logrotate` / override |
| `_log_rotate_frequency` | `daily` | `plugin.yaml.logrotate` / override |
| `_log_compress` | `True` | `plugin.yaml.logrotate` / override |
| `_log_max_size` | `None` | `plugin.yaml.logrotate` / override |

## Events emitted

| Event | Payload |
|---|---|
| `syslog.ready` | `{log_dir, fastfirewall_conf}` |
| `syslog.setup.complete` | `{log_dir, fastfirewall_conf, fluent_bit_main_conf}` |
| `syslog.config.updated` | full `_get_config()` dict |
| `syslog.logrotate.updated` | full `_get_logrotate()` dict |
| `syslog.logrotate.ran` | `{logrotate_conf}` |

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `overrides_file` | `syslog_overrides.json` | filename inside `data/` |
| `log_dir` | `/var/log/fastfirewall` | directory where fluent-bit writes logs |
| `fastfirewall_conf` | `/etc/fluent-bit/conf.d/fastfirewall.conf` | rendered fluent-bit config path |
| `fluent_bit_main_conf` | `/etc/fluent-bit/fluent-bit.conf` | main config checked for `conf.d` include |
| `fluent_bit_key_url` | `https://packages.fluentbit.io/fluentbit.key` | GPG key URL for the fluent-bit apt repo |
| `fluent_bit_key_dest` | `/usr/share/keyrings/fluentbit-keyring.gpg` | destination path for the dearmored key |
| `fluent_bit_repo_url` | `https://packages.fluentbit.io/debian` | base URL of the fluent-bit apt repo |
| `fluent_bit_repo_filename` | `fluent-bit` | `.list` filename under `/etc/apt/sources.list.d/` |
| `ignore_state_on_boot` | `false` | skip loading overrides and re-applying config on startup |
| `syslog_port` | `514` | base-level port (overridable at runtime) |
| `syslog_mode` | `udp` | base-level mode (overridable at runtime) |
| `syslog_unix_path` | — | base-level Unix socket path |
| `syslog_unix_mode` | `unix_udp` | base-level Unix socket mode |
| `enable_systemd_input` | `true` | base-level systemd journal toggle |
| `logrotate.conf` | `/etc/logrotate.d/fastfirewall` | logrotate config path |
| `logrotate.rotate` | `7` | base-level rotate count |
| `logrotate.frequency` | `daily` | base-level rotation frequency |
| `logrotate.compress` | `true` | base-level gzip compression toggle |
| `logrotate.max_size` | — | base-level max file size before rotation |
| `max_tail_lines` | `1000` | upper bound for `/logs` and `/tail` endpoints |

## Testing

Tests in `test_syslog_plugin.py`. pyinfra calls are mocked via `plugin._pyinfra_run = MagicMock()` before `setup()`. `subprocess.run` is patched with `unittest.mock.patch` for all tests that trigger systemctl, journalctl, or logrotate calls.

The fluent-bit repo is now declared in `plugin.yaml` and registered by the loader — `__init__` has no side effects, so there is no bus interaction to worry about when constructing the plugin in tests.

```python
plugin._pyinfra_run = MagicMock()
with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
    plugin.setup()
```

All tests use `_make_plugin(tmp_path, config=None)` + `_make_client(plugin)` — no shared session fixture. The `log_dir` fixture creates `tmp_path / "logs"` and is passed via `config={"log_dir": ...}`.

The raw state file test reads `envelope["desired_state"]` since the file uses the envelope format.
