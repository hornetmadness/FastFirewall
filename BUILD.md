# Building and publishing FastFirewall packages

## Build

```bash
# Sync the workspace (resolves all members into the shared lockfile)
uv sync

# Build wheels + sdists for every workspace member
uv build --all-packages
```

Artifacts land in `dist/`. Expect one wheel and one sdist per package:
- `fastfirewall_core-0.1.0-py3-none-any.whl`
- `fastfirewall_plugin_firewall-1.0.0-py3-none-any.whl`
- … (one pair per plugin + meta)

## Run

After installing, start the server with:

```bash
fastfirewall
```

Config is discovered in this order:
1. `$FASTFIREWALL_CONFIG` env var
2. `./app_config.yaml` (current working directory)
3. `/etc/fastfirewall/app_config.yaml`
4. `~/.config/fastfirewall/app_config.yaml`
5. Bundled package default (safe to use as a starting point)

Plugins are loaded from two sources:
- `./plugins/` if that directory exists (dev/repo mode)
- Installed packages that declare a `fastfirewall.plugins` entry point

## Test

```bash
uv run pytest
```

## Publish to Gitea

You need a Gitea API token with `package:write` scope.

```bash
uv publish \
  --publish-url http://<gitea-host>/api/packages/$GITEA_OWNER/pypi/ \
  --token ${GITEA_API_TOKEN}
```

## Install from Gitea

FastFirewall packages live on Gitea; their transitive dependencies (fastapi, bcrypt, etc.) live on PyPI. Use `--extra-index-url` so uv/pip checks both — do **not** replace `--index-url`, which would drop PyPI entirely.

```bash
# Core framework only
uv pip install fastfirewall-core \
  --index-strategy unsafe-best-match \
  --extra-index-url http://${GITEA_API_TOKEN}@<gitea-host>/api/packages/${GITEA_OWNER}/pypi/simple/

# Full appliance stack (core + all plugins)
uv pip install fastfirewall \
  --index-strategy unsafe-best-match \
  --extra-index-url http://${GITEA_API_TOKEN}@<gitea-host>/api/packages/${GITEA_OWNER}/pypi/simple/
```

`--index-strategy unsafe-best-match` tells uv to look across all indexes and pick the best available version rather than stopping at the first index that has the package.
