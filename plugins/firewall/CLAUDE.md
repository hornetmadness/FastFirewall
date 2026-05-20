# Firewall Plugin

Manages firewall rules and compiles them to platform-specific ACL output via **aerleon** / `aclgen`. Rules are stored in a JSON file; call `POST /apply` to compile and apply them. Routes mount at `/v1/firewall/`.

**Mutation model: deferred apply.** Rule mutations (`POST`, `PUT`, `DELETE`) only update the JSON state file — nothing is applied to the kernel until `POST /apply` is called. `commit()` is called after a successful apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

**Default platform: `nftables`.** The plugin compiles to nftables format and applies via `sudo nft -f <output_path>`. Auto-apply is only supported for `nftables`; other platforms require manual application of the compiled output.

## Routes

| Method | Path | Summary |
|---|---|---|
| `GET` | `/rules` | List all firewall rules |
| `POST` | `/rules` | Create a firewall rule |
| `GET` | `/rules/{rule_id}` | Get a firewall rule |
| `PUT` | `/rules/{rule_id}` | Update a firewall rule |
| `DELETE` | `/rules/{rule_id}` | Delete a firewall rule |
| `POST` | `/check` | Dry-run compile (no apply) |
| `POST` | `/apply` | Compile and apply rules to nftables |
| `POST` | `/compile` | Compile rules with aerleon (preview only) |
| `GET` | `/policy` | Show raw aerleon policy |
| `GET` | `/platforms` | List supported platforms |
| `GET` | `/status` | Plugin status |

## Rule IDs

Rule IDs are a 16-character SHA-256 prefix of the rule's field dict (`sort_keys=True`). This makes IDs content-addressable — submitting an identical rule twice returns `409 Conflict` instead of creating a duplicate. The same hash is used for default rules seeded on fresh install, so they are idempotent.

## Fresh-install defaults

On first boot (when the state file does not yet exist), the plugin seeds two default rules: `allow-ssh` (TCP/22) and `allow-fastfirewall-api` (TCP/8000). These prevent lockout. They are only seeded once; if you delete them, they do not return.

## State file

`data/firewall_rules.json` — stored as a flat list inside `desired_state`:

```json
{
  "desired_state": [
    {"id": "...", "name": "allow-ssh", "action": "accept", "protocol": "tcp", ...}
  ],
  "current_state": [...]
}
```

## Compiled output

After a successful `POST /apply`, the compiled nftables script is written to `data/<filter_name>.nft` (default: `data/fastfirewall.nft`). The path is reported in `GET /status` as `compiled_output`.

## Debug mode

Set `debug: true` in `plugin.yaml` `config:` to enable:
- `aerleon_debug/` directory written alongside the state file with the last `networks.yaml` and `policy.yaml` inputs passed to `aclgen`.
- `debug_dir` key added to `GET /status` response.

## `POST /check`

Dry-run compile — runs `aclgen` and returns `{success, platform, rule_count, output}` without writing any files or calling `nft`. Use this to validate rules before applying.

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `rules_file` | `firewall_rules.json` | filename inside `data/` |
| `default_platform` | `nftables` | ACL target platform |
| `default_filter_name` | `fastfirewall` | aerleon filter/policy name |
| `auto_compile` | `false` | reserved; not currently wired |
| `ignore_state_on_boot` | `false` | skip rule reload and re-apply on startup |
| `debug` | `false` | write aerleon inputs to `data/aerleon_debug/` |

## Supported platforms

`checkpoint`, `ciscoasa`, `juniper`, `paloalto`, `arista`, `nftables`, `nsxv`, `srx`, `gce`.

## Events emitted

| Event | Payload |
|---|---|
| `firewall.rule.added` | `{rule_id, name, action, protocol}` |
| `firewall.rule.updated` | `{rule_id}` |
| `firewall.rule.deleted` | `{rule_id}` |
| `firewall.compiled` | `{platform, filter_name, rule_count}` |
| `firewall.applied` | `{platform, filter_name, rule_count}` |

## Events consumed

`firewall.compile_request` — payload may include `platform` and `filter_name` overrides; triggers a compile (no apply).

## Testing

Tests in `test_firewall_api_routes.py`. The plugin is loaded directly (not via `PluginLoader`) using the pattern described in `CLAUDE.md` at the repo root. Key fixtures:

- **`plugin` / `client`** (session-scoped) — shared instance with `tmp_path` for state isolation. Fast; tests accumulate state.
- **`_make_plugin(tmp_path, config=None)` / `_make_client(plugin)`** — fresh instance per test. Use for persistence, fresh-install, and boot-apply tests.

Macro seeding for port-based rules:
```python
macro_registry.set_service_ports({"dns": {"udp": [53]}})
try:
    # ... test
finally:
    macro_registry.set_service_ports({})
```
