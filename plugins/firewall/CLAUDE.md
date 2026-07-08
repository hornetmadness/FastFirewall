# Firewall Plugin

Manages firewall rules and compiles them to nftables scripts applied via a sudo wrapper (`nft_cmd`). Rules are stored in a JSON state file; call `POST /apply` to compile and apply them. Routes mount at `/v1/firewall/`.

**Mutation model: deferred apply.** Rule mutations (`POST`, `PUT`, `DELETE`) and chain mutations (`PUT`) only update the JSON state file — nothing is applied to the kernel until `POST /apply` is called. `commit()` is called after a successful apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

`PUT /rules/{rule_id}` accepts a **partial body** — only the fields you include are changed; omitted fields keep their current values. For example, to disable a rule: `{"enabled": false}`.

## Routes

| Method | Path | Summary |
|---|---|---|
| `GET` | `/rules` | List all firewall rules |
| `POST` | `/rules` | Create a firewall rule |
| `GET` | `/rules/{rule_id}` | Get a firewall rule |
| `PUT` | `/rules/{rule_id}` | Partially update a firewall rule — send only the fields to change |
| `DELETE` | `/rules/{rule_id}` | Delete a firewall rule |
| `GET` | `/chains` | List chains and their policies |
| `GET` | `/chains/{name}` | Get a single chain |
| `PUT` | `/chains/{name}` | Update chain policy, priority, preamble, or epilogue |
| `GET` | `/sets` | List named sets |
| `POST` | `/sets` | Create a named set |
| `GET` | `/sets/{name}` | Get a named set |
| `DELETE` | `/sets/{name}` | Delete a named set |
| `POST` | `/sets/{name}/elements` | Add elements to a set |
| `DELETE` | `/sets/{name}/elements` | Remove elements from a set |
| `GET` | `/nat/rules` | List NAT rules |
| `POST` | `/nat/rules` | Create a NAT rule |
| `GET` | `/nat/rules/{rule_id}` | Get a NAT rule |
| `PUT` | `/nat/rules/{rule_id}` | Update a NAT rule |
| `DELETE` | `/nat/rules/{rule_id}` | Delete a NAT rule |
| `GET` | `/custom-chains` | List custom (non-hook) chains |
| `POST` | `/custom-chains` | Create a custom chain |
| `GET` | `/custom-chains/{name}` | Get a custom chain |
| `DELETE` | `/custom-chains/{name}` | Delete a custom chain |
| `GET` | `/flowtables` | List flowtables |
| `POST` | `/flowtables` | Create a flowtable |
| `GET` | `/flowtables/{name}` | Get a flowtable |
| `DELETE` | `/flowtables/{name}` | Delete a flowtable |
| `GET` | `/ingress/rules` | List ingress (netdev) rules |
| `POST` | `/ingress/rules` | Create an ingress rule |
| `GET` | `/ingress/rules/{rule_id}` | Get an ingress rule |
| `PUT` | `/ingress/rules/{rule_id}` | Update an ingress rule |
| `DELETE` | `/ingress/rules/{rule_id}` | Delete an ingress rule |
| `GET` | `/maps` | List verdict maps |
| `POST` | `/maps` | Create a verdict map |
| `GET` | `/maps/{name}` | Get a verdict map |
| `DELETE` | `/maps/{name}` | Delete a verdict map |
| `POST` | `/maps/{name}/entries` | Add entries to a verdict map |
| `DELETE` | `/maps/{name}/entries` | Remove entries from a verdict map by key |
| `GET` | `/counters` | Live counter values from kernel |
| `POST` | `/counters/{name}/reset` | Atomically reset a named counter |
| `GET` | `/table` | Show current table name, family, and chain list |
| `POST` | `/check` | Dry-run validate (no apply) |
| `POST` | `/apply` | Compile and apply rules to nftables |
| `POST` | `/compile` | Compile rules to nft script (preview only) |
| `POST` | `/discard` | Revert pending changes to last applied state |
| `GET` | `/live-state` | Current kernel ruleset as parsed JSON |
| `GET` | `/status` | Plugin status |

## Rule fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `str` | required | max 100 chars |
| `chain` | `str` | `"input"` | hook chain or custom chain name |
| `action` | `"accept" \| "deny" \| "reject" \| "jump" \| "return"` | `"deny"` | `reject` sends ICMP unreachable; `deny` silently drops |
| `jump_target` | `str` | `null` | required when `action` is `"jump"` |
| `protocol` | `"tcp" \| "udp" \| "icmp" \| "icmpv6" \| "esp" \| "ah" \| "any"` | `null` | |
| `src_address` | `str` | `"any"` | IPv4 CIDR, IPv6 CIDR, or `"any"` |
| `dst_address` | `str` | `"any"` | IPv4 CIDR, IPv6 CIDR, or `"any"` |
| `src_address_set` | `str` | `null` | reference to a named set via `@setname` |
| `dst_address_set` | `str` | `null` | reference to a named set via `@setname` |
| `src_interface` | `str` | `null` | `iif` match (max 15 chars) |
| `dst_interface` | `str` | `null` | `oif` match (max 15 chars) |
| `src_port` | `int \| macro` | `null` | TCP/UDP only |
| `dst_port` | `int \| macro` | `null` | TCP/UDP only |
| `src_port_range` | `[int, int]` | `null` | TCP/UDP port range, e.g. `[1024, 65535]` |
| `dst_port_range` | `[int, int]` | `null` | TCP/UDP port range |
| `dst_port_vmap` | `str` | `null` | verdict map name; emits `tcp/udp dport vmap @name` as the verdict |
| `src_port_vmap` | `str` | `null` | verdict map name; emits `tcp/udp sport vmap @name` as the verdict |
| `tcp_flags` | `list[flag]` | `null` | TCP flag match: `syn`, `ack`, `fin`, `rst`, `urg`, `psh`, `ece`, `cwr` |
| `tcp_flags_mask` | `list[flag]` | `null` | mask for `tcp_flags`; if set, emits `tcp flags & (mask) == (flags)` |
| `icmp_type` | `int \| str` | `null` | ICMP type, e.g. `"echo-request"` or `8` |
| `ct_state` | `list[state]` | `null` | CT state match: `new`, `established`, `related`, `invalid`, `untracked` |
| `counter_name` | `str` | `null` | named counter; emits `counter name <n>` before verdict |
| `rate_limit` | `RateLimit` | `null` | rate-limiting; emits `limit rate [over] N/unit [burst M packets]` |
| `log` | `LogConfig` | `null` | logging; emits `log prefix "..." level ...` before verdict |
| `comment` | `str` | `null` | max 255 chars |
| `priority` | `int` | `100` | lower = matched first |
| `enabled` | `bool` | `true` | disabled rules are compiled out |

## `applied` field

Every rule and chain response includes `applied: bool`. It is computed at response time by comparing the resource's full current dict against the last committed snapshot — a full dict equality check, not just an ID check. This means `applied` correctly returns `false` after a `PUT` that changes any field, even though the rule ID is unchanged.

- `applied: true` — the resource's current state exactly matches what was last successfully applied to the kernel
- `applied: false` — the resource has pending changes or has never been applied

## Chains and policies

The compiler always generates all three chains regardless of whether user rules target them:

| Chain | Hook | Default policy | Default preamble | Default epilogue |
|---|---|---|---|---|
| `input` | `input` | `drop` | `["iif lo accept", "ct state established,related accept", "ct state invalid drop"]` | `['log prefix "input-drop: " level warn drop']` |
| `forward` | `forward` | `drop` | `["ct state established,related accept"]` | `['log prefix "forward-drop: " level warn drop']` |
| `output` | `output` | `accept` | `[]` | `[]` |

Each chain has a `preamble` — a list of raw nft expressions compiled into the script before user rules. Preamble rules are stored in state and are editable via `PUT /chains/{name}` with `{"preamble": [...]}`. Changes are deferred — `POST /apply` is required to push them to the kernel.

Each chain also has an `epilogue` — raw nft expressions compiled in **after** all user rules for that chain, right before the implicit chain policy takes over. The `input` and `forward` chains (both `policy: drop`) default to a `log prefix "..." level warn drop` epilogue rule so packets falling through to the default-deny are logged instead of silently dropped; `output` (`policy: accept`) has none. Editable via `PUT /chains/{name}` with `{"epilogue": [...]}`, same deferred-apply semantics as `preamble`.

## Rule IDs

Rule IDs are a 16-character SHA-256 prefix of the rule's field dict (`sort_keys=True`), computed at creation time from the `RuleCreate` body (no `id` field included). This makes creation idempotent — submitting an identical rule twice returns `409 Conflict`. The same hash is used for default rules seeded on fresh install.

## Compiler deduplication

If two enabled rules would produce an identical nft expression (same chain + same match/action), the compiler emits only the first (by priority order) and logs a warning for the skipped duplicate. The state file is unchanged — deduplication is compile-time only.

`FirewallPlugin` composes a `FirewallAPI(ApiRouterAspect)` aspect (`api = FirewallAPI`, taking over what was `_register_routes()`), instantiated by the loader after `configure()` runs. State loading (all rule/chain/set/NAT/flowtable/custom-chain/ingress/verdict-map/quota dicts) lives in `configure()`; `setup()` only runs `_apply_state()` (when not `ignore_state_on_boot`), logs the loaded rule count, and calls `_sync_os_boot_service()`. Because every plugin's `setup()` is now deferred until all plugins are configured, `setup()` always sees fully-registered macros on its first (and only) apply — the old `@on("plugins.all_loaded") _on_plugins_loaded` re-apply-if-macros-changed workaround (and its supporting `_collect_macro_snapshot()`) has been removed.

## Fresh-install defaults

On first boot (when the state file does not yet exist), the plugin seeds two default rules: `allow-ssh` (TCP/22) and `allow-fastfirewall-api` (TCP/8000), both targeting the `input` chain. These prevent lockout. They are only seeded once; if you delete them, they do not return.

## State file

`data/firewall_state.json` — single file with both rules and chain config inside `desired_state`:

```json
{
  "desired_state": {
    "rules": [
      {"id": "...", "name": "allow-ssh", "chain": "input", "action": "accept", "protocol": "tcp", ...}
    ],
    "chains": {
      "input":   {"policy": "drop",   "priority": 0, "preamble": ["iif lo accept", "ct state established,related accept", "ct state invalid drop"], "epilogue": ["log prefix \"input-drop: \" level warn drop"]},
      "forward": {"policy": "drop",   "priority": 0, "preamble": ["ct state established,related accept"], "epilogue": ["log prefix \"forward-drop: \" level warn drop"]},
      "output":  {"policy": "accept", "priority": 0, "preamble": [], "epilogue": []}
    }
  },
  "current_state": {
    "rules": [...],
    "chains": {...}
  }
}
```

## Compiled output

After a successful `POST /apply`, the compiled nftables script is written to `data/<filter_name>.nft` (default: `data/fastfirewall.nft`). The path is reported in `GET /status` as `compiled_output`. This file is also useful for manual inspection.

## Script format

`_compile_to_script` generates a script with all three chains. IPv4 addresses use `ip saddr`/`ip daddr`; IPv6 addresses use `ip6 saddr`/`ip6 daddr` (auto-detected). Non-TCP/UDP protocols use `meta l4proto` (works for both IPv4 and IPv6 in the `inet` family):

```
# FastFirewall managed ruleset — do not edit manually
add table inet fastfirewall
flush table inet fastfirewall
add chain inet fastfirewall input { type filter hook input priority 0; policy drop; }
add chain inet fastfirewall forward { type filter hook forward priority 0; policy drop; }
add chain inet fastfirewall output { type filter hook output priority 0; policy accept; }
add rule inet fastfirewall input ct state established,related accept
add rule inet fastfirewall forward ct state established,related accept
add rule inet fastfirewall input tcp dport 22 accept comment "Allow SSH from any source"
add rule inet fastfirewall input tcp dport 8000 accept comment "Allow FastFirewall API from any source"
add rule inet fastfirewall input log prefix "input-drop: " level warn drop
add rule inet fastfirewall forward log prefix "forward-drop: " level warn drop
```

`add table` is idempotent (no-op if already exists). `flush table` atomically removes all existing chains and rules. `add chain` + `add rule` rebuild the ruleset from the current desired state.

## `POST /check`

Dry-run validate — runs `sudo nft_cmd --check` with the compiled script fed via stdin. Returns `{success, rule_count, chain_count, output}` where `output` is the error string on failure.

## `POST /apply`

Compiles the ruleset, writes it to `data/<filter_name>.nft`, and applies it via `sudo nft_cmd`. Returns `{success, rule_count, chain_count, pending_changes}`.

## `POST /compile`

Compiles the current ruleset to a preview script without applying it. Writes the script to `data/<filter_name>.nft` and returns `{filter_name, rule_count, output, output_path}` where `output` is a `list[str]` — one nft statement per element, and `output_path` is the absolute path to the written file.

## `POST /discard`

Reverts `desired_state` back to the last committed `current_state`. Returns `409` if no snapshot exists (never applied). Matches the networking plugin pattern.

## `nft_cmd` wrapper

`plugins/firewall/nft_cmd` is a small bash script that reads an nft script from stdin and applies it via the `nft` CLI binary:

```bash
# Usage: nft_cmd [--check]
#   (no flag)  Apply the script to the live kernel ruleset.
#   --check    Validate the script without modifying the kernel.
```

It must be invoked via `sudo`. For non-root deployments add a sudoers entry — see `tools/sudoers-fastfirewall.example`.

The wrapper path defaults to `plugin_dir / "nft_cmd"` and can be overridden with the `nft_wrapper` config key.

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `firewall_state.json` | filename inside `data/` |
| `default_filter_name` | `fastfirewall` | nftables table/chain name |
| `ignore_state_on_boot` | `false` | skip rule reload and re-apply on startup |
| `enable_os_boot` | `false` | register (or remove) a oneshot systemd service that applies the compiled `.nft` script at OS boot via `nft -f` |
| `nft_wrapper` | `<plugin_dir>/nft_cmd` | path to the sudo wrapper script |

## Events emitted

| Event | Payload |
|---|---|
| `firewall.rule.added` | `{rule_id, name}` |
| `firewall.rule.updated` | `{rule_id, changes}` |
| `firewall.rule.deleted` | `{rule_id, name}` |
| `firewall.compiled` | `{rule_count}` |
| `firewall.applied` | `{rule_count, success}` |
| `initsys.service.add` | emitted at `setup()` when `enable_os_boot: true` — registers `fastfirewall-nft` as a oneshot service running `nft -f <compiled.nft>` |
| `initsys.service.remove` | emitted at `setup()` when `enable_os_boot: false` — removes the service if it exists |


## Testing

Tests in `test_firewall_api_routes.py`. The plugin is loaded directly (not via `PluginLoader`) using the pattern described in `CLAUDE.md` at the repo root. Key fixtures:

- **`client(tmp_path)`** — fresh plugin instance per test via `_make_app`, which calls `inst.configure()`, then `inst.api = mod.FirewallAPI(inst)`, then `inst.setup()` — mirroring what the loader does. Fast; default rules seeded automatically. Mounts `inst.api.router` (not `inst.router`).
- **`_make_inst(tmp_path, config=None)`** — returns `(inst, mod)` with `inst.configure()` and `inst.api = mod.FirewallAPI(inst)` already done, but `setup()` **not** called. Use for boot-apply tests where you need to mock `_apply_nft_script` before `setup()` runs.

Boot-apply tests mock two things:
```python
inst._apply_nft_script = MagicMock()
with patch.object(mod, "_compile_to_script", return_value=_CLEAN_SCRIPT):
    inst.setup()
```

Check/apply tests mock the instance methods directly:
```python
inst._validate_nft_script = MagicMock(return_value=(True, ""))
inst._apply_nft_script = MagicMock()
```

No nftables module stub is needed — `plugin.py` uses `subprocess` + `sudo nft_cmd`, not the Python nftables bindings.

Macro seeding for port-based rules:
```python
macro_registry.set_service_ports({"dns": {"udp": [53]}})
try:
    # ... test
finally:
    macro_registry.set_service_ports({})
```
