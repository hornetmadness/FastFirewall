# Firewall Plugin

Manages firewall rules and compiles them to nftables config via the **nftables Python module** (libnftables bindings). Rules are stored in a JSON file; call `POST /apply` to compile and apply them. Routes mount at `/v1/firewall/`.

**Mutation model: deferred apply.** Rule mutations (`POST`, `PUT`, `DELETE`) only update the JSON state file — nothing is applied to the kernel until `POST /apply` is called. `commit()` is called after a successful apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Routes

| Method | Path | Summary |
|---|---|---|
| `GET` | `/rules` | List all firewall rules |
| `POST` | `/rules` | Create a firewall rule |
| `GET` | `/rules/{rule_id}` | Get a firewall rule |
| `PUT` | `/rules/{rule_id}` | Update a firewall rule |
| `DELETE` | `/rules/{rule_id}` | Delete a firewall rule |
| `POST` | `/check` | Dry-run validate (no apply) |
| `POST` | `/apply` | Compile and apply rules to nftables |
| `POST` | `/compile` | Compile rules to nft script (preview only) |
| `POST` | `/discard` | Revert pending changes to last applied state |
| `GET` | `/status` | Plugin status |

## Rule fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `str` | required | max 100 chars |
| `chain` | `"input" \| "forward" \| "output"` | `"input"` | which chain the rule targets |
| `action` | `"accept" \| "deny" \| "reject"` | `"deny"` | `reject` sends ICMP unreachable; `deny` silently drops |
| `protocol` | `"tcp" \| "udp" \| "icmp" \| "icmpv6" \| "esp" \| "ah" \| "any"` | `null` | |
| `src_address` | `str` | `"any"` | IPv4 CIDR, IPv6 CIDR, or `"any"` |
| `dst_address` | `str` | `"any"` | IPv4 CIDR, IPv6 CIDR, or `"any"` |
| `src_port` | `int \| macro` | `null` | TCP/UDP only |
| `dst_port` | `int \| macro` | `null` | TCP/UDP only |
| `comment` | `str` | `null` | max 255 chars |
| `priority` | `int` | `100` | lower = matched first |
| `enabled` | `bool` | `true` | disabled rules are compiled out |

## Chains and policies

The compiler always generates all three chains regardless of whether user rules target them:

| Chain | Hook | Default policy | Notes |
|---|---|---|---|
| `input` | `input` | `drop` | traffic destined for the host |
| `forward` | `forward` | `drop` | traffic routed through the host (gateway use) |
| `output` | `output` | `accept` | traffic originating from the host |

## Stateful connection tracking

`ct state established,related accept` is injected by the compiler as the first rule in both `input` and `forward` chains. It is **not** stored in the rule list and cannot be removed — it is a compiler invariant that ensures return traffic for established connections is never dropped.

## Rule IDs

Rule IDs are a 16-character SHA-256 prefix of the rule's field dict (`sort_keys=True`). This makes IDs content-addressable — submitting an identical rule twice returns `409 Conflict` instead of creating a duplicate. The same hash is used for default rules seeded on fresh install, so they are idempotent.

## Fresh-install defaults

On first boot (when the state file does not yet exist), the plugin seeds two default rules: `allow-ssh` (TCP/22) and `allow-fastfirewall-api` (TCP/8000), both targeting the `input` chain. These prevent lockout. They are only seeded once; if you delete them, they do not return.

## State file

`data/firewall_rules.json` — stored as a flat list inside `desired_state`:

```json
{
  "desired_state": [
    {"id": "...", "name": "allow-ssh", "chain": "input", "action": "accept", "protocol": "tcp", ...}
  ],
  "current_state": [...]
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
```

`add table` is idempotent (no-op if already exists). `flush table` atomically removes all existing chains and rules. `add chain` + `add rule` rebuild the ruleset from the current desired state.

## `POST /check`

Dry-run validate — uses `nftables.Nftables().set_dry_run(True)` to validate the compiled script against the kernel without modifying state. Returns `{success, rule_count, output}` where `output` is the error string on failure.

## `POST /discard`

Reverts `desired_state` back to the last committed `current_state`. Returns `409` if no snapshot exists (never applied). Matches the networking plugin pattern.

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `rules_file` | `firewall_rules.json` | filename inside `data/` |
| `default_filter_name` | `fastfirewall` | nftables table/chain name |
| `ignore_state_on_boot` | `false` | skip rule reload and re-apply on startup |

## Events emitted

| Event | Payload |
|---|---|
| `firewall.rule.added` | `{rule_id, name}` |
| `firewall.rule.updated` | `{rule_id, changes}` |
| `firewall.rule.deleted` | `{rule_id, name}` |
| `firewall.compiled` | `{rule_count}` |
| `firewall.applied` | `{rule_count, success}` |

## Events consumed

`firewall.compile` — payload may include `filter_name` override; triggers a compile (no apply) and logs the result.

## Testing

Tests in `test_firewall_api_routes.py`. The plugin is loaded directly (not via `PluginLoader`) using the pattern described in `CLAUDE.md` at the repo root. Key fixtures:

- **`client(tmp_path)`** — fresh plugin instance per test via `_make_app`. Fast; default rules seeded automatically.
- **`_make_inst(tmp_path, config=None)`** — bare instance without `setup()` called. Use for boot-apply tests where you need to mock `_apply_nft_script` before setup runs.

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

Macro seeding for port-based rules:
```python
macro_registry.set_service_ports({"dns": {"udp": [53]}})
try:
    # ... test
finally:
    macro_registry.set_service_ports({})
```
