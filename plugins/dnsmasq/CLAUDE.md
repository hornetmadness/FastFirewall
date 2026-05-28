# DNSMasq Plugin

DNS forwarding/caching, DHCP, TFTP, PXE boot, and mDNS via dnsmasq. Routes mount at `/v1/dnsmasq/`.

**Mutation model: deferred apply.** Every `PUT`/`POST`/`DELETE` mutation only updates the desired-state dicts and saves to disk — nothing is written to `/etc/dnsmasq.d/` and dnsmasq is not restarted until `POST /apply` is called. Uses `PluginStateFile` with `mutation_model="deferred"`, so `save_desired()` only writes desired state; `commit()` is called explicitly after a successful `systemctl restart dnsmasq`. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## Resources

| Resource | List | Create | Update | Delete |
|---|---|---|---|---|
| DNS records | `GET /dns/records` | `POST /dns/records` (201) | — | `DELETE /dns/records/{record_id}` |
| DHCP ranges | `GET /dhcp/ranges` | `POST /dhcp/ranges` (201) | `PUT /dhcp/ranges/{range_id}` | `DELETE /dhcp/ranges/{range_id}` |
| Static leases | `GET /dhcp/static-leases` | `POST /dhcp/static-leases` (201) | `PUT /dhcp/static-leases/{lease_id}` | `DELETE /dhcp/static-leases/{lease_id}` |
| PXE services | `GET /pxe/services` | `POST /pxe/services` (201) | — | `DELETE /pxe/services/{index}` |
| Blocklists | `GET /blocklists` | `POST /blocklists` (201) | `POST /blocklists/{id}/refresh` | `DELETE /blocklists/{id}` |

Config-level settings (not keyed resources) are managed via dedicated `GET`/`PUT` pairs:

| Subsystem | Read | Write |
|---|---|---|
| DNS | `GET /dns` | `PUT /dns` |
| DHCP | `GET /dhcp` | `PUT /dhcp` |
| TFTP | `GET /tftp` | `PUT /tftp` |
| PXE | `GET /pxe` | `PUT /pxe` |
| mDNS | `GET /mdns` | `PUT /mdns` |

Additional routes: `GET /status`, `GET /dhcp/leases`, `GET /config`, `POST /apply`, `POST /check`, `POST /discard`.

## DNS macro support

Three fields in the `dns` config section accept macro strings that are resolved at `POST /apply` time (stored as-is in the state file, expanded when `render_config()` builds the dnsmasq config):

| Field | Type | Macro example |
|---|---|---|
| `port` | `int \| str` | `"$service_port.dns.udp"` → first element of the resolved list |
| `listen_addresses` | `list[int \| str]` | `["$interface.lan.address"]` → expanded in-place to all resolved addresses |
| `interface` | `str` | `"$interface.lan.name"` → resolved to the interface device name |

Non-macro values (plain integers and strings) pass through unchanged. Unresolvable macros fall back to the raw macro string so the config file always contains something meaningful.

## State file

`data/dnsmasq_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "dns": { "port": "$service_port.dns.udp", "listen_addresses": ["$interface.lan.address"], "interface": "$interface.lan.name", "upstream": ["8.8.8.8", "1.1.1.1"], ... },
    "records": {},
    "dhcp": { "enabled": false, "authoritative": true, "options": {} },
    "dhcp_ranges": {},
    "static_leases": {},
    "tftp": { "enabled": false, "root": "/srv/tftp", "secure": false, "no_fail": false },
    "pxe": { "enabled": false, "prompt": null },
    "pxe_services": [],
    "mdns": { "enabled": false, "interfaces": [] },
    "blocklists": {}
  },
  "current_state": { ... }
}
```

`desired_state` holds what FF should enforce. `current_state` is committed only after a successful `POST /apply` or boot-time apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## In-memory state

Ten dicts/lists are kept in memory, populated from the state file by `_load_state()`:

| Attribute | Type | Key |
|---|---|---|
| `_dns` | `dict` | flat config fields |
| `_records` | `dict[str, dict]` | `{record_id: record}` |
| `_dhcp` | `dict` | flat config fields |
| `_dhcp_ranges` | `dict[str, dict]` | `{range_id: range}` |
| `_static_leases` | `dict[str, dict]` | `{lease_id: lease}` |
| `_tftp` | `dict` | flat config fields |
| `_pxe` | `dict` | flat config fields |
| `_pxe_services` | `list[dict]` | ordered list (index = position) |
| `_mdns` | `dict` | flat config fields |
| `_blocklists` | `dict[str, dict]` | `{blocklist_id: blocklist}` |

## Key methods

**`_load_state()`** — calls `self._state_file.load_desired(default={})`, merges with per-subsystem defaults (`_default_dns()`, etc.), then calls `_save_state()` if no prior state exists on disk so that `_desired` is immediately accurate.

**`_apply_state()`** — called on every boot (unless `ignore_state_on_boot` is true). Reads the on-disk config files via `_read_on_disk()` and compares them to the generated desired config. If both files match exactly, logs and returns without touching the system. If either differs (or is missing), validates with `dnsmasq --test`, writes both config files via `_write_file_sudo`, then restarts dnsmasq via `systemctl`. Calls `commit()` on success; logs a warning and returns on any failure (does not raise).

**`_read_on_disk(path)`** — reads a system config file and returns its contents as a string, or `None` if the file is missing or unreadable (no exception raised).

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Does **not** update `current_state` — that only happens via `commit()`.

**`_desired_snapshot()`** — returns `json.loads(json.dumps({dns, records, dhcp, ...}))`: a normalized deep copy used as the argument to `save_desired()` and `commit()`. Also the response body of `GET /config`.

**`_build_config()`** — serializes all in-memory state into a dnsmasq config string. DNS `port`, `listen_addresses`, and `interface` values are resolved via `macro_registry.resolve()` before writing — macros expand to their current values; plain values pass through unchanged. DNS section emits `interface=` for every non-empty value (including `"*"`), `listen-address=`, upstream `server=`, per-domain `server=/domain/ns`, `local=/domain/`, `cache-size=`, `dnssec`, `log-queries`, `domain=`, `local-ttl=`, `neg-ttl=`, `strict-order`, `stop-dns-rebind`, `rebind-localhost-ok`. Record directives: `address=/name/ip`, `aaaa=/name/ip`, `cname=`, `txt-record=`, `mx-host=`, `srv-host=`, `ptr-record=`. DHCP section (when enabled): `dhcp-authoritative`, `dhcp-leasefile=`, `dhcp-range=`, `dhcp-host=`, `dhcp-option=`. TFTP: `enable-tftp`, `tftp-root=`, `tftp-secure`, `tftp-no-fail`. PXE: `pxe-service=`, `pxe-prompt=`. mDNS: `enable-ra`, `interface=`.

**`_build_blocklist_config()`** — iterates `_blocklists`, emitting one `address=/{domain}/#` line per blocked domain.

**`_fetch_blocklist_domains(url, fmt)`** — async; validates the URL with `_validate_blocklist_url` (async DNS check via `loop.getaddrinfo`), then downloads the content with `httpx.AsyncClient`. Supports two formats:
- `"hosts"` — parses lines like `0.0.0.0 domain.com` or `127.0.0.1 domain.com`; skips `localhost`, `broadcasthost`, and `0.0.0.0` itself
- `"domains"` — plain one-domain-per-line list; skips comment lines

Deduplicates while preserving order via `dict.fromkeys`.

## DNS `interface` field

`_default_dns()` sets `"interface": "*"`. The value is resolved via `macro_registry.resolve()` at config-build time — a macro like `"$interface.lan.name"` expands to the device name; plain strings (including `"*"`) pass through unchanged. `"*"` is emitted literally as `interface=*`. Set to a specific interface name (e.g. `"eth0"`) or a macro to restrict dnsmasq to that interface; clear it (empty string) to omit the directive.

## `GET /config`

Returns `_desired_snapshot()` as a JSON object — the full structured desired state across all ten subsections. This is the canonical view of what will be written to disk on the next `POST /apply`.

## `POST /apply` flow

When `debug: true` is set in plugin config, the temp file path, `dnsmasq --test` output, and `systemctl` output are logged and included in the response under a `"debug"` key. The temp file is also retained on disk for inspection.

1. `_desired_snapshot()` captured
2. `_build_config()` + `_build_blocklist_config()` written to a temp file
3. `_run_dnsmasq_test(tmp)` — `sudo dnsmasq --test --conf-file=<tmp>` (non-zero → return failure, no file written)
4. `_write_file_sudo(config_path, content)` — `sudo tee <path>` for main config
5. `_write_file_sudo(blocklist_path, content)` — `sudo tee <path>` for blocklist
6. `_run_systemctl("restart")` — `sudo systemctl restart dnsmasq`
7. On success: `self._state_file.commit(desired)` and emit `dnsmasq.applied`

## `POST /discard`

Reverts all ten in-memory dicts/lists to `self._state_file.current_snapshot`. Raises 409 if `current_snapshot` is `None` (never applied).

## DNS records

Records are stored as `{record_id: record}` where `record_id` is the first 8 characters of a `uuid4`. Supported record types and the dnsmasq directive each maps to:

| Type | Directive | Extra fields |
|---|---|---|
| A | `address=/{name}/{value}` | — |
| AAAA | `aaaa=/{name}/{value}` | — |
| CNAME | `cname={name},{value}` | — |
| TXT | `txt-record={name},"{value}"` | — |
| MX | `mx-host={name},{value},{priority}` | `priority` (default 10) |
| SRV | `srv-host={name},{value},{port},{priority},{weight}` | `port`, `priority`, `weight` |
| PTR | `ptr-record={name},{value}` | — |

## DHCP

Ranges are stored as `{range_id: range}`. The `mode` field controls non-standard DHCP range modes (`proxy`, `ra-only`, `slaac`, `ra-stateless`, `ra-names`); when mode is `"dhcp"` (default), no mode tag is emitted. Example directive for a basic range: `dhcp-range=10.0.0.100,10.0.0.200,12h`.

Static leases enforce uniqueness by MAC address — a 409 is returned if the same MAC is added twice. MAC addresses are normalized to lowercase on input.

`GET /dhcp/leases` reads the live lease file from `config.lease_file` (default `/var/lib/dnsmasq/dnsmasq.leases`). Returns an empty list if the file is missing or unreadable — no error is raised.

## Blocklists

Blocklist entries store the fetched domain list inline in the state file under `"domains"`:

```json
{
  "blocklist_id": {
    "name": "My List",
    "url": "https://...",
    "format": "hosts",
    "domains": ["bad.com", "evil.org"],
    "last_fetched": "2026-05-16T10:00:00+00:00"
  }
}
```

`POST /blocklists/{id}/refresh` re-fetches the URL and replaces `domains` in-place. Neither add nor refresh applies the blocklist to dnsmasq — call `POST /apply` separately.

## PXE services

PXE service entries are stored in `_pxe_services` as an ordered list. Deletion is by zero-based index; indices shift after deletion. The generated directive is `pxe-service={type},"{menu_name}"[,{boot_file}[,{server}]]`.

## mDNS

When enabled, the plugin emits `enable-ra` plus one `interface=` line per entry in `_mdns["interfaces"]`. This enables dnsmasq's router-advertisement and mDNS reflection between the listed interfaces. This is not the same as a standalone mDNS daemon (e.g. Avahi).

## Subprocess wrappers

| Method | Command |
|---|---|
| `_run_dnsmasq_test(path)` | `sudo dnsmasq --test --conf-file=<path>` |
| `_run_systemctl(action)` | `sudo systemctl <action> dnsmasq` |
| `_write_file_sudo(path, content)` | `sudo tee <path>` (stdin = content) |

In tests, replace these with `MagicMock` on the instantiated plugin before calling any route handler. Also mock `_read_on_disk` to control what the boot-time diff check sees.

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `dnsmasq_state.json` | filename inside `data/` |
| `config_path` | `/etc/dnsmasq.d/ff-managed.conf` | main dnsmasq config written on apply |
| `blocklist_path` | `/etc/dnsmasq.d/ff-blocklist.conf` | blocklist config written on apply |
| `lease_file` | `/var/lib/dnsmasq/dnsmasq.leases` | path read by `GET /dhcp/leases` |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` on startup |
| `debug` | `false` | log temp config path and dnsmasq/systemctl output; include `debug` key in `POST /apply` response |

## Events emitted

| Event | Payload |
|---|---|
| `dnsmasq.dns.updated` | `{config}` |
| `dnsmasq.record.added` | `{record_id, type, name}` |
| `dnsmasq.record.removed` | `{record_id}` |
| `dnsmasq.dhcp.updated` | `{enabled}` |
| `dnsmasq.range.added` | `{range_id}` |
| `dnsmasq.range.removed` | `{range_id}` |
| `dnsmasq.lease.added` | `{lease_id, mac, ip}` |
| `dnsmasq.lease.removed` | `{lease_id}` |
| `dnsmasq.tftp.updated` | `{enabled}` |
| `dnsmasq.pxe.updated` | `{enabled}` |
| `dnsmasq.mdns.updated` | `{enabled}` |
| `dnsmasq.blocklist.added` | `{blocklist_id, name, domain_count}` |
| `dnsmasq.blocklist.removed` | `{blocklist_id}` |
| `dnsmasq.applied` | `{success, returncode}` |

## Testing

Tests in `test_dnsmasq_api_routes.py`. Subprocess calls are mocked via `MagicMock` — no real system changes are made.

**`_make_plugin(tmp_path, config=None)` / `_make_client(plugin)`** — creates a fresh isolated instance per test. All tests use this pattern via the `plugin` / `client` fixtures.

**`_ok(returncode, stdout, stderr)`** — helper that returns a `MagicMock` with the appropriate `CompletedProcess` attributes. Pass `returncode=1` to simulate failures.

Key mock targets:
- `plugin._run_dnsmasq_test` — controls `dnsmasq --test` exit code
- `plugin._write_file_sudo` — prevents actual file writes
- `plugin._run_systemctl` — controls `systemctl restart` exit code
- `plugin._read_on_disk` — controls what the boot-time diff sees (return `None` to simulate missing file, or return the exact desired config string to simulate no change needed)
- `plugin._fetch_blocklist_domains` — since this is now `async`, `patch.object` auto-creates an `AsyncMock` in Python 3.8+; `return_value=[...]` is what `await` resolves to

Direct-call tests for `_fetch_blocklist_domains` must be `async def` and mock both `_validate_blocklist_url` (as `AsyncMock`) and `httpx.AsyncClient`.
