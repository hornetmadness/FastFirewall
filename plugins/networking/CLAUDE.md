# Networking Plugin

Manages network interfaces and routes declaratively via **systemd-networkd**. Desired state is stored in a JSON file; call `POST /apply` to push it to the running kernel by writing INI-format `.network` (and `.netdev`) files to `/etc/systemd/network/` and reloading with `networkctl reload`. Routes mount at `/v1/networking/`.

Sysctl management is delegated to the host plugin. To set a sysctl from this plugin emit `host.sysctl.set` instead of calling `sysctl` directly — the host plugin will apply, persist, and track it.

**Mutation model: deferred apply.** Every `PUT`/`POST`/`DELETE` mutation only updates the desired-state dict and saves it to disk — nothing is applied to the kernel until `POST /apply` is called. Uses `PluginStateFile` with `mutation_model="deferred"`, so `save_desired()` only writes desired state; `commit()` is called explicitly after a successful apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

Depends on: `host` plugin.

## Resources

| Resource | List | Mutate | Delete | Import |
|---|---|---|---|---|
| interfaces | `GET /config/interfaces` | `PUT /config/interfaces/{name}` | `DELETE /config/interfaces/{name}` | `POST /config/interfaces/import` |
| routes | `GET /config/routes` | `POST /config/routes` | `DELETE /config/routes/{route_id}` | `POST /config/routes/import` |
| bonds | `GET /config/bonds` | `POST /config/bonds`, `PUT /config/bonds/{name}` | `DELETE /config/bonds/{name}` | — |
| bridges | `GET /config/bridges` | `POST /config/bridges`, `PUT /config/bridges/{name}` | `DELETE /config/bridges/{name}` | — |
| WireGuard peers | `GET /config/interfaces/{name}/peers` | `POST /config/interfaces/{name}/peers`, `PUT /config/interfaces/{name}/peers/{peer_id}` | `DELETE /config/interfaces/{name}/peers/{peer_id}` | — |

Additional routes: `GET /status`, `GET /interfaces`, `GET /interfaces/{name}`, `GET /identify`, `GET /config`, `GET /config/diff`, `POST /apply`, `POST /check`, `POST /discard`, `POST /ping`, `POST /mtr`.

Bond member routes: `POST /config/bonds/{name}/members`, `DELETE /config/bonds/{name}/members/{member}`, `GET /bonds/{name}/status`.

Bridge member routes: `POST /config/bridges/{name}/members`, `DELETE /config/bridges/{name}/members/{member}`.

## Route prefixes: live vs config

- `/interfaces` — reads live running state via `ip -j addr show` (no config side-effects)
- `/config/interfaces` — reads/writes the managed desired-state dict
- `/config` — returns a JSON dict of `{filename: content}` for all managed `.network` and `.netdev` files

## State file

`data/networking_state.json` — two top-level keys:

```json
{
  "desired_state": {
    "interfaces": {},
    "routes": {},
    "aliases": {}
  },
  "current_state": {
    "interfaces": {},
    "routes": {},
    "aliases": {}
  }
}
```

`desired_state` holds what FF should enforce. `current_state` is committed only after a successful `POST /apply` or boot-time apply. `GET /status` reports `pending_changes: self._state_file.pending_changes`.

## DHCP interfaces

Set `dhcp4: true` and/or `dhcp6: true` on an interface to enable a DHCP client via systemd-networkd's native DHCP support:

```http
PUT /v1/networking/config/interfaces/eth0
{"dhcp4": true, "link": {"state": "up"}}
```

The generated `.network` file gets a `DHCP=ipv4` (dhcp4 only), `DHCP=ipv6` (dhcp6 only), or `DHCP=yes` (both) line. No hook scripts or dhclient are involved.

## Virtual devices: bonds, bridges, WireGuard

Virtual devices are stored in `_interfaces` with `link.kind` set to `"bond"`, `"bridge"`, or `"wireguard"`. Member interfaces (physical NICs enslaved to the virtual device) have `link.master` set to the parent's name.

At apply time, `_build_all_networkd_configs()` generates:
- `10-ff-{name}.netdev` — device declaration (`[NetDev]` + type-specific section)
- `10-ff-{name}.network` — addressing, DHCP, routes
- `10-ff-{member}.network` — bare `.network` with `Bond={name}` or `Bridge={name}` for each member

WireGuard `.netdev` files are written with mode `640`, group `systemd-network` to protect the inline private key.

## WiFi interfaces

Set `link.kind = "wifi"` and provide a `wifi: {ssid, psk}` body. At apply time:
1. `10-ff-wlan0.network` is written with `IgnoreCarrierLoss=3s` (prevents flapping during association)
2. `/etc/wpa_supplicant/wpa_supplicant-wlan0.conf` is written with mode `600` via pyinfra
3. `initsys.service.start` is emitted for `wpa_supplicant@wlan0.service`

## Key methods

**`_load_state()`** — calls `self._state_file.load_desired(default={})`, then reads `interfaces`, `routes`, `aliases` into `self._interfaces`, `self._routes`, `self._aliases`. `current_snapshot` is restored automatically from the on-disk `current_state`.

**`_save_state()`** — calls `self._state_file.save_desired(self._desired_snapshot())`. Does **not** update `current_state` — that only happens via `commit()`.

**`_desired_snapshot()`** — returns `json.loads(json.dumps({interfaces, routes, aliases}))`: a normalized deep copy used for diffing and snapshotting.

**`_apply_state()`** — re-applies desired state on boot by calling `_build_all_networkd_configs()`, writing files, running `networkctl reload` + per-interface `networkctl reconfigure`, then `_save_state()` + `commit()` on success.

**`_import_state_from_system()`** — read-only OS query called from `configure()` (not `setup()`) when the state file is empty; seeds `_interfaces` from `ip -j addr show` and `_routes` from `ip -j route show` (skipping loopback and kernel/redirect routes), then calls `save_and_commit()`.

**`_build_networkd_file(name, iface, routes)`** — generates an INI string for a `.network` file: `[Match]`, `[Network]` (addresses, DHCP, IgnoreCarrierLoss for WiFi), `[Link]` (MTU, ActivationPolicy), `[Route]` (one stanza per route). `"default"` destination is normalized to `0.0.0.0/0`.

**`_build_netdev_file(name, iface)`** — generates a `.netdev` file for bond, bridge, or wireguard virtual devices.

**`_build_all_networkd_configs()`** — iterates `_interfaces`, calls the appropriate builder per type, assigns routes by `dev` field or gateway subnet match. Raises `ValueError` for orphan routes (no `dev` and no gateway subnet match).

**`_write_networkd_files(files)`** — calls `_pyinfra_run(files_ops.put, ...)` for each file. WireGuard `.netdev` files get mode `640` + group `systemd-network`.

**`_prune_networkd_files(active_names)`** — finds existing `10-ff-*.network` and `10-ff-*.netdev` files in `/etc/systemd/network/` via `sudo find`, deletes any whose interface name is not in `active_names`.

**`_ip_addr_show()`** — runs `ip -j addr show` and returns parsed JSON list.

**`_ip_route_show()`** — runs `ip -j route show` and returns parsed JSON list.

**`_identify()`** — reads `perm_hwaddr` (or `address`) from `/sys/class/net/{name}/`. Uses module-level `_SYS_NET_DIR` constant (patchable in tests).

**`_sync_os_boot_service()`** — when `use_systemd_networkd=true`: disables competing managers, emits `initsys.service.start` for `systemd-networkd.service`. When false: emits `initsys.service.remove` for `fastfirewall-networking` (cleans up old custom unit).

`NetworkingPlugin` composes a `NetworkingAPI(ApiRouterAspect)` aspect (`api = NetworkingAPI`, taking over what was `_register_routes()`) and a `NetworkingMacros(MacroProviderAspect)` aspect (`macros = NetworkingMacros`, taking over `_register_interface_macros()` and `macro_snapshot()`) — both instantiated by the loader after `configure()` runs, so they read already-loaded state. State loading (and the first-boot `_import_state_from_system()` call) lives in `configure()`; `setup()` only runs `_apply_state()` (when needed) and `_sync_os_boot_service()`.

## `GET /config/diff`

Returns a structured diff between the last applied state (`current_snapshot`) and the current desired state. Response: `{pending_changes: bool, diff: {...}}`.

## `POST /discard`

Reverts `_interfaces`, `_routes`, `_aliases` back to `self._state_file.current_snapshot`. If `current_snapshot` is `None` (never applied), raises 409.

## `POST /check`

Returns `{success, returncode, changes, preview}`. `preview` is a dict of `{filename: content}` showing the files that would be written. If an orphan route would cause apply failure, returns `success: false` with `errors` list.

## Route IDs

Routes are keyed by a 16-character SHA-256 prefix of the serialized route dict. The same route submitted twice produces the same id and gets a 409.

## Import endpoints

`POST /config/interfaces/import` reads `ip -j addr show` and upserts the named (or all) interfaces into desired state. `POST /config/routes/import` does the same for routes using `ip -j route show`.

## Diagnostics

`POST /ping` — runs `ping -c <count> <host>`.  
`POST /mtr` — runs `mtr --report --json --report-cycles <count> <host>`.

## Alias mutations and `pending_changes`

Interface alias `PUT`/`DELETE` mutations call `self._state_file.commit(self._desired_snapshot())` immediately after `_save_state()`. Alias changes do not leave `pending_changes: true`.

## Events emitted

| Event | Payload |
|---|---|
| `networking.interface.configured` | `{name, addresses?, link?}` |
| `networking.interface.removed` | `{name}` |
| `networking.route.added` | `{route_id, to}` |
| `networking.route.removed` | `{route_id, to}` |
| `networking.applied` | `{success, returncode}` |

## Events emitted to init system

| Event | When |
|---|---|
| `initsys.service.disable` | `use_systemd_networkd: true` — one event per entry in `disable_os_managers` |
| `initsys.service.start` | `use_systemd_networkd: true` — starts `systemd-networkd.service` |
| `initsys.service.remove` | `use_systemd_networkd: false` — removes `fastfirewall-networking` legacy unit if it exists |

## Config options (`plugin.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `state_file` | `networking_state.json` | filename inside `data/` |
| `ignore_state_on_boot` | `false` | skip `_apply_state()` / `_import_state_from_system()` on startup |
| `use_systemd_networkd` | `false` | start `systemd-networkd` and disable competing managers at setup time |
| `disable_os_managers` | `[NetworkManager, networking]` | service names to stop/disable when `use_systemd_networkd: true` |
| `debug` | `false` | include `debug` key in `POST /apply` response with networkd filenames |

## Testing

Tests in `test_networking_api_routes.py`. All subprocess calls are mocked — no real system changes are made.

- **`_make_plugin(tmp_path, config=None)`** — creates a fresh isolated instance. `plugin._pyinfra_run` is mocked to `MagicMock()`. `subprocess.run` is patched with `_subprocess_run_ok` during `setup()` to handle `networkctl` and `ip` calls.
- **`_make_client(plugin)`** — wraps the plugin router in a `FastAPI()` and returns `TestClient`.
- **Mock `_ip_addr_show` / `_ip_route_show`** on the plugin instance to control live-state results.
- **`_make_ip_addr_list(interfaces)` / `_make_ip_route_list(routes)`** — helpers that produce `ip -j` style JSON from simplified input dicts.
- **Boot-state tests** write `_BOOT_STATE` via `_write_boot_state(tmp_path)`, then call `_make_plugin_raw` which does NOT reset the `_pyinfra_run` mock — use it to assert boot-time apply calls.
- **Boot-import tests** use `_make_plugin_boot_import(tmp_path, ip_addr_data=..., ip_route_data=...)` to inject mock ip command output.
- **`_identify` tests** patch `_SYS_NET_DIR` via `setattr(mod, "_SYS_NET_DIR", net_dir)` using a real `tmp_path` directory structure.
