# FastFirewall

An API-first firewall and router (network appliance) management system. FastFirewall exposes a REST API for managing firewall rules, network interfaces, DNS, DHCP, system users, and more — everything you'd configure manually on a Linux router or gateway, controllable via HTTP from anywhere on your network.

Built on FastAPI and driven entirely by plugins. Every feature is a plugin; the core app has only a few API routes of its own.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Running the server](#running-the-server)
- [fastfirewall-api CLI reference](#fastfirewall-api-cli-reference)
- [Authentication](#authentication)
- [Plugin system](#plugin-system)
- [State files](#state-files)
- [Plugins](#plugins)
  - [Firewall](#firewall-plugin)
  - [Networking](#networking-plugin)
  - [DNS + DHCP (dnsmasq)](#dnsmasq-plugin)
  - [Host](#host-plugin)
  - [SMTP](#smtp-plugin)
  - [Syslog](#syslog-plugin)
  - [Audit](#audit-plugin)
- [Bootstrapping](#bootstrapping)
  - [With the bootstrap wizard](#with-the-bootstrap-wizard)
  - [Without the wizard (curl)](#without-the-wizard-curl)
- [Macros](#macros)
- [Configuration reference](#configuration-reference)

---

## Requirements

- Python 3.12+
- `pipx` and `uv` (see install steps below)
- Root or sudo access (plugins call `nftables`, `systemctl`, `ifstate`, etc.)
- Linux (Debian/Ubuntu tested; most plugins work on any systemd-based distro)

## Installation

### From source (development)

```bash
git clone <repo>
cd FastFirewall
uv sync
```

`uv sync` creates a virtualenv and installs all Python dependencies from `uv.lock`.

### From the package registry (production)

**As root — create the service user and grant passwordless sudo:**

```bash
# Create a dedicated service user
useradd -m -s /bin/bash fastfirewall

# Create a no-password sudo group and add the user to it
groupadd sudo-np
usermod -a -G sudo-np fastfirewall
echo '%sudo-np ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudo-np
```
# System packages to install
```bash
apt install pipx
```

Passwordless sudo is required because FastFirewall actively manages the system — plugins configure network interfaces, firewall rules, DNS, DHCP, users, packages, and more, all of which require elevated privileges.

**As the `fastfirewall` user — install and configure:**

```bash
# 1. Install pipx
pipx install uv
pipx ensurepath

# 2. Create a virtualenv and activate it
uv venv
source ~/.venv/bin/activate

# 3. Install FastFirewall from the package registry
uv pip install fastfirewall \
  --index-strategy unsafe-best-match \
  --extra-index-url "http://<token>@<gitea-host>/api/packages/<owner>/pypi/simple/"

# 4. Add the venv bin to your PATH (add to ~/.bashrc to persist)
export PATH="$PATH:$HOME/.venv/bin"

# 5. Scaffold the config directory
fastfirewall-api --makecfg ~/.config/fastfirewall
```

`--makecfg` takes a **directory path** and creates it if needed, writing a starter `app_config.yaml` and a `plugins/` subdirectory into it. Edit the generated file to set a strong `secret_key` and update `auth.users` before starting the server.

See [BUILD.md](BUILD.md) for how to build and publish packages.

---

## Running the server

```bash
# From source
uv run python fastfirewall_app.py

# When installed
fastfirewall-api

# Interactive API docs
open http://localhost:8000/docs
```

The server loads all enabled plugins at startup. Each plugin mounts its API routes at `/v1/<plugin_id>/`. Plugins that need system packages (nftables, dnsmasq, fluent-bit, etc.) install them automatically via pyinfra when they load.

Use `--showcfg` to confirm which config file and paths are active before starting:

```bash
fastfirewall-api --showcfg
```

---

## fastfirewall-api CLI reference

`fastfirewall-api` is the main command-line interface for FastFirewall. It starts the API server, manages configuration, controls the systemd service, and handles plugin state — all through the same entry point. Many flags handle configuration tasks and exit without starting the server:

```bash
# Show the active config file and all resolved plugin paths
fastfirewall-api --showcfg

# Scaffold a production config directory (creates dirs + starter app_config.yaml)
fastfirewall-api --makecfg ~/.config/fastfirewall

# List all discovered plugins with their state, version, and port claims
fastfirewall-api --list-plugins

# Enable or disable a plugin (edits plugin.yaml, then exits)
fastfirewall-api --enable-plugin syslog
fastfirewall-api --disable-plugin smtp

# Show all macro namespaces and their current resolved values, then exit
fastfirewall-api --show-macros

# Load only specific plugins (useful for testing or minimal deployments)
fastfirewall-api --plugin firewall --plugin networking

# Skip re-applying saved state to the system on boot (state files are still read,
# but nothing is pushed to the kernel/daemons until you explicitly call /apply)
fastfirewall-api --ignore-plugins-states

# Install the systemd service (enables for boot, does not start immediately)
fastfirewall-api --install-service

# Remove the systemd service
fastfirewall-api --uninstall-service

# Full help
fastfirewall-api --help
```

`--list-plugins` output looks like:

```
ID          NAME                VERSION  STATE     REQUIRES    SERVICES      PORTS
----------  ------------------  -------  --------  ----------  ------------  -----
firewall    Firewall Plugin     1.0.0    enabled   -           FIREWALL      -
host        Host Plugin         1.0.0    enabled   -           HOST          -
networking  Networking Plugin   1.0.0    enabled   host        NETWORKING    -
dnsmasq     DNSMasq Plugin      1.0.0    enabled   networking  DNS, DHCP     udp:53  tcp:53  udp:67
```

---

## Authentication

Every route requires authentication. Two methods are supported:

**HTTP Basic:**
```bash
curl -u admin:admin http://localhost:8000/v1/firewall/status
```

**Bearer JWT (obtain via `/token`):**
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/token \
  -d "username=admin&password=admin" | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/me
```

The interactive docs at `/docs` have an **Authorize** button that handles both methods.

Default credentials are `admin` / `admin`. **Change these before exposing the API to a network.** See [Configuration reference](#configuration-reference) for how to set users and generate a strong JWT secret.

### Brute-force protection

`POST /token` is rate-limited per client IP. After **5 failed attempts within a 5-minute sliding window**, the endpoint returns `429 Too Many Requests` with a `Retry-After: 300` header. The counter resets automatically when the window expires or when a login succeeds.

Both limits are tunable in `app_config.yaml` under `auth.rate_limit`:

```yaml
auth:
  rate_limit:
    max_attempts: 5      # failures allowed before lockout
    window_seconds: 300  # sliding window length
```

---

## Plugin system

FastFirewall is entirely plugin-driven. Every plugin lives in `plugins/<name>/` and consists of two files:

- **`plugin.yaml`** — metadata, config, dependencies, and port declarations
- **`plugin.py`** — the Python implementation (a class that inherits `PluginBase`)

On startup, the loader discovers all enabled plugins, registers any third-party apt repos declared in `plugin.yaml`, batch-installs all `os_requirements` in a single `apt-get install`, runs `uv sync` once to install Python dependencies (declared in each plugin's `pyproject.toml`), then loads plugins in dependency order and mounts their API routes.

### Service exclusivity

Each plugin claims one or more **services** (e.g. `FIREWALL`, `DNS`, `DHCP`). Only one plugin may own a given service at a time. This prevents conflicts — you can't accidentally load two DHCP plugins.

### Port conflict detection

Plugins declare which ports they use in `plugin.yaml`. The loader checks for conflicts between plugins and verifies no other process on the OS is already using the port (reads `/proc/net/tcp` and `/proc/net/udp`).

### Plugin load order

Plugins declare `plugin_requirements` (a list of other plugin IDs they depend on). The loader topologically sorts the full plugin list so dependencies always load first. Alphabetical order breaks ties.

### Enabling and disabling plugins

```bash
# Disable the SMTP plugin
fastfirewall-api --disable-plugin smtp

# Re-enable it
fastfirewall-api --enable-plugin smtp
```

This edits the `enabled` field in the plugin's `plugin.yaml` and exits. The change takes effect on the next server start.

### OS boot service registration (`enable_os_boot`)

Some plugins can register a lightweight systemd oneshot service that applies their configuration at OS boot — before FastFirewall itself starts. This is useful for critical services like the firewall and networking, where you want rules and interfaces active during early boot even if FastFirewall fails to start.

Set `enable_os_boot: true` in the relevant plugin's `plugin.yaml` config block:

```yaml
# plugins/firewall/plugin.yaml
config:
  enable_os_boot: true   # registers fastfirewall-nft.service — applies nft rules at boot
```

Supported plugins and their registered services:

| Plugin | Service name | What it applies |
|---|---|---|
| `firewall` | `fastfirewall-nft` | Compiled `.nft` ruleset via `nft -f` |
| `networking` | `fastfirewall-networking` | Interface config via `ifstate apply` — see warning below |
| `dnsmasq` | `dnsmasq` | Ensures dnsmasq is enabled for boot |
| `apt_cacher_ng` | `apt-cacher-ng` | Ensures apt-cacher-ng is enabled for boot |

The registration or removal happens automatically each time FastFirewall starts — setting the flag and restarting FastFirewall is all that's needed.

> **Warning — non-reversible change for the networking plugin:** When `enable_os_boot: true` is set, the networking plugin stops and disables every service listed in `disable_os_managers` in `plugins/networking/plugin.yaml` (by default: `NetworkManager`, `networking`, `systemd-networkd`). This lets ifstate fully own interface bring-up at boot. **FastFirewall will not re-enable those services if you later set `enable_os_boot` back to `false`.** To restore a previous network manager run `sudo systemctl enable --now <service>` manually. Review `disable_os_managers` and remove any entries that should remain running before enabling this flag.

### API error responses

FastFirewall does not include internal details in error responses. When a plugin operation fails (subprocess non-zero exit, service unreachable, etc.), the API returns a generic message:

```json
{"detail": "Postfix reload failed; check server logs"}
```

The full detail — stderr output, exception traceback, internal paths — is logged at `ERROR` level on the server side. To diagnose a failure, check the server console or the audit log (`plugins/audit/data/audit.log`).

This applies to all `5xx` responses. `4xx` responses (404 Not Found, 409 Conflict, 422 Validation Error) do include the specific reason, since those describe a client-side problem rather than a server-side failure.

### Input validation

All request bodies are validated by Pydantic before reaching plugin code. String fields have maximum length constraints to prevent oversized payloads. A `422 Unprocessable Entity` is returned when any constraint is violated:

```json
{
  "message": "Name: String should have at most 100 characters",
  "source_errors": [...]
}
```

Key limits across the API:

| Field type | Limit |
|---|---|
| Names, labels, identifiers | 100 chars |
| Comments, GECOS | 255 chars |
| Hostnames, DNS names | 253 chars (RFC 1035) |
| IP addresses | 39 chars (max IPv6) |
| CIDR ranges | 43 chars (max IPv6/128) |
| Linux interface names | 15 chars (IFNAMSIZ) |
| File/socket paths | 4096 chars |
| URLs (blocklists) | 2048 chars |
| Email addresses | 254 chars (RFC 5321) |
| Email subjects | 998 chars (RFC 2822) |
| Email bodies | 65536 chars |
| Sysctl values | 64 chars |
| Cron commands | 4096 chars |

---

## State files

FastFirewall plugins store their configuration in JSON state files under `plugins/<name>/data/`. These files survive server restarts; the plugin re-reads them on boot and re-applies the configuration to the system.

### The desired/current envelope

Every state file uses a two-key envelope:

```json
{
  "desired_state": { ... },
  "current_state": { ... }
}
```

- **`desired_state`** — what you've asked FastFirewall to configure. Updated on every API mutation.
- **`current_state`** — the last state that was successfully applied to the system. Only updated after a successful apply.

When `desired_state != current_state`, the plugin reports `pending_changes: true` in its `GET /status` response.

### Mutation models

Plugins use one of two mutation models depending on whether they manage stateful external services:

**Immediate** (host, smtp, syslog) — the mutation calls the system tool inline and `current_state` is updated automatically on every write. `pending_changes` is always `false`. No `/apply` endpoint.

**Deferred** (firewall, networking, dnsmasq) — mutations only update `desired_state`. You explicitly call `POST /apply` when ready. This lets you stage multiple changes and validate them with `POST /check` before pushing to the kernel.

**Example flow for a deferred plugin:**
```bash
# 1. Make changes
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/rules -d '{...}'
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/rules -d '{...}'

# 2. Check pending changes
curl -su admin:admin http://localhost:8000/v1/firewall/status
# → {"pending_changes": true, ...}

# 3. Dry-run validate
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/check

# 4. Apply
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/apply
# → current_state is now committed; pending_changes: false
```

### Discarding changes

Deferred plugins support `POST /discard` to revert all pending changes back to `current_state` (the last successfully applied state):

```bash
curl -su admin:admin -X POST http://localhost:8000/v1/networking/discard
```

### State file backups

When `state.backup.enabled: true` in `app_config.yaml`, FastFirewall snapshots every state file before every write — whether that's a desired state update, a commit after apply, or an import. Backup filenames include a timestamp (`<stem>_<YYYYMMDD_HHMMSS>.json`) and land in `/var/tmp/ff-backups/states/`. This gives you a full history to roll back to if something goes wrong.

```yaml
state:
  backup:
    enabled: true
    directory: /var/tmp/ff-backups/states
```

### Boot-time re-apply

On startup, each plugin reads its state file and re-applies `desired_state` to the system. This means the system configuration survives a reboot — FastFirewall restores its managed state automatically.

To skip the boot-time re-apply for all plugins (state files are still loaded, but nothing is pushed to the system until you explicitly call `/apply`):
```bash
uv run python fastfirewall_app.py --ignore-plugins-states
```

---

## Plugins

### Firewall Plugin

**Routes:** `/v1/firewall/`

Manages firewall rules and compiles them to an nftables script applied via a sudo wrapper (`nft_cmd`). Rules are defined declaratively via the API; call `POST /apply` to push them to the kernel.

Rules are stored in a JSON file. An implicit `deny all` is always appended at the end of the compiled policy — you only need to write `accept` rules.

**On fresh install**, two default rules are seeded automatically: one allowing SSH (TCP/22) and one allowing the FastFirewall API (TCP/8000). This prevents lockout. Delete them if you want to manage those rules yourself.

**Rule IDs** are a content hash of the rule fields. Submitting an identical rule twice returns `409 Conflict` instead of creating a duplicate.

**`PUT /rules/{id}`** accepts a partial body — only the fields you include are changed; omitted fields keep their current values.

| Route | Method | Description |
|---|---|---|
| `/rules` | GET | List all rules |
| `/rules` | POST | Create a rule |
| `/rules/{id}` | GET | Get a rule |
| `/rules/{id}` | PUT | Partially update a rule (omitted fields unchanged) |
| `/rules/{id}` | DELETE | Delete a rule |
| `/chains` | GET | List chains and their policies |
| `/chains/{name}` | GET | Get a chain |
| `/chains/{name}` | PUT | Update chain policy, priority, or preamble |
| `/sets` | GET | List named sets |
| `/sets` | POST | Create a named set |
| `/sets/{name}` | GET / DELETE | Get or delete a named set |
| `/sets/{name}/elements` | POST / DELETE | Add or remove set elements |
| `/nat/rules` | GET | List NAT rules |
| `/nat/rules` | POST | Create a NAT rule |
| `/nat/rules/{id}` | GET / PUT / DELETE | Read, update, or delete a NAT rule |
| `/custom-chains` | GET | List custom chains |
| `/custom-chains` | POST | Create a custom chain |
| `/custom-chains/{name}` | GET / DELETE | Get or delete a custom chain |
| `/flowtables` | GET | List flowtables |
| `/flowtables` | POST | Create a flowtable |
| `/flowtables/{name}` | GET / DELETE | Get or delete a flowtable |
| `/ingress/rules` | GET | List ingress (netdev) rules |
| `/ingress/rules` | POST | Create an ingress rule |
| `/ingress/rules/{id}` | GET / PUT / DELETE | Read, update, or delete an ingress rule |
| `/quotas` | GET | List named quotas |
| `/quotas` | POST | Create a named quota |
| `/quotas/{name}` | GET / DELETE | Get or delete a named quota |
| `/maps` | GET | List verdict maps |
| `/maps` | POST | Create a verdict map |
| `/maps/{name}` | GET / DELETE | Get or delete a verdict map |
| `/maps/{name}/entries` | POST / DELETE | Add or remove verdict map entries |
| `/counters` | GET | Live counter values from the kernel |
| `/counters/{name}/reset` | POST | Atomically reset a named counter |
| `/table` | GET | Current table name, family, and chain list |
| `/check` | POST | Dry-run validate — validates without applying |
| `/apply` | POST | Compile and apply to nftables |
| `/compile` | POST | Compile to nft script (preview, no apply) |
| `/discard` | POST | Revert pending changes to last applied state |
| `/live-state` | GET | Current kernel ruleset as parsed JSON |
| `/status` | GET | Plugin status and pending changes |

**Rule fields:**

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `str` | required | max 100 chars |
| `chain` | `str` | `"input"` | hook chain or custom chain name |
| `action` | `"accept" \| "deny" \| "reject" \| "jump" \| "return"` | `"deny"` | `reject` sends ICMP unreachable; `deny` silently drops |
| `jump_target` | `str` | `null` | required when `action` is `"jump"` |
| `protocol` | `"tcp" \| "udp" \| "icmp" \| "icmpv6" \| "esp" \| "ah" \| "any"` | `null` | |
| `src_address` | `str` | `"any"` | IPv4/IPv6 CIDR or `"any"` |
| `dst_address` | `str` | `"any"` | IPv4/IPv6 CIDR or `"any"` |
| `src_address_set` | `str` | `null` | named set reference, e.g. `@blocked-ips` |
| `dst_address_set` | `str` | `null` | named set reference |
| `src_interface` | `str` | `null` | `iif` match |
| `dst_interface` | `str` | `null` | `oif` match |
| `src_port` | `int \| macro` | `null` | TCP/UDP only; accepts `$service_port.*` macros |
| `dst_port` | `int \| macro` | `null` | TCP/UDP only; accepts `$service_port.*` macros |
| `src_port_range` | `[int, int]` | `null` | TCP/UDP port range |
| `dst_port_range` | `[int, int]` | `null` | TCP/UDP port range |
| `src_port_vmap` | `str` | `null` | verdict map for `sport vmap @name` |
| `dst_port_vmap` | `str` | `null` | verdict map for `dport vmap @name` |
| `tcp_flags` | `list[str]` | `null` | flag match: `syn`, `ack`, `fin`, `rst`, `urg`, `psh` |
| `tcp_flags_mask` | `list[str]` | `null` | mask for `tcp_flags` |
| `icmp_type` | `int \| str` | `null` | ICMP type, e.g. `"echo-request"` or `8` |
| `ct_state` | `list[str]` | `null` | CT state: `new`, `established`, `related`, `invalid` |
| `counter_name` | `str` | `null` | named counter; emits `counter name <n>` before the verdict |
| `quota_name` | `str` | `null` | named quota; emits `quota name <n>` before the verdict |
| `mark` | `int` | `null` | packet mark match |
| `dscp` | `int \| str` | `null` | DSCP match, e.g. `"cs0"` or `0` |
| `pkttype` | `"unicast" \| "broadcast" \| "multicast"` | `null` | packet type match |
| `rate_limit` | object | `null` | rate-limiting; emits `limit rate [over] N/unit [burst M]` |
| `log` | object | `null` | logging; emits `log prefix "..." level ...` before the verdict |
| `comment` | `str` | `null` | max 255 chars |
| `priority` | `int` | `100` | lower = matched first |
| `enabled` | `bool` | `true` | disabled rules are compiled out |

**Chains and preamble:**

Each chain has a `preamble` — a list of raw nft expressions inserted before user rules. The defaults are:

| Chain | Default policy | Default preamble |
|---|---|---|
| `input` | `drop` | `["iif lo accept", "ct state established,related accept", "ct state invalid drop"]` |
| `forward` | `drop` | `["ct state established,related accept"]` |
| `output` | `accept` | `[]` |

Preamble rules are stored in state and compiled into the script. Update them via `PUT /chains/{name}` with `{"preamble": [...]}`. Changes are deferred; `POST /apply` is required.

**Example — create and apply a rule:**
```bash
# Allow HTTP from your LAN
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"allow-http-from-lan","action":"accept","protocol":"tcp",
       "src_address":"192.168.0.0/24","dst_port":80,"priority":40}'

# Dry-run to validate first
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/check

# Apply
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/apply
```

---

### Networking Plugin

**Routes:** `/v1/networking/`  
**Depends on:** host plugin

Manages network interfaces and static routes via [ifstate](https://github.com/ipinfra/ifstate). Desired state is stored in a JSON file; nothing is applied to the kernel until `POST /apply`. Sysctl parameters are managed by the host plugin (`PUT /v1/host/sysctl/{key}`).

**Deferred apply model:** mutations (PUT/POST/DELETE) only update the state file. `GET /status` will show `pending_changes: true` until you apply.

| Route | Method | Description |
|---|---|---|
| `/config/interfaces` | GET | List managed interfaces |
| `/config/interfaces/{name}` | PUT / DELETE | Set or remove an interface |
| `/config/interfaces/import` | POST | Import live interface into management |
| `/config/routes` | GET | List managed routes |
| `/config/routes` | POST | Add a route |
| `/config/routes/{id}` | DELETE | Remove a route |
| `/config/diff` | GET | Diff between last applied and desired state |
| `/config` | GET | Full desired state (YAML or JSON) |
| `/interfaces` | GET | Live interface state from `ifstatecli show` |
| `/check` | POST | Dry-run via `ifstatecli check` |
| `/apply` | POST | Apply via `ifstatecli apply` |
| `/discard` | POST | Revert pending changes to last applied state |
| `/ping` | POST | Run ping from the gateway |
| `/mtr` | POST | Run mtr and return hop table |
| `/status` | GET | Plugin status and pending changes |

**Interface aliases** let you assign friendly names to interface device names (e.g. `lan` → `enp3s0`). Each alias exposes two macros — `$interface.lan.name` (the OS device name) and `$interface.lan.address` (the L3 address of that device) — and are used by the bootstrap wizard.

```bash
# Assign LAN alias
curl -su admin:admin -X PUT http://localhost:8000/v1/networking/config/aliases/lan \
  -H "Content-Type: application/json" \
  -d '{"interface": "enp3s0"}'
```

---

### DNSMasq Plugin

**Routes:** `/v1/dnsmasq/`  
**Depends on:** networking plugin

Manages dnsmasq for DNS forwarding/caching and DHCP. Supports static DNS records, DHCP scopes, static leases, PXE boot, and domain blocklists.

**Deferred apply model:** mutations only update state. Call `POST /apply` to write configs to `/etc/dnsmasq.d/` and restart dnsmasq.

**Key resources:**

| What | Read | Write |
|---|---|---|
| DNS settings | `GET /dns` | `PUT /dns` |
| DNS records | `GET /dns/records` | `POST /dns/records` |
| DHCP settings | `GET /dhcp` | `PUT /dhcp` |
| DHCP scopes | `GET /dhcp/ranges` | `POST /dhcp/ranges` |
| Static leases | `GET /dhcp/static-leases` | `POST /dhcp/static-leases` |
| Live leases | `GET /dhcp/leases` | — |
| Blocklists | `GET /blocklists` | `POST /blocklists` |
| Full config | `GET /config` | — |

The `dns` config fields `port`, `listen_addresses`, and `interface` accept macro strings that are resolved at apply time. For example, `"listen_addresses": ["$interface.lan.address"]` automatically expands to the LAN interface's current IP.

```bash
# Set upstream DNS, domain, and listen on the LAN interface via macro
curl -su admin:admin -X PUT http://localhost:8000/v1/dnsmasq/dns \
  -H "Content-Type: application/json" \
  -d '{"domain":"home.lan","upstream":["8.8.8.8","1.1.1.1"],"listen_addresses":["$interface.lan.address"],"interface":"$interface.lan.name"}'

# Add a DHCP scope
curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/dhcp/ranges \
  -H "Content-Type: application/json" \
  -d '{"start":"192.168.0.100","end":"192.168.0.200","lease_time":"24h","interface":"eth1"}'

# Validate config before restarting dnsmasq
curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/check

# Apply
curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/apply
```

**Blocklists** download a hosts file or domain list from a URL and block every domain in it via dnsmasq's `address=` directive:

```bash
# Add a blocklist (hosts format)
curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/blocklists \
  -H "Content-Type: application/json" \
  -d '{"name":"StevenBlack","url":"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts","format":"hosts"}'

# Refresh it later
curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/blocklists/<id>/refresh

# Then apply to activate
curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/apply
```

---

### Host Plugin

**Routes:** `/v1/host/`

Manages local system configuration: hostname, domain name, users, groups, cron jobs, packages, repos, sysctl, and services — all via pyinfra operations.

**Immediate apply model:** every mutation calls the system tool inline and returns. There is no `/apply` step — changes take effect immediately.

| Resource | List | Create/Update | Delete | Import |
|---|---|---|---|---|
| Users | `GET /users` | `POST /users/{name}` | `DELETE /users/{name}` | `POST /users/{name}/import` |
| Groups | `GET /groups` | `POST /groups/{name}` | `DELETE /groups/{name}` | `POST /groups/{name}/import` |
| Group members | `GET /groups/{name}/members` | `POST /groups/{name}/members` | `DELETE /groups/{name}/members/{user}` | — |
| Cron | `GET /cron` | `POST /cron/{name}` | `DELETE /cron/{name}` | — |
| Packages | `GET /packages` | `POST /packages/{name}` | `DELETE /packages/{name}` | — |
| Repos | `GET /repos` | `POST /repos/{name}` | `DELETE /repos/{name}` | — |
| Services | `GET /services` | `PUT /services/{name}` | `DELETE /services/{name}` | `POST /services/{name}/import` |
| Sysctl | `GET /sysctl` | `PUT /sysctl/{key}` | `DELETE /sysctl/{key}` | — |

**Hostname and domain name** are managed via dedicated endpoints:

```bash
# Get/set the short hostname
curl -su admin:admin http://localhost:8000/v1/host/hostname
curl -su admin:admin -X PUT http://localhost:8000/v1/host/hostname \
  -H "Content-Type: application/json" -d '{"hostname":"gateway"}'

# Get/set/delete the domain name (applied as the full FQDN)
curl -su admin:admin http://localhost:8000/v1/host/domainname
curl -su admin:admin -X PUT http://localhost:8000/v1/host/domainname \
  -H "Content-Type: application/json" -d '{"domainname":"home.lan"}'
curl -su admin:admin -X DELETE http://localhost:8000/v1/host/domainname
```

The host plugin also registers the **`$host` macro namespace**:

| Macro | Resolves to |
|---|---|
| `$host.hostname` | Short hostname (live from OS) |
| `$host.domainname` | FF-managed domain, falling back to OS FQDN-derived domain |
| `$host.fqdn` | `hostname.domainname` |

On first boot the domain is automatically seeded from the OS FQDN so `$host.fqdn` resolves correctly without manual configuration.

```bash
# Create a user
curl -su admin:admin -X POST http://localhost:8000/v1/host/users/netadmin \
  -H "Content-Type: application/json" \
  -d '{"shell":"/bin/bash"}'

# Add them to a group (group must be FF-managed — import it first)
curl -su admin:admin -X POST http://localhost:8000/v1/host/groups/sudo/import
curl -su admin:admin -X POST http://localhost:8000/v1/host/groups/sudo/members \
  -H "Content-Type: application/json" \
  -d '{"username":"netadmin"}'
```

**Import endpoints** let you claim an existing system resource into FastFirewall management without recreating it. Useful for adopting a system that was configured by hand.

```bash
# Take management of an existing service
curl -su admin:admin -X POST http://localhost:8000/v1/host/services/nginx/import
```

List endpoints (`GET /users`, `GET /groups`, etc.) read live system state and merge it with the FF-managed dict. Every entry includes `ff_managed: true/false` so you can tell if FastFirewall manages it.

**OS service coordinator:** The host plugin also acts as the init system manager for all other plugins. Plugins that need a service enabled or restarted (firewall, networking, dnsmasq, apt-cacher-ng) emit events like `initsys.service.restart` on the internal bus rather than calling `systemctl` directly — the host plugin handles the actual systemctl/upstart/sysvinit call. This keeps all init system logic in one place and makes the rest of the plugins init-system-agnostic.

---

### SMTP Plugin

**Routes:** `/v1/smtp/`

Manages Postfix configuration and provides send/test email endpoints. Applies settings via `postconf -e`.

**Immediate apply model:** `PUT /config` updates Postfix and returns immediately.

| Route | Method | Description |
|---|---|---|
| `/config` | GET / PUT | Read or apply Postfix settings |
| `/queue` | GET / DELETE | Show or flush the mail queue |
| `/send` | POST | Send an email |
| `/test` | POST | Send a test email |
| `/reload` | POST | Reload Postfix |
| `/status` | GET | Plugin and Postfix service status |

```bash
# Set relay host
curl -su admin:admin -X PUT http://localhost:8000/v1/smtp/config \
  -H "Content-Type: application/json" \
  -d '{"relayhost":"[smtp.example.com]:587"}'

# Send a test email
curl -su admin:admin -X POST http://localhost:8000/v1/smtp/test \
  -H "Content-Type: application/json" \
  -d '{"to":"you@example.com"}'
```

---

### Syslog Plugin

**Routes:** `/v1/syslog/`

Installs and configures [fluent-bit](https://fluentbit.io/) as a syslog server. Listens on UDP/TCP 514, optionally ingests the systemd journal, and writes structured logs to `/var/log/fastfirewall/`.

**Immediate apply model:** `PATCH /config` writes the new fluent-bit config and restarts the service inline.

| Route | Method | Description |
|---|---|---|
| `/config` | GET / PATCH | Read or update fluent-bit settings |
| `/config/reload` | POST | Reload fluent-bit |
| `/config/raw` | GET | Raw fluent-bit config file |
| `/config/diagnose` | GET | Diagnose setup and journal access |
| `/config/logrotate` | GET / PATCH | Read or update logrotate settings |
| `/files` | GET | List log files |
| `/logs/{filename}` | GET | Read last N lines of a log file |
| `/journal` | GET | Read systemd journal entries |
| `/status` | GET | Plugin and service status |

Point remote syslog sources (routers, switches, other servers) at `<host>:514` to start collecting their logs.

---

### Audit Plugin

**Routes:** none (internal only)

Subscribes to every event on the internal event bus and writes them to `plugins/audit/data/audit.log`. Useful for seeing what FastFirewall is doing and when.

Macro values in event payloads are automatically resolved before logging — so `$service_port.dns.udp` appears alongside its resolved value `[53]` in the log entry.

Ignored events are configurable in `plugin.yaml` (default: `heartbeat`, `ping`).

---

## Bootstrapping

### With the bootstrap wizard

The bootstrap wizard (`tools/bootstrap.py`) drives the API to configure common scenarios. It prompts you through a series of questions, shows you a review summary, then calls the API to configure everything.

**Interactive wizard:**
```bash
fastfirewall-bootstrap --save init.json
```

The wizard will ask you to choose a scenario:

1. **gateway** — Full router/gateway: networking interfaces, firewall rules, DNS/DHCP, and a host user
2. **firewall** — Firewall rules only
3. **dns-dhcp** — DNS and DHCP via dnsmasq only

It queries `GET /v1/networking/identify` to show you the available network interfaces by name, so you can pick WAN and LAN from a numbered list rather than typing device names.

**From a config file (non-interactive):**
```bash
# Copy an example config and edit it
cp tools/examples/gateway.yaml my-setup.yaml
# edit my-setup.yaml with your interface names, addresses, domain, etc.

fastfirewall-bootstrap --config my-setup.yaml
```

Example configs live in `tools/examples/`:

| File | Scenario |
|---|---|
| `gateway.yaml` | Full router/gateway |
| `firewall.yaml` | Firewall rules only |
| `dns-dhcp.yaml` | DNS and DHCP only |

**Save and replay sessions:**

The wizard can record every API call it makes to a JSON file. You can replay this file later — useful for provisioning identical boxes or keeping a record of what was applied.

```bash
# Interactive wizard + save the session
fastfirewall-bootstrap --save my-setup.json

# Replay against the same server later
fastfirewall-bootstrap --apply my-setup.json

# Replay against a different server
fastfirewall-bootstrap --apply my-setup.json --host http://10.0.0.2:8000
```

**Full wizard options:**
```
--config FILE    YAML or JSON config file (skips interactive prompts)
--save FILE      Write all API calls to FILE for later replay
--apply FILE     Replay a previously saved JSON session
--host URL       Override server URL (default: http://localhost:8000)
--username/-u    API username
--password/-p    API password
```

#### Example gateway.yaml

```yaml
server:
  host: "http://localhost:8000"
  username: "admin"
  password: "admin"

scenario: "gateway"
hostname: "gateway"

network:
  wan:
    interface: "eth0"
    mode: "dhcp"
  lan:
    interface: "eth1"
    address: "192.168.0.1/24"

dns:
  domain: "home.lan"
  upstream:
    - "8.8.8.8"
    - "1.1.1.1"
  records:
    - type: "A"
      name: "gateway.home.lan"
      value: "192.168.0.1"

dhcp:
  start: "192.168.0.100"
  end: "192.168.0.200"
  lease_time: "24h"

firewall:
  lan_subnet: "192.168.0.0/24"
  allow_ssh_from_lan: true
  allow_http_from_lan: true
  allow_https_from_lan: true

user:
  username: "netadmin"
  shell: "/bin/bash"
  sudo: true
```

### Without the wizard (curl)

If you prefer to wire things up yourself, here's the sequence for a typical gateway setup:

#### 1. Configure the LAN interface

```bash
curl -su admin:admin -X PUT http://localhost:8000/v1/networking/config/interfaces/eth1 \
  -H "Content-Type: application/json" \
  -d '{"addresses":["192.168.0.1/24"],"link":{"state":"up"}}'
```

#### 2. Enable IP forwarding

```bash
curl -su admin:admin -X PUT \
  http://localhost:8000/v1/host/sysctl/net.ipv4.ip_forward \
  -H "Content-Type: application/json" \
  -d '{"value":"1"}'
```

#### 3. Apply networking

```bash
curl -su admin:admin -X POST http://localhost:8000/v1/networking/check
curl -su admin:admin -X POST http://localhost:8000/v1/networking/apply
```

#### 4. Configure DNS and DHCP

```bash
curl -su admin:admin -X PUT http://localhost:8000/v1/dnsmasq/dns \
  -H "Content-Type: application/json" \
  -d '{"domain":"home.lan","upstream":["8.8.8.8"],"listen_addresses":["192.168.0.1"]}'

curl -su admin:admin -X PUT http://localhost:8000/v1/dnsmasq/dhcp \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"authoritative":true}'

curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/dhcp/ranges \
  -H "Content-Type: application/json" \
  -d '{"start":"192.168.0.100","end":"192.168.0.200","lease_time":"24h","interface":"eth1"}'

curl -su admin:admin -X POST http://localhost:8000/v1/dnsmasq/apply
```

#### 5. Add firewall rules

```bash
# Allow ICMP
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"allow-icmp","action":"accept","protocol":"icmp","priority":10}'

# Allow DNS from LAN
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"allow-dns","action":"accept","protocol":"udp","src_address":"192.168.0.0/24","dst_port":53,"priority":20}'

# Explicit deny-all at the end (aerleon also adds an implicit one)
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"deny-all","action":"deny","priority":1000}'

# Dry-run then apply
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/check
curl -su admin:admin -X POST http://localhost:8000/v1/firewall/apply
```

#### 6. Create an admin user

```bash
curl -su admin:admin -X POST http://localhost:8000/v1/host/users/netadmin \
  -H "Content-Type: application/json" \
  -d '{"shell":"/bin/bash"}'

# Import the sudo group, then add the user to it
curl -su admin:admin -X POST http://localhost:8000/v1/host/groups/sudo/import
curl -su admin:admin -X POST http://localhost:8000/v1/host/groups/sudo/members \
  -H "Content-Type: application/json" \
  -d '{"username":"netadmin"}'
```

---

## Macros

Macros let plugins and rules reference each other by name rather than hardcoded values. The syntax is `$namespace.key`.

**Built-in namespace: `$service_port`**

Automatically populated from each plugin's `service_ports` declaration in `plugin.yaml`. For example, if the dnsmasq plugin declares `dns: { udp: [53] }`, then `$service_port.dns.udp` resolves to `[53]`.

**Plugin-defined namespaces: `$interface`, `$host`**

The networking plugin exposes interface aliases as the `$interface` namespace. Each alias provides two sub-keys:

| Macro | Resolves to |
|---|---|
| `$interface.lan.name` | OS device name (e.g. `"enp3s0"`) |
| `$interface.lan.address` | L3 addresses on that device (e.g. `["192.168.0.1"]`) |
| `$interface.lan.net_addr` | Network address (e.g. `["192.168.0.0/24"]`) |

Set an alias with `PUT /v1/networking/config/aliases/lan` `{"interface": "enp3s0"}` and both macros become available immediately.

The host plugin exposes the `$host` namespace:

| Macro | Resolves to |
|---|---|
| `$host.hostname` | Short hostname (live from OS) |
| `$host.domainname` | FF-managed domain (or OS FQDN-derived domain) |
| `$host.fqdn` | Full FQDN (`hostname.domainname`) |

```bash
# See all registered macros and their current values
uv run python fastfirewall_app.py --show-macros

# Or via API while the server is running
curl -su admin:admin http://localhost:8000/v1/macros
```

---

## Configuration reference

`app_config.yaml` controls the server, authentication, logging, plugin directory, and state backups:

```yaml
logging:
  level: INFO                     # DEBUG, INFO, WARNING, ERROR
  format: "%(levelname)s %(name)s: %(message)s"

plugins:
  directory: plugins              # path to the plugins directory

server:
  host: "0.0.0.0"
  port: 8000
  reload: false                   # set true during development
  max_payload_bytes: 5242880      # 5 MB — requests larger than this return 413
  cors:
    allowed_origins: []           # e.g. ["https://myfirewall.local"] — empty = no CORS headers

state:
  backup:
    enabled: true                 # snapshot state files before each save
    directory: /var/tmp/ff-backups/states

auth:
  enabled: true
  # Generate: openssl rand -hex 32
  secret_key: "CHANGE-ME-use-openssl-rand-hex-32-in-production"
  algorithm: HS256
  token_expire_minutes: 60
  exempt_paths:
    - /token
    - /docs
    - /openapi.json
    - /redoc
  rate_limit:
    max_attempts: 5       # failed /token attempts before 429
    window_seconds: 300   # sliding window length in seconds
  trusted_proxies: []     # IPs whose X-Forwarded-For is trusted for rate limiting
  users:
    - username: admin
      password: "admin"           # plaintext — hashed at startup
      roles: [admin]
```

**Hashing passwords in advance:**
```bash
uv run python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```

Paste the `$2b$…` output as the `password` value. The loader detects the prefix and skips re-hashing.
