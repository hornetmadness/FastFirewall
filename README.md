# FastFirewall

An API-first firewall and router management system. FastFirewall exposes a REST API for managing firewall rules, network interfaces, DNS, DHCP, system users, and more — everything you'd configure manually on a Linux router or gateway, controllable via HTTP from anywhere on your network.

Built on FastAPI and driven entirely by plugins. Every feature is a plugin; the core app has no routes of its own.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Running the server](#running-the-server)
- [app.py CLI reference](#apppy-cli-reference)
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
- [uv](https://docs.astral.sh/uv/) (package manager — replaces pip/virtualenv)
- Root or sudo access (plugins call `nftables`, `systemctl`, `ifstatecli`, etc.)
- Linux (Debian/Ubuntu tested; most plugins work on any systemd-based distro)

## Installation

```bash
git clone <repo>
cd FastFirewall
uv sync
```

That's it. `uv sync` creates a virtualenv and installs all Python dependencies from `uv.lock`.

---

## Running the server

```bash
# Start the server (listens on 0.0.0.0:8000 by default)
uv run python app.py

# Interactive API docs
open http://localhost:8000/docs
```

The server loads all enabled plugins at startup. Each plugin mounts its API routes at `/v1/<plugin_id>/`. Plugins that need system packages (nftables, dnsmasq, fluent-bit, etc.) install them automatically via pyinfra when they load.

To change the listen address, port, or other server settings, edit `app_config.yaml`.

---

## app.py CLI reference

`app.py` doubles as a management tool. These flags handle configuration tasks and exit without starting the server:

```bash
# List all discovered plugins with their state, version, and port claims
uv run python app.py --list-plugins

# Enable or disable a plugin (edits plugin.yaml, then exits)
uv run python app.py --enable-plugin syslog
uv run python app.py --disable-plugin smtp

# Show all macro namespaces and their current resolved values, then exit
uv run python app.py --show-macros

# Load only specific plugins (useful for testing or minimal deployments)
uv run python app.py --plugin firewall --plugin networking

# Skip re-applying saved state to the system on boot (state files are still read,
# but nothing is pushed to the kernel/daemons until you explicitly call /apply)
uv run python app.py --ignore-plugins-states

# Full help
uv run python app.py --help
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

On startup, the loader discovers all enabled plugins, installs any declared `py_requirements` and `os_requirements` via pyinfra, then loads them in dependency order and mounts their API routes.

### Service exclusivity

Each plugin claims one or more **services** (e.g. `FIREWALL`, `DNS`, `DHCP`). Only one plugin may own a given service at a time. This prevents conflicts — you can't accidentally load two DHCP plugins.

### Port conflict detection

Plugins declare which ports they use in `plugin.yaml`. The loader checks for conflicts between plugins and verifies no other process on the OS is already using the port (reads `/proc/net/tcp` and `/proc/net/udp`).

### Plugin load order

Plugins declare `plugin_requirements` (a list of other plugin IDs they depend on). The loader topologically sorts the full plugin list so dependencies always load first. Alphabetical order breaks ties.

### Enabling and disabling plugins

```bash
# Disable the SMTP plugin
uv run python app.py --disable-plugin smtp

# Re-enable it
uv run python app.py --enable-plugin smtp
```

This edits the `enabled` field in the plugin's `plugin.yaml` and exits. The change takes effect on the next server start.

### API error responses

FastFirewall does not include internal details in error responses. When a plugin operation fails (subprocess non-zero exit, service unreachable, etc.), the API returns a generic message:

```json
{"detail": "Postfix reload failed; check server logs"}
```

The full detail — stderr output, exception traceback, internal paths — is logged at `ERROR` level on the server side. To diagnose a failure, check the server console or the audit log (`plugins/audit/data/audit.log`).

This applies to all `5xx` responses. `4xx` responses (404 Not Found, 409 Conflict, 422 Validation Error) do include the specific reason, since those describe a client-side problem rather than a server-side failure.

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
uv run python app.py --ignore-plugins-states
```

---

## Plugins

### Firewall Plugin

**Routes:** `/v1/firewall/`

Manages firewall rules and compiles them to nftables using [aerleon](https://github.com/aerleon/aerleon). Rules are defined declaratively via the API; call `POST /apply` to push them to the kernel.

Rules are stored in a JSON file. An implicit `deny all` is always appended at the end of the compiled policy — you only need to write `accept` rules.

**On fresh install**, two default rules are seeded automatically: one allowing SSH (TCP/22) and one allowing the FastFirewall API (TCP/8000). This prevents lockout. Delete them if you want to manage those rules yourself.

**Rule IDs** are a content hash of the rule fields. Submitting an identical rule twice returns `409 Conflict` instead of creating a duplicate.

| Route | Method | Description |
|---|---|---|
| `/rules` | GET | List all rules |
| `/rules` | POST | Create a rule |
| `/rules/{id}` | GET / PUT / DELETE | Read, update, or delete a rule |
| `/check` | POST | Dry-run compile — validates without applying |
| `/apply` | POST | Compile and apply to nftables |
| `/compile` | POST | Preview compiled output for any supported platform |
| `/policy` | GET | Show the raw aerleon policy YAML |
| `/platforms` | GET | List supported target platforms |
| `/status` | GET | Plugin status, pending changes, compiled output path |

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

**Supported platforms:** `nftables` (default, auto-applied), `checkpoint`, `ciscoasa`, `juniper`, `paloalto`, `arista`, `gce`, and others for generating configs to paste elsewhere.

**Debugging:** set `debug: true` in `plugin.yaml` config to have aerleon's intermediate `networks.yaml` and `policy.yaml` written to `plugins/firewall/data/aerleon_debug/` on every compile. The `debug_dir` path appears in `GET /status`.

---

### Networking Plugin

**Routes:** `/v1/networking/`  
**Depends on:** host plugin

Manages network interfaces, static routes, and kernel sysctl settings via [ifstate](https://github.com/ipinfra/ifstate) (`ifstatecli`). Desired state is stored in a JSON file; nothing is applied to the kernel until `POST /apply`.

**Deferred apply model:** mutations (PUT/POST/DELETE) only update the state file. `GET /status` will show `pending_changes: true` until you apply.

| Route | Method | Description |
|---|---|---|
| `/config/interfaces` | GET | List managed interfaces |
| `/config/interfaces/{name}` | PUT / DELETE | Set or remove an interface |
| `/config/interfaces/import` | POST | Import live interface into management |
| `/config/routes` | GET | List managed routes |
| `/config/routes` | POST | Add a route |
| `/config/routes/{id}` | DELETE | Remove a route |
| `/config/sysctl/{key}` | PUT / DELETE | Set or remove a sysctl value |
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

```bash
# Set upstream DNS and local domain
curl -su admin:admin -X PUT http://localhost:8000/v1/dnsmasq/dns \
  -H "Content-Type: application/json" \
  -d '{"domain":"home.lan","upstream":["8.8.8.8","1.1.1.1"],"listen_addresses":["192.168.0.1"]}'

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

Manages local system configuration: users, groups, cron jobs, packages, repos, sysctl, and services — all via pyinfra operations.

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
uv run tools/bootstrap.py
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

uv run tools/bootstrap.py --config my-setup.yaml
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
uv run tools/bootstrap.py --save my-setup.json

# Replay against the same server later
uv run tools/bootstrap.py --apply my-setup.json

# Replay against a different server
uv run tools/bootstrap.py --apply my-setup.json --host http://10.0.0.2:8000
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
  http://localhost:8000/v1/networking/config/sysctl/net.ipv4.ip_forward \
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

**Plugin-defined namespaces: `$interface`**

The networking plugin exposes interface aliases as the `$interface` namespace. Each alias provides two sub-keys:

| Macro | Resolves to |
|---|---|
| `$interface.lan.name` | OS device name (e.g. `"enp3s0"`) |
| `$interface.lan.address` | L3 addresses on that device (e.g. `["192.168.0.1"]`) |

Set an alias with `PUT /v1/networking/config/aliases/lan` `{"interface": "enp3s0"}` and both macros become available immediately.

```bash
# See all registered macros and their current values
uv run python app.py --show-macros

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
