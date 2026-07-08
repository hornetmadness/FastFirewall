# FastFirewall Installation Guide

Step-by-step instructions for deploying FastFirewall on a fresh Debian/Ubuntu system.

---

## Prerequisites

- Debian or Ubuntu (other systemd-based distros work but are less tested)
- Python 3.12+
- Root access to create the service user and grant sudo

---

## 1. Prepare the OS

Run the following as **root**.

**Create a dedicated service user with passwordless sudo:**

```bash
groupadd sudo-np
echo '%sudo-np ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudo-np
adduser --disabled-password --ingroup sudo-np fastfirewall
```

> If the `fastfirewall` user already exists, use `usermod -a -G sudo-np fastfirewall` instead.

Passwordless sudo is required because FastFirewall actively manages the system — plugins configure network interfaces, firewall rules, DNS, DHCP, users, packages, and more, all of which require elevated privileges.

**Install system dependencies:**

```bash
apt install pipx
```

---

## 2. Install FastFirewall

Switch to the `fastfirewall` user for all remaining steps:

```bash
su - fastfirewall
```

**Install `uv` and set up the virtualenv:**

```bash
pipx install uv
pipx ensurepath

cd ~
uv venv
echo 'source ~/.venv/bin/activate' >> ~/.bashrc
source ~/.bashrc
```

**Install FastFirewall:**

```bash
uv pip install fastfirewall
```

---

## 3. Initialize Configuration

Scaffold the config directory:

```bash
fastfirewall-api --makecfg ~/.config/fastfirewall
```

The argument is a **directory path** — FastFirewall writes `app_config.yaml` and a `plugins/` subdirectory into it.

If you skip `--makecfg`, `fastfirewall-api` searches for an existing `app_config.yaml` in this order:

1. `$FASTFIREWALL_CONFIG` env var
2. `./app_config.yaml` (current working directory)
3. `/etc/fastfirewall/app_config.yaml`
4. `~/.config/fastfirewall/app_config.yaml`
5. The bundled default inside the installed package (last resort)

`--makecfg` auto-generates a strong `auth.secret_key` (replacing any placeholder it finds, including on a config directory that already exists — safe to re-run as a repair). **Before starting the server, still edit the generated config:**

- `~/.config/fastfirewall/app_config.yaml` — change the default `admin` password under `auth.users`
- `~/.config/fastfirewall/plugins/<plugin_id>/plugin.yaml` — enable or disable individual plugins and adjust per-plugin settings

> **Scripting `fastfirewall-api` over SSH:** `ssh fastfirewall@host "fastfirewall-api ..."` runs a non-interactive shell, which does not source `~/.bashrc` — so the `PATH` addition from step 2 (`source ~/.venv/bin/activate` in `.bashrc`) won't be in effect. Use the absolute path instead: `~/.venv/bin/fastfirewall-api`.

---

## 4. Install and Start the systemd Service

`fastfirewall-api` is the main command-line interface for FastFirewall. It starts the API server, manages configuration, controls the systemd service, and handles plugin state — all through the same entry point.

```bash
fastfirewall-api --install-service
sudo systemctl start fastfirewall
systemctl status fastfirewall
```

`--install-service` writes `/etc/systemd/system/fastfirewall.service`, reloads the daemon, and enables the service for boot but does **not** start it immediately — run `sudo systemctl start fastfirewall` to start it now. The API will be available at `http://localhost:8000` and interactive docs at `http://localhost:8000/docs`.

Alternatively, run `fastfirewall-api` directly as the `fastfirewall` user to start the server in the foreground — useful for debugging or testing config changes before handing off to systemd.

### Optional: Apply firewall and networking rules at OS boot

By default, firewall rules and network interface config are applied by FastFirewall when it starts. If you want them active during early boot — before FastFirewall itself is up — enable the `enable_os_boot` flag in each plugin's `plugin.yaml`:

```yaml
# ~/.config/fastfirewall/plugins/firewall/plugin.yaml
config:
  enable_os_boot: true   # installs fastfirewall-nft.service (oneshot, runs at boot)

# ~/.config/fastfirewall/plugins/networking/plugin.yaml
config:
  enable_os_boot: true   # installs fastfirewall-networking.service (oneshot, runs at boot)
```

> **Warning — non-reversible change for the networking plugin:** Setting `enable_os_boot: true` in the networking plugin stops and disables every service listed in `disable_os_managers` (by default: `NetworkManager`, `networking`, `systemd-networkd`). FastFirewall will **not** re-enable those services if you later set the flag back to `false`. To restore the original network manager you must manually run:
> ```bash
> sudo systemctl enable --now NetworkManager   # or networking / systemd-networkd
> ```
> Review `disable_os_managers` in `plugins/networking/plugin.yaml` before enabling and remove any entries that should remain running on your system.

Restart FastFirewall after editing — it registers the systemd units automatically on startup.

---

## 5. Bootstrap (Optional)

The bootstrap wizard configures common scenarios (gateway, firewall-only, DNS/DHCP) by driving the API through a series of prompts.

```bash
uv pip install fastfirewall-bootstrap
```

Run the interactive wizard and save the session to a file:

```bash
fastfirewall-bootstrap --save ~/.config/fastfirewall/fw-init.json
```

A few things to know for a gateway setup:

- Answer **yes** to `Allow LAN forwarding (gateway mode)?` to configure this machine as a router.
- Answer **no** to `Create a new host user?` (known issue — skip this for now).
- Answer **yes** to `Apply these changes?` to apply immediately.

The saved JSON file can be replayed later to provision an identical machine:

```bash
fastfirewall-bootstrap --apply ~/.config/fastfirewall/fw-init.json
```

---

## From Source (Development)

Clone the repo and install all workspace packages with dev extras:

```bash
git clone https://github.com/hornetmadness/FastFirewall.git
cd FastFirewall
uv sync --all-packages --extra dev
```

`--all-packages` is required — without it, transitive dependencies of workspace member plugins are not installed and the dev environment is incomplete.

Run the server from the repo root:

```bash
uv run python fastfirewall_app.py
```

---

All set!
