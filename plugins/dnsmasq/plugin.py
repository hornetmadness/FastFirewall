"""
DNSMasq Plugin
──────────────
DNS forwarding/caching, DHCP, TFTP, PXE boot, and mDNS via dnsmasq.
Includes blocklist support for domain filtering.

Mutation model: deferred — mutations update desired state only; call
POST /apply to write /etc/dnsmasq.d/ff-managed.conf and restart dnsmasq.

Routes mount at /v1/dnsmasq/.
"""
import json
import os
import subprocess
import tempfile
from typing import Any, Optional

from fastapi import Depends, HTTPException
from ff_auth import require_role
from plugin_system.core import ApiRouterPlugin, PluginBase, PluginStateFile, Service
from plugin_system.core.events import Event, bus

from .libs.blocklist import BlocklistMixin
from .libs.dhcp import DhcpMixin
from .libs.dns import DnsMixin
from .libs.mdns import MdnsMixin
from .libs.pxe import PxeMixin
from .libs.tftp import TftpMixin


# ── defaults ──────────────────────────────────────────────────────────────────

def _default_dns() -> dict[str, Any]:
    return {
        "port": 53,
        "listen_addresses": ["0.0.0.0"],
        "interface": "*",
        "upstream": ["8.8.8.8", "1.1.1.1"],
        "cache_size": 1000,
        "no_resolv": False,
        "dnssec": False,
        "log_queries": False,
        "domain": None,
        "local_ttl": 0,
        "neg_ttl": 3600,
        "strict_order": False,
        "rebind_protection": True,
        "rebind_localhost_ok": True,
        "domain_servers": {},
        "local": [],
    }


def _default_dhcp() -> dict[str, Any]:
    return {"enabled": False, "authoritative": True, "options": {}}


def _default_tftp() -> dict[str, Any]:
    return {"enabled": False, "root": "/srv/tftp", "secure": False, "no_fail": False}


def _default_pxe() -> dict[str, Any]:
    return {"enabled": False, "prompt": None}


def _default_mdns() -> dict[str, Any]:
    return {"enabled": False, "interfaces": []}


# ── plugin class ───────────────────────────────────────────────────────────────

class DnsmasqPlugin(PluginBase, ApiRouterPlugin,
                    DnsMixin, DhcpMixin, TftpMixin, PxeMixin, MdnsMixin, BlocklistMixin):
    services = [
        Service.DNS,
        Service.DHCP,
        Service.TFTP,
        Service.PXE,
        Service.MDNS,
    ]

    def setup(self) -> None:
        self._state_file = PluginStateFile.from_config(
            self.plugin_dir, self.config, "state_file", "dnsmasq_state.json", self.logger,
            mutation_model="deferred", data_dir=self.data_dir, plugin_version=self.meta["version"],
        )
        self._dns: dict[str, Any] = {}
        self._records: dict[str, dict[str, Any]] = {}
        self._dhcp: dict[str, Any] = {}
        self._dhcp_ranges: dict[str, dict[str, Any]] = {}
        self._static_leases: dict[str, dict[str, Any]] = {}
        self._tftp: dict[str, Any] = {}
        self._pxe: dict[str, Any] = {}
        self._pxe_services: list[dict[str, Any]] = []
        self._mdns: dict[str, Any] = {}
        self._blocklists: dict[str, dict[str, Any]] = {}
        self._load_state()
        if not self.config.get("ignore_state_on_boot", False):
            self._apply_state()
        self._register_routes()
        self._sync_os_boot_service()
        self.logger.info(
            "DNSMasq plugin loaded: %d DNS record(s), %d DHCP range(s), %d blocklist(s)",
            len(self._records), len(self._dhcp_ranges), len(self._blocklists),
        )

    def teardown(self) -> None:
        self._save_state()
        self.logger.info("DNSMasq plugin shut down — state saved")

    # ── state helpers ──────────────────────────────────────────────────

    def _load_state(self) -> None:
        desired = self._state_file.load_desired(default={})
        self._dns = desired.get("dns") or _default_dns()
        self._records = desired.get("records") or {}
        self._dhcp = desired.get("dhcp") or _default_dhcp()
        self._dhcp_ranges = desired.get("dhcp_ranges") or {}
        self._static_leases = desired.get("static_leases") or {}
        self._tftp = desired.get("tftp") or _default_tftp()
        self._pxe = desired.get("pxe") or _default_pxe()
        self._pxe_services = desired.get("pxe_services") or []
        self._mdns = desired.get("mdns") or _default_mdns()
        self._blocklists = desired.get("blocklists") or {}
        if not desired:
            self._save_state()

    def _save_state(self) -> None:
        self._state_file.save_desired(self._desired_snapshot())

    def _desired_snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps({
            "dns": self._dns,
            "records": self._records,
            "dhcp": self._dhcp,
            "dhcp_ranges": self._dhcp_ranges,
            "static_leases": self._static_leases,
            "tftp": self._tftp,
            "pxe": self._pxe,
            "pxe_services": self._pxe_services,
            "mdns": self._mdns,
            "blocklists": self._blocklists,
        }))

    def _read_on_disk(self, path: str) -> Optional[str]:
        try:
            with open(path) as fh:
                return fh.read()
        except (FileNotFoundError, PermissionError):
            return None

    def _apply_state(self) -> None:
        """On boot, write desired config and restart dnsmasq if on-disk config differs."""
        config_path = self.config.get("config_path", "/etc/dnsmasq.d/ff-managed.conf")
        blocklist_path = self.config.get("blocklist_path", "/etc/dnsmasq.d/ff-blocklist.conf")
        config_content = self._build_config()
        blocklist_content = self._build_blocklist_config()

        if (self._read_on_disk(config_path) == config_content
                and self._read_on_disk(blocklist_path) == blocklist_content):
            results = bus.emit(Event("initsys.service.status", payload={"service_name": "dnsmasq"}))
            is_active = bool(results and results[0] and results[0].get("running"))
            if is_active:
                self.logger.info("Boot-time config check: on-disk config matches desired and dnsmasq is active, skipping restart")
                return
            self.logger.info("Boot-time config check: on-disk config matches desired but dnsmasq is not active, restarting")

        tmp_conf = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as fh:
                fh.write(config_content)
                tmp_conf = fh.name
            test_result = self._run_dnsmasq_test(tmp_conf)
            if test_result.returncode != 0:
                self.logger.warning(
                    "Boot-time config validation failed: %s",
                    (test_result.stdout + test_result.stderr).strip(),
                )
                return
            self._write_file_sudo(config_path, config_content)
            self._write_file_sudo(blocklist_path, blocklist_content)
            if self._dhcp.get("enabled"):
                self._ensure_lease_file(self.config.get("dhcp", {}).get("lease_file", "/var/lib/dnsmasq/dnsmasq.leases"))
            if self._pxe.get("enabled"):
                self._mkdir(self.config.get("pxe", {}).get("data_dir", "/srv/tftp"))
            if self._restart_dnsmasq():
                self._state_file.commit(self._desired_snapshot())
                self.logger.info("Boot-time config updated and dnsmasq restarted")
            else:
                self.logger.warning("Boot-time dnsmasq restart failed")
        except Exception as exc:
            self.logger.warning("Could not re-apply dnsmasq config on boot: %s", exc)
        finally:
            if tmp_conf:
                try:
                    os.unlink(tmp_conf)
                except OSError:
                    pass

    # ── config builders ────────────────────────────────────────────────

    def _build_config(self) -> str:
        lines: list[str] = []
        lines.extend(DnsMixin.render_config(self))
        lines.extend(DhcpMixin.render_config(self))
        lines.extend(TftpMixin.render_config(self))
        lines.extend(PxeMixin.render_config(self))
        lines.extend(MdnsMixin.render_config(self))
        return "\n".join(lines) + "\n"

    def _build_blocklist_config(self) -> str:
        return "\n".join(BlocklistMixin.render_config(self)) + "\n"

    # ── subprocess wrappers ────────────────────────────────────────────

    def _run_dnsmasq_test(self, config_path: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sudo", "dnsmasq", "--test", f"--conf-file={config_path}"],
            capture_output=True, text=True, timeout=15,
        )

    def _sync_os_boot_service(self) -> None:
        if self.config.get("enable_os_boot", False):
            bus.emit(Event("initsys.service.add", payload={"service_name": "dnsmasq"}))
        else:
            bus.emit(Event("initsys.service.disable", payload={"service_name": "dnsmasq"}))

    def _restart_dnsmasq(self) -> bool:
        results = bus.emit(Event("initsys.service.restart", payload={"service_name": "dnsmasq"}))
        return bool(results and results[0].get("success"))

    def _write_file_sudo(self, path: str, content: str) -> None:
        owner = str(os.getuid())
        grp = str(os.getgid())
        result = subprocess.run(
            ["sudo", "install", "-o", owner, "-g", grp, "-m", "644", "/dev/null", path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            self.logger.error("Failed to create %r: %s", path, result.stderr.strip())
            raise RuntimeError(f"Failed to write {path}; check server logs")
        with open(path, "w") as fh:
            fh.write(content)

    def _mkdir(self, path: str, user: str = "", group: str = "", mode: str = "774") -> bool:
        owner = user or str(os.getuid())
        grp = group or str(os.getgid())
        r = subprocess.run(
            ["sudo", "install", "-d", f"--owner={owner}", f"--group={grp}", f"--mode={mode}", path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            self.logger.warning("Could not create directory %r: %s", path, r.stderr.strip())
            return False
        return True

    def _ensure_lease_file(self, path: str) -> None:
        if not self._mkdir(os.path.dirname(path), "root", "root", "755"):
            return
        r = subprocess.run(["sudo", "touch", path], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            self.logger.warning("Could not create lease file %r: %s", path, r.stderr.strip())

    # ── route registration ─────────────────────────────────────────────

    def _register_routes(self) -> None:
        add = self.router.add_api_route
        _admin = [require_role("admin")]

        add("/status",                            self._status,              methods=["GET"],    summary="Plugin status and counts", dependencies=_admin)

        add("/dns",                               self._get_dns,             methods=["GET"],    summary="Get DNS config", dependencies=_admin)
        add("/dns",                               self._update_dns,          methods=["PUT"],    summary="Update DNS config", dependencies=_admin)
        add("/dns/records",                       self._list_records,        methods=["GET"],    summary="List DNS records", dependencies=_admin)
        add("/dns/records",                       self._add_record,          methods=["POST"],   summary="Add a DNS record", status_code=201, dependencies=_admin)
        add("/dns/records/{record_id}",           self._delete_record,       methods=["DELETE"], summary="Remove a DNS record", dependencies=_admin)

        add("/dhcp",                              self._get_dhcp,            methods=["GET"],    summary="Get DHCP config", dependencies=_admin)
        add("/dhcp",                              self._update_dhcp,         methods=["PUT"],    summary="Update DHCP config", dependencies=_admin)
        add("/dhcp/ranges",                       self._list_ranges,         methods=["GET"],    summary="List DHCP ranges", dependencies=_admin)
        add("/dhcp/ranges",                       self._add_range,           methods=["POST"],   summary="Add a DHCP range", status_code=201, dependencies=_admin)
        add("/dhcp/ranges/{range_id}",            self._update_range,        methods=["PUT"],    summary="Update a DHCP range", dependencies=_admin)
        add("/dhcp/ranges/{range_id}",            self._delete_range,        methods=["DELETE"], summary="Remove a DHCP range", dependencies=_admin)
        add("/dhcp/leases",                       self._live_leases,         methods=["GET"],    summary="Live DHCP leases (from lease file)", dependencies=_admin)
        add("/dhcp/static-leases",                self._list_static_leases,  methods=["GET"],    summary="List static DHCP leases", dependencies=_admin)
        add("/dhcp/static-leases",                self._add_static_lease,    methods=["POST"],   summary="Add a static DHCP lease", status_code=201, dependencies=_admin)
        add("/dhcp/static-leases/{lease_id}",     self._update_static_lease, methods=["PUT"],    summary="Update a static DHCP lease", dependencies=_admin)
        add("/dhcp/static-leases/{lease_id}",     self._delete_static_lease, methods=["DELETE"], summary="Remove a static DHCP lease", dependencies=_admin)

        add("/tftp",                              self._get_tftp,            methods=["GET"],    summary="Get TFTP config", dependencies=_admin)
        add("/tftp",                              self._update_tftp,         methods=["PUT"],    summary="Update TFTP config", dependencies=_admin)

        add("/pxe",                               self._get_pxe,             methods=["GET"],    summary="Get PXE config", dependencies=_admin)
        add("/pxe",                               self._update_pxe,          methods=["PUT"],    summary="Update PXE config", dependencies=_admin)
        add("/pxe/services",                      self._list_pxe_services,   methods=["GET"],    summary="List PXE service entries", dependencies=_admin)
        add("/pxe/services",                      self._add_pxe_service,     methods=["POST"],   summary="Add a PXE service entry", status_code=201, dependencies=_admin)
        add("/pxe/services/{index}",              self._delete_pxe_service,  methods=["DELETE"], summary="Remove a PXE service entry by index", dependencies=_admin)
        add("/pxe/images",                        self._list_pxe_images,     methods=["GET"],    summary="List PXE images in data_dir", dependencies=_admin)
        add("/pxe/images",                        self._upload_pxe_image,    methods=["POST"],   summary="Upload a PXE image", status_code=201, dependencies=_admin)
        add("/pxe/images/{filename}",             self._get_pxe_image,       methods=["GET"],    summary="Get PXE image metadata", dependencies=_admin)
        add("/pxe/images/{filename}",             self._delete_pxe_image,    methods=["DELETE"], summary="Delete a PXE image", dependencies=_admin)
        add("/pxe/images/{filename}/rename",      self._rename_pxe_image,    methods=["POST"],   summary="Rename a PXE image", dependencies=_admin)

        add("/mdns",                              self._get_mdns,            methods=["GET"],    summary="Get mDNS config", dependencies=_admin)
        add("/mdns",                              self._update_mdns,         methods=["PUT"],    summary="Update mDNS config", dependencies=_admin)

        add("/blocklists",                        self._list_blocklists,     methods=["GET"],    summary="List blocklists", dependencies=_admin)
        add("/blocklists",                        self._add_blocklist,       methods=["POST"],   summary="Add a blocklist (fetches immediately)", status_code=201, dependencies=_admin)
        add("/blocklists/{blocklist_id}",         self._delete_blocklist,    methods=["DELETE"], summary="Remove a blocklist", dependencies=_admin)
        add("/blocklists/{blocklist_id}/refresh", self._refresh_blocklist,   methods=["POST"],   summary="Re-fetch a blocklist from its URL", dependencies=_admin)

        add("/config",                            self._get_config,          methods=["GET"],    summary="Full dnsmasq config text", dependencies=_admin)
        add("/apply",                             self._apply,               methods=["POST"],   summary="Write config and restart dnsmasq", dependencies=_admin)
        add("/check",                             self._check,               methods=["POST"],   summary="Validate config (dnsmasq --test)", dependencies=_admin)
        add("/discard",                           self._discard,             methods=["POST"],   summary="Discard pending changes", dependencies=_admin)

    # ── status ─────────────────────────────────────────────────────────

    def _status(self) -> dict[str, Any]:
        return {
            "plugin": self.meta["name"],
            "version": self.meta["version"],
            "pending_changes": self._state_file.pending_changes,
            "state_file": str(self._state_file.path),
            "counts": {
                "dns_records": len(self._records),
                "dhcp_ranges": len(self._dhcp_ranges),
                "static_leases": len(self._static_leases),
                "pxe_services": len(self._pxe_services),
                "blocklists": len(self._blocklists),
                "blocked_domains": sum(len(bl.get("domains", [])) for bl in self._blocklists.values()),
            },
            "services": {
                "dhcp": self._dhcp.get("enabled", False),
                "tftp": self._tftp.get("enabled", False),
                "pxe": self._pxe.get("enabled", False),
                "mdns": self._mdns.get("enabled", False),
            },
        }

    # ── config view ────────────────────────────────────────────────────

    def _get_config(self) -> dict[str, Any]:
        return self._desired_snapshot()

    # ── apply / check / discard ────────────────────────────────────────

    def _apply(self) -> dict[str, Any]:
        debug: bool = bool(self.config.get("debug", False))
        desired = self._desired_snapshot()
        config_content = self._build_config()
        blocklist_content = self._build_blocklist_config()
        tmp_conf = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as fh:
                fh.write(config_content)
                tmp_conf = fh.name
            if debug:
                self.logger.info("[debug] apply config: %s", tmp_conf)
            test_result = self._run_dnsmasq_test(tmp_conf)
            test_output = (test_result.stdout + test_result.stderr).strip()
            if debug:
                self.logger.info("[debug] dnsmasq --test returncode=%d output=%r", test_result.returncode, test_output)
            if test_result.returncode != 0:
                return {
                    "success": False,
                    "error": "Config validation failed",
                    "details": test_output,
                }
            config_path = self.config.get("config_path", "/etc/dnsmasq.d/ff-managed.conf")
            blocklist_path = self.config.get("blocklist_path", "/etc/dnsmasq.d/ff-blocklist.conf")
            try:
                self._write_file_sudo(config_path, config_content)
                self._write_file_sudo(blocklist_path, blocklist_content)
            except RuntimeError as exc:
                self.logger.error("Failed to write config: %s", exc)
                return {"success": False, "error": "Failed to write config; check server logs"}
            if self._dhcp.get("enabled"):
                self._ensure_lease_file(self.config.get("dhcp", {}).get("lease_file", "/var/lib/dnsmasq/dnsmasq.leases"))
            if self._pxe.get("enabled"):
                self._mkdir(self.config.get("pxe", {}).get("data_dir", "/srv/tftp"))
            success = self._restart_dnsmasq()
            if debug:
                self.logger.info("[debug] initsys.service.restart dispatched, success=%s", success)
            if success:
                self._state_file.commit(desired)
            bus.emit(Event("dnsmasq.applied",
                           payload={"success": success, "returncode": 0 if success else 1}))
            resp: dict[str, Any] = {
                "success": success,
                "returncode": 0 if success else 1,
                "config_path": config_path,
                "blocklist_path": blocklist_path,
            }
            if debug:
                resp["debug"] = {"config_file": tmp_conf, "test_output": test_output}
            return resp
        finally:
            if tmp_conf:
                if debug:
                    self.logger.info("[debug] temp config retained at: %s", tmp_conf)
                else:
                    try:
                        os.unlink(tmp_conf)
                    except OSError:
                        pass

    def _check(self) -> dict[str, Any]:
        tmp_conf = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as fh:
                fh.write(self._build_config())
                tmp_conf = fh.name
            result = self._run_dnsmasq_test(tmp_conf)
            return {
                "valid": result.returncode == 0,
                "returncode": result.returncode,
                "output": (result.stdout + result.stderr).strip(),
                "pending_changes": self._state_file.pending_changes,
            }
        finally:
            if tmp_conf:
                try:
                    os.unlink(tmp_conf)
                except OSError:
                    pass

    def _discard(self) -> dict[str, Any]:
        current = self._state_file.current_snapshot
        if current is None:
            raise HTTPException(409, "No applied snapshot to restore — apply first")
        self._dns = current.get("dns") or _default_dns()
        self._records = current.get("records") or {}
        self._dhcp = current.get("dhcp") or _default_dhcp()
        self._dhcp_ranges = current.get("dhcp_ranges") or {}
        self._static_leases = current.get("static_leases") or {}
        self._tftp = current.get("tftp") or _default_tftp()
        self._pxe = current.get("pxe") or _default_pxe()
        self._pxe_services = current.get("pxe_services") or []
        self._mdns = current.get("mdns") or _default_mdns()
        self._blocklists = current.get("blocklists") or {}
        self._save_state()
        return {"discarded": True}
