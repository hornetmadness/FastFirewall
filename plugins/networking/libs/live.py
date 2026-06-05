from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from pyroute2 import IPRoute

from .models import _IFF_UP, _IFF_LOOPBACK, _RTPROT_NAMES

_SYS_NET_DIR = Path("/sys/class/net")


class LiveMixin:
    _interfaces: dict[str, Any]
    logger: Any

    def _ip_addr_show(self) -> list[dict[str, Any]]:
        entries: dict[int, dict[str, Any]] = {}
        with IPRoute() as ipr:
            for link in ipr.get_links():
                idx = link["index"]
                attrs = dict(link["attrs"])
                flags_int = link.get("flags", 0)
                flag_names: list[str] = []
                if flags_int & _IFF_UP:       flag_names.append("UP")
                if flags_int & _IFF_LOOPBACK: flag_names.append("LOOPBACK")
                entries[idx] = {
                    "ifname": attrs.get("IFLA_IFNAME", ""),
                    "flags": flag_names,
                    "mtu": attrs.get("IFLA_MTU"),
                    "address": attrs.get("IFLA_ADDRESS"),
                    "addr_info": [],
                }
            for addr in ipr.get_addr():
                idx = addr["index"]
                if idx not in entries:
                    continue
                family = addr.get("family")
                if family == socket.AF_INET:
                    fam_str = "inet"
                elif family == socket.AF_INET6:
                    fam_str = "inet6"
                else:
                    continue
                a = dict(addr["attrs"])
                local = a.get("IFA_LOCAL") or a.get("IFA_ADDRESS")
                prefixlen = addr.get("prefixlen")
                if local and prefixlen is not None:
                    entries[idx]["addr_info"].append({
                        "family": fam_str,
                        "local": local,
                        "prefixlen": prefixlen,
                    })
        return list(entries.values())

    def _ip_route_show(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        with IPRoute() as ipr:
            ifmap = {
                link["index"]: dict(link["attrs"]).get("IFLA_IFNAME", "")
                for link in ipr.get_links()
            }
            for family in (socket.AF_INET, socket.AF_INET6):
                for route in ipr.get_routes(family=family):
                    attrs = dict(route["attrs"])
                    proto = route.get("proto", 0)
                    dst_addr = attrs.get("RTA_DST")
                    dst_len = route.get("dst_len", 0)
                    dst = f"{dst_addr}/{dst_len}" if dst_addr and dst_len else "default"
                    entry: dict[str, Any] = {
                        "dst": dst,
                        "protocol": _RTPROT_NAMES.get(proto, str(proto)),
                    }
                    gw = attrs.get("RTA_GATEWAY")
                    if gw:
                        entry["gateway"] = gw
                    oif = attrs.get("RTA_OIF")
                    if oif and oif in ifmap:
                        entry["dev"] = ifmap[oif]
                    metric = attrs.get("RTA_PRIORITY")
                    if metric is not None:
                        entry["metric"] = metric
                    result.append(entry)
        return result

    def _show_interfaces(self) -> dict:
        try:
            entries = self._ip_addr_show()
        except RuntimeError:
            self.logger.error("ip addr show failed")
            raise HTTPException(500, "Failed to read interface state; check server logs")
        interfaces: dict[str, Any] = {}
        for entry in entries:
            name = entry.get("ifname", "")
            flags = entry.get("flags") or []
            addr_info = entry.get("addr_info") or []
            addresses = [
                f"{ai['local']}/{ai['prefixlen']}"
                for ai in addr_info
                if ai.get("family") in ("inet", "inet6")
                and ai.get("local") and ai.get("prefixlen") is not None
            ]
            interfaces[name] = {
                "addresses": addresses,
                "link": {
                    "state": "up" if "UP" in flags else "down",
                    "mtu": entry.get("mtu"),
                    "address": entry.get("address"),
                },
                "ff_managed": name in self._interfaces,
            }
        return {"interfaces": interfaces, "source": "running"}

    def _show_interface(self, name: str) -> dict:
        try:
            entries = self._ip_addr_show()
        except RuntimeError:
            self.logger.error("ip addr show failed")
            raise HTTPException(500, "Failed to read interface state; check server logs")
        for entry in entries:
            if entry.get("ifname") == name:
                flags = entry.get("flags") or []
                addr_info = entry.get("addr_info") or []
                addresses = [
                    f"{ai['local']}/{ai['prefixlen']}"
                    for ai in addr_info
                    if ai.get("family") in ("inet", "inet6")
                    and ai.get("local") and ai.get("prefixlen") is not None
                ]
                return {
                    "name": name,
                    "addresses": addresses,
                    "link": {
                        "state": "up" if "UP" in flags else "down",
                        "mtu": entry.get("mtu"),
                        "address": entry.get("address"),
                    },
                    "ff_managed": name in self._interfaces,
                }
        raise HTTPException(404, f"Interface {name!r} not found in running state")

    def _identify(self) -> dict:
        result: dict[str, dict[str, str]] = {}
        try:
            for entry in _SYS_NET_DIR.iterdir():
                iface_name = entry.name
                perm_path = entry / "perm_hwaddr"
                addr_path = entry / "address"
                mac: str | None = None
                if perm_path.exists():
                    mac = perm_path.read_text().strip()
                elif addr_path.exists():
                    mac = addr_path.read_text().strip()
                if mac:
                    result[iface_name] = {"perm_address": mac}
        except OSError as exc:
            self.logger.error("Failed to read %s: %s", _SYS_NET_DIR, exc)
            raise HTTPException(500, "Failed to identify interfaces; check server logs")
        return result
