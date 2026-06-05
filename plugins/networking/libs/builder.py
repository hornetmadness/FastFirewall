from __future__ import annotations

import io
import ipaddress
from typing import Any

from pyinfra.operations import files as files_ops

from plugin_system.core.events import Event, bus


class BuilderMixin:
    _interfaces: dict[str, Any]
    _routes: dict[str, Any]
    data_dir: Any
    _pyinfra_run: Any
    logger: Any

    @staticmethod
    def _networkd_filename(name: str) -> str:
        return f"10-ff-{name}.network"

    def _build_networkd_file(
        self, name: str, iface: dict[str, Any], routes: list[dict[str, Any]]
    ) -> str:
        lines = ["[Match]", f"Name={name}", ""]

        net_lines: list[str] = []
        for addr in (iface.get("addresses") or []):
            net_lines.append(f"Address={addr}")

        dhcp4 = iface.get("dhcp4", False)
        dhcp6 = iface.get("dhcp6", False)
        if dhcp4 and dhcp6:
            net_lines.append("DHCP=yes")
        elif dhcp4:
            net_lines.append("DHCP=ipv4")
        elif dhcp6:
            net_lines.append("DHCP=ipv6")
        else:
            net_lines.append("DHCP=no")

        kind = (iface.get("link") or {}).get("kind")
        if kind == "wifi":
            net_lines.append("IgnoreCarrierLoss=3s")

        lines.append("[Network]")
        lines.extend(net_lines)

        link = iface.get("link") or {}
        link_lines: list[str] = []
        if link.get("mtu") is not None:
            link_lines.append(f"MTUBytes={link['mtu']}")
        state = link.get("state")
        if state == "up":
            link_lines.append("ActivationPolicy=always-up")
        elif state == "down":
            link_lines.append("ActivationPolicy=always-down")
        if link_lines:
            lines.append("")
            lines.append("[Link]")
            lines.extend(link_lines)

        for route in routes:
            lines.append("")
            lines.append("[Route]")
            dst = route.get("to", "")
            if dst == "default":
                dst = "0.0.0.0/0"
            lines.append(f"Destination={dst}")
            if route.get("via") is not None:
                lines.append(f"Gateway={route['via']}")
            if route.get("preference") is not None:
                lines.append(f"Metric={route['preference']}")
            if route.get("table") is not None:
                lines.append(f"Table={route['table']}")

        return "\n".join(lines) + "\n"

    def _build_netdev_file(self, name: str, iface: dict[str, Any]) -> str:
        kind = (iface.get("link") or {}).get("kind", "")
        lines = ["[NetDev]", f"Name={name}", f"Kind={kind}", ""]

        if kind == "bond":
            bond = iface.get("bond") or {}
            lines.append("[Bond]")
            lines.append(f"Mode={bond.get('mode', '802.3ad')}")
            if bond.get("miimon") is not None:
                lines.append(f"MIIMonitorSec={bond['miimon'] / 1000}")
            if bond.get("ad_lacp_rate") is not None:
                lines.append(f"LACPTransmitRate={bond['ad_lacp_rate']}")
            if bond.get("xmit_hash_policy") is not None:
                lines.append(f"TransmitHashPolicy={bond['xmit_hash_policy']}")
            if bond.get("updelay") is not None:
                lines.append(f"UpDelaySec={bond['updelay'] / 1000}")
            if bond.get("downdelay") is not None:
                lines.append(f"DownDelaySec={bond['downdelay'] / 1000}")
            if bond.get("min_links") is not None:
                lines.append(f"MinLinks={bond['min_links']}")

        elif kind == "bridge":
            bridge = iface.get("bridge") or {}
            lines.append("[Bridge]")
            lines.append(f"STP={'yes' if bridge.get('stp', False) else 'no'}")
            lines.append(f"ForwardDelaySec={bridge.get('forward_delay_sec', 0.0)}")

        elif kind == "wireguard":
            wg = iface.get("wireguard") or {}
            lines.append("[WireGuard]")
            if wg.get("private_key"):
                lines.append(f"PrivateKey={wg['private_key']}")
            if wg.get("listen_port") is not None:
                lines.append(f"ListenPort={wg['listen_port']}")
            for peer in (wg.get("peers") or []):
                lines.append("")
                lines.append("[WireGuardPeer]")
                lines.append(f"PublicKey={peer['public_key']}")
                for ip in (peer.get("allowed_ips") or []):
                    lines.append(f"AllowedIPs={ip}")
                if peer.get("endpoint"):
                    lines.append(f"Endpoint={peer['endpoint']}")
                if peer.get("preshared_key"):
                    lines.append(f"PresharedKey={peer['preshared_key']}")
                if peer.get("persistent_keepalive") is not None:
                    lines.append(f"PersistentKeepalive={peer['persistent_keepalive']}")

        return "\n".join(lines) + "\n"

    def _find_route_interface(self, route: dict[str, Any]) -> str | None:
        via = route.get("via")
        if not via:
            return None
        try:
            gw = ipaddress.ip_address(via)
        except ValueError:
            return None
        for name, iface in self._interfaces.items():
            for addr in (iface.get("addresses") or []):
                try:
                    net = ipaddress.ip_interface(addr).network
                    if gw in net:
                        return name
                except ValueError:
                    continue
        return None

    def _build_all_networkd_configs(self) -> dict[str, str]:
        interface_routes: dict[str, list[dict[str, Any]]] = {n: [] for n in self._interfaces}
        unroutable: list[str] = []

        for route in self._routes.values():
            dev = route.get("dev")
            if dev and dev in interface_routes:
                interface_routes[dev].append(route)
            elif dev:
                pass  # dev not managed — silently skip
            else:
                matched = self._find_route_interface(route)
                if matched:
                    interface_routes[matched].append(route)
                else:
                    unroutable.append(route.get("to", "unknown"))

        if unroutable:
            raise ValueError(
                f"Unroutable routes (no dev and no gateway subnet match): {', '.join(unroutable)}"
            )

        files: dict[str, str] = {}

        for name, iface in self._interfaces.items():
            link = iface.get("link") or {}
            kind = link.get("kind")
            master = link.get("master")

            if master:
                parent_kind = (self._interfaces.get(master, {}).get("link") or {}).get("kind")
                net_lines = ["[Match]", f"Name={name}", "", "[Network]"]
                if parent_kind == "bond":
                    net_lines.append(f"Bond={master}")
                elif parent_kind == "bridge":
                    net_lines.append(f"Bridge={master}")
                files[self._networkd_filename(name)] = "\n".join(net_lines) + "\n"

            elif kind in ("bond", "bridge", "wireguard"):
                files[f"10-ff-{name}.netdev"] = self._build_netdev_file(name, iface)
                files[self._networkd_filename(name)] = self._build_networkd_file(
                    name, iface, interface_routes.get(name, [])
                )

            else:
                files[self._networkd_filename(name)] = self._build_networkd_file(
                    name, iface, interface_routes.get(name, [])
                )

        return files

    @property
    def _networkd_staging_dir(self) -> Any:
        return self.data_dir / "networkd"

    def _write_networkd_files(self, files: dict[str, str]) -> None:
        staging = self._networkd_staging_dir
        staging.mkdir(parents=True, exist_ok=True)
        for filename, content in files.items():
            (staging / filename).write_text(content)
            dest = f"/etc/systemd/network/{filename}"
            mode = "644"
            group: str | None = None
            if filename.endswith(".netdev"):
                iface_name = filename[len("10-ff-"):-len(".netdev")]
                kind = (self._interfaces.get(iface_name, {}).get("link") or {}).get("kind")
                if kind == "wireguard":
                    mode = "640"
                    group = "systemd-network"
            kwargs: dict[str, Any] = dict(
                name=f"Write {filename}",
                src=str(staging / filename),
                dest=dest,
                mode=mode,
                _sudo=True,
            )
            if group:
                kwargs["group"] = group
            self._pyinfra_run(files_ops.put, **kwargs)

    def _prune_networkd_files(self, active_names: set[str]) -> None:
        staging = self._networkd_staging_dir
        if not staging.exists():
            return
        for local_path in staging.glob("10-ff-*"):
            filename = local_path.name
            for suffix in (".network", ".netdev"):
                if filename.endswith(suffix):
                    iface_name = filename[len("10-ff-"):-len(suffix)]
                    if iface_name not in active_names:
                        local_path.unlink(missing_ok=True)
                        try:
                            self._pyinfra_run(
                                files_ops.file,
                                path=f"/etc/systemd/network/{filename}",
                                present=False,
                                _sudo=True,
                            )
                        except RuntimeError as exc:
                            self.logger.warning("Could not prune %s: %s", filename, exc)
                    break

    def _write_wpa_supplicant_configs(self) -> None:
        for name, iface in self._interfaces.items():
            if (iface.get("link") or {}).get("kind") != "wifi":
                continue
            wifi = iface.get("wifi")
            if not wifi:
                continue
            content = (
                "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n"
                "update_config=1\n\n"
                "network={\n"
                f'    ssid="{wifi["ssid"]}"\n'
                f'    psk="{wifi["psk"]}"\n'
                "}\n"
            )
            self._pyinfra_run(
                files_ops.put,
                name=f"Write wpa_supplicant config for {name}",
                src=io.StringIO(content),
                dest=f"/etc/wpa_supplicant/wpa_supplicant-{name}.conf",
                mode="600",
                _sudo=True,
            )
            bus.emit(Event(
                "initsys.service.start",
                payload={"service_name": f"wpa_supplicant@{name}.service"},
            ))
