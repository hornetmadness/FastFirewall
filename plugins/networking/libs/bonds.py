from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import HTTPException

from plugin_system.core.events import Event, bus

from .models import BondCreate, BondUpdate, BondAddMember, _parse_proc_bond


class BondsMixin:
    _interfaces: dict[str, Any]
    _aliases: dict[str, str]
    _save_state: Any
    logger: Any

    def _list_bonds(self) -> dict:
        bonds = [
            {"name": n, **cfg}
            for n, cfg in self._interfaces.items()
            if (cfg.get("link") or {}).get("kind") == "bond"
        ]
        return {"bonds": bonds, "count": len(bonds)}

    def _create_bond(self, body: BondCreate) -> dict:
        if body.name in self._interfaces:
            raise HTTPException(409, f"Interface {body.name!r} already exists")
        for member in body.members:
            existing_master = (self._interfaces.get(member, {}).get("link") or {}).get("master")
            if existing_master and existing_master != body.name:
                raise HTTPException(409, f"Interface {member!r} is already a member of {existing_master!r}")

        bond_cfg: dict[str, Any] = {"mode": body.mode}
        for field in ("miimon", "ad_lacp_rate", "xmit_hash_policy", "updelay", "downdelay", "min_links"):
            val = getattr(body, field, None)
            if val is not None:
                bond_cfg[field] = val

        iface: dict[str, Any] = {
            "link": {"kind": "bond", "state": "up"},
            "bond": bond_cfg,
            "dhcp4": False,
            "dhcp6": False,
        }
        if body.addresses:
            iface["addresses"] = body.addresses
        if body.mtu is not None:
            iface["link"]["mtu"] = body.mtu

        self._interfaces[body.name] = iface
        self._aliases.setdefault(body.name, body.name)

        for member in body.members:
            for alias, target in list(self._aliases.items()):
                if target == member:
                    self._aliases[alias] = body.name

            member_cfg = dict(self._interfaces.get(member, {}))
            member_link = dict(member_cfg.get("link") or {})
            member_link["master"] = body.name
            if "kind" not in member_link:
                member_link["kind"] = "physical"
            member_cfg["link"] = member_link
            self._interfaces[member] = member_cfg
            self._aliases.setdefault(member, member)

        self._save_state()
        bus.emit(Event("networking.interface.configured", payload={"name": body.name, **iface}))
        return {"name": body.name, **iface}

    def _get_bond(self, name: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        return {"name": name, **iface}

    def _update_bond(self, name: str, body: BondUpdate) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")

        updates = body.model_dump(exclude_unset=True)
        if "addresses" in updates:
            iface["addresses"] = updates.pop("addresses")
        if "mtu" in updates:
            iface.setdefault("link", {})["mtu"] = updates.pop("mtu")
        if "members" in updates:
            new_members = updates.pop("members") or []
            for n, cfg in self._interfaces.items():
                if (cfg.get("link") or {}).get("master") == name and n not in new_members:
                    link = dict(cfg.get("link") or {})
                    link.pop("master", None)
                    cfg["link"] = link
            for member in new_members:
                member_cfg = dict(self._interfaces.get(member, {}))
                member_link = dict(member_cfg.get("link") or {})
                member_link["master"] = name
                if "kind" not in member_link:
                    member_link["kind"] = "physical"
                member_cfg["link"] = member_link
                self._interfaces[member] = member_cfg

        bond_fields = ("mode", "miimon", "ad_lacp_rate", "xmit_hash_policy", "updelay", "downdelay", "min_links")
        bond_updates = {k: updates[k] for k in bond_fields if k in updates}
        if bond_updates:
            iface.setdefault("bond", {}).update(bond_updates)

        self._interfaces[name] = iface
        self._save_state()
        bus.emit(Event("networking.interface.configured", payload={"name": name, **iface}))
        return {"name": name, **iface}

    def _delete_bond(self, name: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        for n in [k for k, v in self._interfaces.items() if (v.get("link") or {}).get("master") == name]:
            del self._interfaces[n]
        del self._interfaces[name]
        self._save_state()
        bus.emit(Event("networking.interface.removed", payload={"name": name}))
        return {"deleted": name}

    def _get_bond_status(self, name: str) -> dict:
        proc_path = Path(f"/proc/net/bonding/{name}")
        if not proc_path.exists():
            raise HTTPException(404, f"Bond {name!r} not found in /proc/net/bonding/")
        try:
            text = proc_path.read_text()
        except OSError as exc:
            self.logger.error("Failed to read %s: %s", proc_path, exc)
            raise HTTPException(500, "Failed to read bond status; check server logs")
        return {"name": name, **_parse_proc_bond(text)}

    def _add_bond_member(self, name: str, body: BondAddMember) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        member = body.interface
        existing_master = (self._interfaces.get(member, {}).get("link") or {}).get("master")
        if existing_master and existing_master != name:
            raise HTTPException(409, f"Interface {member!r} is already a member of {existing_master!r}")
        member_cfg = dict(self._interfaces.get(member, {}))
        member_link = dict(member_cfg.get("link") or {})
        member_link["master"] = name
        if "kind" not in member_link:
            member_link["kind"] = "physical"
        member_cfg["link"] = member_link
        member_cfg.setdefault("dhcp4", False)
        member_cfg.setdefault("dhcp6", False)
        self._interfaces[member] = member_cfg
        self._aliases.setdefault(member, member)
        self._save_state()
        return {"bond": name, "member": member}

    def _delete_bond_member(self, name: str, member: str) -> dict:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "bond":
            raise HTTPException(404, f"Bond {name!r} not found")
        member_iface = self._interfaces.get(member)
        if not member_iface or (member_iface.get("link") or {}).get("master") != name:
            raise HTTPException(404, f"Interface {member!r} is not a member of bond {name!r}")
        link = dict(member_iface.get("link") or {})
        link.pop("master", None)
        member_iface = dict(member_iface)
        member_iface["link"] = link
        self._interfaces[member] = member_iface
        self._save_state()
        return {"bond": name, "removed_member": member}
