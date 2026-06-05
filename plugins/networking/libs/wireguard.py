from __future__ import annotations

import hashlib
from typing import Any

from fastapi import HTTPException

from .models import WireguardPeer, WireguardPeerUpdate


class WireguardMixin:
    _interfaces: dict[str, Any]
    _save_state: Any

    def _get_wg_iface(self, name: str) -> dict[str, Any]:
        iface = self._interfaces.get(name)
        if not iface or (iface.get("link") or {}).get("kind") != "wireguard":
            raise HTTPException(404, f"WireGuard interface {name!r} not found")
        return iface

    def _list_wg_peers(self, name: str) -> dict:
        iface = self._get_wg_iface(name)
        peers = (iface.get("wireguard") or {}).get("peers") or []
        return {"peers": peers, "count": len(peers)}

    def _add_wg_peer(self, name: str, body: WireguardPeer) -> dict:
        iface = self._get_wg_iface(name)
        peer_id = hashlib.sha256(body.public_key.encode()).hexdigest()[:8]
        wg = iface.setdefault("wireguard", {"peers": []})
        peers: list[dict[str, Any]] = wg.setdefault("peers", [])
        if any(p.get("public_key") == body.public_key for p in peers):
            raise HTTPException(409, f"Peer with public_key already exists (id={peer_id})")
        peer = body.model_dump(exclude_none=True)
        peer["id"] = peer_id
        peers.append(peer)
        self._interfaces[name] = iface
        self._save_state()
        return peer

    def _get_wg_peer(self, name: str, peer_id: str) -> dict:
        iface = self._get_wg_iface(name)
        peers = (iface.get("wireguard") or {}).get("peers") or []
        for peer in peers:
            if peer.get("id") == peer_id:
                return peer
        raise HTTPException(404, f"Peer {peer_id!r} not found on {name!r}")

    def _update_wg_peer(self, name: str, peer_id: str, body: WireguardPeerUpdate) -> dict:
        iface = self._get_wg_iface(name)
        peers = (iface.get("wireguard") or {}).get("peers") or []
        for i, peer in enumerate(peers):
            if peer.get("id") == peer_id:
                updates = body.model_dump(exclude_unset=True)
                peer.update(updates)
                peers[i] = peer
                self._interfaces[name] = iface
                self._save_state()
                return peer
        raise HTTPException(404, f"Peer {peer_id!r} not found on {name!r}")

    def _delete_wg_peer(self, name: str, peer_id: str) -> dict:
        iface = self._get_wg_iface(name)
        wg = iface.get("wireguard") or {}
        peers = wg.get("peers") or []
        for i, peer in enumerate(peers):
            if peer.get("id") == peer_id:
                peers.pop(i)
                wg["peers"] = peers
                iface["wireguard"] = wg
                self._interfaces[name] = iface
                self._save_state()
                return {"deleted": peer_id}
        raise HTTPException(404, f"Peer {peer_id!r} not found on {name!r}")
