import asyncio
import datetime
import ipaddress
import urllib.parse
import uuid
from typing import Any

import httpx
from fastapi import HTTPException
from plugin_system.core.events import Event, bus

from ..models import BlocklistCreate


async def _validate_blocklist_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(422, "Invalid blocklist URL")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(422, "Blocklist URL must use http or https scheme")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(422, "Blocklist URL must have a valid hostname")
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(hostname, None)
    except OSError:
        raise HTTPException(422, "Blocklist URL hostname could not be resolved")
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise HTTPException(422, "Blocklist URL must not resolve to a private or reserved address")


class BlocklistMixin:
    async def _fetch_blocklist_domains(self, url: str, fmt: str) -> list[str]:
        await _validate_blocklist_url(url)
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise OSError(f"HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise OSError(str(exc)) from exc
        content = resp.text
        domains: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            if fmt == "hosts":
                parts = line.split()
                if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::1", "::"}:
                    domain = parts[1].lower()
                    if domain not in {"localhost", "localhost.localdomain", "0.0.0.0", "broadcasthost"}:
                        domains.append(domain)
            else:
                token = line.split()[0].lower() if line.split() else ""
                if token and "." in token:
                    domains.append(token)
        return list(dict.fromkeys(domains))

    def _list_blocklists(self) -> dict[str, Any]:
        return {
            "blocklists": [
                {
                    "id": bid,
                    "name": bl["name"],
                    "url": bl["url"],
                    "format": bl.get("format", "hosts"),
                    "domain_count": len(bl.get("domains", [])),
                    "last_fetched": bl.get("last_fetched"),
                }
                for bid, bl in self._blocklists.items()
            ],
            "total_blocked_domains": sum(
                len(bl.get("domains", [])) for bl in self._blocklists.values()
            ),
        }

    async def _add_blocklist(self, body: BlocklistCreate) -> dict[str, Any]:
        try:
            domains = await self._fetch_blocklist_domains(body.url, body.format)
        except Exception as exc:
            self.logger.error("Failed to fetch blocklist from %r: %s", body.url, exc)
            raise HTTPException(502, f"Failed to fetch blocklist from {body.url!r}; check server logs")
        blocklist_id = str(uuid.uuid4())[:8]
        self._blocklists[blocklist_id] = {
            "name": body.name,
            "url": body.url,
            "format": body.format,
            "domains": domains,
            "last_fetched": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._save_state()
        bus.emit(Event("dnsmasq.blocklist.added",
                       payload={"blocklist_id": blocklist_id, "name": body.name, "domain_count": len(domains)}))
        return {"id": blocklist_id, "name": body.name, "domain_count": len(domains)}

    def _delete_blocklist(self, blocklist_id: str) -> dict[str, Any]:
        if blocklist_id not in self._blocklists:
            raise HTTPException(404, f"Blocklist {blocklist_id!r} not found")
        self._blocklists.pop(blocklist_id)
        self._save_state()
        bus.emit(Event("dnsmasq.blocklist.removed",
                       payload={"blocklist_id": blocklist_id}))
        return {"deleted": blocklist_id}

    async def _refresh_blocklist(self, blocklist_id: str) -> dict[str, Any]:
        if blocklist_id not in self._blocklists:
            raise HTTPException(404, f"Blocklist {blocklist_id!r} not found")
        bl = self._blocklists[blocklist_id]
        try:
            domains = await self._fetch_blocklist_domains(bl["url"], bl.get("format", "hosts"))
        except Exception as exc:
            self.logger.error("Failed to refresh blocklist from %r: %s", bl["url"], exc)
            raise HTTPException(502, f"Failed to refresh blocklist from {bl['url']!r}; check server logs")
        bl["domains"] = domains
        bl["last_fetched"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save_state()
        return {"id": blocklist_id, "name": bl["name"], "domain_count": len(domains)}

    def render_config(self) -> list[str]:
        lines: list[str] = []
        for bl in self._blocklists.values():
            for domain in bl.get("domains") or []:
                lines.append(f"address=/{domain}/#")
        return lines
