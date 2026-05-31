import datetime
import os
from typing import Any

from fastapi import File, HTTPException, UploadFile
from plugin_system.core.events import Event, bus

from ..models import PxeImageRename, PxeServiceCreate, PxeUpdate


class PxeMixin:
    _pxe: dict[str, Any]
    _pxe_services: list[Any]
    config: dict[str, Any]
    logger: Any
    _save_state: Any

    def _get_pxe(self) -> dict[str, Any]:
        return dict(self._pxe)

    def _update_pxe(self, body: PxeUpdate) -> dict[str, Any]:
        self._pxe.update(body.model_dump(exclude_unset=True))
        self._save_state()
        bus.emit(Event("dnsmasq.pxe.updated",
                       payload={"enabled": self._pxe.get("enabled")}))
        return dict(self._pxe)

    def _list_pxe_services(self) -> dict[str, Any]:
        return {
            "services": [{"index": i, **s} for i, s in enumerate(self._pxe_services)],
            "count": len(self._pxe_services),
        }

    def _add_pxe_service(self, body: PxeServiceCreate) -> dict[str, Any]:
        svc = body.model_dump(exclude_none=True)
        self._pxe_services.append(svc)
        index = len(self._pxe_services) - 1
        self._save_state()
        return {"index": index, **svc}

    def _delete_pxe_service(self, index: int) -> dict[str, Any]:
        if index < 0 or index >= len(self._pxe_services):
            raise HTTPException(404, f"PXE service index {index} out of range (have {len(self._pxe_services)})")
        self._pxe_services.pop(index)
        self._save_state()
        return {"deleted": index}

    def _pxe_data_dir(self) -> str:
        return self.config.get("pxe", {}).get("data_dir", "/srv/tftp")

    def _pxe_image_path(self, filename: str) -> str:
        if "/" in filename or filename.startswith("."):
            raise HTTPException(400, detail="Invalid filename")
        return os.path.join(self._pxe_data_dir(), filename)

    def _image_info(self, path: str) -> dict[str, Any]:
        st = os.stat(path)
        return {
            "name": os.path.basename(path),
            "size": st.st_size,
            "modified": datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc).isoformat(),
        }

    def _list_pxe_images(self) -> dict[str, Any]:
        data_dir = self._pxe_data_dir()
        try:
            entries = [self._image_info(e.path) for e in os.scandir(data_dir) if e.is_file()]
        except FileNotFoundError:
            entries = []
        except PermissionError:
            raise HTTPException(500, "Cannot read PXE data directory; check server logs")
        return {"images": sorted(entries, key=lambda e: e["name"]), "count": len(entries)}

    async def _upload_pxe_image(self, files: list[UploadFile] = File(...)) -> dict[str, Any]:
        uploaded: list[dict[str, Any]] = []
        for file in files:
            filename = os.path.basename(file.filename or "")
            if not filename or "/" in filename or filename.startswith("."):
                raise HTTPException(400, detail=f"Invalid filename {filename!r}")
            dest = os.path.join(self._pxe_data_dir(), filename)
            try:
                data = await file.read()
                with open(dest, "wb") as fh:
                    fh.write(data)
            except PermissionError:
                self.logger.error("Permission denied writing PXE image %r", dest)
                raise HTTPException(500, "Failed to write PXE image; check server logs")
            except OSError as exc:
                self.logger.error("Failed to write PXE image %r: %s", dest, exc)
                raise HTTPException(500, "Failed to write PXE image; check server logs")
            uploaded.append(self._image_info(dest))
        return {"uploaded": uploaded, "count": len(uploaded)}

    def _get_pxe_image(self, filename: str) -> dict[str, Any]:
        path = self._pxe_image_path(filename)
        try:
            return self._image_info(path)
        except FileNotFoundError:
            raise HTTPException(404, detail=f"Image {filename!r} not found")

    def _delete_pxe_image(self, filename: str) -> dict[str, Any]:
        path = self._pxe_image_path(filename)
        try:
            os.remove(path)
        except FileNotFoundError:
            raise HTTPException(404, detail=f"Image {filename!r} not found")
        except OSError as exc:
            self.logger.error("Failed to delete PXE image %r: %s", path, exc)
            raise HTTPException(500, "Failed to delete PXE image; check server logs")
        return {"deleted": filename}

    def _rename_pxe_image(self, filename: str, body: PxeImageRename) -> dict[str, Any]:
        src = self._pxe_image_path(filename)
        dst = self._pxe_image_path(body.name)
        if src == dst:
            raise HTTPException(400, detail="Source and destination filenames are the same")
        if os.path.exists(dst):
            raise HTTPException(409, detail=f"Image {body.name!r} already exists")
        try:
            os.rename(src, dst)
        except FileNotFoundError:
            raise HTTPException(404, detail=f"Image {filename!r} not found")
        except OSError as exc:
            self.logger.error("Failed to rename PXE image %r -> %r: %s", src, dst, exc)
            raise HTTPException(500, "Failed to rename PXE image; check server logs")
        return self._image_info(dst)

    def render_config(self) -> list[str]:
        lines: list[str] = []
        if not self._pxe.get("enabled"):
            return lines
        for svc in self._pxe_services:
            parts = [svc["type"], f'"{svc["menu_name"]}"']
            if svc.get("boot_file"):
                parts.append(svc["boot_file"])
            if svc.get("server"):
                parts.append(svc["server"])
            lines.append(f"pxe-service={','.join(parts)}")
        if self._pxe.get("prompt") is not None:
            lines.append(f'pxe-prompt="{self._pxe["prompt"]}",0')
        return lines
