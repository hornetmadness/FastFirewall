"""
Package and repository management library for the host plugin.

Provides platform detection, Pydantic request schemas, and a PackageManager
class that dispatches installs/removes/repo operations to the appropriate
pyinfra backend (apt, yum, dnf, apk, pacman).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import HTTPException
from pydantic import BaseModel
from pyinfra.operations import apk as apk_ops
from pyinfra.operations import apt as apt_ops
from pyinfra.operations import dnf as dnf_ops
from pyinfra.operations import files as files_ops
from pyinfra.operations import pacman as pacman_ops
from pyinfra.operations import server as server_ops
from pyinfra.operations import yum as yum_ops

_PKG_OPS: dict[str, Any] = {
    "apt": apt_ops,
    "yum": yum_ops,
    "dnf": dnf_ops,
    "apk": apk_ops,
    "pacman": pacman_ops,
}


class PackageBody(BaseModel):
    present: bool = True
    latest: bool = False


class RepoBody(BaseModel):
    present: bool = True
    # apt: full deb line, e.g. "deb https://example.com/apt focal main"
    src: Optional[str] = None
    # apt: drop a separate .list file under /etc/apt/sources.list.d/
    filename: Optional[str] = None
    # apt: GPG key URL to import alongside the repo
    key_url: Optional[str] = None
    # yum/dnf: repo base URL (alternative to embedding it in src)
    baseurl: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    gpgcheck: bool = True
    gpgkey: Optional[str] = None
    # apk/pacman: bare repo URL
    url: Optional[str] = None
    # pacman: signature verification level for this repo
    sig_level: str = "Required DatabaseOptional"


_PACMAN_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_\-\.]+$")


def _validate_pacman_repo(name: str, url: str) -> None:
    if not _PACMAN_REPO_NAME_RE.match(name):
        raise HTTPException(422, "pacman repo name must contain only alphanumerics, hyphens, underscores, or dots")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(422, "pacman repo URL is invalid")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(422, "pacman repo URL must use http or https scheme")


def detect_package_manager() -> str:
    """Return the name of the first supported package manager found on PATH."""
    for pm, binary in [("apt", "apt-get"), ("dnf", "dnf"), ("yum", "yum"), ("apk", "apk"), ("pacman", "pacman")]:
        if shutil.which(binary):
            return pm
    return "unknown"


class PackageManager:
    """Dispatches package and repository operations to the correct pyinfra backend."""

    def __init__(self, pyinfra_run: Callable[..., None], platform: str, cache_ttl: int = 300) -> None:
        self._pyinfra_run = pyinfra_run
        self.platform = platform
        self._cache_ttl = cache_ttl
        self._cache_refreshed_at: float = -1

    def assert_supported(self) -> None:
        if self.platform == "unknown":
            raise HTTPException(503, "No supported package manager detected on this host")

    # ── cache refresh ──────────────────────────────────────────────────────────

    def refresh_cache(self, *, force: bool = False) -> None:
        if not force and self._cache_ttl > 0 and self._cache_refreshed_at >= 0:
            if time.monotonic() - self._cache_refreshed_at < self._cache_ttl:
                return
        if self.platform == "apt":
            self._pyinfra_run(apt_ops.update, name="Refresh apt cache", _sudo=True)
        elif self.platform in ("yum", "dnf"):
            self._pyinfra_run(
                server_ops.shell,
                name=f"Refresh {self.platform} cache",
                commands=[f"{self.platform} makecache -q"],
            )
        elif self.platform == "apk":
            self._pyinfra_run(server_ops.shell, name="Refresh apk cache", commands=["apk update"])
        elif self.platform == "pacman":
            self._pyinfra_run(
                server_ops.shell,
                name="Refresh pacman databases",
                commands=["pacman -Sy --noconfirm"],
            )
        self._cache_refreshed_at = time.monotonic()

    # ── packages ───────────────────────────────────────────────────────────────

    def install(self, name: str, body: PackageBody) -> None:
        self.refresh_cache()
        ops_mod = _PKG_OPS[self.platform]
        kwargs: dict[str, Any] = {
            "name": f"Ensure package {name}",
            "packages": [name],
            "present": body.present,
        }
        if self.platform != "pacman":
            kwargs["latest"] = body.latest
        self._pyinfra_run(ops_mod.packages, **kwargs)

    def update(self, name: str) -> None:
        self.refresh_cache()
        ops_mod = _PKG_OPS[self.platform]
        kwargs: dict[str, Any] = {
            "name": f"Update package {name}",
            "packages": [name],
            "present": True,
        }
        if self.platform != "pacman":
            kwargs["latest"] = True
        self._pyinfra_run(ops_mod.packages, **kwargs)

    def remove(self, name: str) -> None:
        ops_mod = _PKG_OPS[self.platform]
        self._pyinfra_run(
            ops_mod.packages,
            name=f"Remove package {name}",
            packages=[name],
            present=False,
        )

    def upgrade_system(self) -> dict[str, Any]:
        """Refresh cache, then run a full unattended system upgrade.  Returns stdout, stderr, returncode, and platform."""
        self.refresh_cache(force=True)
        cmd = {
            "apt":    ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "dist-upgrade", "-y"],
            "dnf":    ["dnf", "upgrade", "-y", "-q"],
            "yum":    ["yum", "upgrade", "-y", "-q"],
            "apk":    ["apk", "upgrade"],
            "pacman": ["pacman", "-Syu", "--noconfirm"],
        }[self.platform]
        proc = subprocess.run(["sudo"] + cmd, capture_output=True, text=True)
        return {
            "platform":   self.platform,
            "returncode": proc.returncode,
            "stdout":     proc.stdout,
            "stderr":     proc.stderr,
        }

    # ── repos ──────────────────────────────────────────────────────────────────

    def apply_repo(self, name: str, body: RepoBody) -> None:
        """Add or remove a repo entry using the platform-appropriate pyinfra op."""
        if self.platform == "apt":
            if not body.src:
                raise HTTPException(422, "apt repos require 'src' (e.g. 'deb https://... focal main')")
            if body.key_url and body.present:
                self._pyinfra_run(
                    apt_ops.key,
                    name=f"Import GPG key for apt repo {name}",
                    src=body.key_url,
                    _sudo=True,
                )
            self._pyinfra_run(
                apt_ops.repo,
                name=f"Manage apt repo {name}",
                src=body.src,
                present=body.present,
                filename=body.filename,
                _sudo=True,
            )
            
        elif self.platform in ("yum", "dnf"):
            if not body.src:
                raise HTTPException(422, f"{self.platform} repos require 'src' (repo name or .repo URL)")
            ops_mod = _PKG_OPS[self.platform]
            kwargs: dict[str, Any] = {
                "name": f"Manage {self.platform} repo {name}",
                "src": body.src,
                "present": body.present,
                "enabled": body.enabled,
                "gpgcheck": body.gpgcheck,
            }
            if body.baseurl:
                kwargs["baseurl"] = body.baseurl
            if body.description:
                kwargs["description"] = body.description
            if body.gpgkey:
                kwargs["gpgkey"] = body.gpgkey
            self._pyinfra_run(ops_mod.repo, **kwargs)
        elif self.platform == "apk":
            if not body.url:
                raise HTTPException(422, "apk repos require 'url'")
            self._pyinfra_run(
                files_ops.line,
                name=f"Manage apk repo {name}",
                path="/etc/apk/repositories",
                line=body.url,
                present=body.present,
            )
        elif self.platform == "pacman":
            if not body.url:
                raise HTTPException(422, "pacman repos require 'url'")
            _validate_pacman_repo(name, body.url)
            if body.present:
                self._pyinfra_run(
                    server_ops.shell,
                    name=f"Add pacman repo {name}",
                    commands=[
                        f"grep -qxF '[{name}]' /etc/pacman.conf || "
                        f"printf '\\n[{name}]\\nServer = {body.url}\\n' >> /etc/pacman.conf"
                    ],
                )
            else:
                self._pyinfra_run(
                    server_ops.shell,
                    name=f"Remove pacman repo {name}",
                    commands=[
                        f"sed -i '/^\\[{name}\\]$/d; /^Server = {body.url}$/d' /etc/pacman.conf"
                    ],
                )

        if body.present:
            self.refresh_cache(force=True)

    def repo_system_id(self, name: str, attrs: dict[str, Any]) -> str | None:
        """Return the natural system identifier for a managed repo entry.

        This is used to match managed state against system-discovered repos so
        the list endpoint can annotate each repo with its managed status.
        """
        if self.platform == "apt":
            return attrs.get("src")
        if self.platform in ("yum", "dnf"):
            return attrs.get("src")
        if self.platform == "apk":
            return attrs.get("url")
        if self.platform == "pacman":
            return name
        return None

    def list_available_packages(self) -> dict[str, dict[str, Any]]:
        """Return all packages available to install from configured repos."""
        if self.platform == "apt":
            return self._list_apt_available()
        if self.platform in ("yum", "dnf"):
            return self._list_rpm_available()
        if self.platform == "apk":
            return self._list_apk_available()
        if self.platform == "pacman":
            return self._list_pacman_available()
        return {}

    @staticmethod
    def _list_apt_available() -> dict[str, dict[str, Any]]:
        proc = subprocess.run(["apt-cache", "pkgnames"], capture_output=True, text=True, timeout=30)
        return {name.strip(): {} for name in proc.stdout.splitlines() if name.strip()}

    @staticmethod
    def _list_rpm_available() -> dict[str, dict[str, Any]]:
        cmd = (
            ["dnf", "repoquery", "--qf", "%{name}", "--available"]
            if shutil.which("dnf")
            else ["yum", "list", "available", "-q"]
        )
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        result: dict[str, dict[str, Any]] = {}
        for line in proc.stdout.splitlines():
            name = line.split(".")[0].strip()
            if name and not name.startswith(("Last", "Error", "Loaded")):
                result[name] = {}
        return result

    @staticmethod
    def _list_apk_available() -> dict[str, dict[str, Any]]:
        import re
        proc = subprocess.run(["apk", "search", "-q"], capture_output=True, text=True, timeout=30)
        result: dict[str, dict[str, Any]] = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.search(r"-(\d)", line)
            name = line[: m.start()] if m else line
            if name:
                result[name] = {}
        return result

    @staticmethod
    def _list_pacman_available() -> dict[str, dict[str, Any]]:
        proc = subprocess.run(["pacman", "-Slq"], capture_output=True, text=True, timeout=30)
        return {name.strip(): {} for name in proc.stdout.splitlines() if name.strip()}

    def search_packages(self, query: str) -> list[dict[str, str]]:
        """Search available (installable) packages matching query."""
        if self.platform == "apt":
            return self._search_apt_packages(query)
        if self.platform in ("yum", "dnf"):
            return self._search_rpm_packages(query)
        if self.platform == "apk":
            return self._search_apk_packages(query)
        if self.platform == "pacman":
            return self._search_pacman_packages(query)
        return []

    @staticmethod
    def _search_apt_packages(query: str) -> list[dict[str, str]]:
        proc = subprocess.run(
            ["apt-cache", "search", query],
            capture_output=True, text=True, timeout=30,
        )
        results = []
        for line in proc.stdout.splitlines():
            if " - " in line:
                name, _, desc = line.partition(" - ")
                results.append({"name": name.strip(), "description": desc.strip()})
        return results

    @staticmethod
    def _search_rpm_packages(query: str) -> list[dict[str, str]]:
        cmd = ["dnf", "search", query] if shutil.which("dnf") else ["yum", "search", query]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        results: list[dict[str, str]] = []
        seen: set[str] = set()
        for line in proc.stdout.splitlines():
            if " : " not in line or line.startswith(("=", "Last", "Error")):
                continue
            name_arch, _, desc = line.partition(" : ")
            name = name_arch.split(".")[0].strip()
            if name and name not in seen:
                seen.add(name)
                results.append({"name": name, "description": desc.strip()})
        return results

    @staticmethod
    def _search_apk_packages(query: str) -> list[dict[str, str]]:
        import re
        proc = subprocess.run(
            ["apk", "search", query],
            capture_output=True, text=True, timeout=30,
        )
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.search(r"-(\d)", line)
            name = line[: m.start()] if m else line
            results.append({"name": name, "description": ""})
        return results

    @staticmethod
    def _search_pacman_packages(query: str) -> list[dict[str, str]]:
        proc = subprocess.run(
            ["pacman", "-Ss", query],
            capture_output=True, text=True, timeout=30,
        )
        results = []
        lines = proc.stdout.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line and not line[0].isspace():
                parts = line.split()
                if parts:
                    name = parts[0].split("/")[-1]
                    desc = lines[i + 1].strip() if i + 1 < len(lines) else ""
                    results.append({"name": name, "description": desc})
                    i += 2
                    continue
            i += 1
        return results

    def list_system_packages(self) -> dict[str, dict[str, Any]]:
        """Return all packages installed on the system, keyed by package name."""
        if self.platform == "apt":
            return self._list_apt_packages()
        if self.platform in ("yum", "dnf"):
            return self._list_rpm_packages()
        if self.platform == "apk":
            return self._list_apk_packages()
        if self.platform == "pacman":
            return self._list_pacman_packages()
        return {}

    @staticmethod
    def _list_apt_packages() -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        proc = subprocess.run(
            ["dpkg-query", "-W", "--showformat=${Package}\t${Version}\t${db:Status-Abbrev}\n"],
            capture_output=True,
            text=True,
        )
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[2].startswith("ii"):
                result[parts[0]] = {"version": parts[1], "installed": True}
        return result

    @staticmethod
    def _list_rpm_packages() -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        proc = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            capture_output=True,
            text=True,
        )
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                result[parts[0]] = {"version": parts[1], "installed": True}
        return result

    @staticmethod
    def _list_apk_packages() -> dict[str, dict[str, Any]]:
        import re
        result: dict[str, dict[str, Any]] = {}
        proc = subprocess.run(["apk", "info", "-v"], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.search(r"-(\d)", line)
            if m:
                idx = m.start()
                result[line[:idx]] = {"version": line[idx + 1:], "installed": True}
            else:
                result[line] = {"version": "", "installed": True}
        return result

    @staticmethod
    def _list_pacman_packages() -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        proc = subprocess.run(["pacman", "-Q"], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                result[parts[0]] = {"version": parts[1], "installed": True}
        return result

    def list_system_repos(self) -> dict[str, dict[str, Any]]:
        """Return all repos currently configured on the system, keyed by their natural identifier."""
        if self.platform == "apt":
            return self._list_apt_repos()
        if self.platform in ("yum", "dnf"):
            return self._list_yum_repos()
        if self.platform == "apk":
            return self._list_apk_repos()
        if self.platform == "pacman":
            return self._list_pacman_repos()
        return {}

    @staticmethod
    def _list_apt_repos() -> dict[str, dict[str, Any]]:
        repos: dict[str, dict[str, Any]] = {}
        sources_list = Path("/etc/apt/sources.list")
        if sources_list.exists():
            for line in sources_list.read_text().splitlines():
                line = line.strip()
                if line.startswith(("deb ", "deb-src ")):
                    repos[line] = {"src": line}
        sources_dir = Path("/etc/apt/sources.list.d")
        if sources_dir.is_dir():
            for f in sorted(sources_dir.glob("*.list")):
                for line in f.read_text().splitlines():
                    line = line.strip()
                    if line.startswith(("deb ", "deb-src ")):
                        repos[line] = {"src": line, "filename": f.stem}
        return repos

    @staticmethod
    def _list_yum_repos() -> dict[str, dict[str, Any]]:
        repos: dict[str, dict[str, Any]] = {}
        repos_dir = Path("/etc/yum.repos.d")
        if not repos_dir.is_dir():
            return repos
        for f in sorted(repos_dir.glob("*.repo")):
            current: str | None = None
            for line in f.read_text().splitlines():
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    current = line[1:-1]
                    repos[current] = {}
                elif current and "=" in line:
                    key, _, val = line.partition("=")
                    key, val = key.strip(), val.strip()
                    if key == "baseurl":
                        repos[current]["baseurl"] = val
                    elif key == "enabled":
                        repos[current]["enabled"] = val == "1"
                    elif key == "gpgcheck":
                        repos[current]["gpgcheck"] = val == "1"
        return repos

    @staticmethod
    def _list_apk_repos() -> dict[str, dict[str, Any]]:
        repos: dict[str, dict[str, Any]] = {}
        apk_repos = Path("/etc/apk/repositories")
        if apk_repos.exists():
            for line in apk_repos.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    repos[line] = {"url": line}
        return repos

    @staticmethod
    def _list_pacman_repos() -> dict[str, dict[str, Any]]:
        repos: dict[str, dict[str, Any]] = {}
        conf = Path("/etc/pacman.conf")
        if not conf.exists():
            return repos
        current: str | None = None
        for line in conf.read_text().splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1]
                if name.lower() != "options":
                    current = name
                    repos[current] = {}
            elif current and line.lower().startswith("server"):
                _, _, val = line.partition("=")
                repos[current]["url"] = val.strip()
        return repos
