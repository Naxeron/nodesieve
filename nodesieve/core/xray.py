"""Xray as the core nodes are checked through: its binary, its configuration and its log.

Share links are written for Xray, so through Xray a node is checked the way the apps the
links are made for connect to it, FinalMask fragmenting and all.
"""

import copy
import hashlib
import io
import json
import os
import platform
import re
import sys
import tempfile
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

from nodesieve.constants import IS_ANDROID, IS_TERMUX, XRAY_PATH
from nodesieve.core.base import LISTEN_HOST, ProxyCore, download, go_crash, release_assets
from nodesieve.logging import log
from nodesieve.parsers.xray import node_url_to_xray_outbound

XRAY_RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
# What takes the connections no rule names; the listeners each have one.
_REFUSE_TAG = "refuse"
# Xray's log: "2026/11/20 23:31:51.386004 [Warning] message", and how a failed start reads.
_LOG_LINE = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(?:\.\d+)? \[(\w+)\] (.*)$")
_REFUSED = re.compile(r"failed to build outbound config with tag (\S+?) > (.+)$")
_LISTEN_FAILED = re.compile(r"failed to listen TCP on (\d+)")


def xray_asset(machine: Optional[str] = None, android: Optional[bool] = None,
               system: Optional[str] = None) -> Optional[str]:
    """The name of Xray's release archive for this platform, or None for one it has none for."""
    machine = (machine or platform.machine()).lower()
    android = (IS_ANDROID or IS_TERMUX) if android is None else android
    system = system or ("windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux")
    arch = {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a", "armv8l": "arm32-v7a",
            "armv7l": "arm32-v7a", "armv7": "arm32-v7a", "armv6l": "arm32-v6", "i386": "32", "i686": "32",
            "x86": "32", "riscv64": "riscv64"}.get(machine)
    if arch is None:
        return None
    if system == "linux" and android and arch in ("arm64-v8a", "64"):
        # The Android builds look host names up as Android does; there are only these two.
        return f"Xray-android-{'amd64' if arch == '64' else arch}.zip"
    if system in ("windows", "macos") and arch not in ("64", "arm64-v8a", "32"):
        return None
    return f"Xray-{system}-{arch}.zip"


def _sha256(digest_file: str) -> Optional[str]:
    """The SHA-256 a release's .dgst file gives."""
    match = re.search(r"^SHA2-256=\s*([0-9a-f]{64})\s*$", digest_file, re.MULTILINE | re.IGNORECASE)
    return match.group(1).lower() if match else None


def render_xray_config(served: Sequence[Tuple[dict, int]], hosts: Optional[Dict[str, List[str]]] = None) -> str:
    """Xray configuration serving each outbound on a mixed listener of its own at 127.0.0.1:port.

    Each listener has a routing rule to its outbound. Anything no rule names would go to the
    first outbound, a blackhole, so no connection leaves directly. With hosts, outbounds whose
    server they name look it up there (Android).
    """
    inbounds, rules = [], []
    outbounds: List[dict] = [{"tag": _REFUSE_TAG, "protocol": "blackhole"}]
    for outbound, port in served:
        tag = outbound["tag"]
        inbounds.append({"tag": f"in-{tag}", "listen": LISTEN_HOST, "port": port, "protocol": "mixed", "settings": {}})
        rules.append({"type": "field", "inboundTag": [f"in-{tag}"], "outboundTag": tag})
        server = XrayCore.server_of(outbound)
        if hosts and isinstance(server, str) and server.lower() in hosts:
            outbound = copy.deepcopy(outbound)
            stream = outbound.setdefault("streamSettings", {})
            stream.setdefault("sockopt", {})["domainStrategy"] = "UseIP"
        outbounds.append(outbound)
    config: Dict[str, Any] = {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if hosts:
        config["dns"] = {"hosts": hosts}
    return json.dumps(config, ensure_ascii=False, indent=1)


def _record(line: str) -> Tuple[Optional[str], str]:
    """The level and message of one of Xray's log lines; (None, line) for other output."""
    match = _LOG_LINE.match(line)
    return (match.group(1).lower(), match.group(2)) if match else (None, line.strip())


class XrayCore(ProxyCore):
    """Xray: outbounds tagged with nodesieve's names, a mixed inbound and a routing rule for each."""

    name = "xray"
    display = "Xray"
    config_name = "config.json"

    @property
    def path(self) -> str:
        return XRAY_PATH

    def setup(self) -> None:
        """Downloads the latest Xray release for this platform when the binary is absent.

        The archive is checked against the SHA-256 the release publishes with it.
        """
        if os.path.exists(XRAY_PATH):
            return
        asset = xray_asset()
        if asset is None:
            log.error(f"[-] Xray has no release for this platform ({platform.machine()}).")
            sys.exit(1)
        log.info(f"[*] Fetching the latest Xray release for {platform.machine()}...")
        try:
            assets = release_assets(XRAY_RELEASE_API)
            if asset not in assets and asset.startswith("Xray-android-"):
                asset = asset.replace("android", "linux").replace("amd64", "64")
            if asset not in assets or f"{asset}.dgst" not in assets:
                raise RuntimeError(f"the latest release has no {asset}")
            log.info(f"[*] Downloading {assets[asset]}...")
            archive = download(assets[asset])
            expected = _sha256(download(assets[f"{asset}.dgst"], timeout=30.0).decode("utf-8", "replace"))
            if expected is None:
                raise RuntimeError(f"{asset}.dgst gives no SHA-256")
            if hashlib.sha256(archive).hexdigest() != expected:
                raise RuntimeError(f"{asset} does not match its SHA-256")
            binary = "xray.exe" if os.name == "nt" else "xray"
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                data = bundle.read(binary)
            directory = os.path.dirname(XRAY_PATH) or "."
            fd, temporary = tempfile.mkstemp(prefix=".xray-", dir=directory)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                if os.name != "nt":
                    os.chmod(temporary, 0o755)
                os.replace(temporary, XRAY_PATH)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except Exception as e:
            log.error(f"[-] Failed to download Xray: {e}")
            sys.exit(1)
        log.info("[+] Xray setup complete.")

    def proxy(self, link: str, config: dict) -> dict:
        outbound = node_url_to_xray_outbound(link)
        if not outbound:
            raise ValueError("The link does not convert to an Xray outbound")
        return outbound

    def named(self, proxy: dict, name: str) -> dict:
        return {**proxy, "tag": name}

    @staticmethod
    def server_of(outbound: dict) -> Optional[str]:
        settings = outbound.get("settings") or {}
        servers = settings.get("servers") or settings.get("vnext") or [settings]
        return servers[0].get("address") if servers and isinstance(servers[0], dict) else None

    def server(self, proxy: dict) -> Optional[str]:
        return self.server_of(proxy)

    def ready_proxy(self, port: int) -> dict:
        return {"protocol": "http", "settings": {"servers": [{"address": LISTEN_HOST, "port": port}]}}

    def render(self, served: Sequence[Tuple[Any, int]], hosts: Optional[Dict[str, List[str]]] = None) -> str:
        return render_xray_config(served, hosts)

    def command(self, work_dir: str, config_path: str) -> List[str]:
        return [self.path, "run", "-c", config_path]

    def refused(self, lines: Sequence[str], names: Sequence[str]) -> Optional[Tuple[int, str]]:
        for line in reversed(lines):
            match = _REFUSED.search(_record(line)[1])
            if match and match.group(1) in names:
                return list(names).index(match.group(1)), f"Failed to build outbound: {match.group(2)[:300]}"
        return None

    def busy(self, lines: Sequence[str], listeners: Sequence[Tuple[str, int]]) -> Dict[int, str]:
        ports = {port: index for index, (_, port) in enumerate(listeners)}
        found = {}
        for line in lines:
            message = _record(line)[1]
            for port in _LISTEN_FAILED.findall(message):
                if int(port) in ports:
                    found[ports[int(port)]] = message[:300]
        return found

    def detail(self, lines: Sequence[str]) -> str:
        crash = go_crash(lines)
        if crash:
            return crash
        records = [_record(line) for line in lines]
        for wanted in (lambda level, message: message.startswith("Failed to start"),
                       lambda level, message: level == "error",
                       lambda level, message: level == "warning" and "deprecated" not in message):
            for level, message in reversed(records):
                if wanted(level, message):
                    return message[:300]
        return ""
