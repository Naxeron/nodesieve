"""Xray proxy core: binary download, batch configuration rendering, and log parsing."""

import copy
import hashlib
import io
import json
import os
import platform
import re
import sys
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

from nodesieve.constants import IS_ANDROID, IS_TERMUX, XRAY_PATH
from nodesieve.files import write_atomic
from nodesieve.logging import log
from nodesieve.parsers.xray import node_url_to_xray_outbound

LISTEN_HOST = "127.0.0.1"
XRAY_RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
_GO_CRASH = ("panic:", "fatal error:")
_LOG_LINE = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(?:\.\d+)? \[(\w+)\] (.*)$")
_SESSION = re.compile(r"^\[(\d+)\] (.+)$")
_DETOUR = re.compile(r"^app/dispatcher: taking detour \[([^\]]+)\] for \[([^\]]+)\]")
_OUTBOUND_ERR = re.compile(r"failed to process outbound traffic > (.+)$")
_RETRY_LIST = re.compile(r"common/retry: \[(.+?)\](?:\s*>\s*common/retry: all retry attempts failed)?$")
_REFUSED = re.compile(r"failed to build outbound config with tag (\S+?) > (.+)$")
_LISTEN_FAILED = re.compile(r"failed to listen TCP on (\d+)")


def download(url: str, timeout: float = 120.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "nodesieve"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def release_assets(api_url: str) -> Dict[str, str]:
    release = json.loads(download(api_url, timeout=30.0).decode("utf-8"))
    return {a.get("name", ""): a.get("browser_download_url", "") for a in release.get("assets", [])}


def xray_asset(machine: Optional[str] = None, android: Optional[bool] = None,
               system: Optional[str] = None) -> Optional[str]:
    """Xray release archive name for this platform, or None if unsupported."""
    machine = (machine or platform.machine()).lower()
    android = (IS_ANDROID or IS_TERMUX) if android is None else android
    system = system or ("windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux")
    arch = {
        "x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a",
        "armv8l": "arm32-v7a", "armv7l": "arm32-v7a", "armv7": "arm32-v7a", "armv6l": "arm32-v6",
        "i386": "32", "i686": "32", "x86": "32", "riscv64": "riscv64",
    }.get(machine)
    if arch is None:
        return None
    if system == "linux" and android and arch in ("arm64-v8a", "64"):
        return f"Xray-android-{'amd64' if arch == '64' else arch}.zip"
    if system in ("windows", "macos") and arch not in ("64", "arm64-v8a", "32"):
        return None
    return f"Xray-{system}-{arch}.zip"


def render_xray_config(served: Sequence[Tuple[dict, int]], hosts: Optional[Dict[str, List[str]]] = None) -> str:
    """Render an Xray config pinning one mixed listener on 127.0.0.1 to each outbound."""
    inbounds, rules = [], []
    outbounds: List[dict] = [{"tag": "refuse", "protocol": "blackhole"}]
    for outbound, port in served:
        tag = outbound["tag"]
        inbounds.append({"tag": f"in-{tag}", "listen": LISTEN_HOST, "port": port, "protocol": "mixed", "settings": {}})
        rules.append({"type": "field", "inboundTag": [f"in-{tag}"], "outboundTag": tag})
        server = XrayCore.server_of(outbound)
        if hosts and isinstance(server, str) and server.lower() in hosts:
            outbound = copy.deepcopy(outbound)
            outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})["domainStrategy"] = "UseIP"
        outbounds.append(outbound)
    config: Dict[str, Any] = {
        "log": {"loglevel": "info", "access": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if hosts:
        config["dns"] = {"hosts": hosts}
    return json.dumps(config, ensure_ascii=False, indent=1)


def _record(line: str) -> Tuple[Optional[str], str]:
    m = _LOG_LINE.match(line)
    return (m.group(1).lower(), m.group(2)) if m else (None, line.strip())


def summarize_outbound_error(raw: str) -> str:
    """Distill an Xray outbound failure chain into a short user-facing reason."""
    is_hysteria = "proxy/hysteria" in raw
    msg = re.sub(r"^proxy/[^:]+:\s*failed to find an available destination\s*>\s*", "", raw.strip())
    if retry_m := _RETRY_LIST.search(msg):
        inner = retry_m.group(1).strip()
        # Xray joins repeated dial attempts inside [...] with spaces.
        if " transport/internet/" in inner:
            inner = inner.split(" transport/internet/", 1)[0].strip()
        msg = inner
    lower = msg.lower()
    if is_hysteria and ("no recent network activity" in lower or "i/o timeout" in lower or "deadline exceeded" in lower):
        return "QUIC handshake timeout (no UDP response)"
    if "x509:" in msg:
        return f"TLS certificate error: {msg.split('x509:', 1)[1].strip()[:90]}"
    if "tls: failed to verify certificate:" in lower:
        idx = lower.index("tls: failed to verify certificate:") + len("tls: failed to verify certificate:")
        return f"TLS certificate error: {msg[idx:].strip()[:90]}"
    if "tls:" in lower:
        idx = lower.index("tls:") + len("tls:")
        return f"TLS handshake error: {msg[idx:].strip()[:90]}"
    if "auth failed" in lower:
        idx = lower.index("auth failed")
        prefix = "Hysteria 2" if is_hysteria else "Proxy"
        return f"{prefix} {msg[idx:].strip()[:90]}"
    if "lookup " in lower:
        idx = lower.index("lookup ")
        return f"DNS lookup failed: {msg[idx:].strip()[:90]}"
    if "connection refused" in lower:
        return "Proxy connection refused"
    if "connection reset by peer" in lower:
        return "Proxy connection reset"
    if msg == "EOF" or msg.endswith((": EOF", "> EOF", " EOF")):
        return "Proxy closed connection (EOF)"
    if "i/o timeout" in lower or "deadline exceeded" in lower or "no recent network activity" in lower:
        return "Proxy handshake timeout"
    msg = re.sub(r"^transport/internet/[^:]+:\s*failed to dial to dest\s*>\s*", "", msg)
    return msg[:120]


class XrayCore:
    """Xray binary management, outbound conversion, and failure log analysis."""

    name = "xray"
    display = "Xray"
    config_name = "config.json"

    @property
    def path(self) -> str:
        return XRAY_PATH

    def setup(self) -> None:
        """Download and SHA-256-verify the latest Xray binary when absent."""
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
            dgst = download(assets[f"{asset}.dgst"], timeout=30.0).decode("utf-8", "replace")
            match = re.search(r"^SHA2-256=\s*([0-9a-f]{64})\s*$", dgst, re.MULTILINE | re.IGNORECASE)
            if not match:
                raise RuntimeError(f"{asset}.dgst gives no SHA-256")
            if hashlib.sha256(archive).hexdigest() != match.group(1).lower():
                raise RuntimeError(f"{asset} does not match its SHA-256")
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                data = bundle.read("xray.exe" if os.name == "nt" else "xray")
            write_atomic(XRAY_PATH, data, mode=0o755)
        except Exception as e:
            log.error(f"[-] Failed to download Xray: {e}")
            sys.exit(1)
        log.info("[+] Xray setup complete.")

    def proxy(self, link: str, config: Optional[dict] = None) -> dict:
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
            m = _REFUSED.search(_record(line)[1])
            if m and m.group(1) in names:
                return list(names).index(m.group(1)), f"Failed to build outbound: {m.group(2)[:300]}"
        return None

    def busy(self, lines: Sequence[str], listeners: Sequence[Tuple[str, int]]) -> Dict[int, str]:
        ports = {port: idx for idx, (_, port) in enumerate(listeners)}
        found = {}
        for line in lines:
            msg = _record(line)[1]
            for port in _LISTEN_FAILED.findall(msg):
                if int(port) in ports:
                    found[ports[int(port)]] = msg[:300]
        return found

    def outbound_status(self, lines: Sequence[str], tag: str) -> Tuple[str, Optional[str]]:
        """Inspect Xray [Info] logs for an outbound tag: (state, summary).

        States:
        - ("error", summary): Xray logged an outbound dial/handshake/auth failure for this tag.
        - ("tunneled", None): Xray opened a proxy tunnel for this tag (failure happened beyond proxy).
        - ("dialing", None): Xray dispatched to this tag but never completed the proxy handshake.
        - ("none", None): No log entries observed for this tag.
        """
        sessions: Dict[str, str] = {}
        tunneled: set[str] = set()
        errors: Dict[str, str] = {}
        for line in lines:
            _, msg = _record(line)
            sess_m = _SESSION.match(msg)
            if not sess_m:
                continue
            sid, body = sess_m.group(1), sess_m.group(2)
            if detour_m := _DETOUR.match(body):
                if detour_m.group(1) == tag:
                    sessions[sid] = detour_m.group(2)
                continue
            if sid not in sessions:
                continue
            if "tunneling request to " in body:
                tunneled.add(sid)
            elif err_m := _OUTBOUND_ERR.search(body):
                errors[sid] = err_m.group(1)
        if not sessions:
            return "none", None
        # Prefer IPv4/domain probe sessions over IPv6-only probe sessions when summarizing failures.
        primary = [sid for sid, target in sessions.items() if "[" not in target]
        ordered = list(reversed(primary)) + [sid for sid in reversed(list(sessions)) if sid not in primary]
        for sid in ordered:
            if sid in errors:
                return "error", summarize_outbound_error(errors[sid])
        if any(sid in tunneled for sid in ordered):
            return "tunneled", None
        return "dialing", None

    def detail(self, lines: Sequence[str]) -> str:
        for line in lines:
            if line.startswith(_GO_CRASH):
                return line.strip()[:300]
        records = [_record(line) for line in lines]
        for match in (
            lambda lv, msg: msg.startswith("Failed to start"),
            lambda lv, msg: lv == "error",
            lambda lv, msg: lv == "warning" and "deprecated" not in msg,
        ):
            for lv, msg in reversed(records):
                if match(lv, msg):
                    return msg[:300]
        return ""
