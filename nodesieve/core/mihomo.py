"""Mihomo as the core nodes are checked through: its binary, its configuration and its log.

The nodes' proxies come from nodesieve.parsers.mihomo, the same conversion the feed's Clash
profile uses, so through Mihomo a node is checked the way Clash apps connect to it.
"""

import gzip
import io
import json
import os
import platform
import re
import sys
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

from nodesieve.constants import MIHOMO_PATH
from nodesieve.core.base import LISTEN_HOST, ProxyCore, download, go_crash
from nodesieve.logging import log
from nodesieve.parsers.mihomo import node_url_to_mihomo_dict

MIHOMO_RELEASE_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha"
# Mihomo's log lines (logrus text format), and the messages that say what stopped it.
_LOG_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_PROXY_REFUSED = re.compile(r"^Parse config error: proxy (\d+): (.+)$")
_LISTEN_FAILED = re.compile(r"^Listener (\S+) listen err")


def render_batch_config(
    proxies: Sequence[Tuple[dict, int]], hosts: Optional[Dict[str, List[str]]] = None
) -> str:
    """Mihomo configuration serving each proxy on a mixed listener of its own at 127.0.0.1:port.

    A listener pinned to a proxy sends everything it receives through that proxy, whatever
    the rules say. The rules refuse everything else, so no connection leaves directly.
    """
    config: Dict[str, Any] = {
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "ipv6": True,
        "proxies": [proxy for proxy, _ in proxies],
        "listeners": [
            {"name": f"in-{proxy['name']}", "type": "mixed", "listen": LISTEN_HOST, "port": port,
             "proxy": proxy["name"]}
            for proxy, port in proxies
        ],
        "rules": ["MATCH,REJECT"],
    }
    if hosts:
        config["hosts"] = hosts
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)


def _log_record(line: str) -> Tuple[Optional[str], str]:
    """The level and message of one of Mihomo's log lines; (None, line) for other output."""
    fields = dict(_LOG_FIELD.findall(line))
    message = fields.get("msg")
    if message is None:
        return None, line.strip()
    if message.startswith('"'):
        try:
            message = json.loads(message)
        except ValueError:
            message = message[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return fields.get("level"), message


class MihomoCore(ProxyCore):
    """Mihomo: named proxies, each with a mixed listener pinned to it."""

    name = "mihomo"
    display = "Mihomo"
    config_name = "config.yaml"

    @property
    def path(self) -> str:
        return MIHOMO_PATH

    def setup(self) -> None:
        """Ensures the appropriate platform Mihomo binary exists, downloading it from GitHub if absent."""
        if os.path.exists(MIHOMO_PATH):
            return

        arch = platform.machine().lower()
        log.info(f"[*] Fetching latest alpha mihomo release for architecture {platform.machine()}...")

        if os.name == "nt":
            if arch in ["x86_64", "amd64"]:
                prefix, fallback_prefix = "mihomo-windows-amd64-compatible-alpha-", "mihomo-windows-amd64-alpha-"
            elif arch in ["aarch64", "arm64"]:
                prefix, fallback_prefix = "mihomo-windows-arm64-alpha-", "mihomo-windows-arm64-alpha-"
            elif "arm" in arch:
                prefix, fallback_prefix = "mihomo-windows-armv7-alpha-", "mihomo-windows-armv7-alpha-"
            else:
                prefix, fallback_prefix = "mihomo-windows-amd64-compatible-alpha-", "mihomo-windows-amd64-alpha-"
            ext = ".zip"
        else:
            if arch in ["x86_64", "amd64"]:
                prefix, fallback_prefix = "mihomo-linux-amd64-compatible-alpha-", "mihomo-linux-amd64-alpha-"
            elif arch in ["aarch64", "arm64"]:
                prefix, fallback_prefix = "mihomo-linux-arm64-alpha-", "mihomo-linux-arm64-alpha-"
            elif "arm" in arch:
                prefix, fallback_prefix = "mihomo-linux-armv7-alpha-", "mihomo-linux-armv7-alpha-"
            else:
                log.error(f"[-] Unsupported architecture: {arch}")
                sys.exit(1)
            ext = ".gz"

        url = None
        try:
            rel_data = json.loads(download(MIHOMO_RELEASE_API, timeout=30.0).decode("utf-8"))
            assets = rel_data.get("assets", [])
            for a in assets:
                aname = a.get("name", "")
                if aname.startswith(prefix) and aname.endswith(ext):
                    url = a.get("browser_download_url")
                    break

            if not url:
                for a in assets:
                    aname = a.get("name", "")
                    if aname.startswith(fallback_prefix) and aname.endswith(ext):
                        url = a.get("browser_download_url")
                        break
        except Exception as e:
            log.warning(f"[!] Failed to fetch release info from GitHub API: {e}")

        if not url:
            log.error("[-] Could not find matching asset for latest alpha release.")
            sys.exit(1)

        log.info(f"[*] Downloading mihomo from {url}...")
        try:
            data = download(url)
            if url.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for name in z.namelist():
                        if name.endswith(".exe"):
                            with open(MIHOMO_PATH, "wb") as f:
                                f.write(z.read(name))
                            break
            else:
                with open(MIHOMO_PATH, "wb") as f:
                    f.write(gzip.decompress(data))

            if os.name != "nt":
                os.chmod(MIHOMO_PATH, 0o755)
            log.info("[+] Mihomo alpha setup complete.")
        except Exception as e:
            log.error(f"[-] Failed to download mihomo: {e}")
            sys.exit(1)

    def proxy(self, link: str, config: dict) -> dict:
        proxy = node_url_to_mihomo_dict(link, use_mux=config.get("use_mux", True))
        if not proxy:
            raise ValueError("The link does not convert to a Mihomo proxy")
        return proxy

    def named(self, proxy: dict, name: str) -> dict:
        return {**proxy, "name": name}

    def server(self, proxy: dict) -> Optional[str]:
        return proxy.get("server")

    def ready_proxy(self, port: int) -> dict:
        return {"type": "http", "server": LISTEN_HOST, "port": port}

    def render(self, served: Sequence[Tuple[Any, int]], hosts: Optional[Dict[str, List[str]]] = None) -> str:
        return render_batch_config(served, hosts)

    def command(self, work_dir: str, config_path: str) -> List[str]:
        return [self.path, "-d", work_dir, "-f", config_path]

    def refused(self, lines: Sequence[str], names: Sequence[str]) -> Optional[Tuple[int, str]]:
        # "proxy N" numbers the proxies in the configuration's order, so the ready proxy comes last.
        for line in reversed(lines):
            match = _PROXY_REFUSED.match(_log_record(line)[1])
            if match and int(match.group(1)) < len(names):
                return int(match.group(1)), f"Parse config error: {match.group(2)}"
        return None

    def busy(self, lines: Sequence[str], listeners: Sequence[Tuple[str, int]]) -> Dict[int, str]:
        names = {f"in-{name}": index for index, (name, _) in enumerate(listeners)}
        found = {}
        for line in lines:
            message = _log_record(line)[1]
            match = _LISTEN_FAILED.match(message)
            if match and match.group(1) in names:
                found[names[match.group(1)]] = message[:300]
        return found

    def detail(self, lines: Sequence[str]) -> str:
        crash = go_crash(lines)
        if crash:
            return crash
        for line in reversed(lines):
            level, message = _log_record(line)
            if level is None or level in ("error", "fatal", "panic"):
                return message[:300]
        return ""
