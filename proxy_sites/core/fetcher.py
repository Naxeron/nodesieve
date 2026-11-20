"""Fetches remote subscription nodes, decodes, rewrites multiplexing, and deduplicates.

The raw payload of each subscription that downloads with usable nodes is kept in
sub_cache/. When a later download fails or has no usable nodes, the nodes of that
subscription's last good payload are used instead.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import tempfile
import time
from typing import Dict, List, Optional, Set, Tuple
import aiohttp

from proxy_sites.constants import PROJECT_ROOT, SUB_CACHE_DIR
from proxy_sites.logging import ErrorTracker, log
from proxy_sites.parsers.awg import parse_amnezia_conf
from proxy_sites.parsers.base import extract_host_port
from proxy_sites.warp import WarpScanner


def _format_age(seconds: float) -> str:
    """Compact age such as 45m, 3h 5m or 2d 4h."""
    minutes = max(0, int(seconds)) // 60
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


class NodeFetcher:
    """Retrieves VPN proxy nodes from remote URLs and local configuration sources."""

    # Holds the last good payload of each subscription; tests point it at a temporary directory.
    cache_dir = os.path.join(PROJECT_ROOT, SUB_CACHE_DIR)

    def __init__(self, config: dict):
        self.config = config
        self.allowed_ports = self._get_allowed_ports()
        self.supported_protos = ("vless://", "trojan://")
        if config.get("routing", {}).get("enabled", False):
            self.supported_protos += ("ss://",)

    def _get_allowed_ports(self) -> Set[int]:
        ports = {80, 443, 2053, 2083, 2087, 2096, 8443, 2802, 2302, 2502, 25565, 50001}
        ports.update(range(6112, 6120))
        ports.update(range(6695, 6711))
        ports.update(range(27015, 27031))
        ports.update(range(27036, 27038))
        return ports

    async def fetch_all(self) -> Tuple[List[str], Dict[str, str]]:
        """Downloads all configured subscriptions concurrently, merges local AWG/WARP nodes, and deduplicates."""
        raw_subs = self.config.get("subscriptions", [])
        if isinstance(raw_subs, list):
            subs = [s.strip() for s in raw_subs if isinstance(s, str) and s.strip()]
            subs = list(dict.fromkeys(subs))
        else:
            subs = []

        all_nodes = []
        node_to_url: Dict[str, str] = {}

        if subs:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "v2rayN/6.31"}) as session:
                tasks = [self._process_url(session, url) for url in subs]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for url, nodes in zip(subs, results):
                    if isinstance(nodes, list):
                        for n in nodes:
                            if n not in node_to_url:
                                node_to_url[n] = url
                        all_nodes.extend(nodes)
        else:
            log.info("[-] No remote subscriptions configured.")

        # Deduplicate and filter blocked SNIs
        unique_nodes = []
        seen_cores = set()

        for node in all_nodes:
            host, port = extract_host_port(node)
            sni_match = re.search(r"[?&]sni=([^&#]+)", node)
            sni = sni_match.group(1).lower() if sni_match else ""

            is_blocked_sni = "fuck.rkn" in sni
            if port and port not in self.allowed_ports and is_blocked_sni:
                continue

            core = node.split("#")[0]
            if core not in seen_cores:
                seen_cores.add(core)
                unique_nodes.append(node)

        # Include AmneziaWG .conf files from project directory for testing
        use_awg = self.config.get("use_amnezia_wg", True)
        conf_files = []
        if use_awg:
            awg_conf_setting = self.config.get("amnezia_wg_conf", "US.conf")
            if os.path.exists(os.path.join(PROJECT_ROOT, awg_conf_setting)) or os.path.exists(awg_conf_setting):
                conf_files.append(awg_conf_setting)
            for f in os.listdir(PROJECT_ROOT):
                if f.endswith(".conf") and f not in conf_files:
                    conf_files.append(f)

        for cf in conf_files:
            cpath = os.path.join(PROJECT_ROOT, cf) if not os.path.isabs(cf) else cf
            if not os.path.exists(cpath) and os.path.exists(cf):
                cpath = cf
            if os.path.exists(cpath):
                parsed = parse_amnezia_conf(cpath)
                if parsed:
                    proxy_name = os.path.splitext(os.path.basename(cf))[0]
                    awg_node = f"awg_conf:{cf}#AWG_{proxy_name}"
                    if awg_node not in unique_nodes:
                        unique_nodes.append(awg_node)
                        log.info(f"[*] Included AmneziaWG config for testing: {cf}")

        # Cloudflare WARP endpoints
        if self.config.get("use_warp_scanner", False):
            if WarpScanner.has_identity(self.config):
                warp_nodes = WarpScanner.generate_endpoints(5)
                unique_nodes.extend(warp_nodes)
                log.info(f"[*] Generated {len(warp_nodes)} WARP endpoints for testing.")
            else:
                log.warning("[!] WARP scanner is on but warp_private_key is not set. Skipping WARP endpoints.")

        if not unique_nodes:
            log.info("[-] No candidate nodes found from configured subscriptions or local files.")

        return unique_nodes, node_to_url

    async def _process_url(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Downloads one subscription, falling back to its last good payload when that fails or has no nodes."""
        sub_content = await self._download(session, url)
        if sub_content is not None:
            nodes = self._parse_subscription(sub_content)
            if nodes:
                self._save_cache(url, sub_content)
                log.info(f"[*] Found {len(nodes)} valid nodes from {url}")
                return nodes
            log.warning(f"[!] Subscription {url} returned no usable nodes.")
        return self._load_cached_nodes(url)

    async def _download(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Returns the subscription payload as text, or None when it cannot be downloaded."""
        try:
            req_timeout = aiohttp.ClientTimeout(total=25.0)
            async with session.get(url, timeout=req_timeout) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")
                data = await response.read()
                return data.decode("utf-8", errors="ignore")
        except Exception as e:
            ErrorTracker.record_error("Fetch Sub", e)
            log.error(f"[-] Failed to fetch subscription {url}: {str(e).strip() or type(e).__name__}")
            return None

    def _cache_path(self, url: str) -> str:
        """Cache file of one subscription, named by a hash so the link's token stays out of the name."""
        return os.path.join(self.cache_dir, hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + ".json")

    def _save_cache(self, url: str, sub_content: str) -> None:
        """Keeps a good payload for later fallback. A failed write is reported and never fails the fetch."""
        entry = {"url": url, "fetched_at": int(time.time()), "content": sub_content}
        try:
            path = self._cache_path(url)
            os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)
            # mkstemp creates the file readable by this user only; the payload holds proxy credentials.
            # Writing a temporary file and renaming it means a crash never leaves a truncated cache.
            fd, temporary = tempfile.mkstemp(prefix=".sub-", suffix=".tmp", dir=self.cache_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as cache_file:
                    json.dump(entry, cache_file)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except Exception as e:
            log.warning(f"[!] Could not cache subscription {url}: {e}")

    def _load_cached_nodes(self, url: str) -> List[str]:
        """Nodes of the last good payload of a subscription, or [] when there is none."""
        try:
            with open(self._cache_path(url), encoding="utf-8") as cache_file:
                entry = json.load(cache_file)
            if entry.get("url") != url or not isinstance(entry.get("content"), str):
                raise ValueError("it is not a saved copy of this subscription")
            saved_at = float(entry["fetched_at"])
            saved = time.strftime("%Y-%m-%d %H:%M", time.localtime(saved_at))
            age = _format_age(time.time() - saved_at)
        except FileNotFoundError:
            log.info(f"[-] No cached copy of {url} to fall back to.")
            return []
        except Exception as e:
            log.warning(f"[!] Ignoring unreadable cache of {url}: {e}")
            return []

        nodes = self._parse_subscription(entry["content"])
        if not nodes:
            log.warning(f"[!] The cached copy of {url} has no usable nodes.")
            return []
        log.warning(f"[!] Using {len(nodes)} cached nodes for {url}, saved {saved} ({age} ago).")
        return nodes

    def _parse_subscription(self, sub_content: str) -> List[str]:
        """Decodes base64 if needed, keeps the supported nodes, and applies multiplexing parameter injection."""
        if not any(proto in sub_content for proto in self.supported_protos):
            try:
                cleaned_b64 = re.sub(r"\s+", "", sub_content)
                cleaned_b64 = cleaned_b64.replace("-", "+").replace("_", "/")
                cleaned_b64 += "=" * (-len(cleaned_b64) % 4)
                decoded = base64.b64decode(cleaned_b64).decode("utf-8", errors="ignore")
                if any(proto in decoded for proto in self.supported_protos):
                    sub_content = decoded
            except Exception:
                pass

        nodes = [
            line.strip()
            for line in sub_content.splitlines()
            if line.strip() and any(line.strip().startswith(p) for p in self.supported_protos)
        ]

        valid_nodes = []
        for n in nodes:
            pbk_match = re.search(r"[?&]pbk=([^&#]+)", n)
            if pbk_match:
                pbk = pbk_match.group(1).replace("=", "")
                if len(pbk) % 4 == 1:
                    continue

            if self.config.get("use_mux", True) and "xtls-rprx-vision" not in n:
                if "?" in n:
                    if "smux=" not in n:
                        n = n.replace("?", "?smux=1&", 1)
                else:
                    if "#" in n:
                        n = n.replace("#", "?smux=1#", 1)
                    else:
                        n = n + "?smux=1"
            valid_nodes.append(n)

        return valid_nodes
