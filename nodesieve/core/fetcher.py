"""Fetches remote subscriptions, caches last good payloads, decodes, and deduplicates."""

import asyncio
import base64
import hashlib
import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple
import aiohttp

from nodesieve.constants import PROJECT_ROOT, SUB_CACHE_DIR
from nodesieve.files import write_atomic
from nodesieve.logging import ErrorTracker, log
from nodesieve.parsers.base import is_header_node, node_key
from nodesieve.parsers.hysteria2 import HYSTERIA2_SCHEMES, parse_hysteria2


def _format_age(seconds: float) -> str:
    minutes = max(0, int(seconds)) // 60
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    return f"{days}d {hours}h" if days else f"{hours}h {minutes}m" if hours else f"{minutes}m"


class NodeFetcher:
    """Retrieves VPN proxy nodes from configured subscription URLs with fallback caching."""

    cache_dir = os.path.join(PROJECT_ROOT, SUB_CACHE_DIR)

    def __init__(self, config: dict):
        self.config = config
        self.supported_protos = {"vless", "trojan", *HYSTERIA2_SCHEMES}
        if config.get("routing", {}).get("enabled", False):
            self.supported_protos.add("ss")

    async def fetch_all(self) -> Tuple[List[str], Dict[str, str]]:
        """Download configured subscriptions concurrently and deduplicate their nodes."""
        raw_subs = self.config.get("subscriptions", [])
        subs = list(dict.fromkeys(s.strip() for s in raw_subs if isinstance(s, str) and s.strip())) if isinstance(raw_subs, list) else []

        all_nodes: List[str] = []
        node_to_url: Dict[str, str] = {}
        if subs:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "v2rayN/6.31"}) as session:
                results = await asyncio.gather(*(self._process_url(session, url) for url in subs), return_exceptions=True)
                for url, nodes in zip(subs, results):
                    if isinstance(nodes, list):
                        for n in nodes:
                            if is_header_node(n):
                                continue
                            node_to_url.setdefault(n, url)
                            all_nodes.append(n)
        else:
            log.info("[-] No remote subscriptions configured.")

        unique_nodes, seen = [], set()
        for node in all_nodes:
            core = node_key(node)
            if core not in seen:
                seen.add(core)
                unique_nodes.append(node)

        if not unique_nodes:
            log.info("[-] No candidate nodes found in the configured subscriptions.")
        return unique_nodes, node_to_url

    async def _process_url(self, session: aiohttp.ClientSession, url: str) -> List[str]:
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
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=25.0)) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                return (await resp.read()).decode("utf-8", errors="ignore")
        except Exception as e:
            ErrorTracker.record_error("Fetch Sub", e)
            log.error(f"[-] Failed to fetch subscription {url}: {str(e).strip() or type(e).__name__}")
            return None

    def _cache_path(self, url: str) -> str:
        return os.path.join(self.cache_dir, hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + ".json")

    def _save_cache(self, url: str, sub_content: str) -> None:
        try:
            path = self._cache_path(url)
            try:
                with open(path, encoding="utf-8") as existing:
                    cached = json.load(existing)
                if isinstance(cached, dict) and cached.get("url") == url and cached.get("content") == sub_content:
                    return
            except (OSError, ValueError):
                pass
            os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)
            entry = {"url": url, "fetched_at": int(time.time()), "content": sub_content}
            write_atomic(path, json.dumps(entry), mode=0o600)
        except Exception as e:
            log.warning(f"[!] Could not cache subscription {url}: {e}")

    def _load_cached_nodes(self, url: str) -> List[str]:
        try:
            with open(self._cache_path(url), encoding="utf-8") as f:
                entry = json.load(f)
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
        if "://" not in sub_content:
            try:
                b64 = re.sub(r"\s+", "", sub_content).replace("-", "+").replace("_", "/")
                b64 += "=" * (-len(b64) % 4)
                sub_content = base64.b64decode(b64).decode("utf-8", errors="ignore")
            except Exception:
                pass

        valid = []
        for line in sub_content.splitlines():
            scheme, sep, rest = line.strip().partition("://")
            scheme = scheme.lower()
            if not sep or scheme not in self.supported_protos:
                continue
            n = scheme + sep + rest
            if is_header_node(n):
                continue
            if scheme in HYSTERIA2_SCHEMES:
                if parse_hysteria2(n):
                    valid.append(n)
                continue
            pbk_match = re.search(r"[?&]pbk=([^&#]+)", n)
            if pbk_match and len(pbk_match.group(1).replace("=", "")) % 4 == 1:
                continue
            valid.append(n)
        return valid
