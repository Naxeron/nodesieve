"""Fetches fresh remote subscription nodes, decodes, rewrites multiplexing, and deduplicates."""

import asyncio
import base64
import os
import re
from typing import Dict, List, Set, Tuple
import aiohttp

from proxy_sites.constants import PROJECT_ROOT
from proxy_sites.logging import ErrorTracker, log
from proxy_sites.parsers.awg import parse_amnezia_conf
from proxy_sites.parsers.base import extract_host_port
from proxy_sites.warp import WarpScanner


class NodeFetcher:
    """Retrieves VPN proxy nodes from remote URLs and local configuration sources."""

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
        """Downloads fresh subscription payload, decodes base64 if needed, and applies multiplexing parameter injection."""
        sub_content = None
        try:
            req_timeout = aiohttp.ClientTimeout(total=25.0)
            async with session.get(url, timeout=req_timeout) as response:
                if response.status == 200:
                    data = await response.read()
                    sub_content = data.decode("utf-8", errors="ignore")
                else:
                    raise Exception(f"HTTP {response.status}")
        except Exception as e:
            ErrorTracker.record_error("Fetch Sub", e)
            log.error(f"[-] Failed to fetch subscription {url}: {e}")
            return []

        if not sub_content:
            return []

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

        log.info(f"[*] Found {len(valid_nodes)} valid nodes from {url}")
        return valid_nodes
