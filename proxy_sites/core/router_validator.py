"""Router-representative staged proxy validation pipeline (Stage 2).

Stages candidate nodes on the OpenWrt router's Mihomo instance and keeps the
ones that answer a connectivity probe through the router's own WAN, which
removes candidates that only work from the scanning host.
"""

import asyncio
import os
from typing import Any, Dict, List, Optional, Tuple

import yaml

from proxy_sites.config import ConfigManager
from proxy_sites.constants import GOOGLE_HEALTHCHECK_URL, PROJECT_ROOT
from proxy_sites.logging import log
from proxy_sites.parsers.awg import parse_amnezia_conf
from proxy_sites.parsers.base import extract_host_port, get_node_name
from proxy_sites.parsers.mihomo import node_url_to_mihomo_dict
from proxy_sites.router.client import RouterClient
from proxy_sites.warp import WarpScanner


class RouterUnreachableError(Exception):
    """Raised when router external controller or SSH is unreachable."""
    pass


class RouterValidator:
    """Stage 2 router-representative proxy validator."""

    def __init__(
        self,
        router_client: Optional[RouterClient] = None,
        config: Optional[Dict[str, Any]] = None,
        fallback_on_unreachable: bool = True,
    ):
        self.config = config if config is not None else ConfigManager.load()
        if router_client is not None:
            self.router_client = router_client
        else:
            self.router_client = RouterClient(
                host=self.config.get("router_host", "192.168.1.1"),
                api_port=self.config.get("router_api_port", 9090),
                proxy_port=self.config.get("router_proxy_port", 7890),
                ssh_port=self.config.get("router_ssh_port", 22),
                ssh_user=self.config.get("router_ssh_user", "root"),
                ssh_pass=self.config.get("router_ssh_pass", ""),
            )

        self.fallback_on_unreachable = fallback_on_unreachable
        self.use_mux = self.config.get("use_mux", True)
        self.group_name = "Gemini_Auto"
        self.provider_name = "Gemini_Nodes"
        self.remote_sub_path = "/etc/mihomo/proxy-providers/sub.yaml"

        # Diagnostic tracking
        self.wan_unreachable_dropped: List[str] = []
        self.last_verified_nodes: List[Any] = []

        # Concurrency safety: Single-attempt cache pattern
        self._lock = asyncio.Lock()
        self._alive_attempted = False
        self._is_alive = False

    def reset_alive_cache(self) -> None:
        """Resets the pre-flight reachability cache flag."""
        self._alive_attempted = False
        self._is_alive = False

    def _normalize_candidate(self, item: Any) -> Tuple[str, str, Any]:
        """Extracts (node_url_or_empty, node_name, original_item)."""
        if isinstance(item, str):
            return item, get_node_name(item), item
        elif isinstance(item, (tuple, list)) and len(item) > 0:
            url = str(item[0] or "")
            return url, get_node_name(url), item
        elif isinstance(item, dict):
            raw_url = item.get("node") or item.get("url") or ""
            url = str(raw_url) if raw_url is not None else ""
            raw_name = item.get("name")
            name = str(raw_name) if raw_name else get_node_name(url)
            return url, name, item
        return str(item or ""), "Unknown", item

    def build_candidate_sub_yaml(
        self, candidates: List[Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Builds sub.yaml content and returns (yaml_str, name_to_cand_map)."""
        proxy_dicts: List[Dict[str, Any]] = []
        raw_nodes: List[str] = []
        name_to_cand: Dict[str, Any] = {}

        for cand in candidates:
            url, name, orig = self._normalize_candidate(cand)
            if not url and not (isinstance(cand, dict) and "type" in cand):
                continue
            unique_name = name
            if unique_name in name_to_cand:
                counter = 2
                while f"{name}_{counter}" in name_to_cand:
                    counter += 1
                unique_name = f"{name}_{counter}"

            if isinstance(cand, dict) and "type" in cand:
                p_copy = dict(cand)
                p_copy["name"] = unique_name
                proxy_dicts.append(p_copy)
                name_to_cand[unique_name] = orig
            elif url and url.startswith("warp://"):
                hw, pw = extract_host_port(url)
                if hw and pw:
                    proxy_dicts.append(
                        WarpScanner.generate_warp_proxy_dict(
                            hw, pw, unique_name, config=self.config
                        )
                    )
                    name_to_cand[unique_name] = orig
            elif url and url.startswith("awg_conf:"):
                conf_file = url.split("awg_conf:", 1)[1].split("#", 1)[0]
                conf_path = os.path.join(PROJECT_ROOT, conf_file)
                if not os.path.exists(conf_path) and os.path.exists(conf_file):
                    conf_path = conf_file
                if os.path.exists(conf_path):
                    awg_p = parse_amnezia_conf(conf_path, proxy_name=unique_name)
                    if awg_p:
                        proxy_dicts.append(awg_p)
                        name_to_cand[unique_name] = orig
            else:
                p_dict = (
                    node_url_to_mihomo_dict(url, use_mux=self.use_mux)
                    if url
                    else None
                )
                if p_dict:
                    p_dict["name"] = unique_name
                    proxy_dicts.append(p_dict)
                    name_to_cand[unique_name] = orig
                elif url:
                    raw_nodes.append(url)
                    name_to_cand[unique_name] = orig

        parts: List[str] = []
        if proxy_dicts:
            parts.append(
                yaml.dump(
                    {"proxies": proxy_dicts},
                    allow_unicode=True,
                    sort_keys=False,
                ).strip()
            )
        for raw in raw_nodes:
            parts.append(raw.strip())

        content = "\n".join(parts) + "\n" if parts else ""
        return content, name_to_cand

    async def is_router_alive(self) -> bool:
        """Checks router REST API reachability with single-attempt lock."""
        if not self._alive_attempted:
            async with self._lock:
                if not self._alive_attempted:
                    try:
                        self._is_alive = (
                            await self.router_client.is_api_alive()
                        )
                    except Exception as e:
                        log.warning(
                            f"[-] Router pre-flight check exception: {e}"
                        )
                        self._is_alive = False
                    finally:
                        self._alive_attempted = True
        return self._is_alive

    async def verify_nodes_on_router(
        self, candidate_nodes: List[Any]
    ) -> List[Any]:
        """Main Stage 2 verification entry point."""
        if not candidate_nodes:
            return []

        # 1. Pre-flight reachability
        alive = await self.is_router_alive()
        if not alive:
            if self.fallback_on_unreachable:
                log.warning(
                    f"[!] Router at {self.router_client.api_url} is "
                    "unreachable. Skipping Stage 2 router validation; "
                    "falling back to candidate nodes."
                )
                return candidate_nodes
            raise RouterUnreachableError(
                f"Router API unreachable at {self.router_client.api_url}"
            )

        # 2. Build candidate sub.yaml and upload to router
        sub_yaml, name_to_cand = self.build_candidate_sub_yaml(
            candidate_nodes
        )
        if not sub_yaml.strip():
            log.warning(
                "[-] No valid candidate proxies could be formatted "
                "for router."
            )
            return []

        log.info(
            f"[*] Uploading candidate sub.yaml ({len(candidate_nodes)} nodes) "
            "to router..."
        )
        try:
            stream_ok = self.router_client.stream_file_to_router(
                sub_yaml, self.remote_sub_path, mode="0644"
            )
        except Exception as e:
            log.warning(f"[-] Exception streaming sub.yaml: {e}")
            stream_ok = False

        if not stream_ok:
            if self.fallback_on_unreachable:
                log.warning(
                    "[-] Failed to stream sub.yaml to router via SSH. "
                    "Falling back to candidate nodes."
                )
                return candidate_nodes
            return []

        # 3. Dynamic reload of Gemini_Nodes provider
        log.info(f"[*] Reloading provider '{self.provider_name}' on router...")
        try:
            reloaded = await self.router_client.reload_provider(
                self.provider_name
            )
        except Exception as e:
            log.warning(f"[-] Exception reloading provider: {e}")
            reloaded = False

        if not reloaded:
            log.error(f"[-] Failed to reload provider '{self.provider_name}'.")
            if self.fallback_on_unreachable:
                log.warning(
                    "[!] Preserving Stage 1 candidates in fallback mode."
                )
                return candidate_nodes
            return []

        await asyncio.sleep(0.1)

        # 4. Concurrent batch delay probe on Gemini_Auto
        log.info(
            f"[*] Probing batch delays on group '{self.group_name}' "
            "via router WAN..."
        )
        try:
            delays = await self.router_client.probe_group_delay(
                self.group_name,
                url=GOOGLE_HEALTHCHECK_URL,
                timeout_ms=3000,
            )
        except Exception as e:
            log.warning(f"[-] Exception during probe_group_delay: {e}")
            delays = {}

        surviving_names: List[str] = []
        for name in name_to_cand.keys():
            d = delays.get(name, 0)
            if d and d > 0:
                surviving_names.append(name)
            else:
                self.wan_unreachable_dropped.append(name)

        log.info(
            f"[*] Batch delay probe complete: {len(surviving_names)} / "
            f"{len(candidate_nodes)} nodes alive on router WAN."
        )

        if not surviving_names:
            log.warning(
                "[-] Zero candidate nodes responded to Google 204 via "
                "router WAN."
            )
            return []

        # 5. Keep the survivors, replacing host-measured latency with the router's
        verified_candidates: List[Any] = []
        for node_name in surviving_names:
            orig_item = name_to_cand[node_name]
            delay_ms = delays.get(node_name, 0)
            if isinstance(orig_item, tuple) and len(orig_item) >= 3:
                verified_candidates.append(
                    (orig_item[0], float(delay_ms), *orig_item[2:])
                )
            elif isinstance(orig_item, list) and len(orig_item) >= 3:
                verified_candidates.append(
                    [orig_item[0], float(delay_ms), *orig_item[2:]]
                )
            else:
                verified_candidates.append(orig_item)

        log.info(
            f"[*] Stage 2 Router Verification Complete: "
            f"{len(verified_candidates)} / {len(candidate_nodes)} "
            "nodes verified."
        )
        self.last_verified_nodes = verified_candidates
        return verified_candidates
