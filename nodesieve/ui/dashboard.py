"""VPN dashboard coordinating fresh on-demand testing, router-side verification, and automated router deployment."""

import asyncio
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple
import aiohttp

from nodesieve.config import ConfigManager
from nodesieve.constants import (
    IS_TERMUX,
    PROJECT_ROOT,
    ROUTER_SCRIPT_FILE,
)
from nodesieve.core.fetcher import NodeFetcher
from nodesieve.core.limits import ResourceLimits
from nodesieve.core.mihomo import MihomoManager
from nodesieve.core.tester import NodeTester
from nodesieve.logging import ErrorTracker, log, update_progress
from nodesieve.router.client import RouterClient
from nodesieve.router.pusher import push_to_router
from nodesieve.router.script_generator import generate_router_script
from nodesieve.routing import normalize_routing, select_main_pool


class VPNDashboard:
    """High-level application coordinator managing fresh on-demand evaluation and deployment."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config if config is not None else ConfigManager.load()

    async def filter_tcp(self, nodes: List[str], workers: int) -> List[str]:
        """Phase 0: Concurrently ping TCP ports of raw subscription nodes."""
        log.info(f"[*] Phase 0: TCP Ping filter on {len(nodes)} nodes using {workers} concurrent async connections...")
        queue = asyncio.Queue()
        for n in nodes:
            queue.put_nowait(n)

        alive_nodes = []
        completed = 0
        start_time = time.time()
        tester = NodeTester(self.config, len(nodes))

        async def tcp_worker():
            nonlocal completed
            while True:
                try:
                    node = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    res = await tester.async_check_tcp_node(node, 1.5)
                    if res:
                        alive_nodes.append(res)
                except Exception as e:
                    ErrorTracker.record_error("TCP Worker", e)
                finally:
                    completed += 1
                    if completed % 50 == 0 or completed == len(nodes):
                        update_progress(completed, len(nodes), start_time)

        num_workers = min(workers, len(nodes))
        tasks = [asyncio.create_task(tcp_worker()) for _ in range(num_workers)]
        await asyncio.gather(*tasks)
        print()
        return alive_nodes

    async def _get_real_ip(self) -> Optional[str]:
        """Discovers the direct WAN IP of the host machine to prevent false positives during node testing."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://1.1.1.1/cdn-cgi/trace", timeout=5) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        ip_match = re.search(r"(?:^|\n)ip=([^\r\n]+)", text)
                        if ip_match:
                            return ip_match.group(1).strip()
        except Exception:
            pass
        return None

    async def fetch_and_verify_candidates_async(self) -> Tuple[List[Any], Optional[NodeTester]]:
        """Executes fresh node fetching, Phase 0 TCP filtering, Phase 1 local IP checks, and Stage 2 router verification."""
        ErrorTracker.reset()

        # Scale file descriptors BEFORE any connections are made
        max_safe_workers, free_mem_mb = ResourceLimits.get_max_safe_workers(self.config)

        configured_workers = self.config.get("workers", "auto")
        if configured_workers == "auto":
            self.config["workers"] = max_safe_workers
        else:
            try:
                val = int(configured_workers)
                if val > max_safe_workers:
                    log.warning(
                        f"[*] Configured HTTP workers ({val}) exceeds safe limit ({max_safe_workers}). Capping to {max_safe_workers}."
                    )
                    self.config["workers"] = max_safe_workers
                else:
                    self.config["workers"] = val
            except (ValueError, TypeError):
                self.config["workers"] = max_safe_workers

        real_ip = await self._get_real_ip()

        fetcher = NodeFetcher(self.config)
        all_nodes, source_map = await fetcher.fetch_all()
        total_nodes = len(all_nodes)

        if total_nodes == 0:
            log.warning("[-] No candidate nodes found from configured subscriptions.")
            return [], None

        log.info(f"[*] Total unique fresh nodes to process: {total_nodes}")

        tcp_workers = self.config.get("tcp_workers", 128)
        tcp_survivors = await self.filter_tcp(all_nodes, tcp_workers)
        tcp_survivors_count = len(tcp_survivors)

        if tcp_survivors_count == 0:
            log.info("[-] No nodes survived the TCP ping filter.")
            return [], None

        log.info(f"[*] Survived TCP ping: {tcp_survivors_count}")
        log.info(f"[*] System has {free_mem_mb:.0f}MB free memory. HTTP workers set to {self.config['workers']}.")
        log.info(f"[*] Starting concurrent IP checks with {self.config['workers']} workers...\n")

        MihomoManager.setup()

        supported_nodes = []
        completed = 0
        start_time = time.time()
        tester = NodeTester(self.config, tcp_survivors_count, real_ip)

        queue = asyncio.Queue()
        for i, node in enumerate(tcp_survivors):
            queue.put_nowait((i + 1, node))

        async def http_worker():
            nonlocal completed
            while True:
                try:
                    idx, node = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    res = await tester.test_node_full(idx, node)
                    if res:
                        supported_nodes.append(res)
                except Exception as e:
                    ErrorTracker.record_error("HTTP Worker", e)
                finally:
                    completed += 1
                    update_progress(completed, tcp_survivors_count, start_time)

        num_workers = min(self.config["workers"], tcp_survivors_count)
        tasks = [asyncio.create_task(http_worker()) for _ in range(num_workers)]
        await asyncio.gather(*tasks)
        print()

        log.info("\n[*] Phase 1 testing complete.")
        ErrorTracker.print_summary()

        if not supported_nodes:
            log.info("[-] No nodes survived Phase 1 local IP checks.")
            return [], tester

        supported_nodes.sort(key=lambda x: x[1])
        log.info(f"\n[*] Phase 1 complete. Found {len(supported_nodes)} working nodes.")
        if tester.mux_offered:
            log.info(
                f"[*] Multiplexing: {tester.mux_supported} of {tester.mux_offered} eligible working nodes support it"
                + ("; the rest are used without it." if tester.mux_supported < tester.mux_offered else ".")
            )

        # Steer runs its own core; the legacy verifier changes Mihomo's
        # provider and cannot verify this target. Keep these results explicitly local.
        if self.config.get("routing", {}).get("enabled", False):
            log.info("[*] Steer: IP checks measured on this computer; router-side validation is not available.")
        elif self.config.get("enable_router_validation", True):
            try:
                from nodesieve.core.router_validator import RouterValidator
                validator = RouterValidator(config=self.config)
                verified_nodes = await validator.verify_nodes_on_router(supported_nodes)
                if verified_nodes:
                    supported_nodes = verified_nodes
                else:
                    log.warning("[-] No candidate nodes passed Stage 2 router validation.")
                    return [], tester
            except Exception as e:
                log.error(f"[-] Stage 2 router validation encountered an error: {e}")
                log.warning("[!] Preserving Stage 1 candidates in fallback mode.")
        else:
            log.info("[*] Router validation disabled in configuration. Skipping Stage 2.")

        return supported_nodes, tester

    async def run_speedtest_nodes_async(
        self,
        nodes: List[Any],
        tester: Optional[NodeTester] = None,
    ) -> List[Tuple[str, float, float]]:
        """Runs Phase 2 speedtests on in-memory candidate nodes without writing to disk stockpile."""
        if not nodes:
            return []

        clean_node_strs: List[str] = []
        for item in nodes:
            if isinstance(item, (tuple, list)) and len(item) > 0:
                clean_node_strs.append(str(item[0]))
            elif isinstance(item, str):
                clean_node_strs.append(item)

        cfg_workers = self.config.get("workers", 8)
        if not isinstance(cfg_workers, int):
            cfg_workers = 8
        speed_workers = min(8, max(4, cfg_workers), len(clean_node_strs))

        log.info(f"[*] Speedtesting {len(clean_node_strs)} surviving verified nodes with {speed_workers} workers...")

        MihomoManager.setup()
        speedtest_timeout = self.config.get("speedtest_timeout", 30)
        speed_tested_nodes: List[Tuple[str, float, float]] = []
        completed = 0
        start_time = time.time()
        active_tester = tester or NodeTester(self.config, len(clean_node_strs))

        queue = asyncio.Queue()
        for i, n in enumerate(clean_node_strs):
            queue.put_nowait((i + 1, n))

        async def speed_worker():
            nonlocal completed
            while True:
                try:
                    idx, node = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    res = await active_tester.speedtest_node(idx, node, speedtest_timeout)
                    if res:
                        speed_tested_nodes.append(res)
                except Exception as e:
                    ErrorTracker.record_error("Speed Worker", e)
                finally:
                    completed += 1
                    update_progress(completed, len(clean_node_strs), start_time)

        tasks = [asyncio.create_task(speed_worker()) for _ in range(speed_workers)]
        await asyncio.gather(*tasks)
        print()

        log.info("\n[*] Speedtesting complete.")
        ErrorTracker.print_summary()

        if not speed_tested_nodes:
            log.info("[-] All nodes failed speedtest transfer check.")
            return []

        allowed_countries = self.config.get("allowed_countries", [])
        if allowed_countries:
            speed_tested_nodes.sort(key=lambda x: (x[2], x[1]), reverse=True)
            log.info("[*] Sorted nodes by geolocation score, then speed...")
        else:
            speed_tested_nodes.sort(key=lambda x: x[1], reverse=True)
            log.info("[*] Sorted nodes by speed...")

        return speed_tested_nodes

    async def run_pipeline_async(
        self,
        check_only: bool = False,
        deploy_only: bool = False,
        dry_run: bool = False,
    ) -> bool:
        """Executes the streamlined single-command pipeline: fetch, verify, speedtest, and deploy."""
        if self.config.get("routing", {}).get("enabled", False):
            return await self.run_routing_pipeline_async(check_only, deploy_only, dry_run)
        script_path = os.path.join(PROJECT_ROOT, ROUTER_SCRIPT_FILE)

        # 1. Deploy-only mode
        if deploy_only:
            log.info("[*] Deploy-only phase requested.")
            if not os.path.exists(script_path):
                log.error(f"[-] Cannot deploy: {ROUTER_SCRIPT_FILE} not found. Run check first.")
                return False
            if dry_run:
                log.info("[*] [DRY RUN] Existing configuration syntax checked. Skipping remote deployment.")
                return True
            if IS_TERMUX:
                log.info("[*] Router deployment is not supported on Termux.")
                return False
            log.info("[*] Deploying existing configuration to router...")
            return self.push_to_router()

        # 2. Fresh On-Demand Evaluation & Router-Side Verification
        candidates, tester = await self.fetch_and_verify_candidates_async()
        if not candidates:
            log.warning("[-] Pipeline aborted: No surviving verified nodes.")
            return False

        # 3. Phase 2 Speedtesting & Ranking
        speed_tested = await self.run_speedtest_nodes_async(candidates, tester)

        final_nodes: List[str] = []
        if speed_tested:
            for n, speed_bps, loc_score in speed_tested[:30]:
                if speed_bps > 0:
                    final_nodes.append(n)
            if not final_nodes:
                final_nodes = [n for n, _, _ in speed_tested[:30]]
        else:
            for cand in candidates[:30]:
                node_str = cand[0] if isinstance(cand, (tuple, list)) and len(cand) > 0 else str(cand)
                final_nodes.append(node_str)

        # 4. Generate router deployment script & configurations
        generate_router_script(final_nodes, self.config)
        log.info(f"[*] Generated OpenWrt deployment script '{ROUTER_SCRIPT_FILE}' with {len(final_nodes)} top verified nodes.")

        # 5. Check-only or dry-run completion
        if check_only:
            log.info(f"[+] Check-only complete: {len(final_nodes)} top verified nodes formatted for deployment.")
            return True

        if dry_run:
            log.info(f"[+] [DRY RUN] Staged and verified {len(final_nodes)} nodes. Skipping remote router deployment.")
            return True

        if IS_TERMUX:
            log.info(f"[+] Verified {len(final_nodes)} nodes. Remote deployment skipped on Termux.")
            return True

        # 6. Automated Deployment & Rollback Safety
        log.info("[*] Automatically deploying verified configuration to router via SSH...")
        deploy_ok = self.push_to_router()
        if deploy_ok:
            log.info("[+] Deployment to router completed successfully.")
        else:
            log.error("[-] Deployment to router failed. Router was automatically rolled back to working state.")
        return deploy_ok

    async def run_routing_pipeline_async(self, check_only=False, deploy_only=False, dry_run=False) -> bool:
        """Export the location-ranked main server list for Steer without touching the Mihomo verifier."""
        from nodesieve.router.steer import SCRIPT_NAME, SERVERS_NAME, output_directory, write_steer_artifacts

        self.config["routing"] = normalize_routing(self.config.get("routing"))
        if deploy_only:
            return self.deploy_steer(dry_run)

        # An interrupted/failed new scan must not leave an older script deployable.
        directory = output_directory(self.config)
        try:
            for filename in (SCRIPT_NAME, SERVERS_NAME):
                (directory / filename).unlink(missing_ok=True)
        except OSError as exc:
            log.error(f"[-] Cannot invalidate previous Steer artifacts: {exc}")
            return False

        candidates, tester = await self.fetch_and_verify_candidates_async()
        metadata = tester.node_metadata if tester else {}
        # Include nodes that failed the location policy in the report as exclusions.
        evaluated = list(candidates) + [
            node for node, meta in metadata.items() if meta.get("dropped") and "location" in meta
        ]
        pool = select_main_pool(evaluated, metadata, self.config["routing"])
        try:
            artifacts = write_steer_artifacts(pool, self.config)
        except (OSError, ValueError) as exc:
            log.error(f"[-] Cannot generate the Steer server list: {exc}")
            return False
        log.info(f"[*] Main pool: {len(pool['eligible'])} qualifying proxies.")
        log.info(f"[*] Routing report: {artifacts['report_path']}")
        if not artifacts["ready"]:
            log.error("[-] Steer export unresolved: no proxy qualifies for the main pool. See the report; change preferences or check new proxies.")
            return False
        log.info(f"[+] Steer server list generated: {artifacts['servers_path']}")
        if check_only or dry_run or IS_TERMUX:
            return True
        return self.deploy_steer()

    def deploy_steer(self, dry_run=False) -> bool:
        """Deploy a fresh reviewed artifact through Zapret Manager's own Steer backend."""
        from nodesieve.router.steer import REPORT_NAME, SCRIPT_NAME, output_directory, routing_fingerprint

        directory = output_directory(self.config)
        try:
            report = json.loads((directory / REPORT_NAME).read_text(encoding="utf-8"))
            script = (directory / SCRIPT_NAME).read_text(encoding="utf-8")
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(report["created_at"])).total_seconds()
            if not report.get("ready") or not 0 <= age <= 86400:
                raise ValueError("Routing results are unresolved or older than 24 hours; run check again")
            if report.get("config_fingerprint") != routing_fingerprint(self.config):
                raise ValueError("Routing preferences or router changed; run check again")
            if report.get("script_sha256") != hashlib.sha256(script.encode("utf-8")).hexdigest():
                raise ValueError("Deployment script differs from the checked artifact; run check again")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.error(f"[-] Cannot deploy to Steer: {exc}")
            return False
        if dry_run:
            log.info("[+] Steer artifact is fresh and matches current preferences. Dry run: no router changes.")
            return True
        client = RouterClient(
            host=self.config.get("router_host", "192.168.1.1"),
            ssh_port=self.config.get("router_ssh_port", 22),
            ssh_user=self.config.get("router_ssh_user", "root"),
            ssh_pass=self.config.get("router_ssh_pass", ""),
            ssh_key_path=self.config.get("router_ssh_key_path"),
        )
        # SSH channel stdin avoids leaving a second copy of proxy credentials in /tmp.
        # The panel may install core plugins first, and a failed apply is followed by a restore.
        code, out, err = client.exec_command("/bin/sh -s", timeout=900, stdin_data=script)
        lines = (err + "\n" + out).splitlines()
        for line in lines:
            if line.startswith("PSC_NOTE: "):
                log.warning("[!] " + line.removeprefix("PSC_NOTE: ")[:300])
        # Exit status alone is not proof: a script that never ran to its end also exits 0.
        confirmed = [line.removeprefix("PSC_OK: ")[:300] for line in lines if line.startswith("PSC_OK: ")]
        if code != 0 or not confirmed:
            for line in lines:
                if line.startswith("PSC_ERROR: "):
                    log.error("[-] " + line.removeprefix("PSC_ERROR: ")[:300])
                elif line.startswith("PSC_LOG: "):
                    log.error("    " + line.removeprefix("PSC_LOG: ")[:300])
            if code == 0:
                log.error("[-] The router did not confirm the change.")
            log.error("[-] Steer deployment failed; check Steer in the Zapret Manager panel.")
            return False
        log.info("[+] " + confirmed[-1])
        return True

    async def run_checks_async(self) -> bool:
        """Runs the complete verification pipeline in check-only mode without deploying to router."""
        return await self.run_pipeline_async(check_only=True)

    async def run_speedtest_async(self, candidate_nodes: Optional[List[Any]] = None) -> bool:
        """Runs speedtests on candidate nodes and regenerates router configuration."""
        nodes_to_test = candidate_nodes
        if not nodes_to_test:
            # Re-fetch fresh candidates on-demand
            candidates, tester = await self.fetch_and_verify_candidates_async()
            nodes_to_test = candidates
        else:
            tester = None

        if not nodes_to_test:
            log.info("[-] No candidates available to speedtest.")
            return False

        speed_tested = await self.run_speedtest_nodes_async(nodes_to_test, tester)
        if not speed_tested:
            log.info("[-] All nodes failed the speedtest.")
            return False

        final_nodes = [n for n, speed_bps, _ in speed_tested[:30] if speed_bps > 0]
        if not final_nodes:
            final_nodes = [n for n, _, _ in speed_tested[:30]]

        generate_router_script(final_nodes, self.config)
        log.info(f"[*] Regenerated {ROUTER_SCRIPT_FILE} with top {len(final_nodes)} nodes.")
        return True

    def push_to_router(self) -> bool:
        """Deploys apply_to_router.sh to the router via SSH using configured parameters."""
        client = RouterClient(
            host=self.config.get("router_host", "192.168.1.1"),
            api_port=self.config.get("router_api_port", 9090),
            proxy_port=self.config.get("router_proxy_port", 7890),
            ssh_port=self.config.get("router_ssh_port", 22),
            ssh_user=self.config.get("router_ssh_user", "root"),
            ssh_pass=self.config.get("router_ssh_pass", ""),
        )
        return push_to_router(router_client=client, config=self.config)
