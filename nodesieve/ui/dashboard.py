"""Coordinates a scan: fetch the subscriptions, check and rank the nodes, publish them to the feed."""

import asyncio
import re
import time
from typing import Any, List, Optional, Tuple
import aiohttp

from nodesieve.config import ConfigManager
from nodesieve.core.fetcher import NodeFetcher
from nodesieve.core.limits import ResourceLimits
from nodesieve.core.mihomo import MihomoManager, NodeEndpoint, run_in_batches
from nodesieve.core.tester import NodeTester
from nodesieve.feed import feed_status, run_feed_command, write_feed
from nodesieve.logging import ErrorTracker, log, update_progress
from nodesieve.routing import normalize_routing, select_main_pool


class VPNDashboard:
    """Runs a scan of the configured subscriptions and publishes the result to the feed."""

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
        """Fetches the subscriptions, then runs Phase 0 (TCP reachability) and Phase 1 (exit IP and location checks)."""
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
        num_workers = min(self.config["workers"], tcp_survivors_count)
        per_instance, instances = ResourceLimits.mihomo_instances(num_workers)
        log.info(f"[*] Starting concurrent IP checks with {num_workers} workers, through up to {instances} "
                 f"Mihomo instances of {per_instance} nodes each...\n")

        MihomoManager.setup()

        supported_nodes = []
        completed = 0
        start_time = time.time()
        tester = NodeTester(self.config, tcp_survivors_count, real_ip)

        def record(idx: int, node: str, res: Any) -> None:
            nonlocal completed
            if res:
                supported_nodes.append(res)
            completed += 1
            update_progress(completed, tcp_survivors_count, start_time)

        await run_in_batches(
            list(enumerate(tcp_survivors, 1)), tester.check_links, tester.test_node_full, record,
            config=self.config, workers=num_workers, total_nodes=tcp_survivors_count,
            temp_prefix="mihomo_", error_context="HTTP Worker",
        )
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

        def record(idx: int, node: str, res: Any) -> None:
            nonlocal completed
            if res:
                speed_tested_nodes.append(res)
            completed += 1
            update_progress(completed, len(clean_node_strs), start_time)

        async def speedtest(idx: int, node: str, endpoint: Optional[NodeEndpoint]) -> Any:
            return await active_tester.speedtest_node(idx, node, speedtest_timeout, endpoint)

        await run_in_batches(
            list(enumerate(clean_node_strs, 1)), active_tester.speedtest_links, speedtest, record,
            config=self.config, workers=speed_workers, total_nodes=active_tester.total_nodes,
            temp_prefix="speed_mihomo_", error_context="Speed Worker",
        )
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

    async def run_pipeline_async(self, dry_run: bool = False) -> bool:
        """Scan: fetch, check and rank the nodes, then publish them to the subscription feed.

        A Steer scan ranks by location (run_routing_pipeline_async); any other by exit
        country and speed, keeping the 30 fastest. With dry_run, feed_command doesn't run.
        """
        if self.config.get("routing", {}).get("enabled", False):
            return await self.run_routing_pipeline_async(dry_run)

        candidates, tester = await self.fetch_and_verify_candidates_async()
        if not candidates:
            log.warning("[-] Pipeline aborted: No surviving verified nodes.")
            self.report_kept_feed()
            return False

        speed_tested = await self.run_speedtest_nodes_async(candidates, tester)
        final_nodes: List[str] = []
        if speed_tested:
            final_nodes = [n for n, speed_bps, _ in speed_tested[:30] if speed_bps > 0]
            if not final_nodes:
                final_nodes = [n for n, _, _ in speed_tested[:30]]
        else:
            for cand in candidates[:30]:
                final_nodes.append(cand[0] if isinstance(cand, (tuple, list)) and len(cand) > 0 else str(cand))
        log.info(f"[+] Scan complete: {len(final_nodes)} top verified nodes.")
        return self.publish_feed(final_nodes, run_command=not dry_run)

    async def run_routing_pipeline_async(self, dry_run: bool = False) -> bool:
        """Rank the Steer main pool by location, write its report, and publish the pool to the feed."""
        from nodesieve.router.steer import write_routing_report

        self.config["routing"] = normalize_routing(self.config.get("routing"))
        candidates, tester = await self.fetch_and_verify_candidates_async()
        metadata = tester.node_metadata if tester else {}
        # Include nodes that failed the location policy in the report as exclusions.
        evaluated = list(candidates) + [
            node for node, meta in metadata.items() if meta.get("dropped") and "location" in meta
        ]
        pool = select_main_pool(evaluated, metadata, self.config["routing"])
        try:
            report = write_routing_report(pool, self.config)
        except (OSError, ValueError) as exc:
            log.error(f"[-] Cannot write the routing report: {exc}")
            return False
        log.info(f"[*] Main pool: {len(pool['eligible'])} qualifying proxies.")
        log.info(f"[*] Routing report: {report['report_path']}")
        if not report["ready"]:
            log.error("[-] No proxy qualifies for the main pool. See the report; change preferences or check new proxies.")
            self.report_kept_feed()
            return False
        return self.publish_feed(report["servers"], run_command=not dry_run)

    def publish_feed(self, nodes: List[str], run_command: bool = True) -> bool:
        """Write the scan's nodes to the subscription feed; False only when it could not be written.

        A feed that changed is followed by the feed_command setting, unless run_command is
        False (a dry run). Its failure is reported but leaves the scan's result alone: the
        feed is in place, and apps fetch it on their own schedule as well.
        """
        try:
            result = write_feed(nodes, self.config)
        except (OSError, ValueError, TypeError) as exc:
            log.error(f"[-] Cannot write the subscription feed: {exc}")
            return False
        if result["left_out"]:
            log.info(f"[*] Left out of the subscription feed: {result['left_out']} nodes without a share link.")
        if result["written"]:
            log.info(f"[+] Subscription feed updated with {result['count']} nodes: {result['directory']}")
            if run_command:
                run_feed_command(self.config)
        else:
            self.report_kept_feed()
        return True

    def report_kept_feed(self) -> None:
        """Say what subscribed apps get when a scan leaves the feed as it was."""
        status = feed_status(self.config)
        if status:
            log.warning(f"[!] The subscription feed is unchanged: it keeps the {status['count']} nodes "
                        f"of the scan from {status['written_at']:%Y-%m-%d %H:%M}.")
