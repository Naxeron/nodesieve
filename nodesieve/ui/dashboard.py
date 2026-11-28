"""Coordinates a scan: fetch the subscriptions, check and rank the nodes, publish them to the feed."""

import asyncio
import math
import re
import time
from typing import Any, List, Optional, Tuple
import aiohttp

from nodesieve.config import ConfigManager
from nodesieve.constants import DEFAULT_CONFIG
from nodesieve.core.fetcher import NodeFetcher
from nodesieve.core.limits import NODES_PER_INSTANCE, ResourceLimits
from nodesieve.core.batch import NodeEndpoint, run_in_batches, setup_core
from nodesieve.core.tester import NodeTester
from nodesieve.feed import feed_server_keys, feed_status, run_feed_command, write_feed
from nodesieve.logging import ErrorTracker, log, update_progress
from nodesieve.routing import normalize_routing, select_main_pool


class VPNDashboard:
    """Runs a scan of the configured subscriptions and publishes the result to the feed."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config if config is not None else ConfigManager.load()

    async def filter_tcp(self, nodes: List[str], workers: int) -> List[str]:
        """Filter TCP-based candidates and pass QUIC nodes through to the exit IP check."""
        log.info(f"[*] Phase 0: Filtering {len(nodes)} candidates with {workers} TCP workers (Hysteria 2 skips TCP)...")
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
            log.info("[-] No candidates for the exit IP check.")
            return [], None

        log.info(f"[*] Candidates for the exit IP check: {tcp_survivors_count}")
        log.info(f"[*] System has {free_mem_mb:.0f}MB free memory. HTTP workers set to {self.config['workers']}.")
        num_workers = min(self.config["workers"], tcp_survivors_count)
        per_instance, instances = ResourceLimits.core_instances(num_workers)
        core = setup_core(self.config)
        log.info(f"[*] Starting concurrent IP checks with {num_workers} workers, through up to {instances} "
                 f"{core.display} instances of {per_instance} nodes each...\n")

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
            temp_prefix="core_", error_context="HTTP Worker",
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
        elif (self.config.get("use_mux", True) and core.name != "mihomo"
              and not self.config.get("routing", {}).get("enabled", False)):
            log.info(f"[*] Multiplexing: only a scan through Mihomo can tell which nodes support it, "
                     f"so after this {core.display} scan the Clash profile has none.")

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

        # Measure one node at a time so downloads do not split the host's WAN bandwidth,
        # while still sharing one core instance across up to NODES_PER_INSTANCE nodes.
        speed_workers = 1
        batch_size = min(NODES_PER_INSTANCE, len(clean_node_strs))

        log.info(f"[*] Speedtesting {len(clean_node_strs)} surviving verified nodes sequentially...")

        setup_core(self.config)
        speedtest_timeout = self.config.get("speedtest_timeout", 30)
        speed_tested_nodes: List[Tuple[str, float, float]] = []
        completed = 0
        start_time = time.time()
        active_tester = tester or NodeTester(self.config, len(clean_node_strs))
        active_tester.total_nodes = len(clean_node_strs)

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
            config=self.config, workers=speed_workers, total_nodes=len(clean_node_strs),
            temp_prefix="speed_core_", error_context="Speed Worker",
            nodes_per_instance=batch_size,
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

        A Steer scan ranks by location. A Mihomo-target scan keeps up to 30 ranked
        nodes after applying the speed cutoff. With dry_run, feed_command doesn't run.
        """
        if self.config.get("routing", {}).get("enabled", False):
            return await self.run_routing_pipeline_async(dry_run)

        candidates, tester = await self.fetch_and_verify_candidates_async()
        if not candidates:
            log.warning("[-] Pipeline aborted: No surviving verified nodes.")
            self.report_kept_feed()
            return False

        speed_tested = await self.run_speedtest_nodes_async(candidates, tester)
        measured = [(node, speed) for node, speed, _ in speed_tested if math.isfinite(speed) and speed > 0]
        if measured:
            fastest = max(speed for _, speed in measured)
            percent = self.config.get("min_speed_percent", DEFAULT_CONFIG["min_speed_percent"])
            min_fraction = percent / 100
            eligible = [node for node, speed in measured if speed / fastest >= min_fraction]
            log.info(f"[*] Speed cutoff {percent:g}% of the fastest node ({fastest / 1024**2:.2f} MB/s). "
                     f"Kept {len(eligible)} of {len(measured)} measured nodes.")
            final_nodes = eligible[:30]
        else:
            log.warning("[!] No usable speed measurements. Selecting IP-verified nodes in latency order.")
            final_nodes = [
                cand[0] if isinstance(cand, (tuple, list)) and cand else str(cand)
                for cand in candidates[:30]
            ]
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
        before_keys = feed_server_keys(self.config)
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
                after_keys = feed_server_keys(self.config)
                if before_keys is not None and after_keys is not None and before_keys == after_keys:
                    log.info("[*] Subscription feed servers and order are unchanged; skipping feed_command.")
                else:
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
