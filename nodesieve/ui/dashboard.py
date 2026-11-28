"""Scan coordinator: fetch subscriptions, verify and rank nodes, publish feed."""

import asyncio
import math
import time
from typing import Any, List, Optional, Tuple
import aiohttp

from nodesieve.config import ConfigManager
from nodesieve.constants import DEFAULT_CONFIG
from nodesieve.core.batch import NodeEndpoint, run_in_batches, setup_core
from nodesieve.core.fetcher import NodeFetcher
from nodesieve.core.limits import NODES_PER_INSTANCE, ResourceLimits
from nodesieve.core.tester import NodeTester, TRACE_URL_IPV4, parse_cf_trace
from nodesieve.feed import feed_server_keys, feed_status, run_feed_command, write_feed
from nodesieve.logging import ErrorTracker, log, update_progress
from nodesieve.routing import normalize_routing, select_main_pool, write_routing_report


class VPNDashboard:
    """Runs a scan of configured subscriptions and publishes the result to the feed."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config if config is not None else ConfigManager.load()

    async def filter_tcp(self, nodes: List[str], workers: int) -> List[str]:
        """Phase 0 TCP reachability filter; Hysteria 2 passes through to QUIC."""
        log.info(f"[*] Phase 0: Filtering {len(nodes)} candidates with {workers} TCP workers (Hysteria 2 skips TCP)...")
        sem = asyncio.Semaphore(max(1, min(workers, len(nodes))))
        tester = NodeTester(self.config, len(nodes))
        alive: List[str] = []
        completed, total, start = 0, len(nodes), time.time()

        async def check(node: str) -> None:
            nonlocal completed
            async with sem:
                try:
                    if res := await tester.async_check_tcp_node(node, 1.5):
                        alive.append(res)
                except Exception as e:
                    ErrorTracker.record_error("TCP Worker", e)
                finally:
                    completed += 1
                    if completed % 50 == 0 or completed == total:
                        update_progress(completed, total, start)

        await asyncio.gather(*(check(n) for n in nodes))
        print()
        return alive

    async def _get_real_ip(self) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(TRACE_URL_IPV4, timeout=5) as resp:
                    if resp.status == 200:
                        return parse_cf_trace(await resp.text())[0]
        except Exception:
            pass
        return None

    async def fetch_and_verify_candidates_async(self) -> Tuple[List[Any], Optional[NodeTester]]:
        """Fetch subscriptions and run Phase 0 (TCP) + Phase 1 (exit IP & GeoIP)."""
        ErrorTracker.reset()
        max_safe, free_mem = ResourceLimits.get_max_safe_workers(self.config)
        cfg_w = self.config.get("workers", "auto")
        if cfg_w == "auto":
            self.config["workers"] = max_safe
        else:
            try:
                val = int(cfg_w)
                if val > max_safe:
                    log.warning(f"[*] Configured HTTP workers ({val}) exceeds safe limit ({max_safe}). Capping to {max_safe}.")
                self.config["workers"] = min(val, max_safe)
            except (ValueError, TypeError):
                self.config["workers"] = max_safe

        real_ip = await self._get_real_ip()
        all_nodes, _ = await NodeFetcher(self.config).fetch_all()
        if not all_nodes:
            log.warning("[-] No candidate nodes found from configured subscriptions.")
            return [], None

        log.info(f"[*] Total unique fresh nodes to process: {len(all_nodes)}")
        survivors = await self.filter_tcp(all_nodes, self.config.get("tcp_workers", 128))
        if not survivors:
            log.info("[-] No candidates for the exit IP check.")
            return [], None

        total = len(survivors)
        num_workers = min(self.config["workers"], total)
        per_inst, instances = ResourceLimits.core_instances(num_workers)
        core = setup_core(self.config)
        log.info(f"[*] Candidates for the exit IP check: {total}")
        log.info(f"[*] System has {free_mem:.0f}MB free memory. HTTP workers set to {self.config['workers']}.")
        log.info(f"[*] Starting concurrent IP checks with {num_workers} workers, through up to {instances} "
                 f"{core.display} instances of {per_inst} nodes each...\n")

        supported: List[Any] = []
        completed, start = 0, time.time()
        tester = NodeTester(self.config, total, real_ip)

        def record(idx: int, node: str, res: Any) -> None:
            nonlocal completed
            if res:
                supported.append(res)
            completed += 1
            update_progress(completed, total, start)

        await run_in_batches(
            list(enumerate(survivors, 1)), tester.check_link, tester.test_node_full, record,
            config=self.config, workers=num_workers, total_nodes=total,
            temp_prefix="core_", error_context="HTTP Worker",
        )
        print()
        log.info("\n[*] Phase 1 testing complete.")
        ErrorTracker.print_summary()
        if not supported:
            log.info("[-] No nodes survived Phase 1 local IP checks.")
            return [], tester

        supported.sort(key=lambda x: x[1])
        log.info(f"\n[*] Phase 1 complete. Found {len(supported)} working nodes.")
        return supported, tester

    async def run_speedtest_nodes_async(
        self, nodes: List[Any], tester: Optional[NodeTester] = None,
    ) -> List[Tuple[str, float]]:
        """Phase 2 sequential speedtest sharing one Xray instance per batch."""
        clean = [str(item[0]) if isinstance(item, (tuple, list)) and item else item
                 for item in nodes if isinstance(item, (str, tuple, list)) and item]
        if not clean:
            return []

        total = len(clean)
        log.info(f"[*] Speedtesting {total} surviving verified nodes sequentially...")
        setup_core(self.config)
        timeout = self.config.get("speedtest_timeout", 30)
        results: List[Tuple[str, float]] = []
        completed, start = 0, time.time()
        active = tester or NodeTester(self.config, total)
        active.total_nodes = total

        def record(idx: int, node: str, res: Any) -> None:
            nonlocal completed
            if res:
                results.append(res)
            completed += 1
            update_progress(completed, total, start)

        async def speedtest(idx: int, node: str, ep: Optional[NodeEndpoint]) -> Any:
            return await active.speedtest_node(idx, node, timeout, ep)

        await run_in_batches(
            list(enumerate(clean, 1)), active.speedtest_link, speedtest, record,
            config=self.config, workers=1, total_nodes=total,
            temp_prefix="speed_core_", error_context="Speed Worker",
            nodes_per_instance=min(NODES_PER_INSTANCE, total),
        )
        print()
        log.info("\n[*] Speedtesting complete.")
        ErrorTracker.print_summary()
        if not results:
            log.info("[-] All nodes failed speedtest transfer check.")
            return []

        results.sort(key=lambda x: x[1], reverse=True)
        log.info("[*] Sorted nodes by speed...")
        return results

    async def run_pipeline_async(self, dry_run: bool = False) -> bool:
        """Scan, rank by speed or location consensus, and publish the feed."""
        if self.config.get("routing", {}).get("enabled", False):
            return await self.run_routing_pipeline_async(dry_run)

        candidates, tester = await self.fetch_and_verify_candidates_async()
        if not candidates:
            log.warning("[-] Pipeline aborted: No surviving verified nodes.")
            self.report_kept_feed()
            return False

        speed_tested = await self.run_speedtest_nodes_async(candidates, tester)
        measured = [(node, speed) for node, speed in speed_tested if math.isfinite(speed) and speed > 0]
        if measured:
            fastest = max(speed for _, speed in measured)
            percent = self.config.get("min_speed_percent", DEFAULT_CONFIG["min_speed_percent"])
            eligible = [node for node, speed in measured if speed / fastest >= percent / 100]
            log.info(f"[*] Speed cutoff {percent:g}% of the fastest node ({fastest / 1048576:.2f} MB/s). "
                     f"Kept {len(eligible)} of {len(measured)} measured nodes.")
            final_nodes = eligible[:30]
        else:
            log.warning("[!] No usable speed measurements. Selecting IP-verified nodes in latency order.")
            final_nodes = [c[0] if isinstance(c, (tuple, list)) and c else str(c) for c in candidates[:30]]
        log.info(f"[+] Scan complete: {len(final_nodes)} top verified nodes.")
        return self.publish_feed(final_nodes, run_command=not dry_run)

    async def run_routing_pipeline_async(self, dry_run: bool = False) -> bool:
        """Rank the Steer main pool by GeoIP consensus, write redacted report, and publish."""
        self.config["routing"] = normalize_routing(self.config.get("routing"))
        candidates, tester = await self.fetch_and_verify_candidates_async()
        metadata = tester.node_metadata if tester else {}
        evaluated = list(candidates) + [n for n, m in metadata.items() if m.get("dropped") and "location" in m]
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
        """Write feed files and run feed_command when the server list/order changed."""
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
        if status := feed_status(self.config):
            log.warning(f"[!] The subscription feed is unchanged: it keeps the {status['count']} nodes "
                        f"of the scan from {status['written_at']:%Y-%m-%d %H:%M}.")
