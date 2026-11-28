"""Node testing: TCP ping, exit IP/country checks, GeoIP consensus, and speedtests."""

import asyncio
import re
import time
import urllib.parse
from typing import Optional, Set, Tuple
import aiohttp

from nodesieve.constants import GEOBLOCKED_REGIONS
from nodesieve.core.batch import CoreInstanceLost, CoreRunner, NodeEndpoint
from nodesieve.geo import GeolocationService
from nodesieve.location import probe_location
from nodesieve.logging import ErrorTracker, safe_close_writer, safe_print
from nodesieve.parsers.base import (
    extract_host_port,
    extract_node_protocol,
    format_descriptive_node_name,
    get_node_name,
)
from nodesieve.routing import main_policy_failure, normalize_routing

TRACE_URL_IPV4 = "https://1.1.1.1/cdn-cgi/trace"
TRACE_URL_IPV6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
SPEEDTEST_URLS = (
    "https://speed.cloudflare.com/__down?bytes=100000000",
    "http://proof.ovh.net/files/100Mb.dat",
)
SPEEDTEST_MAX_DURATION = 6.0
SPEEDTEST_WARMUP_SECONDS = 0.5
SPEEDTEST_MIN_STEADY_DURATION = 0.25
SPEEDTEST_EARLY_STOP_STEADY_SECONDS = 2.5
SPEEDTEST_EARLY_STOP_STEADY_BYTES = 20 * 1024 * 1024
SPEEDTEST_MIN_BYTES = 65536


def parse_cf_trace(text: str) -> Tuple[Optional[str], Optional[str]]:
    ip_m = re.search(r"(?:^|\n)ip=([^\r\n]+)", text)
    loc_m = re.search(r"(?:^|\n)loc=([^\r\n]+)", text)
    return (ip_m.group(1).strip() if ip_m else None), (loc_m.group(1).strip().upper() if loc_m else None)


class NodeTester:
    """Runs TCP reachability, exit IP/location checks, and speedtests on proxy nodes."""

    BLOCKED_REGIONS: Set[str] = GEOBLOCKED_REGIONS

    def __init__(self, config: dict, total_nodes: int = 0, real_ip: Optional[str] = None):
        self.config = config
        if self.config.get("routing", {}).get("enabled", False):
            self.config["routing"] = normalize_routing(self.config["routing"])
        self.total_nodes = total_nodes
        self.real_ip = real_ip
        self.node_metadata: dict = {}
        self._location_semaphore = asyncio.Semaphore(6)

    @staticmethod
    def _is_header_node(node: str) -> bool:
        name = get_node_name(node)
        return "Авто" in name or "⬇" in name

    @staticmethod
    def _as_checked(node: str) -> str:
        return re.sub(r"encryption=[^&#]+", "encryption=none", node) if node.startswith("vless://") else node

    def check_link(self, node: str) -> Optional[str]:
        """Link to serve for the Phase 1 IP check, or None if filtered out before Xray."""
        node = self._as_checked(node)
        if self._is_header_node(node):
            return None
        host, port = extract_host_port(node)
        return node if host and port else None

    def speedtest_link(self, node: str) -> Optional[str]:
        node = self._as_checked(node)
        host, port = extract_host_port(node)
        return node if host and port else None

    async def async_check_tcp_node(self, node: str, timeout: float = 1.5) -> Optional[str]:
        """Phase 0 TCP reachability filter; valid Hysteria 2 nodes proceed directly to QUIC."""
        if self._is_header_node(node):
            return None
        host, port = extract_host_port(node)
        if not host or not port:
            return None
        if extract_node_protocol(node) == "HYSTERIA2":
            return node
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            await safe_close_writer(writer)
            return node
        except Exception as e:
            ErrorTracker.record_error("TCP Ping", e)
            return None

    async def _fetch_ip(
        self, url: str, proxy: str, session: Optional[aiohttp.ClientSession] = None,
    ) -> Tuple[Optional[str], Optional[str], float]:
        """Query Cloudflare trace via proxy for (exit_ip, country_code, latency_ms)."""
        is_v6 = "2606:4700:4700::1111" in url
        # Never fall back to dual-stack domain for IPv6 (it would return IPv4).
        urls = [url] + (["https://cloudflare.com/cdn-cgi/trace"] if not is_v6 and "1.1.1.1" in url else [])
        close_session = session is None
        if session is None:
            session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=3.5 if is_v6 else 4.5, connect=2.5),
            )
        try:
            req_timeout = aiohttp.ClientTimeout(total=3.0 if is_v6 else 4.0, connect=2.5)
            for u in urls:
                t0 = time.perf_counter()
                try:
                    async with session.get(u, proxy=proxy, timeout=req_timeout) as resp:
                        if resp.status == 200:
                            ip_val, loc_val = parse_cf_trace(await resp.text())
                            latency = (time.perf_counter() - t0) * 1000
                            if ip_val and loc_val and ((":" in ip_val) == is_v6):
                                return ip_val, loc_val, latency
                except Exception:
                    pass
        finally:
            if close_session:
                await session.close()
        return None, None, 99999.0

    async def fetch_location(
        self, base_port: int, ipv4_ip: Optional[str] = None, ipv6_ip: Optional[str] = None,
    ) -> dict:
        families = [f for f, ip in (("ipv4", ipv4_ip), ("ipv6", ipv6_ip)) if ip]
        async with self._location_semaphore:
            return await probe_location(f"http://127.0.0.1:{base_port}", families=families, real_ip=self.real_ip)

    async def test_node_full(
        self, idx: int, node: str, endpoint: Optional[NodeEndpoint] = None,
    ) -> Optional[Tuple[str, float, str]]:
        """Phase 1 exit IP, leak, and country/GeoIP verification."""
        original_node = node
        routing_enabled = self.config.get("routing", {}).get("enabled", False)
        checked = self.check_link(node)
        if checked is None:
            return None
        node = checked
        node_name = get_node_name(node)

        async def drop(label: str, reason: str, **details) -> None:
            await runner.ensure_alive()
            safe_print(f"[-] Node {idx}/{self.total_nodes} [{node_name}] -> Dropped ({label})")
            self.node_metadata[node] = self.node_metadata[original_node] = {
                "dropped": True, "reason": reason, **details,
            }

        try:
            async with CoreRunner(
                node=node, config=self.config, temp_prefix="core_",
                node_idx=idx, total_nodes=self.total_nodes, endpoint=endpoint,
            ) as runner:
                connector = aiohttp.TCPConnector(ssl=bool(routing_enabled), limit=10)
                async with aiohttp.ClientSession(
                    connector=connector, timeout=aiohttp.ClientTimeout(total=6.0, connect=4.0),
                    max_line_size=65536, max_field_size=65536,
                ) as session:
                    (ipv4_ip, ipv4_loc, v4_lat), (ipv6_ip, ipv6_loc, v6_lat) = await asyncio.gather(
                        self._fetch_ip(TRACE_URL_IPV4, runner.proxy_url, session=session),
                        self._fetch_ip(TRACE_URL_IPV6, runner.proxy_url, session=session),
                    )

                if not routing_enabled and not ipv4_ip and not ipv6_ip:
                    await drop("No outbound internet", "No outbound internet connectivity")
                    return None
                if self.real_ip and self.real_ip in (ipv4_ip, ipv6_ip):
                    await drop("IP leak", "Proxy leaks real IP")
                    return None

                latency = min(v4_lat, v6_lat)
                location = None

                if routing_enabled:
                    location = await self.fetch_location(runner.port, ipv4_ip, ipv6_ip)
                    if location.get("ip_leak"):
                        await drop("IP leak", "Proxy leaks real IP", location=location)
                        return None
                    country_code = location.get("country")
                    failure = main_policy_failure(self.config["routing"]["main"], location)
                    if failure:
                        if location.get("reason"):
                            failure += ": " + location["reason"]
                        await drop(failure, failure, country_code=country_code, location=location)
                        return None
                else:
                    country_code = ipv4_loc or ipv6_loc
                    if not country_code:
                        await drop("Could not determine node location", "Could not determine node location")
                        return None
                    locs = [c for c in (country_code, ipv4_loc, ipv6_loc) if c]
                    allowed = {c.upper() for c in self.config.get("allowed_countries", [])}
                    blocked = next((c for c in locs if c in self.BLOCKED_REGIONS), None)
                    disallowed = next((c for c in locs if allowed and c not in allowed), None)
                    if blocked or disallowed:
                        reason = f"Geo-blocked region ({blocked})" if blocked else f"Location not allowed ({disallowed})"
                        await drop(reason, reason, country_code=country_code)
                        return None

            country_name = await GeolocationService.get_country_name(country_code)
            ips = list(dict.fromkeys(ip for ip in (ipv4_ip, ipv6_ip) if ip))
            new_name = format_descriptive_node_name(node, country_code, country_name, " | ".join(ips))
            if location is not None:
                new_name += (f" | Location {location.get('country') or 'unknown'} "
                             f"{location.get('score', 0.0):.0%} ({location.get('votes', 0)}/{location.get('total', 0)} votes)")
            supported_node = f"{node.split('#', 1)[0]}#{urllib.parse.quote(new_name)}"
            meta = {"country_code": country_code, "country_name": country_name,
                    "latency_ms": latency, "location": location}
            self.node_metadata[node] = self.node_metadata[original_node] = self.node_metadata[supported_node] = meta
            safe_print(f"[*] Node {idx}/{self.total_nodes} -> {new_name}")
            return supported_node, latency, node
        except CoreInstanceLost as lost:
            if lost.retry:
                raise
            ErrorTracker.record_error("Test Node", lost)
            return None
        except Exception as e:
            ErrorTracker.record_error("Test Node", e)
            return None

    async def speedtest_node(
        self, idx: int, node: str, timeout: int, endpoint: Optional[NodeEndpoint] = None,
    ) -> Optional[Tuple[str, float]]:
        """Phase 2 sustained throughput speedtest, excluding TCP slow-start warmup and teardown."""
        node = self.speedtest_link(node)
        if node is None:
            return None
        node_name = get_node_name(node)

        try:
            async with CoreRunner(
                node=node, config=self.config, temp_prefix="speed_core_",
                node_idx=idx, total_nodes=self.total_nodes, endpoint=endpoint,
            ) as runner:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False, limit=10),
                    timeout=aiohttp.ClientTimeout(total=max(timeout, 10), connect=4.0),
                    max_line_size=65536, max_field_size=65536,
                ) as session:
                    speed_bps = 0.0
                    max_dur = min(float(timeout), SPEEDTEST_MAX_DURATION)
                    warmup = min(SPEEDTEST_WARMUP_SECONDS, max_dur * 0.25)
                    req_timeout = aiohttp.ClientTimeout(total=max_dur + 3.0, connect=3.5, sock_read=4.0)

                    for test_url in SPEEDTEST_URLS:
                        t_first = t_last = t_steady = None
                        total_bytes = steady_bytes = 0
                        errored = False
                        try:
                            async with session.get(test_url, proxy=runner.proxy_url, timeout=req_timeout) as resp:
                                if resp.status == 200:
                                    async for chunk in resp.content.iter_chunked(131072):
                                        now = time.perf_counter()
                                        if t_first is None:
                                            t_first = t_last = now
                                            continue
                                        total_bytes += len(chunk)
                                        t_last = now
                                        elapsed = now - t_first
                                        if t_steady is None:
                                            if elapsed >= warmup:
                                                t_steady = now
                                        else:
                                            steady_bytes += len(chunk)
                                        if (elapsed >= max_dur
                                                or (elapsed > 2.0 and total_bytes / elapsed / 1048576 < 0.05)
                                                or (t_steady is not None
                                                    and now - t_steady >= SPEEDTEST_EARLY_STOP_STEADY_SECONDS
                                                    and steady_bytes >= SPEEDTEST_EARLY_STOP_STEADY_BYTES)):
                                            break
                        except Exception as e:
                            errored = True
                            ErrorTracker.record_error("Speedtest", e)

                        if errored:
                            await runner.ensure_alive()
                        t_end = t_last if not errored and t_last is not None else time.perf_counter()
                        if t_steady is not None and steady_bytes >= SPEEDTEST_MIN_BYTES and t_end - t_steady >= SPEEDTEST_MIN_STEADY_DURATION:
                            speed_bps = steady_bytes / (t_end - t_steady)
                            break
                        if t_first is not None and total_bytes >= SPEEDTEST_MIN_BYTES and t_end - t_first > 0.05:
                            speed_bps = total_bytes / (t_end - t_first)
                            break

                    if speed_bps == 0:
                        await runner.ensure_alive()
                        safe_print(f"[-] Speedtest {idx}/{self.total_nodes} [{node_name}] -> Speedtest failed (0 MB/s)")
                        return None

                    tag = f"⚡ {speed_bps / 1048576:.1f} MB/s"
                    base, sep, frag = node.partition("#")
                    if sep:
                        orig = urllib.parse.unquote(frag)
                        if " | ⚡ " in orig:
                            label = re.sub(r" \|\s*⚡\s*[\d\.]+\s*MB/s", f" | {tag}", orig)
                        elif " | " in orig:
                            head, tail = orig.split(" | ", 1)
                            label = f"{head} | {tag} | {tail}"
                        else:
                            label = f"{orig} | {tag}"
                    else:
                        label = tag
                    node = f"{base}#{urllib.parse.quote(label)}"
                    safe_print(f"[*] Speedtest {idx}/{self.total_nodes} -> {label}")
                    return node, speed_bps
        except CoreInstanceLost as lost:
            if lost.retry:
                raise
            ErrorTracker.record_error("Speedtest Node", lost)
            return None
        except Exception as e:
            ErrorTracker.record_error("Speedtest Node", e)
            return None
