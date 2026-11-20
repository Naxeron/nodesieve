"""Node testing routines: TCP ping, exit IP and country resolution, GeoIP location consensus, and speedtests."""

import asyncio
import re
import time
import urllib.parse
from typing import Optional, Set, Tuple
import aiohttp

from nodesieve.constants import GEOBLOCKED_REGIONS
from nodesieve.core.mihomo import MihomoInstanceLost, MihomoRunner, NodeEndpoint
from nodesieve.geo import GeolocationService
from nodesieve.logging import ErrorTracker, safe_close_writer, safe_print
from nodesieve.parsers.base import (
    extract_host_port,
    format_descriptive_node_name,
    get_node_name,
)
from nodesieve.parsers.mihomo import node_url_to_mihomo_dict, without_mux
from nodesieve.routing import main_policy_failure, normalize_routing
from nodesieve.location import probe_location

# Cloudflare's trace endpoint by address, one per IP family.
TRACE_URL_IPV4 = "https://1.1.1.1/cdn-cgi/trace"
TRACE_URL_IPV6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"


class NodeTester:
    """Runs the IP check (reachability, exit IP, location) and speedtests against candidate VPN proxy nodes."""

    BLOCKED_REGIONS: Set[str] = GEOBLOCKED_REGIONS

    def __init__(
        self,
        config: dict,
        total_nodes: int = 0,
        real_ip: Optional[str] = None,
    ):
        self.config = config
        if self.config.get("routing", {}).get("enabled", False):
            self.config["routing"] = normalize_routing(self.config["routing"])
        self.total_nodes = total_nodes
        self.real_ip = real_ip
        self.node_metadata: dict = {}
        # Working nodes that were offered multiplexing, and how many of them answered through it.
        self.mux_offered = 0
        self.mux_supported = 0

        # Nodes whose GeoIP providers are asked at once, each with up to
        # location.REQUESTS_PER_NODE requests in flight.
        self._location_semaphore = asyncio.Semaphore(6)

    async def async_check_tcp_node(self, node: str, timeout: float = 1.5) -> Optional[str]:
        """Phase 0 TCP Ping: Tests raw TCP port reachability."""
        node_name = get_node_name(node)
        if "Авто" in node_name or "⬇" in node_name:
            return None

        host, port = extract_host_port(node)
        if not host or not port:
            return None

        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            await safe_close_writer(writer)
            return node
        except Exception as e:
            ErrorTracker.record_error("TCP Ping", e)
            return None

    async def _fetch_ip(
        self,
        url: str,
        proxy: str,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> Tuple[Optional[str], Optional[str], float]:
        """Queries Cloudflare trace endpoint via proxy to extract outgoing IP, ISO country, and latency."""
        is_v6 = "2606:4700:4700::1111" in url

        # IPv6 MUST NOT fallback to dual-stack domain because that returns IPv4 and corrupts IPv6 detection
        urls = [url]
        if not is_v6 and ("1.1.1.1" in url):
            urls.append("https://cloudflare.com/cdn-cgi/trace")

        close_session = False
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout_obj = aiohttp.ClientTimeout(total=3.5 if is_v6 else 4.5, connect=2.5)
            session = aiohttp.ClientSession(connector=connector, timeout=timeout_obj)
            close_session = True

        try:
            for u in urls:
                req_start = time.perf_counter()
                try:
                    req_timeout = aiohttp.ClientTimeout(total=3.0 if is_v6 else 4.0, connect=2.5)
                    async with session.get(u, proxy=proxy, timeout=req_timeout) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            latency = (time.perf_counter() - req_start) * 1000
                            ip_match = re.search(r"(?:^|\n)ip=([^\r\n]+)", text)
                            loc_match = re.search(r"(?:^|\n)loc=([^\r\n]+)", text)
                            if ip_match and loc_match:
                                ip_val = ip_match.group(1).strip()
                                loc_val = loc_match.group(1).strip().upper()
                                if is_v6:
                                    if ":" in ip_val:
                                        return ip_val, loc_val, latency
                                else:
                                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_val):
                                        return ip_val, loc_val, latency
                                    elif ":" not in ip_val:
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
        """Collect independent GeoIP votes through this node's local listener.

        The families the Cloudflare trace reached the node in need a consensus; the
        addresses the providers look up are found by the probe itself.
        """
        families = [family for family, address in (("ipv4", ipv4_ip), ("ipv6", ipv6_ip)) if address]
        async with self._location_semaphore:
            return await probe_location(f"http://127.0.0.1:{base_port}", families=families, real_ip=self.real_ip)

    async def fetch_loc_score(
        self, base_port: int, allowed: list,
        ipv4_ip: Optional[str] = None, ipv6_ip: Optional[str] = None,
    ) -> float:
        """Legacy allowed-country agreement score, using the GeoIP providers' reports."""
        if not allowed:
            return 0.0
        evidence = await self.fetch_location(base_port, ipv4_ip, ipv6_ip)
        if evidence.get("status") == "failed" or not evidence.get("total"):
            return 0.0
        accepted = {country.upper() for country in allowed}
        return sum(count for country, count in evidence["counts"].items() if country in accepted) / evidence["total"]

    def _mux_applies(self, node: str) -> bool:
        """Whether use_mux would give this node's Mihomo proxy multiplexing."""
        if not self.config.get("use_mux", True):
            return False
        proxy = node_url_to_mihomo_dict(node, use_mux=True)
        return bool(proxy and "smux" in proxy)

    @staticmethod
    def _as_checked(node: str) -> str:
        """The link as Mihomo gets it: VLESS with encryption=none."""
        if node.startswith("vless://"):
            return re.sub(r"encryption=[^&#]+", "encryption=none", node)
        return node

    def check_links(self, node: str) -> Optional[Tuple[str, Optional[str]]]:
        """What the IP check needs Mihomo to serve for a node: the link the node is checked
        with, and the same node with multiplexing for the probe, or None for no probe.

        None instead of the pair when the node is turned away before any Mihomo is needed.
        """
        node = self._as_checked(node)
        node_name = get_node_name(node)
        if "Авто" in node_name or "⬇" in node_name:
            return None
        host, port = extract_host_port(node)
        if not host or not port:
            return None
        # Multiplexing (sing-mux) works only when the server supports it, which a link does
        # not say, and a server without it drops every connection. So the node is checked
        # without multiplexing and keeps it only if it then answers a request through it.
        # Steer connects with its own core and takes no multiplexing from this checker.
        if not self._mux_applies(node):
            return node, None
        routing_enabled = self.config.get("routing", {}).get("enabled", False)
        return without_mux(node), (None if routing_enabled else node)

    def speedtest_links(self, node: str) -> Optional[Tuple[str, Optional[str]]]:
        """The link the speedtest has Mihomo serve for a node, as check_links gives it; None when there is none."""
        node = self._as_checked(node)
        host, port = extract_host_port(node)
        return (node, None) if host and port else None

    async def _answers_multiplexed(
        self, idx: int, node: str, trace_url: str, endpoint: Optional[NodeEndpoint] = None,
    ) -> bool:
        """Whether a working node also answers with multiplexing, which only a server that supports it does."""
        try:
            async with MihomoRunner(
                node=node, config=self.config, temp_prefix="mux_mihomo_", node_idx=idx, endpoint=endpoint,
            ) as runner:
                ip, _, _ = await self._fetch_ip(trace_url, runner.proxy_url)
                if not ip:
                    await runner.ensure_alive()
                return bool(ip)
        except MihomoInstanceLost as lost:
            if lost.retry:
                raise
            ErrorTracker.record_error("Mux Probe", lost)
            return False
        except Exception as e:
            ErrorTracker.record_error("Mux Probe", e)
            return False

    async def test_node_full(
        self, idx: int, node: str, endpoint: Optional[NodeEndpoint] = None,
    ) -> Optional[Tuple[str, float, str]]:
        """Phase 1 IP check: verifies the node's exit IP and location through a local Mihomo.

        endpoint is the node's listener on a shared Mihomo, serving the links check_links
        gives; without one, the node gets a Mihomo of its own for the check. Raises
        MihomoInstanceLost (with retry) when a shared Mihomo exited during the check, as
        any of its nodes may have made it: the node is then to be checked again alone.
        """
        original_node = node
        routing_enabled = self.config.get("routing", {}).get("enabled", False)
        links = self.check_links(node)
        if links is None:
            return None
        checked_link, mux_link = links
        node = self._as_checked(node)
        node_name = get_node_name(node)
        host, port = extract_host_port(node)

        async def drop(label: str, reason: str, **details) -> None:
            # A Mihomo that exited fails a node too, which is not the node's doing.
            await runner.ensure_alive()
            safe_print(f"[-] Node {idx}/{self.total_nodes} [{node_name}] -> Dropped ({label})")
            self.node_metadata[node] = self.node_metadata[original_node] = {
                "dropped": True, "reason": reason, **details,
            }

        try:
            async with MihomoRunner(
                node=checked_link,
                config=self.config,
                temp_prefix="mihomo_",
                node_idx=idx,
                total_nodes=self.total_nodes,
                endpoint=endpoint,
            ) as runner:
                proxy_url = runner.proxy_url
                base_port = runner.port

                connector = aiohttp.TCPConnector(ssl=bool(routing_enabled), limit=10)
                timeout_obj = aiohttp.ClientTimeout(total=6.0, connect=4.0)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout_obj,
                    max_line_size=65536,
                    max_field_size=65536,
                ) as session:
                    # Concurrently query IPv4 and IPv6 endpoints on shared session
                    v4_task = self._fetch_ip(TRACE_URL_IPV4, proxy_url, session=session)
                    v6_task = self._fetch_ip(TRACE_URL_IPV6, proxy_url, session=session)

                    results = await asyncio.gather(v4_task, v6_task)
                    ipv4_ip, ipv4_loc, v4_lat = results[0]
                    ipv6_ip, ipv6_loc, v6_lat = results[1]

                # Early abort if node has no outbound internet connectivity. The Steer
                # main pool relies on the GeoIP probe's own exit discovery instead of this trace.
                if not routing_enabled and not ipv4_ip and not ipv6_ip:
                    await drop("No outbound internet", "No outbound internet connectivity")
                    return None

                if self.real_ip and (ipv4_ip == self.real_ip or ipv6_ip == self.real_ip):
                    await drop("IP leak", "Proxy leaks real IP")
                    return None

                latency = min(v4_lat, v6_lat)
                ip_mode = self.config.get("ip_mode", "off")

                if ip_mode == "two_ips" and not (ipv4_loc and ipv6_loc):
                    await runner.ensure_alive()
                    return None
                elif ip_mode == "one_ip" and not (bool(ipv4_loc) ^ bool(ipv6_loc)):
                    await runner.ensure_alive()
                    return None

                eff_v4 = ipv4_ip
                location = None
                loc_score = 0.0

                if routing_enabled:
                    # Steer main pool: GeoIP consensus decides, per IP family.
                    location = await self.fetch_location(base_port, ipv4_ip, ipv6_ip)
                    loc_score = location.get("score", 0.0)
                    if location.get("ip_leak"):
                        await drop("IP leak", "Proxy leaks real IP", location=location, loc_score=loc_score)
                        return None
                    # A tied/unknown consensus must not keep an earlier
                    # single-provider country label as if it had won.
                    country_code = location.get("country")
                    failure = main_policy_failure(self.config["routing"]["main"], location)
                    if failure:
                        if location.get("reason"):
                            failure += ": " + location["reason"]
                        await drop(failure, failure, country_code=country_code, location=location, loc_score=loc_score)
                        return None
                else:
                    allowed = [c.upper() for c in self.config.get("allowed_countries", [])]
                    if not eff_v4 and host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                        eff_v4 = host

                    country_code = ipv4_loc or ipv6_loc
                    if not country_code and eff_v4:
                        country_code = await GeolocationService.get_ip_country(eff_v4)

                    if not country_code:
                        loc_reason = "Could not determine node location"
                        await drop(loc_reason, loc_reason)
                        return None

                    is_valid_location = True
                    if country_code in self.BLOCKED_REGIONS:
                        is_valid_location = False
                    if ipv4_loc and ipv4_loc in self.BLOCKED_REGIONS:
                        is_valid_location = False
                    if ipv6_loc and ipv6_loc in self.BLOCKED_REGIONS:
                        is_valid_location = False
                    if allowed:
                        if ipv4_loc and ipv4_loc not in allowed:
                            is_valid_location = False
                        if ipv6_loc and ipv6_loc not in allowed:
                            is_valid_location = False
                        if country_code and country_code not in allowed:
                            is_valid_location = False

                    if not is_valid_location:
                        loc_reason = (
                            f"Geo-blocked region ({country_code})"
                            if country_code in self.BLOCKED_REGIONS
                            else f"Location not allowed ({country_code})"
                        )
                        await drop(loc_reason, loc_reason, country_code=country_code)
                        return None

                    if allowed and self.config.get("enable_loc_ranking", False):
                        loc_score = await self.fetch_loc_score(base_port, allowed, eff_v4, ipv6_ip)
                        if not loc_score:
                            await runner.ensure_alive()

            # The node qualifies. A Mihomo of its own is closed by now, so the multiplexing
            # probe starts the next one rather than a second; a shared Mihomo serves the
            # probe's link as well.
            link = node
            if mux_link is not None:
                answered = await self._answers_multiplexed(
                    idx, mux_link, TRACE_URL_IPV4 if ipv4_ip else TRACE_URL_IPV6,
                    endpoint.mux if endpoint is not None else None,
                )
                self.mux_offered += 1
                if answered:
                    self.mux_supported += 1
                else:
                    link = without_mux(node)

            country_name = await GeolocationService.get_country_name(country_code)

            display_ip = []
            if ipv4_ip:
                display_ip.append(ipv4_ip)
            if ipv6_ip and ipv6_ip != ipv4_ip:
                display_ip.append(ipv6_ip)
            ip_str = " | ".join(display_ip) if display_ip else (eff_v4 or "")

            meta = {
                "country_code": country_code,
                "country_name": country_name,
                "latency_ms": latency,
                "location": location,
                "loc_score": loc_score,
            }

            new_name = format_descriptive_node_name(
                node=node,
                country_code=country_code,
                country_name=country_name,
                ip_str=ip_str,
                loc_score=0.0 if routing_enabled else loc_score,
            )
            if location is not None:
                new_name += (f" | Location {location.get('country') or 'unknown'} "
                             f"{loc_score:.0%} ({location.get('votes', 0)}/{location.get('total', 0)} votes)")
            supported_node = f"{link.split('#', 1)[0]}#{urllib.parse.quote(new_name)}"
            self.node_metadata[node] = meta
            self.node_metadata[original_node] = meta
            self.node_metadata[supported_node] = meta

            safe_print(f"[*] Node {idx}/{self.total_nodes} -> {new_name}")
            return supported_node, latency, node
        except MihomoInstanceLost as lost:
            if lost.retry:
                raise
            ErrorTracker.record_error("Test Node", lost)
            return None
        except Exception as e:
            ErrorTracker.record_error("Test Node", e)
            return None

    async def speedtest_node(
        self,
        idx: int,
        node: str,
        timeout: int,
        endpoint: Optional[NodeEndpoint] = None,
    ) -> Optional[Tuple[str, float, float]]:
        """Phase 2 Speedtest: Downloads payload chunks through the node to calculate sustained throughput.

        endpoint, a shared Mihomo, and MihomoInstanceLost work as in test_node_full.
        """
        links = self.speedtest_links(node)
        if links is None:
            return None
        node = links[0]
        host, port = extract_host_port(node)
        node_name = get_node_name(node)

        try:
            async with MihomoRunner(
                node=node,
                config=self.config,
                temp_prefix="speed_mihomo_",
                node_idx=idx,
                total_nodes=self.total_nodes,
                endpoint=endpoint,
            ) as runner:
                proxy_url = runner.proxy_url
                base_port = runner.port

                allowed_countries = [c.upper() for c in self.config.get("allowed_countries", [])]

                connector = aiohttp.TCPConnector(ssl=bool(self.config.get("routing", {}).get("enabled", False)), limit=10)
                session_timeout = aiohttp.ClientTimeout(total=max(timeout, 10), connect=4.0)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=session_timeout,
                    max_line_size=65536,
                    max_field_size=65536,
                ) as session:
                    ipv4_ip = None
                    ipv6_ip = None
                    if host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                        ipv4_ip = host
                    else:
                        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", node)
                        if ip_match:
                            ipv4_ip = ip_match.group(0)

                    speed_bps = 0.0
                    loc_score = 0.0
                    if "LOC: " in node_name:
                        try:
                            existing_str = node_name.split("LOC: ")[1].split("%")[0]
                            loc_score = float(existing_str) / 100.0
                        except Exception:
                            pass

                    test_urls = [
                        "https://speed.cloudflare.com/__down?bytes=25000000",
                        "http://proof.ovh.net/files/100Mb.dat",
                    ]

                    max_duration = min(float(timeout), 6.0)
                    for test_url in test_urls:
                        first_byte_time = None
                        total_bytes = 0
                        try:
                            req_timeout = aiohttp.ClientTimeout(total=max_duration + 3.0, connect=3.5)
                            async with session.get(test_url, proxy=proxy_url, timeout=req_timeout) as resp:
                                if resp.status == 200:
                                    async for chunk in resp.content.iter_chunked(131072):
                                        if first_byte_time is None:
                                            first_byte_time = time.perf_counter()
                                        total_bytes += len(chunk)
                                        download_elapsed = time.perf_counter() - first_byte_time

                                        if download_elapsed >= max_duration:
                                            break

                                        # Abort early on crawling transfers after 2 seconds
                                        if download_elapsed > 2.0 and (total_bytes / download_elapsed / 1024 / 1024) < 0.05:
                                            break

                                        # Sufficient sample size obtained for high speed nodes
                                        if download_elapsed >= 3.0 and total_bytes >= 15 * 1024 * 1024:
                                            break
                        except Exception as e:
                            ErrorTracker.record_error("Speedtest", e)
                            pass

                        if first_byte_time and total_bytes >= 65536:
                            transfer_duration = time.perf_counter() - first_byte_time
                            if transfer_duration > 0.05:
                                speed_bps = total_bytes / transfer_duration
                                break

                    if speed_bps > 0 and allowed_countries and self.config.get("enable_loc_ranking", False):
                        if loc_score == 0.0:
                            fresh_score = await self.fetch_loc_score(base_port, allowed_countries, ipv4_ip, ipv6_ip)
                            if fresh_score > 0:
                                loc_score = fresh_score

                        score_tag = f"LOC: {loc_score*100:.0f}%"
                        parts = node.split("#", 1)
                        if len(parts) == 2:
                            unquoted = urllib.parse.unquote(parts[1])
                            if re.search(r"LOC:\s*\d+%", unquoted):
                                unquoted = re.sub(r"LOC:\s*\d+%", score_tag, unquoted)
                            else:
                                if " | " in unquoted:
                                    n_parts = unquoted.split(" | ", 1)
                                    unquoted = f"{n_parts[0]} | {score_tag} | {n_parts[1]}"
                                else:
                                    unquoted = f"{unquoted} | {score_tag}"
                            node = f"{parts[0]}#{urllib.parse.quote(unquoted)}"
                            node_name = get_node_name(node)

                    if speed_bps == 0:
                        await runner.ensure_alive()
                        safe_print(f"[-] Speedtest {idx}/{self.total_nodes} [{node_name}] -> Speedtest failed (0 MB/s)")
                        return None

                    speed_mbps = speed_bps / 1024 / 1024
                    speed_tag = f"⚡ {speed_mbps:.1f} MB/s"
                    parts = node.split("#", 1)
                    if len(parts) == 2:
                        orig_name = urllib.parse.unquote(parts[1])
                        if " | ⚡ " in orig_name:
                            new_name = re.sub(r" \|\s*⚡\s*[\d\.]+\s*MB/s", f" | {speed_tag}", orig_name)
                        elif " | " in orig_name:
                            n_parts = orig_name.split(" | ", 1)
                            new_name = f"{n_parts[0]} | {speed_tag} | {n_parts[1]}"
                        else:
                            new_name = f"{orig_name} | {speed_tag}"
                        node = f"{parts[0]}#{urllib.parse.quote(new_name)}"
                    else:
                        node = f"{parts[0]}#{urllib.parse.quote(speed_tag)}"
                    node_name = get_node_name(node)

                    safe_print(f"[*] Speedtest {idx}/{self.total_nodes} -> {node_name}")
                    return node, speed_bps, loc_score
        except MihomoInstanceLost as lost:
            if lost.retry:
                raise
            ErrorTracker.record_error("Speedtest Node", lost)
            return None
        except Exception as e:
            ErrorTracker.record_error("Speedtest Node", e)
            return None
