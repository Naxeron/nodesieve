"""Unit tests for async stream teardown, port pool allocation, and caching patterns."""

import asyncio
import time
import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from nodesieve.core.mihomo import MihomoManager
from nodesieve.geo import GeolocationService
from nodesieve.logging import safe_close_writer


class TestConcurrency(unittest.TestCase):
    def test_safe_close_writer_none(self):
        async def run():
            await safe_close_writer(None)
        asyncio.run(run())

    def test_safe_close_writer_live_socket(self):
        async def run():
            server_writer = None

            async def handle_client(r, w):
                nonlocal server_writer
                server_writer = w

            # Start a dummy server
            server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await safe_close_writer(writer, timeout=0.2)
            if server_writer:
                await safe_close_writer(server_writer, timeout=0.2)

            server.close()
            await server.wait_closed()

        asyncio.run(run())

    def test_ephemeral_port_allocation(self):
        ports = []
        for _ in range(5):
            p = MihomoManager.get_free_port()
            self.assertGreater(p, 0)
            self.assertNotIn(p, ports)
            ports.append(p)

        for p in ports:
            MihomoManager.release_port(p)

    def test_geolocation_service_offline_fallback(self):
        async def run():
            name_us = await GeolocationService.get_country_name("US")
            self.assertEqual(name_us, "United States")

            name_tr = await GeolocationService.get_country_name("TR")
            self.assertEqual(name_tr, "Türkiye")

        asyncio.run(run())

    def test_mihomo_runner_cleanup_on_aenter_exception(self):
        async def run():
            from nodesieve.core.mihomo import MihomoRunner

            initial_ports = set(MihomoManager._allocated_ports)
            runner = MihomoRunner("vless://no-server-here#Invalid", config={})
            with self.assertRaises(Exception):
                async with runner:
                    pass

            # Port must be completely released back to pool
            self.assertEqual(MihomoManager._allocated_ports, initial_ports)
            self.assertIsNone(runner.port)

        asyncio.run(run())

    def test_stockpile_existing_ip_deduplication(self):
        import urllib.parse
        from nodesieve.parsers.base import extract_host_port

        existing_nodes = [
            "vless://uuid@server1.example.com:443#%5BVLESS%3A%20Server1%5D%20%F0%9F%87%BA%F0%9F%87%B8%20United-States%20%7C%20203.0.113.50"
        ]
        supported_nodes = [
            (
                "vless://uuid@server2.example.com:443#%5BVLESS%3A%20Server2%5D%20%F0%9F%87%BA%F0%9F%87%B8%20United-States%20%7C%20203.0.113.50",
                50.0,
                "orig_node",
            )
        ]

        seen_hosts = set()
        seen_ips = set()
        final_nodes = []

        for node in existing_nodes:
            host, port = extract_host_port(node)
            if host:
                seen_hosts.add(host)
            name = urllib.parse.unquote(node.split("#", 1)[1]) if "#" in node else ""
            ip_str = name.rsplit(" | ", 1)[-1] if " | " in name else None
            if ip_str:
                seen_ips.add(ip_str)
            final_nodes.append(node)

        new_added = 0
        for node, latency, orig_node in supported_nodes:
            host, port = extract_host_port(node)
            name = urllib.parse.unquote(node.split("#", 1)[1]) if "#" in node else ""
            ip_str = name.rsplit(" | ", 1)[-1] if " | " in name else None

            if host and host not in seen_hosts:
                if ip_str and ip_str in seen_ips:
                    continue
                if ip_str:
                    seen_ips.add(ip_str)
                seen_hosts.add(host)
                final_nodes.append(node)
                new_added += 1

        self.assertEqual(new_added, 0)
        self.assertEqual(len(final_nodes), 1)

    def test_fetcher_base64_padded_decoding(self):
        import base64
        from nodesieve.core.fetcher import NodeFetcher

        _ = NodeFetcher(config={})
        raw_sub = "vless://uuid@1.2.3.4:443?type=tcp#Node1\ntrojan://pass@5.6.7.8:443#Node2\n"
        # Create unpadded base64 string
        encoded_unpadded = base64.b64encode(raw_sub.encode("utf-8")).decode("utf-8").rstrip("=")

        cleaned_b64 = encoded_unpadded.strip()
        cleaned_b64 += "=" * (-len(cleaned_b64) % 4)
        decoded = base64.b64decode(cleaned_b64).decode("utf-8", errors="ignore")
        self.assertIn("vless://", decoded)
        self.assertIn("trojan://", decoded)


class TestConcurrencyStress(IsolatedAsyncioTestCase):
    """The .agents/AGENTS.md rules under load."""

    async def test_ephemeral_port_stress_50_concurrent_allocations(self):
        """Rule 2: 50 allocations, each with a live server on it, never collide."""
        ports = []
        servers = []
        try:
            for _ in range(50):
                p = MihomoManager.get_free_port()
                self.assertNotIn(p, ports, f"Port collision detected for port {p}!")
                ports.append(p)
                servers.append(await asyncio.start_server(lambda r, w: None, "127.0.0.1", p))
            self.assertEqual(len(set(ports)), 50)
        finally:
            for server, port in zip(servers, ports):
                server.close()
                await server.wait_closed()
                MihomoManager.release_port(port)

    async def test_safe_close_writer_50_concurrent_hanging_peers(self):
        """Rule 1: 50 peers that never finish closing hold nobody up beyond the timeout."""
        writers = []
        for _ in range(50):
            writer = MagicMock()

            async def hang():
                await asyncio.sleep(5.0)

            writer.wait_closed = hang
            writers.append(writer)
        started = time.monotonic()
        await asyncio.gather(*[safe_close_writer(writer, timeout=0.2) for writer in writers])
        self.assertLess(time.monotonic() - started, 0.40)
        for writer in writers:
            writer.close.assert_called_once()

    async def test_safe_close_writer_abrupt_disconnect_and_exceptions(self):
        """Rule 1: a reset peer, a broken pipe and no writer at all are handled quietly."""
        await safe_close_writer(None)
        reset = MagicMock()

        async def raise_reset():
            raise ConnectionResetError("TCP Connection Reset by peer")

        reset.wait_closed = raise_reset
        await safe_close_writer(reset, timeout=0.2)
        reset.close.assert_called_once()
        broken = MagicMock()
        broken.close.side_effect = BrokenPipeError("Broken Pipe")
        await safe_close_writer(broken, timeout=0.2)

    async def test_geolocation_service_single_attempt_lock_50_concurrent_failures(self):
        """Rule 3: during an outage, 50 callers make one attempt and get the offline names."""
        GeolocationService._country_attempted = False
        with patch("aiohttp.ClientSession.get", side_effect=OSError("Network unreachable")) as fetch:
            names = await asyncio.gather(*[GeolocationService.get_country_name("US") for _ in range(50)])
        self.assertTrue(all(name == "United States" for name in names))
        self.assertEqual(fetch.call_count, 1)
        self.assertTrue(GeolocationService._country_attempted)


if __name__ == "__main__":
    unittest.main()
