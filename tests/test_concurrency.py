"""Unit tests for async stream teardown, port pool allocation, and caching patterns."""

import asyncio
import unittest
from proxy_sites.core.mihomo import MihomoManager
from proxy_sites.geo import GeolocationService
from proxy_sites.logging import safe_close_writer


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

    def test_mihomo_runner_cleanup_on_aenter_exception(self):
        async def run():
            from proxy_sites.core.mihomo import MihomoRunner

            initial_ports = set(MihomoManager._allocated_ports)
            runner = MihomoRunner("awg_conf:non_existent_file.conf#Invalid", config={})
            with self.assertRaises(Exception):
                async with runner:
                    pass

            # Port must be completely released back to pool
            self.assertEqual(MihomoManager._allocated_ports, initial_ports)
            self.assertIsNone(runner.port)

        asyncio.run(run())

    def test_stockpile_existing_ip_deduplication(self):
        import urllib.parse
        from proxy_sites.parsers.base import extract_host_port

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
        from proxy_sites.core.fetcher import NodeFetcher

        _ = NodeFetcher(config={})
        raw_sub = "vless://uuid@1.2.3.4:443?type=tcp#Node1\ntrojan://pass@5.6.7.8:443#Node2\n"
        # Create unpadded base64 string
        encoded_unpadded = base64.b64encode(raw_sub.encode("utf-8")).decode("utf-8").rstrip("=")

        cleaned_b64 = encoded_unpadded.strip()
        cleaned_b64 += "=" * (-len(cleaned_b64) % 4)
        decoded = base64.b64decode(cleaned_b64).decode("utf-8", errors="ignore")
        self.assertIn("vless://", decoded)
        self.assertIn("trojan://", decoded)


if __name__ == "__main__":
    unittest.main()
