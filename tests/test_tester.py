"""Unit tests for NodeTester: TCP ping, IP resolution fidelity, the Phase 1 IP check, and speedtest logic."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from nodesieve.core.tester import NodeTester


class MockRequestContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class TestNodeTester(unittest.TestCase):
    def setUp(self):
        self.config = {
            "allowed_countries": ["US", "DE"],
            "speedtest_timeout": 5,
            "ip_mode": "off",
            "use_mux": False,
        }
        self.tester = NodeTester(self.config, total_nodes=1)

    def test_tcp_ping_invalid_nodes(self):
        async def run():
            # Filtered tags
            res_auto = await self.tester.async_check_tcp_node("vless://uuid@1.2.3.4:443#Авто_Node")
            self.assertIsNone(res_auto)

            # Invalid host
            res_invalid = await self.tester.async_check_tcp_node("invalid://node")
            self.assertIsNone(res_invalid)

        asyncio.run(run())

    def test_fetch_ip_ipv4_and_ipv6_fidelity(self):
        async def run():
            trace_v4 = "ip=203.0.113.10\nloc=US\nts=12345\n"
            trace_v6 = "ip=2001:db8::1\nloc=DE\nts=12345\n"

            # Test IPv4
            mock_resp_v4 = MagicMock()
            mock_resp_v4.status = 200
            mock_resp_v4.text = AsyncMock(return_value=trace_v4)
            mock_session_v4 = MagicMock()
            mock_session_v4.get.return_value = MockRequestContext(mock_resp_v4)

            ip, loc, lat = await self.tester._fetch_ip(
                "https://1.1.1.1/cdn-cgi/trace", "http://127.0.0.1:8080", session=mock_session_v4
            )
            self.assertEqual(ip, "203.0.113.10")
            self.assertEqual(loc, "US")
            self.assertGreater(lat, 0.0)

            # Test IPv6
            mock_resp_v6 = MagicMock()
            mock_resp_v6.status = 200
            mock_resp_v6.text = AsyncMock(return_value=trace_v6)
            mock_session_v6 = MagicMock()
            mock_session_v6.get.return_value = MockRequestContext(mock_resp_v6)

            ip6, loc6, lat6 = await self.tester._fetch_ip(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace", "http://127.0.0.1:8080", session=mock_session_v6
            )
            self.assertEqual(ip6, "2001:db8::1")
            self.assertEqual(loc6, "DE")

            # Test IPv6 rejection when IPv4 is returned by error
            mock_resp_bad_v6 = MagicMock()
            mock_resp_bad_v6.status = 200
            mock_resp_bad_v6.text = AsyncMock(return_value=trace_v4)  # returns IPv4 for IPv6 URL
            mock_session_bad_v6 = MagicMock()
            mock_session_bad_v6.get.return_value = MockRequestContext(mock_resp_bad_v6)

            ip_bad, loc_bad, _ = await self.tester._fetch_ip(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace", "http://127.0.0.1:8080", session=mock_session_bad_v6
            )
            self.assertIsNone(ip_bad)

        asyncio.run(run())

    def test_speedtest_sustained_measurement(self):
        async def run():
            node = "vless://11111111-1111-4111-8111-111111111111@198.51.100.219:443?security=tls&sni=example.com#TestSpeed"

            mock_runner = AsyncMock()
            mock_runner.proxy_url = "http://127.0.0.1:12345"
            mock_runner.port = 12345

            with patch("nodesieve.core.tester.CoreRunner") as MockRunner:
                MockRunner.return_value.__aenter__.return_value = mock_runner
                chunk_data = b"0" * 131072  # 128KB chunk

                class MockStreamContent:
                    async def iter_chunked(self, size):
                        for _ in range(20):
                            yield chunk_data
                            await asyncio.sleep(0.005)

                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.content = MockStreamContent()

                mock_session = MagicMock()
                mock_session.get.return_value = MockRequestContext(mock_resp)

                class MockSessionContext:
                    async def __aenter__(self):
                        return mock_session

                    async def __aexit__(self, *args):
                        pass

                with patch("aiohttp.ClientSession", return_value=MockSessionContext()):
                    res = await self.tester.speedtest_node(1, node, timeout=5)
                    self.assertIsNotNone(res)
                    res_node, speed_bps, loc = res
                    self.assertGreater(speed_bps, 0.0)
                    import urllib.parse
                    self.assertIn("⚡", urllib.parse.unquote(res_node))

        asyncio.run(run())

    def test_test_node_full_dead_node_aborts_immediately(self):
        async def run():
            node = "vless://uuid@1.2.3.4:443#DeadNode"
            mock_runner = AsyncMock()
            mock_runner.proxy_url = "http://127.0.0.1:12345"
            mock_runner.port = 12345

            with patch("nodesieve.core.tester.CoreRunner") as MockRunner:
                MockRunner.return_value.__aenter__.return_value = mock_runner
                with patch.object(self.tester, "_fetch_ip", return_value=(None, None, 99999.0)):
                    with patch.object(self.tester, "fetch_location") as mock_location:
                        res = await self.tester.test_node_full(1, node)
                        self.assertIsNone(res)
                        # Ensure no location probes were wasted on dead node
                        mock_location.assert_not_called()
                        self.assertEqual(self.tester.node_metadata[node]["reason"], "No outbound internet connectivity")

        asyncio.run(run())

    def test_fetch_ip_latency_reset_on_retry(self):
        async def run():
            # First endpoint fails, second endpoint succeeds immediately
            mock_resp_v4 = MagicMock()
            mock_resp_v4.status = 200
            mock_resp_v4.text = AsyncMock(return_value="ip=203.0.113.10\nloc=US\n")

            mock_session = MagicMock()
            mock_session.get.side_effect = [
                Exception("Timeout connecting to 1.1.1.1"),
                MockRequestContext(mock_resp_v4),
            ]

            ip, loc, lat = await self.tester._fetch_ip(
                "https://1.1.1.1/cdn-cgi/trace", "http://127.0.0.1:8080", session=mock_session
            )
            self.assertEqual(ip, "203.0.113.10")
            self.assertEqual(loc, "US")
            self.assertLess(lat, 5000.0)

        asyncio.run(run())

    def _full_check(self, node, traces, tester=None, country_name="United States", **patches):
        """Runs test_node_full against stubbed Cloudflare traces: (ipv4 result, ipv6 result)."""
        tester = tester or self.tester

        async def run():
            mock_runner = AsyncMock()
            mock_runner.proxy_url = "http://127.0.0.1:12345"
            mock_runner.port = 12345
            with patch("nodesieve.core.tester.CoreRunner") as MockRunner, \
                    patch.object(tester, "_fetch_ip", new=AsyncMock(side_effect=list(traces))), \
                    patch("nodesieve.core.tester.GeolocationService.get_country_name",
                          new=AsyncMock(return_value=country_name)), \
                    patch("nodesieve.core.tester.GeolocationService.get_ip_country",
                          new=AsyncMock(return_value=patches.get("ip_country"))):
                MockRunner.return_value.__aenter__.return_value = mock_runner
                return await tester.test_node_full(1, node)

        return asyncio.run(run())

    def test_node_qualifies_on_ip_check_alone(self):
        import urllib.parse

        node = "vless://uuid@198.51.100.7:443#PrimaryNode"
        res = self._full_check(node, [("203.0.113.10", "US", 25.0), (None, None, 99999.0)])
        self.assertIsNotNone(res)
        survivor, latency, original = res
        self.assertEqual((latency, original), (25.0, node))
        name = urllib.parse.unquote(survivor.split("#", 1)[1])
        self.assertEqual(name, "[VLESS: PrimaryNode] \U0001F1FA\U0001F1F8 United-States | 203.0.113.10")
        meta = self.tester.node_metadata[survivor]
        self.assertIs(meta, self.tester.node_metadata[node])
        self.assertEqual(meta, {
            "country_code": "US", "country_name": "United States",
            "latency_ms": 25.0, "location": None, "loc_score": 0.0,
        })

    def test_node_reports_both_address_families(self):
        import urllib.parse

        res = self._full_check(
            "vless://uuid@198.51.100.7:443#DualStack",
            [("203.0.113.10", "DE", 40.0), ("2001:db8::1", "DE", 30.0)],
            country_name="Germany",
        )
        self.assertEqual(res[1], 30.0)
        self.assertTrue(urllib.parse.unquote(res[0]).endswith("Germany | 203.0.113.10 | 2001:db8::1"))

    def test_node_dropped_for_blocked_or_disallowed_exit_country(self):
        node = "vless://uuid@198.51.100.7:443#Tag"
        for loc, reason in (("RU", "Geo-blocked region (RU)"), ("FR", "Location not allowed (FR)")):
            with self.subTest(loc=loc):
                res = self._full_check(node, [("203.0.113.10", loc, 25.0), (None, None, 99999.0)])
                self.assertIsNone(res)
                self.assertEqual(self.tester.node_metadata[node], {
                    "dropped": True, "reason": reason, "country_code": loc,
                })
        # A blocked IPv6 exit is not hidden behind an acceptable IPv4 exit.
        res = self._full_check(node, [("203.0.113.10", "US", 25.0), ("2001:db8::1", "CN", 30.0)])
        self.assertIsNone(res)

    def test_node_dropped_when_exit_ip_is_the_real_ip(self):
        tester = NodeTester(self.config, total_nodes=1, real_ip="203.0.113.10")
        node = "vless://uuid@198.51.100.7:443#Leaky"
        res = self._full_check(node, [("203.0.113.10", "US", 25.0), (None, None, 99999.0)], tester=tester)
        self.assertIsNone(res)
        self.assertEqual(tester.node_metadata[node]["reason"], "Proxy leaks real IP")

    def test_node_dropped_when_country_unresolvable_records_metadata(self):
        node = "vless://uuid@127.0.0.1:443#UnresolvableNode"
        res = self._full_check(node, [("198.51.100.1", None, 25.0), (None, None, 99999.0)], ip_country=None)
        self.assertIsNone(res)
        self.assertTrue(self.tester.node_metadata[node]["dropped"])
        self.assertIn("location", self.tester.node_metadata[node]["reason"])

    def test_ip_mode_requires_the_configured_address_families(self):
        node = "vless://uuid@198.51.100.7:443#Tag"
        v4_only = [("203.0.113.10", "US", 25.0), (None, None, 99999.0)]
        dual = [("203.0.113.10", "US", 25.0), ("2001:db8::1", "US", 30.0)]
        for ip_mode, traces, survives in (
            ("two_ips", v4_only, False), ("two_ips", dual, True),
            ("one_ip", v4_only, True), ("one_ip", dual, False),
        ):
            with self.subTest(ip_mode=ip_mode, families=len([t for t in traces if t[0]])):
                tester = NodeTester({**self.config, "ip_mode": ip_mode}, total_nodes=1)
                res = self._full_check(node, traces, tester=tester)
                self.assertEqual(res is not None, survives)

    def test_location_ranking_score_is_labelled_and_reused_by_speedtest_naming(self):
        import urllib.parse

        tester = NodeTester({**self.config, "enable_loc_ranking": True}, total_nodes=1)
        with patch.object(tester, "fetch_loc_score", new=AsyncMock(return_value=0.75)) as score:
            res = self._full_check(
                "vless://uuid@198.51.100.7:443#Ranked",
                [("203.0.113.10", "US", 25.0), (None, None, 99999.0)], tester=tester,
            )
        score.assert_awaited_once_with(12345, ["US", "DE"], "203.0.113.10", None)
        name = urllib.parse.unquote(res[0].split("#", 1)[1])
        self.assertEqual(name, "[VLESS: Ranked] \U0001F1FA\U0001F1F8 United-States | LOC: 75% | 203.0.113.10")
        self.assertEqual(tester.node_metadata[res[0]]["loc_score"], 0.75)


if __name__ == "__main__":
    unittest.main()
