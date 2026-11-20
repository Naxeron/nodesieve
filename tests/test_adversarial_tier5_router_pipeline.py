"""Milestone 4 Phase 2: Adversarial Coverage Hardening (Tier 5).

Deep adversarial stress-testing and empirical challenge suite for:
1. RouterValidator candidate boundary inputs, null keys/values, giant batches.
2. Polymorphic candidate output formatting and latency metric fidelity.
3. Network error cascades (REST API 500/502/429/timeout, delay probe errors, TCP resets).
4. Concurrency and AGENTS.md rules compliance (ephemeral ports, safe teardown <= 0.2s).
"""

import asyncio
import socket
import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock

import aiohttp
from aiohttp import web

from nodesieve.core.router_validator import RouterUnreachableError, RouterValidator
from nodesieve.router.client import RouterClient


def get_ephemeral_port() -> int:
    """Dynamically requests an available free port from the OS kernel."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestAdversarialCandidateBoundaryInputs(unittest.TestCase):
    """Stress-tests boundary, malformed, and adversarial candidate structures."""

    def setUp(self):
        self.mock_client = MagicMock(spec=RouterClient)
        self.mock_client.api_url = "http://192.168.1.1:9090"
        self.mock_client.is_api_alive = AsyncMock(return_value=True)
        self.mock_client.reload_provider = AsyncMock(return_value=True)
        self.mock_client.probe_group_delay = AsyncMock(return_value={})
        self.mock_client.stream_file_to_router = MagicMock(return_value=True)

        self.config = {
            "allowed_countries": [],
            "use_mux": True,
            "enable_router_validation": True,
        }
        self.validator = RouterValidator(
            router_client=self.mock_client,
            config=self.config,
            fallback_on_unreachable=True,
        )

    def test_empty_candidate_list_returns_empty_immediately(self):
        """Empty candidate input returns [] without any network or SSH calls."""
        async def run():
            res = await self.validator.verify_nodes_on_router([])
            self.assertEqual(res, [])
            self.mock_client.is_api_alive.assert_not_called()
            self.mock_client.reload_provider.assert_not_called()

        asyncio.run(run())

    def test_reproducible_defect_null_url_candidate_crash(self):
        """Hardened behavior: Candidates with null 'url' or missing 'node' keys
        are safely handled and filtered without raising TypeError or AttributeError.
        """
        async def run():
            # Scenario A: {'url': None}
            res_a = await self.validator.verify_nodes_on_router([{"url": None}])
            self.assertEqual(res_a, [])

            # Scenario B: {'name': 'test', 'url': None}
            res_b = await self.validator.verify_nodes_on_router([{"name": "test", "url": None}])
            self.assertEqual(res_b, [])

            # Scenario C: {'node': None, 'url': None}
            res_c = await self.validator.verify_nodes_on_router([{"node": None, "url": None}])
            self.assertEqual(res_c, [])

            # Mixed scenario: valid node along with null/malformed candidates
            sub_yaml, name_to_cand = self.validator.build_candidate_sub_yaml(
                [{"url": None}, {"name": "test", "url": None}, {"node": None, "url": None}]
            )
            self.assertEqual(sub_yaml.strip(), "")
            self.assertEqual(name_to_cand, {})

        asyncio.run(run())

    def test_non_ascii_and_emoji_node_names_preservation(self):
        """Non-ASCII names with emojis, Cyrillic, Chinese, and symbols are parsed cleanly."""
        candidates = [
            "vless://uuid@1.1.1.1:443#🚀⚡_Speedy_Node_🔥",
            "vless://uuid@2.2.2.2:443#Москва_Сервер_🇷🇺",
            "vless://uuid@3.3.3.3:443#香港直连_HK_🇭🇰",
            "vless://uuid@4.4.4.4:443#Special;Chars&'Double\"_`Node`",
        ]
        sub_yaml, name_to_cand = self.validator.build_candidate_sub_yaml(candidates)

        self.assertIn("🚀⚡_Speedy_Node_🔥", name_to_cand)
        self.assertIn("Москва_Сервер_🇷🇺", name_to_cand)
        self.assertIn("香港直连_HK_🇭🇰", name_to_cand)
        self.assertIn("Special;Chars&'Double\"_`Node`", name_to_cand)

        # Ensure YAML dump preserves UTF-8 unicode cleanly without corruption
        self.assertIn("🚀⚡_Speedy_Node_🔥", sub_yaml)
        self.assertIn("Москва_Сервер_🇷🇺", sub_yaml)
        self.assertIn("香港直连_HK_🇭🇰", sub_yaml)

    def test_1000_candidates_stress_and_name_collision_performance(self):
        """Stress test with 1000 candidates with identical names to verify collision handling."""
        candidates = [
            f"vless://uuid@10.0.{i // 256}.{i % 256}:443#SameName"
            for i in range(1000)
        ]
        sub_yaml, name_to_cand = self.validator.build_candidate_sub_yaml(candidates)

        self.assertEqual(len(name_to_cand), 1000)
        self.assertIn("SameName", name_to_cand)
        self.assertIn("SameName_2", name_to_cand)
        self.assertIn("SameName_1000", name_to_cand)


class TestAdversarialPolymorphicFormatting(unittest.TestCase):
    """Verifies polymorphic candidate formatting across various lengths and types."""

    def setUp(self):
        self.mock_client = MagicMock(spec=RouterClient)
        self.mock_client.api_url = "http://192.168.1.1:9090"
        self.mock_client.is_api_alive = AsyncMock(return_value=True)
        self.mock_client.reload_provider = AsyncMock(return_value=True)
        self.mock_client.stream_file_to_router = MagicMock(return_value=True)

        self.validator = RouterValidator(
            router_client=self.mock_client,
            config={"allowed_countries": [], "use_mux": True},
        )

    def test_polymorphic_heterogeneous_batch_with_varying_tuple_lengths(self):
        """Batch containing 1, 2, 3, 4, 5+ tuples, lists, dicts, and raw strings.
        Verifies correct latency updating and original structure preservation."""
        async def run():
            delays = {
                "T1": 15,
                "T2": 25,
                "T3": 35,
                "T4": 45,
                "T5": 55,
                "L2": 65,
                "L3": 75,
                "D1": 85,
                "D2": 95,
                "Raw": 105,
            }
            self.mock_client.probe_group_delay = AsyncMock(return_value=delays)

            candidates = [
                ("vless://uuid@1.1.1.1:443#T1",),
                ("vless://uuid@1.1.1.2:443#T2", 999.0),
                ("vless://uuid@1.1.1.3:443#T3", 999.0, "orig_t3"),
                ("vless://uuid@1.1.1.4:443#T4", 999.0, "orig_t4", "meta_t4"),
                ("vless://uuid@1.1.1.5:443#T5", 999.0, "orig_t5", "meta_t5", "extra_t5"),
                ["vless://uuid@2.2.2.1:443#L2", 888.0],
                ["vless://uuid@2.2.2.2:443#L3", 888.0, "orig_l3"],
                {"name": "D1", "type": "vless", "server": "3.3.3.1"},
                {"name": "D2", "node": "vless://uuid@3.3.3.2:443#D2"},
                "vless://uuid@4.4.4.1:443#Raw",
            ]

            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(len(res), 10)

            # T1 (1-tuple): length < 3 -> preserved as is
            self.assertEqual(res[0], ("vless://uuid@1.1.1.1:443#T1",))

            # T2 (2-tuple): length < 3 -> preserved as is
            self.assertEqual(res[1], ("vless://uuid@1.1.1.2:443#T2", 999.0))

            # T3 (3-tuple): latency updated to 35.0
            self.assertEqual(res[2], ("vless://uuid@1.1.1.3:443#T3", 35.0, "orig_t3"))

            # T4 (4-tuple): latency updated to 45.0, metadata preserved
            self.assertEqual(res[3], ("vless://uuid@1.1.1.4:443#T4", 45.0, "orig_t4", "meta_t4"))

            # T5 (5-tuple): latency updated to 55.0, all extra fields preserved
            self.assertEqual(res[4], ("vless://uuid@1.1.1.5:443#T5", 55.0, "orig_t5", "meta_t5", "extra_t5"))

            # L2 (2-list): length < 3 -> preserved as is
            self.assertEqual(res[5], ["vless://uuid@2.2.2.1:443#L2", 888.0])

            # L3 (3-list): latency updated to 75.0, metadata preserved
            self.assertEqual(res[6], ["vless://uuid@2.2.2.2:443#L3", 75.0, "orig_l3"])

            # D1 (dict with type): preserved as dict
            self.assertEqual(res[7], {"name": "D1", "type": "vless", "server": "3.3.3.1"})

            # D2 (dict with node): preserved as dict
            self.assertEqual(res[8], {"name": "D2", "node": "vless://uuid@3.3.3.2:443#D2"})

            # Raw (string): preserved as string
            self.assertEqual(res[9], "vless://uuid@4.4.4.1:443#Raw")

        asyncio.run(run())


class TestAdversarialNetworkCascades(IsolatedAsyncioTestCase):
    """Stress tests on network failure modes: 500/502/429 cascades, timeouts, and TCP resets."""

    async def asyncSetUp(self):
        self.port_rest = get_ephemeral_port()

        self.rest_status = 200
        self.reload_status = 204
        self.delay_status = 200
        self.abort_delay_connection = False

        self.rest_app = web.Application()
        self.rest_app.router.add_get("/version", self._handle_version)
        self.rest_app.router.add_put("/providers/proxies/{name}", self._handle_reload)
        self.rest_app.router.add_get("/group/{name}/delay", self._handle_delay)

        self.rest_runner = web.AppRunner(self.rest_app)
        await self.rest_runner.setup()
        self.rest_site = web.TCPSite(self.rest_runner, "127.0.0.1", self.port_rest)
        await self.rest_site.start()

    async def asyncTearDown(self):
        try:
            await asyncio.wait_for(self.rest_runner.cleanup(), timeout=0.2)
        except Exception:
            pass

    async def _handle_version(self, request):
        if self.rest_status != 200:
            return web.Response(status=self.rest_status)
        return web.json_response({"version": "v1.19.30"})

    async def _handle_reload(self, request):
        if self.reload_status != 204:
            return web.Response(status=self.reload_status)
        return web.Response(status=204)

    async def _handle_delay(self, request):
        if self.abort_delay_connection:
            request.transport.close()
            return web.Response(status=500)
        if self.delay_status != 200:
            return web.Response(status=self.delay_status, text="Error")
        return web.json_response({"Node1": 40, "Node2": 50})

    async def test_rest_api_reload_500_502_429_graceful_fallback(self):
        """REST API returning HTTP 500, 502, or 429 during reload falls back cleanly."""
        client = RouterClient(host="127.0.0.1", api_port=self.port_rest)
        client.stream_file_to_router = lambda content, path, mode="0644": True

        validator = RouterValidator(
            router_client=client,
            fallback_on_unreachable=True,
        )

        candidates = ["vless://uuid@1.1.1.1:443#Node1", "vless://uuid@2.2.2.2:443#Node2"]

        for bad_code in [500, 502, 503, 429]:
            self.reload_status = bad_code
            res = await validator.verify_nodes_on_router(candidates)
            # In fallback mode, candidate nodes are returned safely
            self.assertEqual(res, candidates)

        # Once the router answers again, both nodes pass on the WAN delay probe.
        self.reload_status = 204
        self.assertEqual(await validator.verify_nodes_on_router(candidates), candidates)

    async def test_rest_api_delay_probe_500_or_abrupt_disconnect(self):
        """REST API returning HTTP 500 or abrupt connection drop during delay probe drops dead nodes."""
        client = RouterClient(host="127.0.0.1", api_port=self.port_rest)
        client.stream_file_to_router = lambda content, path, mode="0644": True

        validator = RouterValidator(router_client=client)
        candidates = ["vless://uuid@1.1.1.1:443#Node1"]

        # Case 1: HTTP 500
        self.delay_status = 500
        res = await validator.verify_nodes_on_router(candidates)
        self.assertEqual(res, [])
        self.assertIn("Node1", validator.wan_unreachable_dropped)

        # Case 2: Abrupt socket close
        validator.wan_unreachable_dropped.clear()
        self.abort_delay_connection = True
        res = await validator.verify_nodes_on_router(candidates)
        self.assertEqual(res, [])
        self.assertIn("Node1", validator.wan_unreachable_dropped)

    async def test_router_unreachable_strict_vs_fallback(self):
        """When router is down, fallback=True returns candidates, fallback=False raises RouterUnreachableError."""
        # Point to closed port
        closed_port = get_ephemeral_port()
        client = RouterClient(host="127.0.0.1", api_port=closed_port)

        # Fallback True
        val_fallback = RouterValidator(router_client=client, fallback_on_unreachable=True)
        cands = ["vless://uuid@1.1.1.1:443#Node1"]
        res = await val_fallback.verify_nodes_on_router(cands)
        self.assertEqual(res, cands)

        # Fallback False
        val_strict = RouterValidator(router_client=client, fallback_on_unreachable=False)
        with self.assertRaises(RouterUnreachableError):
            await val_strict.verify_nodes_on_router(cands)


class TestAdversarialE2EStagedWorkflowIntegration(IsolatedAsyncioTestCase):
    """Full end-to-end staged pipeline simulation testing mixed polymorphic candidates
    and WAN-dead node elimination via an ephemeral mock REST API."""

    async def asyncSetUp(self):
        self.port_rest = get_ephemeral_port()

        self.rest_app = web.Application()
        self.rest_app.router.add_get("/version", self._handle_version)
        self.rest_app.router.add_put("/providers/proxies/{name}", self._handle_reload)
        self.rest_app.router.add_get("/group/{name}/delay", self._handle_delay)

        self.rest_runner = web.AppRunner(self.rest_app)
        await self.rest_runner.setup()
        self.rest_site = web.TCPSite(self.rest_runner, "127.0.0.1", self.port_rest)
        await self.rest_site.start()

    async def asyncTearDown(self):
        try:
            await asyncio.wait_for(self.rest_runner.cleanup(), timeout=0.2)
        except Exception:
            pass

    async def _handle_version(self, request):
        return web.json_response({"version": "v1.19.30"})

    async def _handle_reload(self, request):
        return web.Response(status=204)

    async def _handle_delay(self, request):
        # Return delays for all nodes except dead and unlisted ones
        delays = {
            "NodeValid_Tuple": 32,
            "NodeValid_Dict": 42,
            "NodeValid_List": 52,
            "NodeValid_Str": 62,
            "NodeDead_WAN": 0,
            "NodeDead_Dict": 0,
        }
        return web.json_response(delays)

    async def test_full_staged_lifecycle_with_mixed_polymorphism_and_dead_nodes(self):
        """Exercises complete Stage 2 verification lifecycle with mixed polymorphic input,
        verifying that:
        1. WAN-dead and unlisted nodes across varying types are eliminated during the delay probe.
        2. Valid surviving nodes preserve their exact original types (tuple, dict, list, str).
        3. Tuple and list survivors have their latencies updated accurately.
        """
        client = RouterClient(
            host="127.0.0.1",
            api_port=self.port_rest,
        )
        client.stream_file_to_router = lambda content, path, mode="0644": True

        validator = RouterValidator(router_client=client, config={})

        candidates = [
            ("vless://uuid@1.1.1.1:443#NodeValid_Tuple", 999.0, "orig_tuple_extra"),
            {"name": "NodeValid_Dict", "type": "vless", "server": "2.2.2.2"},
            ["vless://uuid@3.3.3.3:443#NodeValid_List", 888.0, "orig_list_extra"],
            "vless://uuid@4.4.4.4:443#NodeValid_Str",
            "vless://uuid@5.5.5.5:443#NodeDead_WAN",
            ("vless://uuid@6.6.6.6:443#NodeUnlisted_Tuple", 999.0, "orig_unlisted"),
            {"name": "NodeDead_Dict", "type": "vless", "server": "7.7.7.7"},
            ["vless://uuid@8.8.8.8:443#NodeUnlisted_List", 888.0, "orig_list"],
        ]

        verified = await validator.verify_nodes_on_router(candidates)

        # 1. Dead and unlisted nodes were dropped during the delay probe
        self.assertEqual(
            validator.wan_unreachable_dropped,
            ["NodeDead_WAN", "NodeUnlisted_Tuple", "NodeDead_Dict", "NodeUnlisted_List"],
        )

        # 2. Exactly 4 valid nodes survived
        self.assertEqual(len(verified), 4)
        self.assertEqual(validator.last_verified_nodes, verified)

        # 3. Check exact types and updated latencies of survivors
        # Item 0: Tuple with updated latency 32.0
        self.assertIsInstance(verified[0], tuple)
        self.assertEqual(verified[0], ("vless://uuid@1.1.1.1:443#NodeValid_Tuple", 32.0, "orig_tuple_extra"))

        # Item 1: Dict preserved as dict
        self.assertIsInstance(verified[1], dict)
        self.assertEqual(verified[1], {"name": "NodeValid_Dict", "type": "vless", "server": "2.2.2.2"})

        # Item 2: List with updated latency 52.0
        self.assertIsInstance(verified[2], list)
        self.assertEqual(verified[2], ["vless://uuid@3.3.3.3:443#NodeValid_List", 52.0, "orig_list_extra"])

        # Item 3: String preserved as string
        self.assertIsInstance(verified[3], str)
        self.assertEqual(verified[3], "vless://uuid@4.4.4.4:443#NodeValid_Str")


class TestAdversarialRouterClientLifecycle(IsolatedAsyncioTestCase):
    """Stress tests on RouterClient session lifecycle, context managers, and IPv6 formatting."""

    async def test_router_client_context_manager_reentrancy_and_cleanup(self):
        """RouterClient context manager cleanly opens, uses, and closes session."""
        port = get_ephemeral_port()
        client = RouterClient(host="127.0.0.1", api_port=port)

        self.assertIsNone(client.session)
        self.assertFalse(client._owned_session)

        async with client:
            self.assertIsNotNone(client.session)
            self.assertFalse(client.session.closed)
            self.assertTrue(client._owned_session)

        self.assertTrue(client.session is None or client.session.closed)
        self.assertFalse(client._owned_session)

    async def test_router_client_external_session_not_closed(self):
        """When an external ClientSession is provided, RouterClient does NOT close it on exit."""
        port = get_ephemeral_port()
        ext_session = aiohttp.ClientSession()
        try:
            client = RouterClient(host="127.0.0.1", api_port=port, session=ext_session)
            async with client:
                self.assertIs(client.session, ext_session)
                self.assertFalse(client._owned_session)

            self.assertFalse(ext_session.closed)
        finally:
            await ext_session.close()

    def test_router_client_ipv6_url_formatting_fidelity(self):
        """IPv6 hosts are properly bracketed in API and proxy URLs."""
        # Unbracketed IPv6
        client1 = RouterClient(host="2001:db8::1", api_port=9090, proxy_port=7890)
        self.assertEqual(client1.api_url, "http://[2001:db8::1]:9090")
        self.assertEqual(client1.proxy_url, "http://[2001:db8::1]:7890")

        # Already-bracketed IPv6
        client2 = RouterClient(host="[2001:db8::1]", api_port=9090, proxy_port=7890)
        self.assertEqual(client2.api_url, "http://[2001:db8::1]:9090")
        self.assertEqual(client2.proxy_url, "http://[2001:db8::1]:7890")

        # IPv4
        client3 = RouterClient(host="192.168.1.1", api_port=9090, proxy_port=7890)
        self.assertEqual(client3.api_url, "http://192.168.1.1:9090")


class TestAdversarialConcurrencyGuardrails(IsolatedAsyncioTestCase):
    """AGENTS.md Concurrency & Stream Teardown Rule Compliance."""

    async def test_ephemeral_port_allocation_kernel_binding(self):
        """Verify dynamic ephemeral port allocation provides valid unique unprivileged ports."""
        ports = [get_ephemeral_port() for _ in range(20)]
        self.assertEqual(len(ports), 20)
        # All ports must be valid unprivileged ports (> 1024)
        for p in ports:
            self.assertGreater(p, 1024)
            self.assertLessEqual(p, 65535)

    async def test_safe_writer_stream_teardown_rule_compliance(self):
        """Verify safe writer stream teardown with timeout <= 0.2s succeeds without hanging."""
        server_port = get_ephemeral_port()

        async def handle_client(reader, writer):
            # Read 4 bytes then close
            await reader.read(4)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            except Exception:
                pass

        server = await asyncio.start_server(handle_client, "127.0.0.1", server_port)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
            writer.write(b"test")
            await writer.drain()
            writer.close()
            # AGENTS.md rule: must wrap in timeout <= 0.2
            await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
