"""Comprehensive test suite for RouterValidator.

Covers unit, isolation, and ephemeral mock subsystem integration tests:
- Offline router fallback (graceful and strict)
- Empty candidate list handling
- Stream file & reload provider error handling
- Delay probe dead node filtering through the router WAN
- Input polymorphism (tuples, strings, dicts)
- AGENTS.md concurrency single-attempt lock pattern
- Ephemeral mock REST API integration
"""

import asyncio
import socket
import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock

from aiohttp import web

from proxy_sites.core.router_validator import (
    RouterUnreachableError,
    RouterValidator,
)
from proxy_sites.router.client import RouterClient


def get_ephemeral_port() -> int:
    """Dynamically requests an available free port from OS kernel."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRouterValidatorUnit(unittest.TestCase):
    """Exhaustive unit test suite using a mock RouterClient."""

    def setUp(self):
        self.mock_client = MagicMock(spec=RouterClient)
        self.mock_client.api_url = "http://192.168.1.1:9090"
        self.mock_client.proxy_url = "http://192.168.1.1:7890"
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

    def test_verify_empty_candidate_nodes(self):
        """Empty input returns [] immediately without invoking router."""
        async def run():
            res = await self.validator.verify_nodes_on_router([])
            self.assertEqual(res, [])
            self.mock_client.is_api_alive.assert_not_called()
            self.mock_client.stream_file_to_router.assert_not_called()
            self.mock_client.reload_provider.assert_not_called()

        asyncio.run(run())

    def test_verify_offline_router_api_graceful_fallback(self):
        """When router API is offline, gracefully returns candidate nodes."""
        async def run():
            self.mock_client.is_api_alive.return_value = False
            candidates = [
                "vless://uuid@1.1.1.1:443#NodeA",
                "vless://uuid@2.2.2.2:443#NodeB",
            ]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, candidates)
            self.mock_client.stream_file_to_router.assert_not_called()

        asyncio.run(run())

    def test_verify_offline_router_strict_exception(self):
        """When fallback_on_unreachable=False, raises RouterUnreachable."""
        async def run():
            self.mock_client.is_api_alive.return_value = False
            validator = RouterValidator(
                router_client=self.mock_client,
                config=self.config,
                fallback_on_unreachable=False,
            )
            with self.assertRaises(RouterUnreachableError):
                await validator.verify_nodes_on_router(
                    ["vless://uuid@1.1.1.1:443#NodeA"]
                )

        asyncio.run(run())

    def test_verify_offline_router_ssh_graceful_fallback(self):
        """SSH stream exception triggers graceful fallback to candidates."""
        async def run():
            self.mock_client.stream_file_to_router.side_effect = (
                RuntimeError("SSH Connection Dropped")
            )
            candidates = ["vless://uuid@1.1.1.1:443#NodeA"]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, candidates)
            self.mock_client.reload_provider.assert_not_called()

        asyncio.run(run())

    def test_verify_stream_file_failure_fallback(self):
        """stream_file_to_router returning False triggers graceful fallback."""
        async def run():
            self.mock_client.stream_file_to_router.return_value = False
            candidates = ["vless://uuid@1.1.1.1:443#NodeA"]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, candidates)
            self.mock_client.reload_provider.assert_not_called()

        asyncio.run(run())

    def test_verify_reload_provider_failure_fallback(self):
        """reload_provider failure triggers graceful fallback."""
        async def run():
            self.mock_client.reload_provider.return_value = False
            candidates = ["vless://uuid@1.1.1.1:443#NodeA"]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, candidates)
            self.mock_client.probe_group_delay.assert_not_called()

        asyncio.run(run())

    def test_verify_delay_probe_all_timeout(self):
        """When all nodes timeout on router WAN, returns empty list."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {
                "NodeA": 0,
                "NodeB": 0,
            }
            candidates = [
                "vless://uuid@1.1.1.1:443#NodeA",
                "vless://uuid@2.2.2.2:443#NodeB",
            ]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, [])
            self.assertEqual(len(self.validator.wan_unreachable_dropped), 2)
            self.assertEqual(self.validator.last_verified_nodes, [])

        asyncio.run(run())

    def test_verify_delay_probe_partial_alive(self):
        """Dead WAN nodes are filtered out; live ones survive on the probe alone."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {
                "NodeA": 65,
                "NodeB": 0,
            }
            candidates = [
                "vless://uuid@1.1.1.1:443#NodeA",
                "vless://uuid@2.2.2.2:443#NodeB",
            ]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, ["vless://uuid@1.1.1.1:443#NodeA"])
            self.assertEqual(self.validator.wan_unreachable_dropped, ["NodeB"])
            self.assertEqual(self.validator.last_verified_nodes, res)
            self.mock_client.reload_provider.assert_awaited_once_with("Gemini_Nodes")
            self.mock_client.probe_group_delay.assert_awaited_once_with(
                "Gemini_Auto",
                url="https://www.gstatic.com/generate_204",
                timeout_ms=3000,
            )

        asyncio.run(run())

    def test_verify_delay_probe_exception_and_missing_or_invalid_delays(self):
        """Probe errors, absent names and non-positive delays all count as dead."""
        async def run():
            candidates = [
                "vless://uuid@1.1.1.1:443#NodeA",
                "vless://uuid@2.2.2.2:443#NodeB",
                "vless://uuid@3.3.3.3:443#NodeC",
            ]
            self.mock_client.probe_group_delay.return_value = {
                "NodeA": -1,
                "NodeB": None,
                "Unrelated": 20,
            }
            self.assertEqual(
                await self.validator.verify_nodes_on_router(candidates), []
            )
            self.assertEqual(
                self.validator.wan_unreachable_dropped,
                ["NodeA", "NodeB", "NodeC"],
            )
            self.mock_client.probe_group_delay.side_effect = RuntimeError(
                "connection reset"
            )
            self.assertEqual(
                await self.validator.verify_nodes_on_router(candidates), []
            )

        asyncio.run(run())

    def test_verify_uploads_candidates_before_reloading_the_provider(self):
        """The staged sub.yaml carries every candidate under its node name."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {"NodeA": 42}
            candidate = "vless://uuid@1.1.1.1:443?security=tls&sni=a.example#NodeA"
            res = await self.validator.verify_nodes_on_router([candidate])
            self.assertEqual(res, [candidate])
            content, path = self.mock_client.stream_file_to_router.call_args.args
            self.assertEqual(path, "/etc/mihomo/proxy-providers/sub.yaml")
            self.assertIn("name: NodeA", content)
            self.assertIn("server: 1.1.1.1", content)

        asyncio.run(run())

    def test_verify_multiple_mixed_candidates(self):
        """Mixed batch: nodes alive on the router WAN survive in input order."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {
                "Node_DE": 45,
                "Node_DeadWAN": 0,
                "Node_Slow": 2900,
                "Node_UK": 38,
            }
            candidates = [
                "vless://uuid@1.1.1.1:443#Node_DE",
                "vless://uuid@2.2.2.2:443#Node_DeadWAN",
                "vless://uuid@3.3.3.3:443#Node_Slow",
                "vless://uuid@4.4.4.4:443#Node_Missing",
                "vless://uuid@5.5.5.5:443#Node_UK",
            ]
            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(res, [candidates[0], candidates[2], candidates[4]])
            self.assertEqual(
                self.validator.wan_unreachable_dropped,
                ["Node_DeadWAN", "Node_Missing"],
            )

        asyncio.run(run())

    def test_polymorphic_input_preservation_tuples_strings_dicts(self):
        """Input types (tuples, strings, dicts) are preserved upon return."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {
                "NodeTuple": 40,
                "NodeStr": 50,
                "NodeDict": 60,
            }

            # Tuple format (url, latency, orig)
            t_input = [
                ("vless://uuid@1.1.1.1:443#NodeTuple", 999.0, "orig")
            ]
            t_res = await self.validator.verify_nodes_on_router(t_input)
            self.assertIsInstance(t_res[0], tuple)
            self.assertEqual(
                t_res[0][0], "vless://uuid@1.1.1.1:443#NodeTuple"
            )
            self.assertEqual(t_res[0][1], 40.0)  # updated router WAN delay
            self.assertEqual(t_res[0][2], "orig")

            # String format
            s_input = ["vless://uuid@2.2.2.2:443#NodeStr"]
            s_res = await self.validator.verify_nodes_on_router(s_input)
            self.assertEqual(s_res, s_input)

            # Dict format
            d_input = [
                {"name": "NodeDict", "type": "vless", "server": "3.3.3.3"}
            ]
            d_res = await self.validator.verify_nodes_on_router(d_input)
            self.assertIsInstance(d_res[0], dict)
            self.assertEqual(d_res[0]["name"], "NodeDict")

        asyncio.run(run())

    def test_verify_mixed_polymorphic_batch_preservation_and_latency(self):
        """A single batch containing tuples, dicts, lists, and strings is
        handled cleanly without KeyError or corruption, with tuple/list latency
        updated to router WAN delay."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {
                "NodeTuple": 40,
                "NodeDict": 50,
                "NodeList": 60,
                "NodeStr": 70,
            }

            batch_input = [
                (
                    "vless://uuid@1.1.1.1:443#NodeTuple",
                    999.0,
                    "orig_tuple",
                    "extra_meta",
                ),
                {
                    "name": "NodeDict",
                    "type": "vless",
                    "server": "2.2.2.2",
                },
                [
                    "vless://uuid@3.3.3.3:443#NodeList",
                    888.0,
                    "orig_list",
                ],
                "vless://uuid@4.4.4.4:443#NodeStr",
            ]

            res = await self.validator.verify_nodes_on_router(batch_input)
            self.assertEqual(len(res), 4)

            # 1. Tuple item: preserved as tuple, latency updated to 40.0
            self.assertIsInstance(res[0], tuple)
            self.assertEqual(
                res[0][0], "vless://uuid@1.1.1.1:443#NodeTuple"
            )
            self.assertEqual(res[0][1], 40.0)
            self.assertEqual(res[0][2:], ("orig_tuple", "extra_meta"))

            # 2. Dict item: preserved as dict, no KeyError: 0
            self.assertIsInstance(res[1], dict)
            self.assertEqual(res[1]["name"], "NodeDict")
            self.assertEqual(res[1]["server"], "2.2.2.2")

            # 3. List item: preserved as list, latency updated to 60.0
            self.assertIsInstance(res[2], list)
            self.assertEqual(
                res[2][0], "vless://uuid@3.3.3.3:443#NodeList"
            )
            self.assertEqual(res[2][1], 60.0)
            self.assertEqual(res[2][2:], ["orig_list"])

            # 4. String item: preserved as string, no string corruption
            self.assertIsInstance(res[3], str)
            self.assertEqual(res[3], "vless://uuid@4.4.4.4:443#NodeStr")

        asyncio.run(run())

    def test_verify_mixed_polymorphic_batch_dict_preceding_tuple(self):
        """Tuples following a dict still have their latency updated."""
        async def run():
            self.mock_client.probe_group_delay.return_value = {
                "NodeDict": 45,
                "NodeTuple": 35,
            }

            batch_input = [
                {
                    "name": "NodeDict",
                    "type": "vless",
                    "server": "2.2.2.2",
                },
                (
                    "vless://uuid@1.1.1.1:443#NodeTuple",
                    999.0,
                    "extra",
                ),
            ]

            res = await self.validator.verify_nodes_on_router(batch_input)
            self.assertEqual(len(res), 2)
            self.assertIsInstance(res[0], dict)
            self.assertEqual(res[0]["name"], "NodeDict")

            self.assertIsInstance(res[1], tuple)
            self.assertEqual(
                res[1],
                ("vless://uuid@1.1.1.1:443#NodeTuple", 35.0, "extra"),
            )

        asyncio.run(run())

    def test_concurrency_single_attempt_lock_pattern(self):
        """Concurrent calls to is_router_alive execute network probe once."""
        async def run():
            call_count = 0

            async def counted_is_alive():
                nonlocal call_count
                call_count += 1
                await asyncio.sleep(0.01)
                return True

            self.mock_client.is_api_alive.side_effect = counted_is_alive
            self.validator.reset_alive_cache()

            # Launch 10 concurrent requests
            tasks = [
                asyncio.create_task(self.validator.is_router_alive())
                for _ in range(10)
            ]
            results = await asyncio.gather(*tasks)

            self.assertTrue(all(results))
            self.assertEqual(call_count, 1)

        asyncio.run(run())


class TestRouterValidatorEphemeralIntegration(IsolatedAsyncioTestCase):
    """End-to-end integration test with a dynamic ephemeral mock REST API."""

    async def asyncSetUp(self):
        self.port_rest = get_ephemeral_port()

        # Shared state
        self.sub_yaml_uploaded = ""
        self.provider_reloaded = None
        self.delay_query = None

        self.rest_app = web.Application()
        self.rest_app.router.add_get("/version", self._handle_rest_version)
        self.rest_app.router.add_put(
            "/providers/proxies/{name}", self._handle_rest_reload
        )
        self.rest_app.router.add_get(
            "/group/{name}/delay", self._handle_rest_delay
        )

        self.rest_runner = web.AppRunner(self.rest_app)
        await self.rest_runner.setup()
        self.rest_site = web.TCPSite(
            self.rest_runner, "127.0.0.1", self.port_rest
        )
        await self.rest_site.start()

    async def asyncTearDown(self):
        # Safe stream teardown with 0.2s timeout per AGENTS.md
        try:
            await asyncio.wait_for(self.rest_runner.cleanup(), timeout=0.2)
        except Exception:
            pass

    async def _handle_rest_version(self, request):
        return web.json_response({"version": "v1.19.30"})

    async def _handle_rest_reload(self, request):
        self.provider_reloaded = request.match_info["name"]
        return web.Response(status=204)

    async def _handle_rest_delay(self, request):
        self.delay_query = (request.match_info["name"], dict(request.query))
        return web.json_response(
            {
                "Node_DE": 45,
                "Node_Dead": 0,
            }
        )

    async def test_ephemeral_integration_pipeline_execution(self):
        """Full end-to-end integration across the ephemeral REST API."""
        router_client = RouterClient(
            host="127.0.0.1",
            api_port=self.port_rest,
        )

        # Mock SSH file streaming to succeed in-memory
        def mock_stream(content, path, mode="0644"):
            self.sub_yaml_uploaded = content
            return True

        router_client.stream_file_to_router = mock_stream

        validator = RouterValidator(router_client=router_client, config={})

        candidates = [
            ("vless://uuid@1.1.1.1:443#Node_DE", 900.0, "orig"),
            "vless://uuid@2.2.2.2:443#Node_Dead",
            "vless://uuid@3.3.3.3:443#Node_Unlisted",
        ]

        verified = await validator.verify_nodes_on_router(candidates)

        # Only the node answering through the router WAN survives, with its delay.
        self.assertEqual(
            verified, [("vless://uuid@1.1.1.1:443#Node_DE", 45.0, "orig")]
        )
        self.assertEqual(
            validator.wan_unreachable_dropped, ["Node_Dead", "Node_Unlisted"]
        )
        self.assertEqual(self.provider_reloaded, "Gemini_Nodes")
        self.assertEqual(self.delay_query, ("Gemini_Auto", {
            "url": "https://www.gstatic.com/generate_204", "timeout": "3000",
        }))
        self.assertIn("proxies:", self.sub_yaml_uploaded)


if __name__ == "__main__":
    unittest.main()
