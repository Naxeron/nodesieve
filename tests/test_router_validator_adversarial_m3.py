"""Adversarial stress testing for Milestone 3 (RouterValidator).

Adversarially tests:
1. Concurrency:
   - 100 concurrent callers on single-attempt cache lock (is_router_alive)
   - Exception handling and cancellation under lock (zero deadlocks)
2. AGENTS.md guardrails:
   - Dynamic ephemeral port allocation via socket binding
   - Stream teardown safety with 0.2s timeout
   - Zero ResourceWarning / socket leaks
3. Robustness & edge cases:
   - Heavy duplicate candidate name collisions (50+ identical names)
   - Polymorphic candidate inputs (tuples, strings, dicts)
"""

import asyncio
import itertools
import socket
import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock

from aiohttp import web

from nodesieve.core.router_validator import RouterValidator
from nodesieve.router.client import RouterClient


def get_ephemeral_port() -> int:
    """Dynamically requests an available free port from OS kernel."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRouterValidatorAdversarialConcurrency(unittest.TestCase):
    """Stress tests for concurrency locks and candidate handling."""

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

    def test_single_attempt_lock_100_concurrent_callers(self):
        """100 concurrent callers trigger exactly 1 is_router_alive probe."""
        async def run():
            probe_count = 0

            async def mock_is_alive():
                nonlocal probe_count
                probe_count += 1
                await asyncio.sleep(0.05)  # Simulate network latency
                return True

            self.mock_client.is_api_alive.side_effect = mock_is_alive
            self.validator.reset_alive_cache()

            tasks = [
                asyncio.create_task(self.validator.is_router_alive())
                for _ in range(100)
            ]
            results = await asyncio.gather(*tasks)

            self.assertEqual(len(results), 100)
            self.assertTrue(all(results))
            self.assertEqual(probe_count, 1)
            self.assertTrue(self.validator._alive_attempted)
            self.assertTrue(self.validator._is_alive)

            # Subsequent 50 calls should return cached True immediately
            more_tasks = [
                asyncio.create_task(self.validator.is_router_alive())
                for _ in range(50)
            ]
            more_results = await asyncio.gather(*more_tasks)
            self.assertTrue(all(more_results))
            self.assertEqual(probe_count, 1)

        asyncio.run(run())

    def test_single_attempt_lock_on_network_exception_no_deadlock(self):
        """On exception, flag is set in finally and all tasks return False."""
        async def run():
            probe_count = 0

            async def mock_failing_is_alive():
                nonlocal probe_count
                probe_count += 1
                await asyncio.sleep(0.02)
                raise ConnectionResetError("Mihomo REST connection reset")

            self.mock_client.is_api_alive.side_effect = mock_failing_is_alive
            self.validator.reset_alive_cache()

            tasks = [
                asyncio.create_task(self.validator.is_router_alive())
                for _ in range(50)
            ]
            results = await asyncio.gather(*tasks)

            self.assertEqual(len(results), 50)
            self.assertTrue(all(r is False for r in results))
            self.assertEqual(probe_count, 1)
            self.assertTrue(self.validator._alive_attempted)
            self.assertFalse(self.validator._is_alive)

        asyncio.run(run())

    def test_single_attempt_lock_cancellation_resilience(self):
        """Cancelling waiting tasks does not poison lock for other callers."""
        async def run():
            async def slow_is_alive():
                await asyncio.sleep(0.1)
                return True

            self.mock_client.is_api_alive.side_effect = slow_is_alive
            self.validator.reset_alive_cache()

            t1 = asyncio.create_task(self.validator.is_router_alive())
            t2 = asyncio.create_task(self.validator.is_router_alive())
            t3 = asyncio.create_task(self.validator.is_router_alive())

            # Cancel t2 while it is waiting on lock
            await asyncio.sleep(0.01)
            t2.cancel()

            res1 = await t1
            self.assertTrue(res1)
            with self.assertRaises(asyncio.CancelledError):
                await t2

            res3 = await t3
            self.assertTrue(res3)

        asyncio.run(run())

    def test_candidate_name_collision_disambiguation_stress(self):
        """50 candidate nodes with identical names are disambiguated."""
        candidates = [
            f"vless://uuid@{i}.1.1.1:443#DupeNode" for i in range(50)
        ]
        sub_yaml, name_to_cand = self.validator.build_candidate_sub_yaml(
            candidates
        )

        self.assertEqual(len(name_to_cand), 50)
        # All 50 original candidates must be preserved
        self.assertEqual(len(set(name_to_cand.values())), 50)
        self.assertIn("DupeNode", name_to_cand)
        self.assertIn("DupeNode_2", name_to_cand)
        self.assertIn("DupeNode_50", name_to_cand)

    def test_polymorphic_candidate_input_crash_on_heterogeneous_dict(self):
        """Heterogeneous list (tuple then dict) succeeds without KeyError."""
        async def run():
            delays = {
                "NodeTuple": 35,
                "NodeDict": 45,
            }
            self.mock_client.probe_group_delay.return_value = delays

            candidates = [
                ("vless://uuid@1.1.1.1:443#NodeTuple", 999.0, "extra"),
                {"name": "NodeDict", "type": "vless", "server": "2.2.2.2"},
            ]

            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(len(res), 2)
            self.assertEqual(
                res[0],
                ("vless://uuid@1.1.1.1:443#NodeTuple", 35.0, "extra"),
            )
            self.assertEqual(
                res[1],
                {"name": "NodeDict", "type": "vless", "server": "2.2.2.2"},
            )

        asyncio.run(run())

    def test_polymorphic_input_string_corruption_demonstration(self):
        """Strings after a tuple remain original URL strings without
        corruption."""
        async def run():
            delays = {
                "NodeTuple": 35,
                "NodeStr": 55,
            }
            self.mock_client.probe_group_delay.return_value = delays

            candidates = [
                ("vless://uuid@1.1.1.1:443#NodeTuple", 999.0, "extra"),
                "vless://uuid@3.3.3.3:443#NodeStr",
            ]

            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(len(res), 2)
            self.assertEqual(
                res[0],
                ("vless://uuid@1.1.1.1:443#NodeTuple", 35.0, "extra"),
            )
            self.assertEqual(res[1], "vless://uuid@3.3.3.3:443#NodeStr")

        asyncio.run(run())

    def test_polymorphic_input_latency_not_updated_when_tuple_after_dict(self):
        """Tuples following a dict have their latency updated correctly."""
        async def run():
            delays = {
                "NodeDict": 35,
                "NodeTuple": 55,
            }
            self.mock_client.probe_group_delay.return_value = delays

            candidates = [
                {"name": "NodeDict", "type": "vless", "server": "2.2.2.2"},
                ("vless://uuid@1.1.1.1:443#NodeTuple", 999.0, "extra"),
            ]

            res = await self.validator.verify_nodes_on_router(candidates)
            self.assertEqual(len(res), 2)
            self.assertEqual(
                res[0],
                {"name": "NodeDict", "type": "vless", "server": "2.2.2.2"},
            )
            self.assertEqual(
                res[1],
                ("vless://uuid@1.1.1.1:443#NodeTuple", 55.0, "extra"),
            )

        asyncio.run(run())

    def test_polymorphic_all_permutations_and_empty_lists(self):
        """Tests all pairwise permutations, full 4-type permutations, and empty
        lists without KeyError or corruption, ensuring accurate latencies."""
        async def run():
            c_tuple = (
                "vless://uuid@1.1.1.1:443#NodeTuple",
                999.0,
                "orig_tuple",
                "extra_meta",
            )
            c_dict = {
                "name": "NodeDict",
                "type": "vless",
                "server": "2.2.2.2",
            }
            c_list = [
                "vless://uuid@3.3.3.3:443#NodeList",
                888.0,
                "orig_list",
                "extra_list_meta",
            ]
            c_str = "vless://uuid@4.4.4.4:443#NodeStr"

            items = {
                "tuple": c_tuple,
                "dict": c_dict,
                "list": c_list,
                "str": c_str,
            }
            delays = {
                "NodeTuple": 25,
                "NodeDict": 35,
                "NodeList": 45,
                "NodeStr": 55,
            }

            self.mock_client.probe_group_delay.return_value = delays

            # All 6 required pair permutations
            pairs = [
                ("dict", "tuple"),
                ("str", "tuple"),
                ("tuple", "str"),
                ("tuple", "dict"),
                ("list", "tuple"),
                ("tuple", "list"),
            ]

            for p1, p2 in pairs:
                cands = [items[p1], items[p2]]
                res = await self.validator.verify_nodes_on_router(cands)
                self.assertEqual(len(res), 2)
                for idx, p in enumerate([p1, p2]):
                    r = res[idx]
                    if p == "tuple":
                        self.assertIsInstance(r, tuple)
                        self.assertEqual(r[1], 25.0)
                        self.assertEqual(
                            r[2:], ("orig_tuple", "extra_meta")
                        )
                    elif p == "list":
                        self.assertIsInstance(r, list)
                        self.assertEqual(r[1], 45.0)
                        self.assertEqual(
                            r[2:], ["orig_list", "extra_list_meta"]
                        )
                    elif p == "dict":
                        self.assertIsInstance(r, dict)
                        self.assertEqual(r, c_dict)
                    elif p == "str":
                        self.assertIsInstance(r, str)
                        self.assertEqual(r, c_str)

            # All 24 permutations of the 4 types
            for perm in itertools.permutations(
                ["tuple", "dict", "list", "str"]
            ):
                cands = [items[k] for k in perm]
                res = await self.validator.verify_nodes_on_router(cands)
                self.assertEqual(len(res), 4)
                for idx, k in enumerate(perm):
                    r = res[idx]
                    if k == "tuple":
                        self.assertIsInstance(r, tuple)
                        self.assertEqual(r[1], 25.0)
                        self.assertEqual(
                            r[2:], ("orig_tuple", "extra_meta")
                        )
                    elif k == "list":
                        self.assertIsInstance(r, list)
                        self.assertEqual(r[1], 45.0)
                        self.assertEqual(
                            r[2:], ["orig_list", "extra_list_meta"]
                        )
                    elif k == "dict":
                        self.assertIsInstance(r, dict)
                        self.assertEqual(r, c_dict)
                    elif k == "str":
                        self.assertIsInstance(r, str)
                        self.assertEqual(r, c_str)

            # Empty list
            empty_res = await self.validator.verify_nodes_on_router([])
            self.assertEqual(empty_res, [])

        asyncio.run(run())

    def test_polymorphic_500_plus_heterogeneous_candidates(self):
        """Stress-tests 600 heterogeneous candidates of mixed types
        and lengths, verifying 100% metric fidelity."""
        async def run():
            num_candidates = 600
            candidates = []
            expected_survivors = []
            delays = {}

            for i in range(num_candidates):
                cand_type = i % 4
                node_name = f"Node_{i:04d}"
                oct2 = i % 250
                oct3 = i % 250
                url = f"vless://uuid@{i}.{oct2}.{oct3}.1:443#{node_name}"
                delay_val = 10.0 + (i % 200)

                # 1 in 6 is dead (delay 0)
                if i % 6 == 0:
                    delays[node_name] = 0
                    is_alive = False
                else:
                    delays[node_name] = delay_val
                    is_alive = True

                if cand_type == 0:
                    extra_len = i % 3
                    if extra_len == 0:
                        item = (url, 999.0, f"orig_{i}")
                        expected = (url, float(delay_val), f"orig_{i}")
                    elif extra_len == 1:
                        item = (url, 999.0, f"orig_{i}", f"extra1_{i}")
                        expected = (
                            url,
                            float(delay_val),
                            f"orig_{i}",
                            f"extra1_{i}",
                        )
                    else:
                        item = (
                            url,
                            999.0,
                            f"orig_{i}",
                            f"extra1_{i}",
                            f"extra2_{i}",
                        )
                        expected = (
                            url,
                            float(delay_val),
                            f"orig_{i}",
                            f"extra1_{i}",
                            f"extra2_{i}",
                        )
                elif cand_type == 1:
                    if i % 2 == 0:
                        item = [url, 888.0, f"orig_{i}"]
                        expected = [url, float(delay_val), f"orig_{i}"]
                    else:
                        item = [url, 888.0, f"orig_{i}", f"extra_{i}"]
                        expected = [
                            url,
                            float(delay_val),
                            f"orig_{i}",
                            f"extra_{i}",
                        ]
                elif cand_type == 2:
                    if i % 3 == 0:
                        item = {
                            "name": node_name,
                            "type": "vless",
                            "server": f"1.1.{i}.1",
                            0: "int_key",
                        }
                    else:
                        item = {
                            "name": node_name,
                            "type": "vless",
                            "server": f"1.1.{i}.1",
                        }
                    expected = item
                else:
                    item = url
                    expected = url

                candidates.append(item)
                if is_alive:
                    expected_survivors.append(
                        (node_name, cand_type, expected)
                    )

            self.mock_client.probe_group_delay.return_value = delays

            res = await self.validator.verify_nodes_on_router(candidates)

            self.assertEqual(len(res), len(expected_survivors))
            self.assertEqual(len(res), 500)
            self.assertEqual(len(self.validator.wan_unreachable_dropped), 100)

            for idx, (node_name, cand_type, exp) in enumerate(
                expected_survivors
            ):
                actual = res[idx]
                if cand_type == 0:
                    self.assertIsInstance(actual, tuple)
                    self.assertEqual(actual, exp)
                    self.assertIsInstance(actual[1], float)
                elif cand_type == 1:
                    self.assertIsInstance(actual, list)
                    self.assertEqual(actual, exp)
                    self.assertIsInstance(actual[1], float)
                elif cand_type == 2:
                    self.assertIsInstance(actual, dict)
                    self.assertEqual(actual, exp)
                elif cand_type == 3:
                    self.assertIsInstance(actual, str)
                    self.assertEqual(actual, exp)

        asyncio.run(run())


class TestRouterValidatorEphemeralMockSafety(IsolatedAsyncioTestCase):
    """Stress tests on ephemeral ports with ResourceWarning safety."""

    async def asyncSetUp(self):
        self.port_rest = get_ephemeral_port()
        self.requests = []

        self.rest_app = web.Application()
        self.rest_app.router.add_get("/version", self._handle_version)
        self.rest_app.router.add_put(
            "/providers/proxies/{name}", self._handle_reload
        )
        self.rest_app.router.add_get(
            "/group/{name}/delay", self._handle_delay
        )

        self.rest_runner = web.AppRunner(self.rest_app)
        await self.rest_runner.setup()
        self.rest_site = web.TCPSite(
            self.rest_runner, "127.0.0.1", self.port_rest
        )
        await self.rest_site.start()

    async def asyncTearDown(self):
        # AGENTS.md: Safe stream teardown with 0.2s timeout
        try:
            await asyncio.wait_for(self.rest_runner.cleanup(), timeout=0.2)
        except Exception:
            pass

    async def _handle_version(self, request):
        self.requests.append("version")
        return web.json_response({"version": "v1.19.30"})

    async def _handle_reload(self, request):
        self.requests.append("reload")
        return web.Response(status=204)

    async def _handle_delay(self, request):
        self.requests.append("delay")
        return web.json_response(
            {
                "NodeGood_1": 40,
                "NodeGood_2": 50,
                "NodeDead": 0,
            }
        )

    async def test_ephemeral_stress_workflow_and_session_cleanup(self):
        """Execute full Stage 2 lifecycle with an ephemeral mock server."""
        client = RouterClient(
            host="127.0.0.1",
            api_port=self.port_rest,
        )
        client.stream_file_to_router = lambda content, path, mode="0644": True

        validator = RouterValidator(router_client=client, config={})

        candidates = [
            "vless://uuid@1.1.1.1:443#NodeGood_1",
            "vless://uuid@2.2.2.2:443#NodeGood_2",
            "vless://uuid@4.4.4.4:443#NodeDead",
        ]

        for _ in range(5):
            verified = await validator.verify_nodes_on_router(candidates)
            # NodeDead is dropped during delay probe; the others survive
            self.assertEqual(
                verified,
                [
                    "vless://uuid@1.1.1.1:443#NodeGood_1",
                    "vless://uuid@2.2.2.2:443#NodeGood_2",
                ],
            )
        self.assertEqual(validator.wan_unreachable_dropped, ["NodeDead"] * 5)
        # Reachability is probed once; every run stages, reloads and probes.
        self.assertEqual(self.requests, ["version"] + ["reload", "delay"] * 5)
        # The validator owns no HTTP session; the client closed each of its own.
        self.assertIsNone(client.session)


if __name__ == "__main__":
    unittest.main()
