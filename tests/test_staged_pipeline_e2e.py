"""Tier 3: Opaque-Box Staged Workflow Simulation.

Simulates the complete dual-stage validation pipeline:
- Stage 1: Local IP check (eliminates dead nodes and nodes in rejected exit countries)
- Stage 2: Router validation (eliminates nodes unreachable through the router WAN)
- Fallback failover parity: Google 204 vs Cloudflare 204 failover behavior
- Atomic deployment script verification (.tmp, pre-flight syntax check, rollback)
"""

import os
import socket
import tempfile
import unittest
from typing import Any, Dict, List
import yaml

from nodesieve.constants import GEOBLOCKED_REGIONS
from nodesieve.router.script_generator import generate_router_script
from nodesieve.parsers.base import get_node_name


def get_ephemeral_port() -> int:
    """Allocates a dynamic ephemeral port from OS kernel per AGENTS.md."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class StagedPipelineSimulator:
    """Opaque-box simulation of the Dual-Stage Validation Pipeline."""

    def __init__(self, simulated_router_responses: Dict[str, Dict[str, Any]]):
        """
        simulated_router_responses: map of node_name -> {
            "tcp_alive": bool,
            "exit_country": str,     # country of the exit IP; "" means no outbound connectivity
            "router_delay_ms": int,  # 0 means unreachable from router WAN
        }
        """
        self.responses = simulated_router_responses
        self.stage1_passed: List[str] = []
        self.stage2_uploaded_sub: str = ""
        self.stage2_passed: List[str] = []
        self.location_dropped: List[str] = []
        self.wan_unreachable_dropped: List[str] = []

    def run_stage1_local_prefilter(self, candidate_nodes: List[str]) -> List[str]:
        """Phase 0 & Stage 1: Local TCP reachability and exit IP check."""
        survivors = []
        for node in candidate_nodes:
            name = get_node_name(node)
            resp = self.responses.get(name, {})
            if not resp.get("tcp_alive", False) or not resp.get("exit_country"):
                continue
            if resp["exit_country"] in GEOBLOCKED_REGIONS:
                self.location_dropped.append(node)
                continue
            survivors.append(node)
        self.stage1_passed = survivors
        return survivors

    def run_stage2_router_verification(self, stage1_candidates: List[str]) -> List[str]:
        """Stage 2: Staging and router WAN delay probe."""
        # 1. Staging upload simulation
        sub_dict = {"proxies": [{"name": get_node_name(n)} for n in stage1_candidates]}
        self.stage2_uploaded_sub = yaml.dump(sub_dict)

        # 2. Router delay probe simulation
        verified = []
        for node in stage1_candidates:
            name = get_node_name(node)
            resp = self.responses.get(name, {})

            # Drop dead nodes on router
            if resp.get("router_delay_ms", 0) <= 0:
                self.wan_unreachable_dropped.append(node)
                continue

            verified.append(node)

        self.stage2_passed = verified
        return verified


class TestStagedPipelineE2E(unittest.TestCase):
    """Tier 3: End-to-end staged pipeline workflow simulation."""

    def setUp(self):
        self.candidate_nodes = [
            "vless://uuid@1.1.1.1:443#Node_A_Healthy_German",
            "vless://uuid@2.2.2.2:443#Node_B_Dead_TCP",
            "vless://uuid@3.3.3.3:443#Node_C_Russian_Exit",
            "vless://uuid@4.4.4.4:443#Node_D_Router_WAN_Unreachable",
            "vless://uuid@5.5.5.5:443#Node_E_Healthy_UK",
            "vless://uuid@6.6.6.6:443#Node_F_No_Outbound",
        ]

        self.simulated_responses = {
            "Node_A_Healthy_German": {
                "tcp_alive": True,
                "exit_country": "DE",
                "router_delay_ms": 75,
            },
            "Node_B_Dead_TCP": {
                "tcp_alive": False,
                "exit_country": "",
                "router_delay_ms": 0,
            },
            "Node_C_Russian_Exit": {
                # Reachable and fast, but its exit IP is in a rejected country
                "tcp_alive": True,
                "exit_country": "RU",
                "router_delay_ms": 60,
            },
            "Node_D_Router_WAN_Unreachable": {
                # Passes Stage 1 locally, but router cannot route to its subnet/ISP
                "tcp_alive": True,
                "exit_country": "NL",
                "router_delay_ms": 0,  # Timeout on router
            },
            "Node_E_Healthy_UK": {
                "tcp_alive": True,
                "exit_country": "GB",
                "router_delay_ms": 82,
            },
            "Node_F_No_Outbound": {
                # Accepts TCP connections, but carries no traffic to the internet
                "tcp_alive": True,
                "exit_country": "",
                "router_delay_ms": 0,
            },
        }

    def test_staged_pipeline_full_lifecycle_and_dead_node_elimination(self):
        """Simulate end-to-end candidate lifecycle: Stage 1 local -> Stage 2 router."""
        sim = StagedPipelineSimulator(self.simulated_responses)

        # Stage 1: Local IP check
        stage1_survivors = sim.run_stage1_local_prefilter(self.candidate_nodes)

        # Dead, no-outbound and rejected-country nodes are eliminated at Stage 1
        self.assertEqual(
            [get_node_name(n) for n in stage1_survivors],
            ["Node_A_Healthy_German", "Node_D_Router_WAN_Unreachable", "Node_E_Healthy_UK"],
        )
        self.assertEqual([get_node_name(n) for n in sim.location_dropped], ["Node_C_Russian_Exit"])

        # Stage 2: Router-Representative Verification
        stage2_survivors = sim.run_stage2_router_verification(stage1_survivors)

        # Exactly Node A (German) and Node E (UK) must survive
        survivor_names = [get_node_name(n) for n in stage2_survivors]
        self.assertEqual(survivor_names, ["Node_A_Healthy_German", "Node_E_Healthy_UK"])
        self.assertEqual(
            [get_node_name(n) for n in sim.wan_unreachable_dropped], ["Node_D_Router_WAN_Unreachable"]
        )
        self.assertIn("Node_D_Router_WAN_Unreachable", sim.stage2_uploaded_sub)

    def test_fallback_failover_parity_simulation(self):
        """Simulates router fallback group behavior between Google 204 and Cloudflare 204.

        Demonstrates that Cloudflare 204 falsely keeps geoblocked nodes active,
        whereas Google 204 with expected-status '204' triggers automatic failover.
        """
        class MockMihomoFallbackGroup:
            def __init__(self, nodes: List[str], healthcheck_url: str, expected_status: str):
                self.nodes = nodes
                self.healthcheck_url = healthcheck_url
                self.expected_status = expected_status

            def evaluate_active_node(self, node_health_provider) -> str:
                """Mihomo fallback picks the FIRST node that passes the health check."""
                for node in self.nodes:
                    status_code, is_geoblocked = node_health_provider(node, self.healthcheck_url)
                    if self.healthcheck_url == "https://cp.cloudflare.com/generate_204":
                        # Cloudflare returns 204 for any node with internet, even if Google is blocked!
                        if status_code == 204:
                            return node
                    elif "google.com" in self.healthcheck_url or "gstatic.com" in self.healthcheck_url:
                        # Google returns 403 or geoblock if region is blocked
                        if self.expected_status == "204" and status_code == 204 and not is_geoblocked:
                            return node
                return "NONE"

        def simulated_provider(node_name: str, probe_url: str):
            if node_name == "Node_1_Russian_Geoblocked":
                # Cloudflare probe succeeds, but Google probe fails with 403
                if "cloudflare" in probe_url:
                    return 204, False
                return 403, True
            if node_name == "Node_2_German_Healthy":
                return 204, False
            return 0, False

        nodes = ["Node_1_Russian_Geoblocked", "Node_2_German_Healthy"]

        # 1. Under legacy Cloudflare health check:
        legacy_group = MockMihomoFallbackGroup(
            nodes=nodes,
            healthcheck_url="https://cp.cloudflare.com/generate_204",
            expected_status="*"
        )
        selected_legacy = legacy_group.evaluate_active_node(simulated_provider)
        # BUG REPRODUCED: Cloudflare keeps Node 1 active, blackholing all user Google traffic!
        self.assertEqual(selected_legacy, "Node_1_Russian_Geoblocked")

        # 2. Under updated Google 204 parity health check:
        parity_group = MockMihomoFallbackGroup(
            nodes=nodes,
            healthcheck_url="https://www.gstatic.com/generate_204",
            expected_status="204"
        )
        selected_parity = parity_group.evaluate_active_node(simulated_provider)
        # PARITY FIX VERIFIED: Router detects Google failure and fails over to Node 2!
        self.assertEqual(selected_parity, "Node_2_German_Healthy")

    def test_deployment_script_atomic_generation_and_syntax_preflight(self):
        """Verifies generate_router_script creates executable shell script with required steps."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_script = os.path.join(tmpdir, "apply_to_router.sh")
            sample_nodes = [
                "vless://uuid@1.1.1.1:443?security=reality&encryption=none&pbk=xyz&sni=google.com#German_Node",
            ]
            generate_router_script(sample_nodes, config={}, out_file=out_script)
            self.assertTrue(os.path.exists(out_script))

            with open(out_script, "r", encoding="utf-8") as f:
                content = f.read()

            # Verify presence of essential deployment operations
            self.assertTrue(content.startswith("#!/bin/sh"))
            self.assertIn("/etc/mihomo/proxy-providers/sub.yaml", content)
            self.assertIn("/etc/mihomo/config.yaml", content)
            self.assertIn("/etc/init.d/mihomo restart", content)
            self.assertIn("/etc/init.d/magitrickle restart", content)
            self.assertIn("German_Node", content)

    def test_real_router_validator_in_staged_pipeline(self):
        """Validates RouterValidator behavior on candidate nodes."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        from nodesieve.core.router_validator import RouterValidator

        mock_client = MagicMock()
        mock_client.is_api_alive = AsyncMock(return_value=True)
        mock_client.stream_file_to_router = MagicMock(return_value=True)
        mock_client.reload_provider = AsyncMock(return_value=True)
        mock_client.probe_group_delay = AsyncMock(
            return_value={
                name: response["router_delay_ms"]
                for name, response in self.simulated_responses.items()
            }
        )

        validator = RouterValidator(
            router_client=mock_client,
            config={"allowed_countries": [], "use_mux": True},
        )

        sim = StagedPipelineSimulator(self.simulated_responses)
        candidates = sim.run_stage1_local_prefilter(self.candidate_nodes)

        survivors = asyncio.run(
            validator.verify_nodes_on_router(candidates)
        )

        # The real validator and the simulation agree on who survives Stage 2
        self.assertEqual(survivors, sim.run_stage2_router_verification(candidates))
        survivor_names = [get_node_name(n) for n in survivors]
        self.assertEqual(
            survivor_names, ["Node_A_Healthy_German", "Node_E_Healthy_UK"]
        )
        self.assertEqual(
            validator.wan_unreachable_dropped, ["Node_D_Router_WAN_Unreachable"]
        )


if __name__ == "__main__":
    unittest.main()
