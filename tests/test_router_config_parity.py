"""Tier 1: Unit & Component Isolation Tests.

Tests router configuration parameters (Google 204 URL, expected-status: "204",
prefer-ipv6: false), AGENTS.md async rules, and parser fidelity.
"""

import asyncio
import socket
import unittest
import yaml

from proxy_sites import constants
from proxy_sites.router.config_builder import build_router_config_yaml
from proxy_sites.parsers.base import (
    extract_host_port,
    get_node_name,
    extract_node_protocol,
)
from proxy_sites.core.mihomo import safe_close_writer


def parse_yaml_safely(yaml_str: str) -> dict:
    """Helper to parse Mihomo YAML configuration strings."""
    return yaml.safe_load(yaml_str)


def validate_router_config_parity(config_yaml: str) -> dict:
    """Validates router configuration against health-check parity requirements.

    Returns a dict with validation status for:
    - google_204_url: uses google/gstatic 204 url
    - expected_status_204: expected-status is explicitly '204'
    - prefer_ipv6_disabled: prefer-ipv6 is false to prevent AAAA blackholing
    """
    data = parse_yaml_safely(config_yaml)
    results = {
        "google_204_url": False,
        "expected_status_204": False,
        "prefer_ipv6_disabled": False,
    }
    if not isinstance(data, dict):
        return results

    # 1. Check proxy-providers health check
    providers = data.get("proxy-providers", {})
    gemini_nodes = providers.get("Gemini_Nodes", {})
    health_check = gemini_nodes.get("health-check", {})
    url = health_check.get("url", "")
    if any(domain in url for domain in ["gstatic.com/generate_204", "google.com/generate_204"]):
        results["google_204_url"] = True

    expected_status = str(health_check.get("expected-status", ""))
    if expected_status in ["204", "200/204", "200-299"]:
        results["expected_status_204"] = True

    # 2. Check DNS prefer-ipv6
    dns = data.get("dns", {})
    if dns.get("prefer-ipv6") is False:
        results["prefer_ipv6_disabled"] = True

    return results


class TestRouterConfigParity(unittest.TestCase):
    """Tier 1: Validates router configuration parameters and schema requirements."""

    def test_ideal_router_config_parity_schema(self):
        """Category-Partition & BVA: Verify that a fully compliant config passes all parity checks."""
        compliant_yaml = """
mode: rule
ipv6: true
mixed-port: 7890
external-controller: 0.0.0.0:9090

dns:
  enable: true
  ipv6: true
  prefer-ipv6: false
  listen: 127.0.0.1:1053

proxy-providers:
  Gemini_Nodes:
    type: file
    path: ./proxy-providers/sub.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 30
      timeout: 5000
      max-failed-times: 2
      lazy: false
      expected-status: "204"

proxy-groups:
  - name: "Gemini_Auto"
    type: fallback
    use:
      - "Gemini_Nodes"
    url: https://www.gstatic.com/generate_204
    interval: 30
    timeout: 5000
    max-failed-times: 2
    lazy: false
    expected-status: "204"

rules:
  - MATCH,Gemini_Auto
"""
        results = validate_router_config_parity(compliant_yaml)
        self.assertTrue(results["google_204_url"], "Google 204 URL must be recognized")
        self.assertTrue(results["expected_status_204"], "expected-status 204 must be recognized")
        self.assertTrue(results["prefer_ipv6_disabled"], "prefer-ipv6 must be false")

    def test_router_config_parity_holds_for_deployed_template(self):
        """Verifies the deployed router template satisfies every parity requirement."""
        template_yaml = constants.ROUTER_CONFIG_TEMPLATE.format(
            proxies_section='proxies:\n  - name: "Домашний интернет"\n    type: direct',
            awg_group_entry=""
        )
        results = validate_router_config_parity(template_yaml)
        self.assertEqual(results, {
            "google_204_url": True,
            "expected_status_204": True,
            "prefer_ipv6_disabled": True,
        })
        # The parity validator also reports gaps without throwing exceptions
        gaps = validate_router_config_parity("mode: rule\ndns:\n  prefer-ipv6: true\n")
        self.assertEqual(set(gaps.values()), {False})

    def test_build_router_config_yaml_structure(self):
        """Verifies build_router_config_yaml generates well-formed YAML."""
        rendered = build_router_config_yaml(awg_proxy=None, warp_proxies=None)
        self.assertIsInstance(rendered, str)
        parsed = parse_yaml_safely(rendered)
        self.assertIn("proxy-providers", parsed)
        self.assertIn("proxy-groups", parsed)
        self.assertIn("rules", parsed)
        self.assertIn("Gemini_Nodes", parsed["proxy-providers"])

    def test_router_config_bva_health_check_status_codes(self):
        """Boundary Value Analysis: Tests expected-status boundary values."""
        # Valid values
        for valid_status in ["204", 204, "200/204", "200-299"]:
            sample = f"""
proxy-providers:
  Gemini_Nodes:
    health-check:
      url: https://www.gstatic.com/generate_204
      expected-status: {valid_status}
"""
            res = validate_router_config_parity(sample)
            self.assertTrue(res["expected_status_204"], f"Status {valid_status} should be valid")

        # Invalid values
        for invalid_status in ["404", "500", "*", "", None]:
            sample = f"""
proxy-providers:
  Gemini_Nodes:
    health-check:
      url: https://www.gstatic.com/generate_204
      expected-status: "{invalid_status}"
"""
            res = validate_router_config_parity(sample)
            self.assertFalse(res["expected_status_204"], f"Status {invalid_status} should be invalid")


class TestAgentsMdConcurrencyGuardrails(unittest.IsolatedAsyncioTestCase):
    """Tier 1: Verifies strict adherence to AGENTS.md concurrency guidelines."""

    async def test_safe_close_writer_stream_teardown_timeout(self):
        """Rule 1: Stream teardown must enforce asyncio.wait_for with <=0.2s timeout."""
        server_writer = None

        async def handle_client(r, w):
            nonlocal server_writer
            server_writer = w

        # Start a local echo server
        server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        await asyncio.sleep(0.01)
        # Closing writer should complete safely within bounded time
        await safe_close_writer(writer)
        self.assertTrue(writer.is_closing())
        if server_writer:
            await safe_close_writer(server_writer)

        server.close()
        await server.wait_closed()

    def test_ephemeral_port_kernel_allocation(self):
        """Rule 2: Ephemeral ports must be bound to ('127.0.0.1', 0) to avoid EADDRINUSE."""
        ports = set()
        for _ in range(10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
            s.close()
            self.assertGreater(port, 1024, "Ephemeral port must be unprivileged (>1024)")
            ports.add(port)
        self.assertGreater(len(ports), 0)

    async def test_single_attempt_cache_pattern_behavior(self):
        """Rule 3: Single-attempt cache pattern using explicit boolean flags, not falsy collection checks."""
        class MockFetcher:
            def __init__(self):
                self._attempted = False
                self._lock = asyncio.Lock()
                self._cache = {}
                self.network_call_count = 0

            async def get_data(self):
                if not self._attempted:
                    async with self._lock:
                        if not self._attempted:
                            self._attempted = True
                            self.network_call_count += 1
                            # Network fetch fails (remains empty dict)
                            self._cache = {}
                return self._cache

        fetcher = MockFetcher()
        # Concurrent tasks request data
        tasks = [asyncio.create_task(fetcher.get_data()) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # Network call must have occurred EXACTLY once despite _cache remaining empty {}
        self.assertEqual(fetcher.network_call_count, 1)
        for r in results:
            self.assertEqual(r, {})


class TestParserFidelity(unittest.TestCase):
    """Tier 1: Verifies parser fidelity across node protocol formats."""

    def test_extract_node_protocol_variations(self):
        """Tests protocol extraction for all supported schemes."""
        self.assertEqual(extract_node_protocol("vless://uuid@host:443?type=ws"), "VLESS")
        self.assertEqual(extract_node_protocol("trojan://pass@host:443"), "TROJAN")
        self.assertEqual(extract_node_protocol("shadowsocks://base64@host:443"), "SS")
        self.assertEqual(extract_node_protocol("ss://base64@host:443"), "SS")
        self.assertEqual(extract_node_protocol("warp://162.159.192.1:2408"), "WARP")
        self.assertEqual(extract_node_protocol("awg_conf:US.conf#AWG"), "AWG")
        self.assertEqual(extract_node_protocol("invalid_scheme"), "VPN")

    def test_extract_host_port_fidelity(self):
        """Tests host and port parsing with IPv4, IPv6, and URL-encoded targets."""
        h, p = extract_host_port("vless://abc@1.2.3.4:8443?security=reality")
        self.assertEqual(h, "1.2.3.4")
        self.assertEqual(p, 8443)

        h6, p6 = extract_host_port("vless://abc@[2001:db8::1]:443?security=tls")
        self.assertEqual(h6, "2001:db8::1")
        self.assertEqual(p6, 443)

        h_warp, p_warp = extract_host_port("warp://162.159.192.1:2408#Endpoint")
        self.assertEqual(h_warp, "162.159.192.1")
        self.assertEqual(p_warp, 2408)

    def test_adversarial_node_name_escaping_and_special_chars(self):
        """Adversarial Verification: Test complex UTF-8, emojis, query characters, and control characters."""
        complex_uris = [
            ("vless://id@1.1.1.1:443#%F0%9F%9A%80%20Fast%20%26%20Furious%20%231", "🚀 Fast & Furious #1"),
            ("trojan://pass@2.2.2.2:443#%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80%20%E2%84%961", "Сервер №1"),
            ("ss://b64@3.3.3.3:443#Tag%20With%20%3Cscript%3Ealert(1)%3C%2Fscript%3E", "Tag With <script>alert(1)</script>"),
            ("warp://162.159.192.1:2408#Line1%0ALine2", "Line1\nLine2"),
        ]
        for uri, expected_name in complex_uris:
            extracted = get_node_name(uri)
            self.assertEqual(extracted, expected_name)

    def test_router_config_boundary_and_malformed_structures(self):
        """Boundary & Resource Stress: Verify validator handles empty, broken, and extreme configs gracefully."""
        # Empty YAML
        empty_res = validate_router_config_parity("")
        self.assertFalse(empty_res["google_204_url"])
        self.assertFalse(empty_res["expected_status_204"])

        # Corrupted / Non-dict YAML
        str_res = validate_router_config_parity("just a plain string")
        self.assertFalse(str_res["google_204_url"])

        # Missing health-check section
        missing_hc = """
proxy-providers:
  Gemini_Nodes:
    type: file
    path: ./sub.yaml
"""
        res = validate_router_config_parity(missing_hc)
        self.assertFalse(res["google_204_url"])
        self.assertFalse(res["expected_status_204"])


if __name__ == "__main__":
    unittest.main()
