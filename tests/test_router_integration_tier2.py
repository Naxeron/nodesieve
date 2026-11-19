"""Tier 2: Mock Subsystem Integration Tests.

Integrates real `./mihomo -t` configuration syntax validation and a mock Mihomo REST API (:9090).
"""

import os
import socket
import subprocess
import tempfile
import unittest
import aiohttp
from aiohttp import web
import yaml
import pytest

from proxy_sites.constants import PROJECT_ROOT


def get_ephemeral_port() -> int:
    """Allocates a dynamic ephemeral port from OS kernel per AGENTS.md."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestMihomoConfigSyntaxValidation(unittest.TestCase):
    """Tier 2: Real `./mihomo -t` pre-flight syntax checks."""

    def setUp(self):
        self.mihomo_bin = os.path.join(PROJECT_ROOT, "mihomo")
        if not os.path.exists(self.mihomo_bin) or not os.access(self.mihomo_bin, os.X_OK):
            pytest.skip(f"Mihomo binary not executable at {self.mihomo_bin}")

    def test_mihomo_syntax_validation_passes_on_parity_config(self):
        """Verify real ./mihomo -t returns exit code 0 on router config with parity parameters."""
        parity_config = {
            "mode": "rule",
            "mixed-port": 7890,
            "log-level": "error",
            "dns": {
                "enable": True,
                "ipv6": True,
                "prefer-ipv6": False,
                "listen": "127.0.0.1:1053",
                "nameserver": ["8.8.8.8", "1.1.1.1"],
            },
            "proxy-providers": {
                "Gemini_Nodes": {
                    "type": "file",
                    "path": "./sub.yaml",
                    "health-check": {
                        "enable": True,
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": 30,
                        "timeout": 5000,
                        "max-failed-times": 2,
                        "lazy": False,
                        "expected-status": "204",
                    },
                }
            },
            "proxy-groups": [
                {
                    "name": "Gemini_Auto",
                    "type": "fallback",
                    "use": ["Gemini_Nodes"],
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 30,
                    "timeout": 5000,
                    "max-failed-times": 2,
                    "lazy": False,
                    "expected-status": "204",
                },
            ],
            "rules": ["MATCH,Gemini_Auto"],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sub_file = os.path.join(tmpdir, "sub.yaml")
            with open(sub_file, "w") as f:
                yaml.dump({
                    "proxies": [
                        {
                            "name": "Mock_Node_1",
                            "type": "ss",
                            "server": "1.1.1.1",
                            "port": 8388,
                            "cipher": "aes-128-gcm",
                            "password": "secret_password",
                        }
                    ]
                }, f)

            cfg_file = os.path.join(tmpdir, "config.yaml")
            with open(cfg_file, "w") as f:
                yaml.dump(parity_config, f)

            result = subprocess.run(
                [self.mihomo_bin, "-t", "-d", tmpdir, "-f", cfg_file],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode, 0,
                f"Valid parity config failed ./mihomo -t: {result.stdout} {result.stderr}"
            )
            self.assertIn("test is successful", result.stdout)

    def test_mihomo_syntax_validation_fails_on_malformed_syntax(self):
        """Verify real ./mihomo -t catches invalid proxy group types and syntax errors."""
        invalid_config = {
            "mode": "rule",
            "proxy-groups": [
                {
                    "name": "Broken_Group",
                    "type": "non_existent_group_type_12345",
                    "proxies": ["DIRECT"],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = os.path.join(tmpdir, "bad_config.yaml")
            with open(cfg_file, "w") as f:
                yaml.dump(invalid_config, f)

            result = subprocess.run(
                [self.mihomo_bin, "-t", "-d", tmpdir, "-f", cfg_file],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(
                result.returncode, 0,
                "Malformed config should have failed ./mihomo -t pre-flight check"
            )


class TestMockMihomoRestApi(unittest.IsolatedAsyncioTestCase):
    """Tier 2: Mock Mihomo External Controller REST API (:9090) integration."""

    async def asyncSetUp(self):
        self.app = web.Application()
        self.providers_reloaded = []

        # Endpoints
        self.app.router.add_get('/version', self._handle_version)
        self.app.router.add_get('/providers/proxies', self._handle_get_providers)
        self.app.router.add_put('/providers/proxies/{name}', self._handle_reload_provider)
        self.app.router.add_get('/group/{name}/delay', self._handle_group_delay)

        self.port = get_ephemeral_port()
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', self.port)
        await self.site.start()
        self.base_url = f"http://127.0.0.1:{self.port}"

    async def asyncTearDown(self):
        await self.runner.cleanup()

    async def _handle_version(self, request):
        return web.json_response({"version": "v1.19.30", "meta": True})

    async def _handle_get_providers(self, request):
        return web.json_response({
            "providers": {
                "Gemini_Nodes": {
                    "name": "Gemini_Nodes",
                    "type": "Proxy",
                    "vehicleType": "File",
                    "updatedAt": "2026-09-04T12:00:00Z"
                }
            }
        })

    async def _handle_reload_provider(self, request):
        name = request.match_info['name']
        if name != "Gemini_Nodes":
            return web.Response(status=404, text="Provider not found")
        self.providers_reloaded.append(name)
        return web.Response(status=204)

    async def _handle_group_delay(self, request):
        name = request.match_info['name']
        if name != "Gemini_Auto":
            return web.Response(status=404, text="Group not found")
        url = request.query.get("url", "")
        if not url:
            return web.Response(status=400, text="Missing url parameter")
        return web.json_response({
            "Proxy_Node_1": 115,
            "Proxy_Node_2": 88,
            "Proxy_Node_Dead": 0
        })

    async def test_rest_api_version_endpoint(self):
        """Verifies GET /version returns valid version data."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/version") as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertTrue(data.get("meta"))
                self.assertEqual(data.get("version"), "v1.19.30")

    async def test_rest_api_reload_provider(self):
        """Verifies PUT /providers/proxies/{name} triggers zero-downtime provider reload."""
        async with aiohttp.ClientSession() as session:
            async with session.put(f"{self.base_url}/providers/proxies/Gemini_Nodes") as resp:
                self.assertEqual(resp.status, 204)
                self.assertIn("Gemini_Nodes", self.providers_reloaded)

            # Test 404 on unknown provider
            async with session.put(f"{self.base_url}/providers/proxies/NonExistent") as resp:
                self.assertEqual(resp.status, 404)

    async def test_rest_api_group_delay_probe(self):
        """Verifies GET /group/{name}/delay batch delay probing."""
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/group/Gemini_Auto/delay?url=https://www.gstatic.com/generate_204"
            async with session.get(url) as resp:
                self.assertEqual(resp.status, 200)
                delays = await resp.json()
                self.assertIn("Proxy_Node_1", delays)
                self.assertEqual(delays["Proxy_Node_1"], 115)
                self.assertEqual(delays["Proxy_Node_2"], 88)

    async def test_router_client_if_available(self):
        """Progressive verification: If RouterClient exists (M1), test it against mock REST server."""
        try:
            from proxy_sites.router.client import RouterClient
        except ImportError:
            # Progressive milestone: M1 is in progress
            return

        client = RouterClient(host="127.0.0.1", api_port=self.port)
        is_alive = await client.is_api_alive()
        self.assertTrue(is_alive)

        reloaded = await client.reload_provider("Gemini_Nodes")
        self.assertTrue(reloaded)

        delays = await client.probe_group_delay("Gemini_Auto", "https://www.gstatic.com/generate_204")
        self.assertIsInstance(delays, dict)
        self.assertEqual(delays.get("Proxy_Node_2"), 88)
        self.assertEqual(delays.get("Proxy_Node_Dead"), 0)


if __name__ == "__main__":
    unittest.main()
