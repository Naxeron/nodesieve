"""Tier 4: Hardware-in-the-Loop Live Router Smoke Test Suite.

Validates operations against the real OpenWrt router at 192.168.1.1:
- Mihomo External Controller REST API on port 9090
- Mixed proxy listener on port 7890 (Google 204 connectivity)
- SSH management service on port 22 (/etc/init.d/mihomo status)

Includes graceful skipping when the router hardware is offline or unreachable.
"""

import json
import os
import socket
import unittest
import urllib.request
import pytest
import paramiko

ROUTER_HOST = "192.168.1.1"
ROUTER_REST_PORT = 9090
ROUTER_PROXY_PORT = 7890
ROUTER_SSH_PORT = 22
ROUTER_SSH_USER = "root"
# Unset: authenticate with the SSH agent or default key files.
ROUTER_SSH_PASS = os.environ.get("ROUTER_SSH_PASS") or None


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Checks if a TCP port is reachable within timeout."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((host, port))
        s.close()
        return res == 0
    except Exception:
        return False


def is_live_router_available() -> bool:
    """Checks whether the physical OpenWrt router is online and reachable."""
    return is_port_open(ROUTER_HOST, ROUTER_REST_PORT, timeout=1.0)


# Module-level skip marker for CI or isolated environments without router hardware
pytestmark = pytest.mark.skipif(
    not is_live_router_available(),
    reason=f"Live router at {ROUTER_HOST}:{ROUTER_REST_PORT} is unreachable (Hardware-in-the-Loop test)",
)


class TestLiveRouterSmoke(unittest.TestCase):
    """Tier 4: Smoke tests for live router hardware at 192.168.1.1."""

    def setUp(self):
        if not is_live_router_available():
            self.skipTest(f"Live router at {ROUTER_HOST} is offline")

    def test_live_router_rest_api_version(self):
        """Verifies router REST API :9090 /version returns valid Mihomo version."""
        url = f"http://{ROUTER_HOST}:{ROUTER_REST_PORT}/version"
        req = urllib.request.Request(url, headers={"User-Agent": "nodesieve_smoke"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("version", data)
            self.assertTrue(data.get("meta", False), "Mihomo Meta binary must be confirmed")

    def test_live_router_rest_api_delay_probe(self):
        """Verifies router REST API can probe latency to Google 204 endpoint."""
        url = (
            f"http://{ROUTER_HOST}:{ROUTER_REST_PORT}/proxies/DIRECT/delay"
            f"?timeout=3000&url=https://www.gstatic.com/generate_204"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "nodesieve_smoke"})
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("delay", data)
            self.assertIsInstance(data["delay"], int)
            self.assertGreater(data["delay"], 0)

    def test_live_router_proxy_connectivity_204(self):
        """Verifies live proxy port :7890 successfully handles Google 204 requests."""
        if not is_port_open(ROUTER_HOST, ROUTER_PROXY_PORT, timeout=1.0):
            self.skipTest(f"Router proxy port {ROUTER_PROXY_PORT} is not open")

        proxy_handler = urllib.request.ProxyHandler({"http": f"http://{ROUTER_HOST}:{ROUTER_PROXY_PORT}"})
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(
            "http://connectivitycheck.gstatic.com/generate_204",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with opener.open(req, timeout=4.0) as resp:
            self.assertIn(resp.status, [200, 204])

    def test_live_router_ssh_service_status(self):
        """Verifies SSH connectivity to router on port 22 and queries /etc/init.d/mihomo status."""
        if not is_port_open(ROUTER_HOST, ROUTER_SSH_PORT, timeout=1.0):
            self.skipTest(f"Router SSH port {ROUTER_SSH_PORT} is not open")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                ROUTER_HOST,
                port=ROUTER_SSH_PORT,
                username=ROUTER_SSH_USER,
                password=ROUTER_SSH_PASS,
                timeout=4.0,
                banner_timeout=4.0,
            )
            stdin, stdout, stderr = ssh.exec_command("/etc/init.d/mihomo status", timeout=5.0)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            self.assertEqual(exit_code, 0, f"/etc/init.d/mihomo status failed with code {exit_code}")
            self.assertIn("running", out.lower())
        finally:
            ssh.close()

    def test_live_router_client_if_available(self):
        """Tests RouterClient directly against live router if M1 implementation exists."""
        try:
            from nodesieve.router.client import RouterClient
        except ImportError:
            return

        client = RouterClient(
            host=ROUTER_HOST,
            api_port=ROUTER_REST_PORT,
            proxy_port=ROUTER_PROXY_PORT,
            ssh_port=ROUTER_SSH_PORT,
            ssh_user=ROUTER_SSH_USER,
            ssh_pass=ROUTER_SSH_PASS,
        )
        code, out, err = client.exec_command("/etc/init.d/mihomo status", timeout=5.0)
        self.assertEqual(code, 0)
        self.assertIn("running", out.lower())


if __name__ == "__main__":
    unittest.main()
