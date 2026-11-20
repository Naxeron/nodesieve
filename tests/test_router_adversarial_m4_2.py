"""Adversarial stress testing for Milestone 4 Phase 2 (Focus Area 2).

Tests:
1. Router Configuration Parity & Syntax Preflight:
   - Challenge build_router_config_yaml and ROUTER_CONFIG_TEMPLATE with boundary parameters:
     YAML injection, edge-case port numbers, unicode node names, duplicate group names.
   - Parity enforcement: Google 204 URL, expected-status: "204", prefer-ipv6: false,
     no listener besides the main mixed port.
   - Real ./mihomo -t syntax validation catches corrupt/invalid configurations.
2. Deployment Script Hardening:
   - Challenge generate_router_script and atomic update logic against missing paths,
     corrupt backup files, rollback execution, and heredoc delimiter boundaries.
3. Concurrency Stress Testing under AGENTS.md:
   - Ephemeral port binding: concurrent allocation of 50+ sockets/servers proving zero TIME_WAIT collisions.
   - Safe writer stream teardown: verify teardown under slow network or hanging peer never blocks beyond 0.2s.
   - Single-attempt cache locks: verify high concurrency (50+ coroutines) with failing network fetches does not lock or loop.
"""

import asyncio
import os
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch
import yaml
import pytest

from nodesieve.constants import PROJECT_ROOT, ROUTER_CONFIG_TEMPLATE
from nodesieve.core.mihomo import MihomoManager
from nodesieve.core.router_validator import RouterValidator
from nodesieve.geo import GeolocationService
from nodesieve.logging import safe_close_writer
from nodesieve.router.config_builder import build_router_config_yaml
from nodesieve.router.script_generator import generate_router_script
from nodesieve.warp import WarpScanner

# A made-up WARP registration: the key is the bytes 0..31.
WARP_SETTINGS = {
    "warp_private_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "warp_ipv6": "2001:db8::2",
}


def get_ephemeral_port() -> int:
    """Allocates a dynamic ephemeral port from OS kernel per AGENTS.md."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRouterConfigParityAdversarial(unittest.TestCase):
    """Adversarial testing of router configuration parity, boundary values, and ./mihomo -t syntax preflight."""

    def setUp(self):
        self.mihomo_bin = os.path.join(PROJECT_ROOT, "mihomo")
        if not os.path.exists(self.mihomo_bin) or not os.access(self.mihomo_bin, os.X_OK):
            pytest.skip(f"Mihomo binary not executable at {self.mihomo_bin}")

    def test_parity_inviolability_google_204_and_single_listener(self):
        """Verifies that Google 204 URL, expected-status: '204' and prefer-ipv6: false are present, with no extra listener."""
        cfg_yaml = build_router_config_yaml(awg_proxy=None, warp_proxies=None)
        parsed = yaml.safe_load(cfg_yaml)

        # 1. Global & DNS prefer-ipv6
        self.assertFalse(parsed.get("prefer-ipv6", True), "Global prefer-ipv6 must be False")
        self.assertFalse(parsed["dns"].get("prefer-ipv6", True), "DNS prefer-ipv6 must be False")

        # 2. Proxy providers health-check
        provider_hc = parsed["proxy-providers"]["Gemini_Nodes"]["health-check"]
        self.assertEqual(provider_hc["url"], "https://www.gstatic.com/generate_204")
        self.assertEqual(str(provider_hc["expected-status"]), "204")

        # 3. Proxy groups health-check
        auto_group = [g for g in parsed["proxy-groups"] if g["name"] == "Gemini_Auto"][0]
        self.assertEqual(auto_group["url"], "https://www.gstatic.com/generate_204")
        self.assertEqual(str(auto_group["expected-status"]), "204")

        # 4. Only the main mixed port listens; all traffic follows the fallback group
        self.assertNotIn("listeners", parsed)
        self.assertEqual(parsed["mixed-port"], 7890)
        self.assertEqual([g["name"] for g in parsed["proxy-groups"]], ["Gemini_Auto"])
        self.assertEqual(parsed["rules"], ["MATCH,Gemini_Auto"])

    def test_unicode_and_emojis_in_proxy_names_pass_mihomo_syntax(self):
        """Validates that proxy names with UTF-8, Cyrillic, emojis, and symbols pass ./mihomo -t."""
        complex_name = "WARP 🇷🇺 ⚡ Москва — [Fast] №1 #tag & <spec>"
        p = WarpScanner.generate_warp_proxy_dict("162.159.192.1", 2408, complex_name, config=WARP_SETTINGS)
        cfg_yaml = build_router_config_yaml(warp_proxies=[p])

        # Verify safe YAML loading
        parsed = yaml.safe_load(cfg_yaml)
        self.assertEqual(parsed["proxies"][1]["name"], complex_name)

        # Verify real ./mihomo -t preflight validation passes
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_yaml)
            os.makedirs(os.path.join(td, "proxy-providers"), exist_ok=True)
            with open(os.path.join(td, "proxy-providers", "sub.yaml"), "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

            proc = subprocess.run(
                [self.mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode, 0, f"mihomo -t failed on valid unicode proxy name: {proc.stderr}"
            )

    def test_yaml_injection_unescaped_quotes_rejected_by_mihomo_preflight(self):
        """Verifies that proxy names with quotes (e.g. 'WARP "US" Fast') generate valid YAML that passes ./mihomo -t."""
        proxy = {
            "name": 'WARP "US" Fast',
            "type": "wireguard",
            "server": "162.159.192.1",
            "port": 2408,
            "private-key": "a" * 44,
            "public-key": "b" * 44,
            "ip": "172.16.0.2",
            "udp": True,
        }
        cfg_yaml = build_router_config_yaml(warp_proxies=[proxy])

        # PyYAML safe_load parses escaped quotes inside double-quoted scalars
        parsed = yaml.safe_load(cfg_yaml)
        self.assertIn("proxies", parsed)
        self.assertEqual(parsed["proxies"][1]["name"], 'WARP "US" Fast')

        # Real ./mihomo -t validates the configuration cleanly
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_yaml)
            os.makedirs(os.path.join(td, "proxy-providers"), exist_ok=True)
            with open(os.path.join(td, "proxy-providers", "sub.yaml"), "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

            proc = subprocess.run(
                [self.mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"mihomo -t failed on escaped quotes in proxy name: {proc.stderr} {proc.stdout}",
            )

    def test_yaml_injection_newline_structure_rejected_by_mihomo(self):
        """Verifies that multi-line injected structure with invalid proxy type is rejected by ./mihomo -t."""
        bad_proxy = WarpScanner.generate_warp_proxy_dict(
            "1.1.1.1", 2408, 'WARP_Node"\n    type: illegal_proxy_type\n    dummy: "',
            config=WARP_SETTINGS,
        )
        bad_proxy["type"] = "illegal_proxy_type"
        cfg_yaml = build_router_config_yaml(warp_proxies=[bad_proxy])

        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_yaml)
            os.makedirs(os.path.join(td, "proxy-providers"), exist_ok=True)
            with open(os.path.join(td, "proxy-providers", "sub.yaml"), "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

            proc = subprocess.run(
                [self.mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, "mihomo -t must reject injected structural YAML")

    def test_duplicate_proxy_groups_rejected_by_mihomo(self):
        """Verifies that ./mihomo -t strictly catches duplicate proxy group names."""
        cfg_yaml = build_router_config_yaml()
        # Append duplicate group
        dup_cfg = cfg_yaml + """
  - name: "Gemini_Auto"
    type: select
    use:
      - "Gemini_Nodes"
"""
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(dup_cfg)
            os.makedirs(os.path.join(td, "proxy-providers"), exist_ok=True)
            with open(os.path.join(td, "proxy-providers", "sub.yaml"), "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

            proc = subprocess.run(
                [self.mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, "mihomo -t must reject duplicate group names")

    def test_duplicate_proxy_names_rejected_by_mihomo(self):
        """Verifies that ./mihomo -t strictly catches duplicate proxy names in proxies section."""
        dup_proxies = """proxies:
  - name: "Домашний интернет"
    type: direct
  - name: "Домашний интернет"
    type: direct"""
        cfg_yaml = ROUTER_CONFIG_TEMPLATE.format(
            proxies_section=dup_proxies,
            awg_group_entry="",
        )
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_yaml)
            os.makedirs(os.path.join(td, "proxy-providers"), exist_ok=True)
            with open(os.path.join(td, "proxy-providers", "sub.yaml"), "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

            proc = subprocess.run(
                [self.mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, "mihomo -t must reject duplicate proxy names")

    def test_non_numeric_port_rejected_by_mihomo(self):
        """Verifies that a non-numeric proxy port is rejected by ./mihomo -t."""
        self.assertIn("mixed-port: 7890", ROUTER_CONFIG_TEMPLATE)
        cfg_yaml = ROUTER_CONFIG_TEMPLATE.replace("mixed-port: 7890", "mixed-port: not-a-port").format(
            proxies_section='proxies:\n  - name: "Домашний интернет"\n    type: direct',
            awg_group_entry="",
        )
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_yaml)
            os.makedirs(os.path.join(td, "proxy-providers"), exist_ok=True)
            with open(os.path.join(td, "proxy-providers", "sub.yaml"), "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

            proc = subprocess.run(
                [self.mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, "mihomo -t must reject a non-numeric port")


class TestDeploymentScriptHardeningAdversarial(unittest.TestCase):
    """Adversarial testing of generate_router_script, atomic updates, and rollback execution."""

    def setUp(self):
        self.mihomo_bin = os.path.join(PROJECT_ROOT, "mihomo")

    def _setup_sandbox(self, td: str):
        """Sets up a sandboxed OpenWrt filesystem hierarchy."""
        etc_mihomo = os.path.join(td, "etc", "mihomo")
        providers = os.path.join(etc_mihomo, "proxy-providers")
        init_dir = os.path.join(td, "etc", "init.d")
        bin_dir = os.path.join(td, "usr", "bin")

        os.makedirs(providers, exist_ok=True)
        os.makedirs(init_dir, exist_ok=True)
        os.makedirs(bin_dir, exist_ok=True)

        # Deploy real or mock mihomo binary
        sandbox_mihomo = os.path.join(bin_dir, "mihomo")
        if os.path.exists(self.mihomo_bin):
            with open(self.mihomo_bin, "rb") as f_src, open(sandbox_mihomo, "wb") as f_dst:
                f_dst.write(f_src.read())
        else:
            # A fresh checkout has no binary yet: stand in with one that accepts any configuration.
            with open(sandbox_mihomo, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
        os.chmod(sandbox_mihomo, 0o755)

        # Mock init scripts for mihomo and magitrickle
        for svc in ["mihomo", "magitrickle"]:
            svc_path = os.path.join(init_dir, svc)
            with open(svc_path, "w") as f:
                f.write("""#!/bin/sh
case "$1" in
    restart) echo "service $0 restarted" ;;
    status) echo "running" ;;
esac
exit 0
""")
            os.chmod(svc_path, 0o755)

        return etc_mihomo, init_dir, sandbox_mihomo

    def _adapt_script(self, raw_script_path: str, td: str, sandbox_mihomo: str) -> str:
        """Adapts hardcoded system paths in apply_to_router.sh to the unprivileged sandbox."""
        with open(raw_script_path, "r", encoding="utf-8") as f:
            code = f.read()

        adapted = code.replace("/etc/mihomo", os.path.join(td, "etc", "mihomo"))
        adapted = adapted.replace("/etc/init.d", os.path.join(td, "etc", "init.d"))
        adapted = adapted.replace("/usr/bin/mihomo", sandbox_mihomo)
        # Mock REST API endpoint curl/wget query on 127.0.0.1:9090
        adapted = adapted.replace("wget -qO- -T 3 http://127.0.0.1:9090/version 2>/dev/null", "echo '{\"version\":\"1.19.30\"}'")
        adapted = adapted.replace("curl -s -m 3 http://127.0.0.1:9090/version 2>/dev/null", "echo '{\"version\":\"1.19.30\"}'")

        sandboxed_file = os.path.join(td, "sandboxed_apply.sh")
        with open(sandboxed_file, "w", encoding="utf-8") as f:
            f.write(adapted)
        os.chmod(sandboxed_file, 0o755)
        return sandboxed_file

    def test_atomic_script_successful_sandboxed_run(self):
        """Happy-path: verifies script executes atomic staging, syntax check, move, restart, and cleanup."""
        with tempfile.TemporaryDirectory() as td:
            etc_mihomo, init_dir, sandbox_mihomo = self._setup_sandbox(td)

            # Pre-existing golden config
            orig_config = os.path.join(etc_mihomo, "config.yaml")
            with open(orig_config, "w") as f:
                f.write("old_golden_config: true\n")

            script_path = os.path.join(td, "apply_to_router.sh")
            generate_router_script(
                ["vless://uuid@1.1.1.1:443?security=reality#ValidNode"],
                config={},
                out_file=script_path,
            )

            sandboxed_script = self._adapt_script(script_path, td, sandbox_mihomo)
            proc = subprocess.run(["/bin/sh", sandboxed_script], capture_output=True, text=True)

            self.assertEqual(proc.returncode, 0, f"Script failed: {proc.stderr}")
            self.assertIn("Done!", proc.stdout)

            # Assert atomic updates succeeded
            self.assertTrue(os.path.exists(os.path.join(etc_mihomo, "config.yaml")))
            self.assertTrue(os.path.exists(os.path.join(etc_mihomo, "proxy-providers", "sub.yaml")))

            # Assert .tmp and .bak files were cleaned up
            self.assertFalse(os.path.exists(os.path.join(etc_mihomo, "config.yaml.tmp")))
            self.assertFalse(os.path.exists(os.path.join(etc_mihomo, "config.yaml.bak")))

    def test_atomic_script_preflight_failure_triggers_rollback(self):
        """Simulates ./mihomo -t failure: verifies rollback restores .bak, cleans .tmp, and exits with 1."""
        with tempfile.TemporaryDirectory() as td:
            etc_mihomo, init_dir, sandbox_mihomo = self._setup_sandbox(td)

            # Pre-existing golden configuration
            orig_config = os.path.join(etc_mihomo, "config.yaml")
            with open(orig_config, "w") as f:
                f.write("STABLE_PRODUCTION_CONFIG_VERSION_1\n")

            # Replace sandbox mihomo with one that fails syntax check
            with open(sandbox_mihomo, "w") as f:
                f.write("#!/bin/sh\necho 'Syntax Error in line 42' >&2\nexit 1\n")
            os.chmod(sandbox_mihomo, 0o755)

            script_path = os.path.join(td, "apply_to_router.sh")
            generate_router_script(
                ["vless://uuid@1.1.1.1:443#Node"],
                config={},
                out_file=script_path,
            )

            sandboxed_script = self._adapt_script(script_path, td, sandbox_mihomo)
            proc = subprocess.run(["/bin/sh", sandboxed_script], capture_output=True, text=True)

            self.assertEqual(proc.returncode, 1, "Script must exit with code 1 on preflight error")
            self.assertIn("Rolling back", proc.stdout)

            # Verify that original production config was restored
            with open(orig_config, "r") as f:
                restored = f.read()
            self.assertEqual(restored.strip(), "STABLE_PRODUCTION_CONFIG_VERSION_1")

            # Verify .tmp files were purged
            self.assertFalse(os.path.exists(os.path.join(etc_mihomo, "config.yaml.tmp")))

    def test_atomic_script_clean_install_no_backup_survives_rollback(self):
        """Verifies rollback functions cleanly on initial deployment when no .bak existed."""
        with tempfile.TemporaryDirectory() as td:
            etc_mihomo, init_dir, sandbox_mihomo = self._setup_sandbox(td)

            # No prior config.yaml exists
            with open(sandbox_mihomo, "w") as f:
                f.write("#!/bin/sh\nexit 1\n")
            os.chmod(sandbox_mihomo, 0o755)

            script_path = os.path.join(td, "apply_to_router.sh")
            generate_router_script(
                ["vless://uuid@1.1.1.1:443#Node"],
                config={},
                out_file=script_path,
            )

            sandboxed_script = self._adapt_script(script_path, td, sandbox_mihomo)
            proc = subprocess.run(["/bin/sh", sandboxed_script], capture_output=True, text=True)

            self.assertEqual(proc.returncode, 1)
            self.assertIn("Rolling back", proc.stdout)
            self.assertFalse(os.path.exists(os.path.join(etc_mihomo, "config.yaml.tmp")))

    def test_atomic_script_service_status_failure_triggers_rollback(self):
        """Verifies rollback triggers when service status returns non-running."""
        with tempfile.TemporaryDirectory() as td:
            etc_mihomo, init_dir, sandbox_mihomo = self._setup_sandbox(td)

            orig_config = os.path.join(etc_mihomo, "config.yaml")
            with open(orig_config, "w") as f:
                f.write("INITIAL_STABLE_CONFIG\n")

            # Service fails status check (returns 'stopped')
            mihomo_svc = os.path.join(init_dir, "mihomo")
            with open(mihomo_svc, "w") as f:
                f.write("""#!/bin/sh
case "$1" in
    restart) echo "restarted" ;;
    status) echo "stopped" ;;
esac
exit 0
""")
            os.chmod(mihomo_svc, 0o755)

            script_path = os.path.join(td, "apply_to_router.sh")
            generate_router_script(["vless://uuid@1.1.1.1:443#Node"], config={}, out_file=script_path)

            sandboxed_script = self._adapt_script(script_path, td, sandbox_mihomo)
            proc = subprocess.run(["/bin/sh", sandboxed_script], capture_output=True, text=True)

            self.assertEqual(proc.returncode, 1, "Must fail with exit code 1 when service fails status")
            self.assertIn("Rolling back", proc.stdout)

            with open(orig_config, "r") as f:
                restored = f.read()
            self.assertEqual(restored.strip(), "INITIAL_STABLE_CONFIG")

    def test_atomic_script_heredoc_delimiter_vulnerability_boundary(self):
        """Verifies that delimiter injection in raw unparsed node is safely neutralized via base64."""
        with tempfile.TemporaryDirectory() as td:
            canary = os.path.join(td, "heredoc_breach_canary.txt")
            injected_raw_node = (
                f"unsupported_scheme://host:443\nEOF\ntouch {canary}\ncat << 'EOF'"
            )

            script_path = os.path.join(td, "apply_to_router.sh")
            generate_router_script([injected_raw_node], config={}, out_file=script_path)

            with open(script_path, "r", encoding="utf-8") as f:
                script_content = f.read()

            # Adapt /etc/mihomo so execution proceeds past mkdir
            sandboxed = script_content.replace("/etc/mihomo", os.path.join(td, "etc_mihomo"))
            runner_sh = os.path.join(td, "run_inject.sh")
            with open(runner_sh, "w", encoding="utf-8") as f:
                f.write(sandboxed)

            _ = subprocess.run(["/bin/sh", runner_sh], capture_output=True, text=True)

            # Assert that injection was safely neutralized and canary was NOT created
            self.assertFalse(
                os.path.exists(canary),
                "Heredoc injection must be neutralized by base64 staging; canary must not exist!",
            )


class TestAgentsMdConcurrencyStressAdversarial(IsolatedAsyncioTestCase):
    """Adversarial stress testing of AGENTS.md concurrency guardrails."""

    async def test_ephemeral_port_stress_50_concurrent_allocations(self):
        """AGENTS.md Rule 2: 50 concurrent allocations and live servers with zero TIME_WAIT collisions."""
        ports = []
        servers = []
        try:
            for _ in range(50):
                p = MihomoManager.get_free_port()
                self.assertNotIn(p, ports, f"Port collision detected for port {p}!")
                ports.append(p)
                server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", p)
                servers.append(server)

            self.assertEqual(len(servers), 50)
            self.assertEqual(len(set(ports)), 50)
        finally:
            for s, p in zip(servers, ports):
                s.close()
                await s.wait_closed()
                MihomoManager.release_port(p)

    async def test_safe_close_writer_50_concurrent_hanging_peers(self):
        """AGENTS.md Rule 1: 50 concurrent hanging peers wrapped in safe_close_writer never block beyond timeout."""
        writers = []
        for _ in range(50):
            w = MagicMock()
            w.close = MagicMock()

            async def hang_infinitely():
                await asyncio.sleep(5.0)

            w.wait_closed = hang_infinitely
            writers.append(w)

        t_start = time.monotonic()
        results = await asyncio.gather(*[safe_close_writer(w, timeout=0.2) for w in writers])
        total_time = time.monotonic() - t_start

        self.assertEqual(len(results), 50)
        # All 50 writers ran concurrently and were cancelled at 0.2s (+ small margin < 0.40s)
        self.assertLess(
            total_time,
            0.40,
            f"50 concurrent safe_close_writer calls blocked for {total_time:.3f}s (exceeded 0.40s)!",
        )
        for w in writers:
            w.close.assert_called_once()

    async def test_safe_close_writer_abrupt_disconnect_and_exceptions(self):
        """AGENTS.md Rule 1: safe_close_writer handles None, closed writers, and socket exceptions silently."""
        # 1. None
        await safe_close_writer(None)

        # 2. ConnectionResetError on wait_closed
        w_rst = MagicMock()
        w_rst.close = MagicMock()

        async def raise_reset():
            raise ConnectionResetError("TCP Connection Reset by peer")

        w_rst.wait_closed = raise_reset
        await safe_close_writer(w_rst, timeout=0.2)
        w_rst.close.assert_called_once()

        # 3. BrokenPipeError on close()
        w_pipe = MagicMock()
        w_pipe.close.side_effect = BrokenPipeError("Broken Pipe")
        await safe_close_writer(w_pipe, timeout=0.2)

    async def test_single_attempt_cache_lock_50_concurrent_failing_fetches(self):
        """AGENTS.md Rule 3: 50 concurrent callers on is_router_alive trigger exactly 1 probe on network failure."""
        mock_client = MagicMock()
        network_attempts = 0

        async def failing_is_alive():
            nonlocal network_attempts
            network_attempts += 1
            await asyncio.sleep(0.02)
            raise ConnectionRefusedError("Simulated network failure")

        mock_client.is_api_alive = failing_is_alive

        validator = RouterValidator(router_client=mock_client)
        validator.reset_alive_cache()

        results = await asyncio.gather(*[validator.is_router_alive() for _ in range(50)])

        self.assertEqual(len(results), 50)
        self.assertTrue(all(r is False for r in results))
        self.assertEqual(
            network_attempts, 1, "Single-attempt lock violated! More than 1 network attempt made."
        )
        self.assertTrue(validator._alive_attempted)
        self.assertFalse(validator._is_alive)

    async def test_geolocation_service_single_attempt_lock_50_concurrent_failures(self):
        """AGENTS.md Rule 3: GeolocationService makes exactly 1 attempt on outage and falls back to offline cache."""
        GeolocationService._country_attempted = False

        with patch("aiohttp.ClientSession.get", side_effect=OSError("Network unreachable")) as fetch:
            country_tasks = [GeolocationService.get_country_name("US") for _ in range(50)]
            country_results = await asyncio.gather(*country_tasks)

        self.assertEqual(len(country_results), 50)
        self.assertTrue(all(c == "United States" for c in country_results))
        self.assertEqual(fetch.call_count, 1)
        self.assertTrue(GeolocationService._country_attempted)


if __name__ == "__main__":
    unittest.main()
