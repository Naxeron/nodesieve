"""Unit tests for WarpScanner and Router config/script generation."""

import asyncio
import os
import subprocess
import tempfile
import unittest
import yaml

from proxy_sites.constants import (
    GOOGLE_HEALTHCHECK_URL,
    PROJECT_ROOT,
)
from proxy_sites.core.fetcher import NodeFetcher
from proxy_sites.router.config_builder import build_router_config_yaml
from proxy_sites.router.script_generator import generate_router_script
from proxy_sites.warp import WarpScanner

# A made-up WARP registration: the key is the bytes 0..31.
WARP_SETTINGS = {
    "warp_private_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "warp_ipv6": "2001:db8::2",
}


class TestWarpAndRouter(unittest.TestCase):
    """Tests for WarpScanner, Router config builder, and script generator."""

    def test_constants_parity_definitions(self):
        """Verify router parity constants are correctly defined."""
        self.assertEqual(
            GOOGLE_HEALTHCHECK_URL,
            "https://www.gstatic.com/generate_204",
        )

    def test_warp_scanner_endpoints(self):
        endpoints = WarpScanner.generate_endpoints(ips_per_subnet=2)
        self.assertGreater(len(endpoints), 0)
        for ep in endpoints:
            self.assertTrue(ep.startswith("warp://"))
            self.assertIn("#WARP", ep)

    def test_warp_proxy_dict(self):
        proxy = WarpScanner.generate_warp_proxy_dict(
            "162.159.192.1", 2408, "WARP_TEST", config=WARP_SETTINGS
        )
        self.assertEqual(proxy["name"], "WARP_TEST")
        self.assertEqual(proxy["type"], "wireguard")
        self.assertEqual(proxy["server"], "162.159.192.1")
        self.assertEqual(proxy["port"], 2408)
        self.assertIn("amnezia-wg-option", proxy)

    def test_warp_proxy_dict_uses_the_configured_registration(self):
        proxy = WarpScanner.generate_warp_proxy_dict(
            "162.159.192.1", 2408, config=WARP_SETTINGS
        )
        self.assertEqual(proxy["private-key"], WARP_SETTINGS["warp_private_key"])
        self.assertEqual(proxy["ipv6"], WARP_SETTINGS["warp_ipv6"])
        self.assertEqual(proxy["public-key"], WarpScanner.PUBLIC_KEY)

        ipv4_only = WarpScanner.generate_warp_proxy_dict(
            "162.159.192.1", 2408,
            config={"warp_private_key": WARP_SETTINGS["warp_private_key"]},
        )
        self.assertNotIn("ipv6", ipv4_only)

    def test_warp_proxy_dict_needs_a_registration(self):
        for config in (None, {}, {"warp_private_key": "  "}):
            with self.assertRaises(ValueError):
                WarpScanner.generate_warp_proxy_dict(
                    "162.159.192.1", 2408, config=config
                )

    def test_fetcher_scans_warp_only_with_a_registration(self):
        settings = {
            "subscriptions": [],
            "use_amnezia_wg": False,
            "use_warp_scanner": True,
        }
        nodes, _ = asyncio.run(NodeFetcher(dict(settings)).fetch_all())
        self.assertEqual(nodes, [])

        nodes, _ = asyncio.run(
            NodeFetcher({**settings, **WARP_SETTINGS}).fetch_all()
        )
        self.assertTrue(nodes)
        for node in nodes:
            self.assertTrue(node.startswith("warp://"))

    def test_build_router_config_yaml(self):
        warp_dict = WarpScanner.generate_warp_proxy_dict(
            "162.159.192.1", 2408, "WARP_1", config=WARP_SETTINGS
        )
        yaml_out = build_router_config_yaml(
            awg_proxy=None, warp_proxies=[warp_dict]
        )

        # Basic proxy entries
        self.assertIn("WARP_1", yaml_out)
        self.assertIn("Gemini_Auto", yaml_out)
        self.assertIn("Домашний интернет", yaml_out)

        # Healthcheck parity URL and expected-status
        self.assertIn(GOOGLE_HEALTHCHECK_URL, yaml_out)
        self.assertIn('expected-status: "204"', yaml_out)

        # Healthcheck parameters (30s interval, 3000ms timeout, 2 fails)
        self.assertIn("timeout: 3000", yaml_out)
        self.assertIn("max-failed-times: 2", yaml_out)

        # IPv6 routing disparity fix
        self.assertIn("prefer-ipv6: false", yaml_out)

        # No extra listener beyond the main mixed port is opened on the router
        self.assertNotIn("listeners:", yaml_out)
        self.assertNotIn("7891", yaml_out)

        # Parse YAML structure
        parsed = yaml.safe_load(yaml_out)
        self.assertEqual(parsed.get("prefer-ipv6"), False)
        self.assertEqual(parsed.get("dns", {}).get("prefer-ipv6"), False)

        providers = parsed.get("proxy-providers", {})
        gn_provider = providers.get("Gemini_Nodes", {})
        gn_hc = gn_provider.get("health-check", {})
        self.assertEqual(gn_hc.get("url"), GOOGLE_HEALTHCHECK_URL)
        self.assertEqual(str(gn_hc.get("expected-status")), "204")
        self.assertEqual(gn_hc.get("timeout"), 3000)
        self.assertEqual(gn_hc.get("max-failed-times"), 2)
        self.assertEqual(gn_hc.get("lazy"), False)

        groups = {g["name"]: g for g in parsed.get("proxy-groups", [])}
        self.assertIn("Gemini_Auto", groups)
        auto_group = groups["Gemini_Auto"]
        self.assertEqual(auto_group.get("url"), GOOGLE_HEALTHCHECK_URL)
        self.assertEqual(str(auto_group.get("expected-status")), "204")
        self.assertEqual(auto_group.get("timeout"), 3000)
        self.assertEqual(auto_group.get("max-failed-times"), 2)
        self.assertEqual(auto_group.get("lazy"), False)

        self.assertEqual(list(groups), ["Gemini_Auto"])
        self.assertEqual(parsed.get("rules"), ["MATCH,Gemini_Auto"])
        self.assertNotIn("listeners", parsed)

        # Validate with local mihomo binary if present
        mihomo_bin = os.path.join(PROJECT_ROOT, "mihomo")
        if os.path.exists(mihomo_bin) and os.access(mihomo_bin, os.X_OK):
            with tempfile.TemporaryDirectory() as td:
                prov_dir = os.path.join(td, "proxy-providers")
                os.makedirs(prov_dir)
                with open(os.path.join(prov_dir, "sub.yaml"), "w") as sf:
                    yaml.dump({"proxies": [{"name": "n1", "type": "direct"}]},
                              sf)
                cfg_path = os.path.join(td, "config.yaml")
                with open(cfg_path, "w") as cf:
                    cf.write(yaml_out)
                res = subprocess.run(
                    [mihomo_bin, "-t", "-d", td, "-f", cfg_path],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    res.returncode,
                    0,
                    f"mihomo -t failed:\n{res.stdout}\n{res.stderr}",
                )

    def test_build_router_config_yaml_awg_and_warp(self):
        """Verify config formatting with both AWG and WARP proxies."""
        awg_mock = {
            "name": "AWG_Test",
            "type": "wireguard",
            "server": "1.2.3.4",
            "port": 51820,
            "ip": "10.0.0.2",
            "public-key": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            "private-key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "amnezia-wg-option": {
                "jc": 1, "jmin": 10, "jmax": 20, "s1": 0, "s2": 0,
                "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            },
        }
        warp1 = WarpScanner.generate_warp_proxy_dict(
            "162.159.192.1", 2408, "WARP_1", config=WARP_SETTINGS
        )
        yaml_out = build_router_config_yaml(
            awg_proxy=awg_mock, warp_proxies=[warp1]
        )
        self.assertIn("AWG_Test", yaml_out)
        self.assertIn("WARP_1", yaml_out)

        parsed = yaml.safe_load(yaml_out)
        auto_group = next(
            g for g in parsed["proxy-groups"] if g["name"] == "Gemini_Auto"
        )
        self.assertIn("AWG_Test", auto_group.get("proxies", []))
        self.assertIn("WARP_1", auto_group.get("proxies", []))

    def test_generate_router_script(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_script = os.path.join(tmp_dir, "apply.sh")
            sample_nodes = [
                "vless://22222222-2222-4222-8222-222222222222@203.0.113.43:"
                "52463?security=reality&encryption=none&pbk=AAECAwQFBgcICQoLD"
                "A0ODxAREhMUFRYXGBkaGxwdHh8&headerType=none&fp=random&spx=%2F"
                "&type=tcp&sni=example.com&sid=0123456789ab#Latvia",
                "warp://162.159.192.1:2408#WARP_Node",
            ]
            generate_router_script(
                sample_nodes, config=dict(WARP_SETTINGS), out_file=out_script
            )
            self.assertTrue(os.path.exists(out_script))

            with open(out_script, "r", encoding="utf-8") as f:
                content = f.read()

            # Script header and staging to .tmp
            self.assertTrue(content.startswith("#!/bin/sh"))
            self.assertIn("set -e", content)
            self.assertIn("/etc/mihomo/proxy-providers/sub.yaml.tmp", content)
            self.assertIn("/etc/mihomo/config.yaml.tmp", content)

            # Backup creation
            self.assertIn("/etc/mihomo/config.yaml.bak", content)
            self.assertIn(
                "/etc/mihomo/proxy-providers/sub.yaml.bak", content
            )

            # Rollback function
            self.assertIn("rollback() {", content)
            self.assertIn(
                "mv -f /etc/mihomo/config.yaml.bak /etc/mihomo/config.yaml",
                content,
            )
            self.assertIn(
                "mv -f /etc/mihomo/proxy-providers/sub.yaml.bak "
                "/etc/mihomo/proxy-providers/sub.yaml",
                content,
            )
            self.assertIn(
                "rm -f /etc/mihomo/config.yaml.tmp "
                "/etc/mihomo/proxy-providers/sub.yaml.tmp",
                content,
            )
            self.assertIn("exit 1", content)

            # Pre-flight syntax validation
            self.assertIn(
                "/usr/bin/mihomo -t -d /etc/mihomo "
                "-f /etc/mihomo/config.yaml.tmp || rollback",
                content,
            )

            # Atomic file move
            self.assertIn(
                "mv -f /etc/mihomo/proxy-providers/sub.yaml.tmp "
                "/etc/mihomo/proxy-providers/sub.yaml",
                content,
            )
            self.assertIn(
                "mv -f /etc/mihomo/config.yaml.tmp /etc/mihomo/config.yaml",
                content,
            )

            # Service restarts with rollback on error
            self.assertIn("/etc/init.d/mihomo restart || rollback", content)
            self.assertIn(
                "/etc/init.d/magitrickle restart || rollback", content
            )

            # Post-restart verification
            self.assertIn(
                "/etc/init.d/mihomo status | grep -q running || rollback",
                content,
            )
            self.assertIn(
                "/etc/init.d/magitrickle status | grep -q running || rollback",
                content,
            )
            self.assertIn("127.0.0.1:9090", content)
            self.assertIn("grep -q 'version' || rollback", content)

            # Node presence
            self.assertIn("WARP_Node", content)
            self.assertIn("Latvia", content)

            # Shell syntax check
            sh_check = subprocess.run(
                ["sh", "-n", out_script],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                sh_check.returncode,
                0,
                f"sh -n failed on generated script: {sh_check.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
