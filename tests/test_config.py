"""Unit tests for configuration manager and serialization."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch
from nodesieve.config import ConfigManager
from nodesieve.constants import CONFIG_FILE, DEFAULT_CONFIG, LEGACY_CONFIG_FILE


class TestConfigManager(unittest.TestCase):
    def test_load_default(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            non_existent_file = os.path.join(tmp_dir, "non_existent.json")
            cfg = ConfigManager.load(non_existent_file)
            self.assertEqual(cfg["tcp_workers"], DEFAULT_CONFIG["tcp_workers"])
            self.assertEqual(cfg["speedtest_timeout"], DEFAULT_CONFIG["speedtest_timeout"])

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_file = os.path.join(tmp_dir, "config.json")
            test_cfg = {
                "subscriptions": ["https://example.com/sub.txt"],
                "tcp_workers": 256,
                "allowed_countries": ["us", "de"],
                "use_goida_proxies": True,  # should normalize to "all"
                "use_warp_scanner": True,
            }
            ConfigManager.save(test_cfg, cfg_file)

            loaded = ConfigManager.load(cfg_file)
            self.assertEqual(loaded["subscriptions"], ["https://example.com/sub.txt"])
            self.assertEqual(loaded["tcp_workers"], 256)
            self.assertEqual(loaded["allowed_countries"], ["US", "DE"])
            self.assertEqual(loaded["use_goida_proxies"], "all")
            self.assertTrue(loaded["use_warp_scanner"])

    def test_load_with_trailing_commas(self):
        """ConfigManager.load seamlessly parses JSON with human-written trailing commas."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_file = os.path.join(tmp_dir, "config_trailing.json")
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write('{\n  "subscriptions": [\n    "https://example.com/sub.txt",\n  ],\n  "workers": 64,\n}\n')
            loaded = ConfigManager.load(cfg_file)
            self.assertEqual(loaded["subscriptions"], ["https://example.com/sub.txt"])
            self.assertEqual(loaded["workers"], 64)

    def test_load_corrupted_json_logs_warning(self):
        """ConfigManager.load logs a warning and falls back to default on unrecoverable syntax error."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_file = os.path.join(tmp_dir, "corrupted.json")
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write('NOT_VALID_JSON{{{')
            loaded = ConfigManager.load(cfg_file)
            self.assertEqual(loaded["tcp_workers"], DEFAULT_CONFIG["tcp_workers"])


class TestDefaultSettingsPath(unittest.TestCase):
    """Settings saved as proxy_sites_config.json, before the project was renamed, carry over."""

    @staticmethod
    def write(path, settings):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f)

    def test_new_project_uses_the_new_name(self):
        with tempfile.TemporaryDirectory() as project:
            self.assertEqual(ConfigManager.default_path(project), os.path.join(project, CONFIG_FILE))
            self.assertEqual(os.listdir(project), [])

    def test_settings_under_the_former_name_are_renamed(self):
        with tempfile.TemporaryDirectory() as project:
            self.write(os.path.join(project, LEGACY_CONFIG_FILE),
                       {"subscriptions": ["https://example.com/sub"], "router_ssh_pass": "secret"})
            with self.assertLogs("nodesieve", "INFO") as logs:
                path = ConfigManager.default_path(project)
            self.assertEqual(path, os.path.join(project, CONFIG_FILE))
            self.assertEqual(os.listdir(project), [CONFIG_FILE])
            loaded = ConfigManager.load(path)
            self.assertEqual(loaded["subscriptions"], ["https://example.com/sub"])
            self.assertEqual(loaded["router_ssh_pass"], "secret")
            self.assertIn(f"Renamed {LEGACY_CONFIG_FILE} to {CONFIG_FILE}", logs.output[0])
            self.assertEqual(ConfigManager.default_path(project), path)

    def test_new_file_wins_and_the_former_one_is_left_alone(self):
        with tempfile.TemporaryDirectory() as project:
            legacy, current = os.path.join(project, LEGACY_CONFIG_FILE), os.path.join(project, CONFIG_FILE)
            self.write(legacy, {"workers": 1})
            self.write(current, {"workers": 2})
            with self.assertLogs("nodesieve", "WARNING") as logs:
                path = ConfigManager.default_path(project)
            self.assertEqual(path, current)
            self.assertEqual(ConfigManager.load(legacy)["workers"], 1)
            self.assertEqual(ConfigManager.load(current)["workers"], 2)
            self.assertIn(f"{LEGACY_CONFIG_FILE} is no longer used", logs.output[0])

    def test_former_file_is_used_when_it_cannot_be_renamed(self):
        with tempfile.TemporaryDirectory() as project:
            legacy = os.path.join(project, LEGACY_CONFIG_FILE)
            self.write(legacy, {"workers": 3})
            with patch("nodesieve.config.os.rename", side_effect=PermissionError("read-only directory")), \
                    self.assertLogs("nodesieve", "WARNING") as logs:
                path = ConfigManager.default_path(project)
            self.assertEqual(path, legacy)
            self.assertEqual(ConfigManager.load(path)["workers"], 3)
            self.assertIn("using the old file", logs.output[0])


if __name__ == "__main__":
    unittest.main()
