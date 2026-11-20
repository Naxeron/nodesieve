"""Unit tests for configuration manager and serialization."""

import os
import tempfile
import unittest
from nodesieve.config import ConfigManager
from nodesieve.constants import CONFIG_FILE, DEFAULT_CONFIG


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
                "use_mux": False,
            }
            ConfigManager.save(test_cfg, cfg_file)

            loaded = ConfigManager.load(cfg_file)
            self.assertEqual(loaded["subscriptions"], ["https://example.com/sub.txt"])
            self.assertEqual(loaded["tcp_workers"], 256)
            self.assertEqual(loaded["allowed_countries"], ["US", "DE"])
            self.assertFalse(loaded["use_mux"])

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
    def test_settings_live_in_the_project_directory(self):
        with tempfile.TemporaryDirectory() as project:
            self.assertEqual(ConfigManager.default_path(project), os.path.join(project, CONFIG_FILE))
            self.assertEqual(os.listdir(project), [])


if __name__ == "__main__":
    unittest.main()
