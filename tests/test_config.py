"""Unit tests for configuration manager and serialization."""

import json
import os
from pathlib import Path
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

    def test_legacy_connection_settings_are_dropped_on_the_next_save(self):
        legacy = {
            "router_host": "router.example", "router_ssh_port": 22, "router_ssh_user": "root",
            "router_ssh_pass": "old-password", "router_ssh_key_path": "/old/key",
            "router_api_port": 9090, "router_proxy_port": 7890, "enable_router_validation": True,
        }
        local = {"subscriptions": ["https://example.com/sub"], "feed_dir": "/www/nodesieve/example",
                 "routing_output_dir": "reports", "workers": 4}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / CONFIG_FILE
            path.write_text(json.dumps({**local, **legacy}), encoding="utf-8")
            loaded = ConfigManager.load(path)
            self.assertTrue(legacy.keys().isdisjoint(loaded))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {**local, **legacy})
            ConfigManager.save(loaded, path)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(legacy.keys().isdisjoint(saved))
            self.assertEqual({key: saved[key] for key in local}, local)

    def test_min_speed_percent_round_trip_and_invalid_values(self):
        default = DEFAULT_CONFIG["min_speed_percent"]
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_file = os.path.join(tmp_dir, "config.json")
            for value, expected in [("62.5", 62.5), (0, 0), (100, 100), (-1, default), (101, default),
                                    ("nan", default), ("invalid", default), (True, default), (None, default)]:
                with self.subTest(value=value):
                    ConfigManager.save({"min_speed_percent": value}, cfg_file)
                    self.assertEqual(ConfigManager.load(cfg_file)["min_speed_percent"], expected)

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
