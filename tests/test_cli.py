"""The command line: which action runs, with what, and which combinations are refused."""

import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from nodesieve.config import ConfigManager
from nodesieve.constants import CONFIG_FILE
from nodesieve.ui.cli import build_parser, main
from nodesieve.ui.dashboard import VPNDashboard


class TestCLI(unittest.TestCase):
    def test_parser_defaults_to_a_scan(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.action, "check")
        self.assertFalse(args.dry_run)

    def test_removed_actions_and_options_are_refused(self):
        for argv in (["run"], ["deploy"], ["--run"], ["--check"], ["--deploy-only"], ["--no-router-validation"],
                     ["--router-api-port", "9090"], ["--router-proxy-port", "7890"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as exit_info:
                build_parser().parse_args(argv)
            self.assertEqual(exit_info.exception.code, 2)

    def test_parser_config_overrides(self):
        args = build_parser().parse_args([
            "--workers", "64", "--tcp-workers", "256", "--countries", "US,GB,DE",
            "--speedtest-timeout", "15", "--router-host", "192.168.1.254",
        ])
        self.assertEqual((args.workers, args.tcp_workers, args.allowed_countries, args.speedtest_timeout,
                          args.router_host), ("64", 256, "US,GB,DE", 15, "192.168.1.254"))

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_a_scan_runs_by_default_and_as_check(self, mock_pipeline):
        mock_pipeline.return_value = True
        for argv in ([], ["check"]):
            with self.subTest(argv=argv):
                mock_pipeline.reset_mock()
                main(argv)
                mock_pipeline.assert_awaited_once_with(dry_run=False)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_dry_run_reaches_the_scan(self, mock_pipeline):
        mock_pipeline.return_value = True
        main(["check", "--dry-run"])
        mock_pipeline.assert_awaited_once_with(dry_run=True)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_a_failed_scan_exits_with_code_1(self, mock_pipeline):
        mock_pipeline.return_value = False
        with self.assertRaises(SystemExit) as cm:
            main(["check"])
        self.assertEqual(cm.exception.code, 1)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_default_config_loads_and_saves_from_project_directory(self, mock_pipeline):
        """Subscription edits use the canonical project config from any working directory."""
        self.assertEqual(CONFIG_FILE, "nodesieve_config.json")
        with tempfile.TemporaryDirectory() as project_dir, tempfile.TemporaryDirectory() as caller_dir:
            config_path = os.path.join(project_dir, "nodesieve_config.json")
            with open(config_path, "w", encoding="utf-8") as config_file:
                json.dump({"subscriptions": ["https://example.com/existing"], "workers": 7}, config_file)
            previous_cwd = os.getcwd()
            try:
                os.chdir(caller_dir)
                with patch("nodesieve.ui.cli.PROJECT_ROOT", project_dir):
                    with self.assertRaises(SystemExit) as exit_result:
                        main(["--add-sub", "https://example.com/new"])
                self.assertEqual(exit_result.exception.code, 0)
                self.assertFalse(os.path.exists("nodesieve_config.json"))
            finally:
                os.chdir(previous_cwd)

            with open(config_path, encoding="utf-8") as config_file:
                saved = json.load(config_file)
            self.assertEqual(saved["subscriptions"], ["https://example.com/existing", "https://example.com/new"])
            self.assertEqual(saved["workers"], 7)
            mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_add_sub_empty_string_exits_with_code_1_without_running_pipeline(self, mock_pipeline):
        """Passing empty string to --add-sub logs error and exits with code 1 without running pipeline."""
        with self.assertRaises(SystemExit) as cm:
            main(["--add-sub", "   "])
        self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_add_sub_duplicate_handling(self, mock_pipeline):
        """Adding already existing subscription exits cleanly without duplicating in config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"subscriptions": ["https://example.com/sub1"]}, f)
            cfg_path = f.name
        try:
            with self.assertRaises(SystemExit) as cm:
                main(["--config-file", cfg_path, "--add-sub", "https://example.com/sub1"])
            self.assertEqual(cm.exception.code, 0)
            mock_pipeline.assert_not_called()
            loaded = ConfigManager.load(cfg_path)
            self.assertEqual(loaded["subscriptions"], ["https://example.com/sub1"])
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_remove_sub_empty_or_nonexistent_exits_with_code_1(self, mock_pipeline):
        """Removing non-existent subscription index or empty string exits with code 1."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"subscriptions": ["https://example.com/sub1"]}, f)
            cfg_path = f.name
        try:
            with self.assertRaises(SystemExit) as cm:
                main(["--config-file", cfg_path, "--remove-sub", ""])
            self.assertEqual(cm.exception.code, 1)

            with self.assertRaises(SystemExit) as cm:
                main(["--config-file", cfg_path, "--remove-sub", "9999"])
            self.assertEqual(cm.exception.code, 1)

            with self.assertRaises(SystemExit) as cm:
                main(["--config-file", cfg_path, "--remove-sub", "https://notfound.com/sub"])
            self.assertEqual(cm.exception.code, 1)

            mock_pipeline.assert_not_called()
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_remove_sub_success_exits_with_code_0(self, mock_pipeline):
        """Successfully removing subscription modifies config and exits with code 0."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"subscriptions": ["https://example.com/sub1", "https://example.com/sub2"]}, f)
            cfg_path = f.name
        try:
            with self.assertRaises(SystemExit) as cm:
                main(["--config-file", cfg_path, "--remove-sub", "1"])
            self.assertEqual(cm.exception.code, 0)
            mock_pipeline.assert_not_called()
            loaded = ConfigManager.load(cfg_path)
            self.assertEqual(loaded["subscriptions"], ["https://example.com/sub2"])
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_conflicting_add_sub_and_remove_sub_exits_code_1(self, mock_pipeline):
        """Specifying both --add-sub and --remove-sub exits with code 1."""
        with self.assertRaises(SystemExit) as cm:
            main(["--add-sub", "https://example.com/sub1", "--remove-sub", "1"])
        self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_dry_run_with_configuration_management_is_refused(self, mock_pipeline):
        for cmd in (["--add-sub", "https://example.com/sub1", "--dry-run"], ["--remove-sub", "1", "--dry-run"],
                    ["config", "--dry-run"], ["--show-config", "--dry-run"], ["serve", "--dry-run"]):
            with self.subTest(cmd=cmd), self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_numeric_arguments_input_validation(self, mock_pipeline):
        """Zero, negative, or non-integer values for workers, tcp-workers, and timeout exit with code 1."""
        for cmd in [
            ["--workers", "0"],
            ["--workers", "-5"],
            ["--workers", "invalid_str"],
            ["--tcp-workers", "0"],
            ["--tcp-workers", "-10"],
            ["--speedtest-timeout", "0"],
            ["--speedtest-timeout", "-3"],
        ]:
            with self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1, f"Failed on command: {cmd}")
            mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_router_ssh_port_input_validation(self, mock_pipeline):
        for cmd in (["--router-ssh-port", "0"], ["--router-ssh-port", "99999"]):
            with self.subTest(cmd=cmd), self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_option_values_are_not_read_as_actions(self, mock_pipeline):
        mock_pipeline.return_value = True
        for cmd in (["--router-ssh-user", "check"], ["--router-ssh-pass", "serve"], ["-s", "https://example.com/sub/check"]):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump({"subscriptions": ["https://example.com/sub"]}, f)
                cfg_path = f.name
            try:
                main(["--config-file", cfg_path] + cmd)
            finally:
                os.remove(cfg_path)
        self.assertEqual(mock_pipeline.call_count, 3)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_empty_subscription_flag_exits_code_1(self, mock_pipeline):
        """Passing empty or whitespace-only subscription in -s exits with code 1."""
        for empty_val in ["", "   "]:
            with self.assertRaises(SystemExit) as cm:
                main(["-s", empty_val])
            self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_empty_router_user_and_host_exits_code_1(self, mock_pipeline):
        """Passing whitespace-only router host or user exits with code 1."""
        for flag in ["--router-host", "--router-ssh-user"]:
            with self.assertRaises(SystemExit) as cm:
                main([flag, "   "])
            self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()


if __name__ == "__main__":
    unittest.main()
