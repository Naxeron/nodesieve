"""Unit and integration tests for streamlined single-command CLI, fresh on-demand evaluation, and rollback safety."""

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from proxy_sites.config import ConfigManager
from proxy_sites.constants import CONFIG_FILE
from proxy_sites.core.fetcher import NodeFetcher
from proxy_sites.core.router_validator import RouterValidator
from proxy_sites.router.script_generator import generate_router_script
from proxy_sites.ui.cli import build_parser, main
import proxy_sites.ui.dashboard as dashboard_module
from proxy_sites.ui.dashboard import VPNDashboard


class TestStreamlinedCLI(unittest.TestCase):
    """Tests for CLI argument parsing and non-interactive execution phases."""

    def test_cli_parser_defaults(self):
        """Default invocation without flags defaults to action 'run' without prompting."""
        parser = build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.action, "run")
        self.assertFalse(args.flag_check_only)
        self.assertFalse(args.flag_deploy_only)
        self.assertFalse(args.dry_run)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_default_config_loads_and_saves_from_project_directory(self, mock_pipeline):
        """Subscription edits use the canonical project config from any working directory."""
        self.assertEqual(CONFIG_FILE, "proxy_sites_config.json")
        with tempfile.TemporaryDirectory() as project_dir, tempfile.TemporaryDirectory() as caller_dir:
            config_path = os.path.join(project_dir, "proxy_sites_config.json")
            with open(config_path, "w", encoding="utf-8") as config_file:
                json.dump({"subscriptions": ["https://example.com/existing"], "workers": 7}, config_file)
            previous_cwd = os.getcwd()
            try:
                os.chdir(caller_dir)
                with patch("proxy_sites.ui.cli.PROJECT_ROOT", project_dir):
                    with self.assertRaises(SystemExit) as exit_result:
                        main(["--add-sub", "https://example.com/new"])
                self.assertEqual(exit_result.exception.code, 0)
                self.assertFalse(os.path.exists("proxy_sites_config.json"))
            finally:
                os.chdir(previous_cwd)

            with open(config_path, encoding="utf-8") as config_file:
                saved = json.load(config_file)
            self.assertEqual(saved["subscriptions"], ["https://example.com/existing", "https://example.com/new"])
            self.assertEqual(saved["workers"], 7)
            mock_pipeline.assert_not_called()

    def test_cli_parser_phase_flags(self):
        """Phase flags allow non-interactive selection of check-only, deploy-only, dry-run."""
        parser = build_parser()

        # Check only
        args_check = parser.parse_args(["--check-only"])
        self.assertTrue(args_check.flag_check_only)

        # Deploy only
        args_deploy = parser.parse_args(["--deploy-only"])
        self.assertTrue(args_deploy.flag_deploy_only)

        # Subcommand check
        args_sub_check = parser.parse_args(["check"])
        self.assertEqual(args_sub_check.action, "check")

        # Subcommand deploy
        args_sub_deploy = parser.parse_args(["deploy"])
        self.assertEqual(args_sub_deploy.action, "deploy")

        # Dry run
        args_dry = parser.parse_args(["--dry-run"])
        self.assertTrue(args_dry.dry_run)

    def test_cli_parser_config_overrides(self):
        """CLI flags override concurrency, country filtering, and timeouts."""
        parser = build_parser()
        args = parser.parse_args([
            "--workers", "64",
            "--tcp-workers", "256",
            "--countries", "US,GB,DE",
            "--speedtest-timeout", "15",
            "--no-router-validation",
            "--router-host", "192.168.1.254",
        ])
        self.assertEqual(args.workers, "64")
        self.assertEqual(args.tcp_workers, 256)
        self.assertEqual(args.allowed_countries, "US,GB,DE")
        self.assertEqual(args.speedtest_timeout, 15)
        self.assertTrue(args.disable_router_validation)
        self.assertEqual(args.router_host, "192.168.1.254")

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_main_default_executes_full_pipeline(self, mock_pipeline):
        """Running main() directly executes end-to-end workflow without prompting."""
        mock_pipeline.return_value = True
        main(["--run"])
        mock_pipeline.assert_awaited_once_with(
            check_only=False, deploy_only=False, dry_run=False
        )

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_main_check_only_phase(self, mock_pipeline):
        """Running main with check phase executes check-only."""
        mock_pipeline.return_value = True
        main(["check"])
        mock_pipeline.assert_awaited_once_with(
            check_only=True, deploy_only=False, dry_run=False
        )

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_main_deploy_only_phase(self, mock_pipeline):
        """Running main with deploy phase executes deploy-only."""
        mock_pipeline.return_value = True
        main(["deploy"])
        mock_pipeline.assert_awaited_once_with(
            check_only=False, deploy_only=True, dry_run=False
        )

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_main_dry_run_phase(self, mock_pipeline):
        """Running main with --dry-run sets dry_run=True."""
        mock_pipeline.return_value = True
        main(["--dry-run"])
        mock_pipeline.assert_awaited_once_with(
            check_only=False, deploy_only=False, dry_run=True
        )

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_main_failure_exits_with_code_1(self, mock_pipeline):
        """When pipeline returns False, main exits with code 1."""
        mock_pipeline.return_value = False
        with self.assertRaises(SystemExit) as cm:
            main(["--run"])
        self.assertEqual(cm.exception.code, 1)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_conflicting_check_and_deploy_phases_exits_with_code_1(self, mock_pipeline):
        """Specifying both check and deploy phases simultaneously aborts with exit code 1."""
        with self.assertRaises(SystemExit) as cm:
            main(["--check-only", "--deploy-only"])
        self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

        with self.assertRaises(SystemExit) as cm:
            main(["check", "--deploy-only"])
        self.assertEqual(cm.exception.code, 1)
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
    def test_cli_conflicting_run_and_phase_flags_exits_code_1(self, mock_pipeline):
        """Combining --run or positional 'run' with check-only or deploy-only exits with code 1."""
        for cmd in [
            ["--run", "--check-only"],
            ["--run", "--deploy-only"],
            ["run", "--check-only"],
            ["run", "--deploy-only"],
            ["check", "--run"],
            ["deploy", "--run"],
        ]:
            with self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1, f"Failed on command: {cmd}")
            mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_conflicting_add_sub_and_remove_sub_exits_code_1(self, mock_pipeline):
        """Specifying both --add-sub and --remove-sub exits with code 1."""
        with self.assertRaises(SystemExit) as cm:
            main(["--add-sub", "https://example.com/sub1", "--remove-sub", "1"])
        self.assertEqual(cm.exception.code, 1)
        mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_conflicting_sub_and_phase_flags_exits_code_1(self, mock_pipeline):
        """Combining subscription management with pipeline execution flags exits with code 1."""
        for cmd in [
            ["--add-sub", "https://example.com/sub1", "--run"],
            ["--remove-sub", "1", "--check-only"],
            ["--add-sub", "https://example.com/sub1", "--deploy-only"],
            ["--remove-sub", "1", "--dry-run"],
        ]:
            with self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1, f"Failed on command: {cmd}")
            mock_pipeline.assert_not_called()

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_conflicting_config_and_phase_flags_exits_code_1(self, mock_pipeline):
        """Combining config management with pipeline phase flags exits with code 1."""
        for cmd in [
            ["config", "--run"],
            ["config", "--check-only"],
            ["--show-config", "--run"],
            ["--show-config", "--deploy-only"],
        ]:
            with self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1, f"Failed on command: {cmd}")
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
    def test_cli_router_ports_input_validation(self, mock_pipeline):
        """Ports outside 1-65535 exit with code 1."""
        for cmd in [
            ["--router-api-port", "0"],
            ["--router-api-port", "70000"],
            ["--router-proxy-port", "0"],
            ["--router-proxy-port", "100000"],
            ["--router-ssh-port", "0"],
            ["--router-ssh-port", "99999"],
        ]:
            with self.assertRaises(SystemExit) as cm:
                main(cmd)
            self.assertEqual(cm.exception.code, 1, f"Failed on command: {cmd}")
            mock_pipeline.assert_not_called()


class TestFreshOnDemandFetcher(unittest.TestCase):
    """Tests on-demand fetching and elimination of Goida bulk aggregators.

    The fallback cache of subscription payloads is covered by test_sub_cache.py.
    """

    def test_fetch_all_excludes_goida_bulk_mirrors(self):
        """Fetcher only queries user-configured subscriptions and does not append Goida mirrors."""
        config = {
            "subscriptions": ["https://example.com/custom_sub.txt"],
            "use_goida_proxies": "all",  # legacy config key should be ignored
            "use_amnezia_wg": False,
            "use_warp_scanner": False,
        }
        fetcher = NodeFetcher(config)

        queried_urls = []

        async def mock_process_url(session, url):
            queried_urls.append(url)
            return ["vless://uuid@1.1.1.1:443#Node1"]

        fetcher._process_url = mock_process_url

        nodes, source_map = asyncio.run(fetcher.fetch_all())
        self.assertEqual(queried_urls, ["https://example.com/custom_sub.txt"])
        self.assertNotIn("goida", str(queried_urls).lower())
        self.assertEqual(len(nodes), 1)

    def test_fetcher_with_empty_remote_subscriptions_loads_local_awg(self):
        """When subscriptions list is empty, fetcher still discovers local AmneziaWG .conf files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            conf_path = os.path.join(tmp_dir, "CustomAWG.conf")
            with open(conf_path, "w") as f:
                f.write(
                    "[Interface]\n"
                    "PrivateKey = aaaa\n"
                    "Address = 10.0.0.2/32\n"
                    "[Peer]\n"
                    "PublicKey = bbbb\n"
                    "Endpoint = 1.2.3.4:51820\n"
                )
            config = {
                "subscriptions": [],
                "use_amnezia_wg": True,
                "amnezia_wg_conf": conf_path,
                "use_warp_scanner": False,
            }
            fetcher = NodeFetcher(config)
            nodes, source_map = asyncio.run(fetcher.fetch_all())
            self.assertEqual(len(nodes), 1)
            self.assertTrue(nodes[0].startswith("awg_conf:"))

    def test_fetcher_deduplicates_duplicate_remote_subscriptions(self):
        """Duplicate subscription URLs in config are requested only once."""
        config = {
            "subscriptions": ["https://example.com/sub1", "https://example.com/sub1"],
            "use_amnezia_wg": False,
            "use_warp_scanner": False,
        }
        fetcher = NodeFetcher(config)
        queried = []

        async def mock_process(session, url):
            queried.append(url)
            return ["vless://uuid@1.1.1.1:443#Node1"]

        fetcher._process_url = mock_process
        nodes, _ = asyncio.run(fetcher.fetch_all())
        self.assertEqual(len(queried), 1)
        self.assertEqual(queried[0], "https://example.com/sub1")

    def test_fetcher_handles_multiline_and_urlsafe_base64_payload(self):
        """_process_url correctly decodes multiline and URL-safe base64 payloads."""
        import base64
        fetcher = NodeFetcher(config={"subscriptions": []})

        raw_nodes = "vless://uuid@1.1.1.1:443?type=tcp#NodeA\nvless://uuid@2.2.2.2:443?type=tcp#NodeB"
        encoded = base64.urlsafe_b64encode(raw_nodes.encode("utf-8")).decode("utf-8")
        # Introduce newlines within base64
        multiline_b64 = encoded[:15] + "\r\n" + encoded[15:]

        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200

        async def async_read():
            return multiline_b64.encode("utf-8")

        mock_resp.read = async_read

        class AsyncContextManager:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_session.get.return_value = AsyncContextManager()
        nodes = asyncio.run(fetcher._process_url(mock_session, "https://example.com/sub"))
        self.assertEqual(len(nodes), 2)


class TestStockpileElimination(unittest.TestCase):
    """Verifies complete removal of gemini_subscription.txt stockpile files."""

    def test_pipeline_does_not_create_or_merge_stockpile(self):
        """Running VPNDashboard does not create or read gemini_subscription.txt."""
        # The project directory the pipeline writes to: an empty temporary one (tests/conftest.py).
        project_dir = dashboard_module.PROJECT_ROOT
        stockpile_path = os.path.join(project_dir, "gemini_subscription.txt")
        tmp_stockpile = os.path.join(project_dir, "gemini_subscription_tmp.txt")

        dash = VPNDashboard(config={
            "subscriptions": ["https://example.com/mock_sub"],
            "workers": 4,
            "tcp_workers": 4,
            "enable_router_validation": False,
        })

        # Mock fetcher and testers
        async def mock_fetch_and_verify():
            return [("vless://uuid@1.1.1.1:443#Fresh_Node", 25.0, "orig")], None

        async def mock_speedtest(nodes, tester=None):
            return [("vless://uuid@1.1.1.1:443#Fresh_Node", 1000000.0, 1.0)]

        dash.fetch_and_verify_candidates_async = mock_fetch_and_verify
        dash.run_speedtest_nodes_async = mock_speedtest

        # Execute check-only pipeline
        success = asyncio.run(dash.run_pipeline_async(check_only=True))
        self.assertTrue(success)

        # The pipeline wrote its router script, and neither stockpile file, to the project directory.
        self.assertTrue(os.path.exists(os.path.join(project_dir, "apply_to_router.sh")))
        self.assertFalse(os.path.exists(stockpile_path), "gemini_subscription.txt must not be created!")
        self.assertFalse(os.path.exists(tmp_stockpile), "gemini_subscription_tmp.txt must not be created!")


class TestAutomatedDeploymentAndRollbackSafety(unittest.TestCase):
    """Verifies pre-flight configuration validation and automatic rollback safety."""

    def test_generated_router_script_has_preflight_and_rollback(self):
        """apply_to_router.sh includes pre-flight validation, PATH export, and rollback EXIT trap."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_script = os.path.join(tmp_dir, "apply_to_router.sh")
            nodes = ["vless://uuid@1.1.1.1:443#TestNode"]
            generate_router_script(nodes, out_file=out_script)

            with open(out_script, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("rollback()", content)
            self.assertIn("/usr/bin/mihomo -t", content)
            self.assertIn("config.yaml.bak", content)
            self.assertIn("sub.yaml.bak", content)
            self.assertIn('export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"', content)
            self.assertIn("trap 'if [ \"$success\" != \"1\" ]; then rollback; fi' EXIT", content)
            self.assertIn("trap - EXIT", content)

    def test_push_to_router_with_custom_config_parameters(self):
        """push_to_router constructs RouterClient using provided config when router_client is None."""
        from proxy_sites.router.pusher import push_to_router
        custom_config = {
            "router_host": "192.168.123.45",
            "router_api_port": 9099,
            "router_proxy_port": 7899,
            "router_ssh_port": 2222,
            "router_ssh_user": "custom_root",
            "router_ssh_pass": "custom_password",
        }
        with patch("proxy_sites.router.pusher.RouterClient") as mock_rc:
            mock_instance = mock_rc.return_value
            mock_instance.stream_file_to_router.return_value = True
            mock_instance.exec_command.return_value = (0, "ok", "")

            with tempfile.TemporaryDirectory() as tmp_dir:
                script_path = os.path.join(tmp_dir, "apply_to_router.sh")
                with open(script_path, "w") as f:
                    f.write("#!/bin/sh\necho ok\n")
                with patch("proxy_sites.router.pusher.ROUTER_SCRIPT_FILE", script_path):
                    res = push_to_router(config=custom_config)
                    self.assertTrue(res)

            mock_rc.assert_called_once_with(
                host="192.168.123.45",
                api_port=9099,
                proxy_port=7899,
                ssh_port=2222,
                ssh_user="custom_root",
                ssh_pass="custom_password",
            )

    def test_dashboard_push_to_router_propagates_custom_config(self):
        """VPNDashboard.push_to_router() instantiates RouterClient with self.config."""
        custom_config = {
            "router_host": "10.10.10.1",
            "router_api_port": 9090,
            "router_proxy_port": 7890,
            "router_ssh_port": 2200,
            "router_ssh_user": "admin_openwrt",
            "router_ssh_pass": "supersecret",
        }
        dash = VPNDashboard(config=custom_config)
        with patch("proxy_sites.ui.dashboard.push_to_router") as mock_pusher:
            mock_pusher.return_value = True
            res = dash.push_to_router()
            self.assertTrue(res)
            mock_pusher.assert_called_once()
            _, kwargs = mock_pusher.call_args
            passed_client = kwargs.get("router_client")
            self.assertIsNotNone(passed_client)
            self.assertEqual(passed_client.host, "10.10.10.1")
            self.assertEqual(passed_client.ssh_port, 2200)
            self.assertEqual(passed_client.ssh_user, "admin_openwrt")
            self.assertEqual(passed_client.ssh_pass, "supersecret")

    def test_router_validator_build_candidate_sub_yaml_awg_conf(self):
        """RouterValidator.build_candidate_sub_yaml parses awg_conf: and adds to proxy_dicts."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            conf_path = os.path.join(tmp_dir, "TestWireguard.conf")
            with open(conf_path, "w") as f:
                f.write(
                    "[Interface]\n"
                    "PrivateKey = aaaa\n"
                    "Address = 10.0.0.2/32\n"
                    "[Peer]\n"
                    "PublicKey = bbbb\n"
                    "Endpoint = 1.2.3.4:51820\n"
                )
            validator = RouterValidator()
            cand = f"awg_conf:{conf_path}#AWG_TestWireguard"
            yaml_str, name_to_cand = validator.build_candidate_sub_yaml([cand])
            self.assertIn("AWG_TestWireguard", name_to_cand)
            self.assertIn("type: wireguard", yaml_str)
            self.assertIn("name: AWG_TestWireguard", yaml_str)

    def test_script_generator_uses_configured_api_port(self):
        """generate_router_script incorporates custom router_api_port in curl/wget connectivity check."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_script = os.path.join(tmp_dir, "apply_to_router.sh")
            custom_config = {"router_api_port": 9099}
            generate_router_script(["vless://uuid@1.1.1.1:443#TestNode"], config=custom_config, out_file=out_script)
            with open(out_script, "r") as f:
                content = f.read()
            self.assertIn("127.0.0.1:9099", content)
            self.assertIn("http://127.0.0.1:9099/version", content)

    @patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock)
    def test_cli_option_value_run_does_not_trigger_false_conflict(self, mock_pipeline):
        """Option arguments with value 'run' do not trigger false conflict with phase flags."""
        mock_pipeline.return_value = True
        for cmd in [
            ["--router-ssh-user", "run", "--check-only"],
            ["--router-ssh-pass", "run", "--deploy-only"],
            ["-s", "https://example.com/sub/run", "--check-only"],
        ]:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump({"subscriptions": ["https://example.com/sub"]}, f)
                cfg_path = f.name
            try:
                full_cmd = ["--config-file", cfg_path] + cmd
                main(full_cmd)
            finally:
                if os.path.exists(cfg_path):
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

    def test_build_router_config_yaml_custom_ports(self):
        """build_router_config_yaml replaces ports when custom configuration is passed."""
        from proxy_sites.router.config_builder import build_router_config_yaml
        custom_cfg = {
            "router_api_port": 9099,
            "router_proxy_port": 7898,
        }
        yaml_out = build_router_config_yaml(config=custom_cfg)
        self.assertIn("external-controller: 0.0.0.0:9099", yaml_out)
        self.assertIn("mixed-port: 7898", yaml_out)
        self.assertNotIn("7890", yaml_out)
        self.assertNotIn("9090", yaml_out)

    def test_generate_router_script_incorporates_custom_ports_in_config_yaml(self):
        """generate_router_script embeds custom ports into the generated config.yaml Base64."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_script = os.path.join(tmp_dir, "apply_to_router.sh")
            custom_cfg = {
                "router_api_port": 9099,
                "router_proxy_port": 7898,
            }
            generate_router_script(["vless://uuid@1.1.1.1:443#Node"], config=custom_cfg, out_file=out_script)
            with open(out_script, "r") as f:
                content = f.read()
            import base64
            # Find the config_b64 line
            match = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d > /etc/mihomo/config\.yaml\.tmp", content)
            self.assertIsNotNone(match)
            decoded_cfg = base64.b64decode(match.group(1)).decode("utf-8")
            self.assertIn("external-controller: 0.0.0.0:9099", decoded_cfg)
            self.assertIn("mixed-port: 7898", decoded_cfg)

    def test_generated_router_script_has_base64_fallback_decoder(self):
        """apply_to_router.sh contains base64 fallback decoder and successfully decodes without system base64 binary."""
        with tempfile.TemporaryDirectory() as td:
            out_script = os.path.join(td, "apply_to_router.sh")
            generate_router_script(["vless://uuid@1.1.1.1:443#TestNode"], config={}, out_file=out_script)
            with open(out_script, "r") as f:
                content = f.read()

            self.assertIn("Fallback base64 decoder for OpenWrt Busybox environments", content)
            self.assertIn("awk '", content)

            # Test decoder execution in an environment where base64 binary does NOT exist
            test_runner = os.path.join(td, "test_b64.sh")
            # Extract header through base64 function definition
            header_match = re.search(r"(#!/bin/sh.*?fi\n\n)", content, re.DOTALL)
            self.assertIsNotNone(header_match)

            with open(test_runner, "w") as f:
                f.write(header_match.group(1))
                # Add test decode invocation
                f.write("echo 'SGVsbG8gV29ybGQh' | base64 -d\n")

            # Create restricted PATH with only basic tools (cat, awk, sh) and NO base64
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            for tool in ["sh", "awk", "cat"]:
                tool_path = shutil.which(tool)
                if tool_path:
                    os.symlink(tool_path, os.path.join(bin_dir, tool))

            # Run with restricted PATH where base64 is completely absent
            res = subprocess.run(
                ["/bin/sh", test_runner],
                env={"PATH": bin_dir},
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout.strip(), "Hello World!")


if __name__ == "__main__":
    unittest.main()
