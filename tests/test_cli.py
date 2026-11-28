"""CLI argument parsing, overrides, config management, and rejected options."""

import io
import json
import os
from unittest.mock import AsyncMock, patch

import pytest

from nodesieve.config import ConfigManager
from nodesieve.constants import CONFIG_FILE
from nodesieve.routing import normalize_routing
from nodesieve.ui.cli import build_parser, main
from nodesieve.ui.dashboard import VPNDashboard


def _run_exit(argv):
    with pytest.raises(SystemExit) as cm:
        main(argv)
    return cm.value.code


def test_parser_defaults_and_overrides():
    args = build_parser().parse_args([])
    assert (args.action, args.dry_run) == ("check", False)

    args = build_parser().parse_args([
        "check", "--workers", "64", "--tcp-workers", "256", "--countries", "US,GB,DE",
        "--speedtest-timeout", "15", "--rank-by", "location", "--output-dir", "out",
    ])
    assert (args.workers, args.tcp_workers, args.allowed_countries, args.speedtest_timeout,
            args.rank_by, args.routing_output_dir) == ("64", 256, "US,GB,DE", 15, "location", "out")


@pytest.mark.parametrize("argv", [
    ["run"], ["--run"], ["--check"], ["install-router"], ["routing"], ["serve"],
    ["--routing-setup"], ["--routing-show"], ["--router-host", "router.example"],
    ["--scan-every", "6"], ["--remove", "1"], ["--target", "steer"],
    ["--rank-by", "forkozz"], ["--core", "mihomo"], ["--feed-host", "0.0.0.0"], ["--feed-port", "9876"],
])
def test_removed_actions_and_options_are_refused(argv):
    with pytest.raises(SystemExit) as cm:
        build_parser().parse_args(argv)
    assert cm.value.code == 2


def test_scan_actions_dry_run_and_exit_code():
    with patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock, return_value=True) as pipe:
        for argv, dry in (([], False), (["check"], False), (["check", "--dry-run"], True),
                          (["--output-dir", "check"], False), (["-s", "https://example.com/sub/check"], False)):
            pipe.reset_mock()
            main(argv)
            pipe.assert_awaited_once_with(dry_run=dry)
        pipe.return_value = False
        assert _run_exit(["check"]) == 1


def test_default_config_uses_project_directory_from_any_cwd(tmp_path, monkeypatch):
    assert CONFIG_FILE == "nodesieve_config.json"
    project_dir, caller_dir = tmp_path / "proj", tmp_path / "caller"
    project_dir.mkdir()
    caller_dir.mkdir()
    cfg_path = project_dir / CONFIG_FILE
    cfg_path.write_text(json.dumps({"subscriptions": ["https://example.com/existing"], "workers": 7}))
    monkeypatch.chdir(caller_dir)
    with patch("nodesieve.ui.cli.PROJECT_ROOT", str(project_dir)), \
            patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock) as pipe:
        assert _run_exit(["--add-sub", "https://example.com/new"]) == 0
        pipe.assert_not_called()
    assert not (caller_dir / CONFIG_FILE).exists()
    saved = json.loads(cfg_path.read_text())
    assert saved["subscriptions"] == ["https://example.com/existing", "https://example.com/new"]
    assert saved["workers"] == 7


def test_subscription_management_flags(tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"subscriptions": ["https://example.com/sub1", "https://example.com/sub2"]}))
    with patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock) as pipe:
        assert _run_exit(["--add-sub", "   "]) == 1
        assert _run_exit(["--config-file", str(cfg), "--add-sub", "https://example.com/sub1"]) == 0
        assert len(ConfigManager.load(str(cfg))["subscriptions"]) == 2
        for bad in ("", "9999", "https://notfound.com/sub"):
            assert _run_exit(["--config-file", str(cfg), "--remove-sub", bad]) == 1
        assert _run_exit(["--config-file", str(cfg), "--remove-sub", "1"]) == 0
        assert ConfigManager.load(str(cfg))["subscriptions"] == ["https://example.com/sub2"]
        assert _run_exit(["--add-sub", "https://example.com/a", "--remove-sub", "1"]) == 1
        pipe.assert_not_called()


@pytest.mark.parametrize("cmd", [
    ["--add-sub", "https://example.com/sub1", "--dry-run"],
    ["--remove-sub", "1", "--dry-run"],
    ["config", "--dry-run"],
    ["--show-config", "--dry-run"],
    ["--workers", "0"], ["--workers", "-5"], ["--workers", "invalid"],
    ["--tcp-workers", "0"], ["--tcp-workers", "-10"],
    ["--speedtest-timeout", "0"], ["--speedtest-timeout", "-3"],
    ["--min-speed-percent", "-1"], ["--min-speed-percent", "101"], ["--min-speed-percent", "nan"],
    ["-s", ""], ["-s", "   "],
    ["config", "--output-dir", "  "], ["check", "--output-dir", "  "],
])
def test_invalid_cli_arguments_exit_code_1(cmd):
    with patch.object(VPNDashboard, "run_pipeline_async", new_callable=AsyncMock) as pipe:
        assert _run_exit(cmd) == 1
        pipe.assert_not_called()


def test_config_display_and_rank_by_overrides(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    with patch("nodesieve.ui.cli.VPNDashboard") as dash, patch("sys.stdout", new_callable=io.StringIO) as out:
        assert _run_exit(["--config-file", str(cfg), "config", "--rank-by", "location", "--output-dir", "example-output"]) == 0
    dash.assert_not_called()
    displayed = json.loads(out.getvalue())
    assert displayed["routing"]["enabled"] is True
    assert displayed["routing_output_dir"] == os.path.abspath("example-output")

    routing = normalize_routing({"enabled": True})
    cfg.write_text(json.dumps({"routing": routing}))
    with patch("nodesieve.ui.cli.VPNDashboard") as dash:
        dash.return_value.run_pipeline_async = AsyncMock(return_value=True)
        main(["--config-file", str(cfg), "check", "--rank-by", "speed"])
    assert dash.call_args.kwargs["config"]["routing"]["enabled"] is False
    assert json.loads(cfg.read_text())["routing"]["enabled"] is True


def test_unknown_routing_settings_refused_before_running(tmp_path):
    cfg = tmp_path / "config.json"
    for routing in ({"enabled": False, "main": {"mode": "preserve"}}, {"enabled": True, "services": {}},
                    {"enabled": True, "target": "forkozz"}):
        cfg.write_text(json.dumps({"routing": routing}))
        for argv in (["config"], ["check", "--rank-by", "location"], ["check"]):
            with patch("nodesieve.ui.cli.VPNDashboard") as dash:
                assert _run_exit(["--config-file", str(cfg), *argv]) == 1
                dash.assert_not_called()
