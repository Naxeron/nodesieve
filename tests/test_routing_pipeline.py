"""End-to-end policy/export/deploy boundaries without contacting a router."""

import asyncio
import copy
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


from proxy_sites.routing import normalize_routing
from proxy_sites.router.client import RouterClient
from proxy_sites.ui.dashboard import VPNDashboard


def config_for(directory):
    return {
        "routing": normalize_routing({"enabled": True}),
        "routing_output_dir": str(directory),
        "router_host": "192.0.2.1",
    }


def candidate(name):
    return f"vless://12345678-1234-1234-1234-123456789012@{name}.example:443?security=tls#{name}"


def evidence():
    first, second = candidate("first"), candidate("second")
    return [(first, 5, first), (second, 7, second)], {
        first: {"location": location(), "latency_ms": 5},
        second: {"location": location(), "latency_ms": 7},
    }


def location(country="DE"):
    summary = {"country": country, "score": 1.0, "votes": 3, "total": 3, "counts": {country: 3}}
    return {**summary, "source": "ipregion", "status": "ok", "tested_families": ["ipv4"],
            "families": {"ipv4": copy.deepcopy(summary)}}


def test_check_exports_main_pool_and_does_not_touch_router(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    dashboard = VPNDashboard(config)
    tester = MagicMock(node_metadata=metadata)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, tester))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock()) as throughput, \
            patch.object(dashboard, "deploy_steer") as deploy:
        assert asyncio.run(dashboard.run_pipeline_async(check_only=True))
    throughput.assert_not_called()
    deploy.assert_not_called()
    script = (tmp_path / "apply_steer.sh").read_text()
    servers = (tmp_path / "steer-servers.txt").read_text()
    assert servers == nodes[0][0] + "\n" + nodes[1][0] + "\n"
    assert servers in script
    assert "Gemini_Nodes" not in script
    # Only the panel's own commands are used; Steer's files are never edited directly.
    assert set(re.findall(r"steer_action (\w+)", script)) == {"sub_status", "sub_links_get", "sub_set"}
    assert "/etc/zm-steer" not in script and "/etc/steer" not in script
    report = json.loads((tmp_path / "routing-report.json").read_text())
    assert report["ready"]
    assert [node["country"] for node in report["main"]["eligible"]] == ["DE", "DE"]
    assert "12345678-1234" not in json.dumps(report)


def test_nodes_failing_the_location_policy_are_reported_as_exclusions(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    rejected = candidate("rejected")
    metadata[rejected] = {"dropped": True, "reason": "Location country excluded: RU", "location": location("RU")}
    metadata[candidate("dead")] = {"dropped": True, "reason": "Proxy leaks real IP"}
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))):
        assert asyncio.run(dashboard.run_pipeline_async(check_only=True))
    report = json.loads((tmp_path / "routing-report.json").read_text())
    assert len(report["main"]["eligible"]) == 2
    assert [item["reason"] for item in report["main"]["excluded"]] == ["Location country is excluded or not allowed"]
    assert "rejected" not in (tmp_path / "apply_steer.sh").read_text()


def test_new_failed_scan_invalidates_previous_deployment(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))):
        assert asyncio.run(dashboard.run_pipeline_async(check_only=True))
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([], None))):
        assert not asyncio.run(dashboard.run_pipeline_async(check_only=True))
    assert not (tmp_path / "apply_steer.sh").exists()
    assert not (tmp_path / "steer-servers.txt").exists()
    with patch("proxy_sites.ui.dashboard.RouterClient") as client:
        assert not dashboard.deploy_steer()
    client.assert_not_called()


def test_deploy_checks_policy_age_and_script_before_ssh(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))):
        assert asyncio.run(dashboard.run_pipeline_async(check_only=True))
    with patch("proxy_sites.ui.dashboard.RouterClient") as client:
        assert asyncio.run(dashboard.run_pipeline_async(deploy_only=True, dry_run=True))
        client.assert_not_called()
        config["routing"]["main"]["min_votes"] = 4
        assert not dashboard.deploy_steer()
        client.assert_not_called()
        config["routing"]["main"]["min_votes"] = 3
        path = tmp_path / "routing-report.json"
        report = json.loads(path.read_text())
        report["created_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        path.write_text(json.dumps(report))
        assert not dashboard.deploy_steer()
        client.assert_not_called()
        report["created_at"] = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(report))
        script = tmp_path / "apply_steer.sh"
        script.write_text(script.read_text() + "# edited after the check\n")
        assert not dashboard.deploy_steer()
        client.assert_not_called()


def test_run_streams_script_only_after_successful_export(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))), \
            patch("proxy_sites.ui.dashboard.RouterClient") as client:
        client.return_value.exec_command.return_value = (0, "PSC_OK: Steer main servers replaced: 2 servers\n", "")
        assert asyncio.run(dashboard.run_pipeline_async())
        args, kwargs = client.return_value.exec_command.call_args
        assert args == ("/bin/sh -s",)
        assert kwargs["timeout"] >= 660
        assert kwargs["stdin_data"] == (tmp_path / "apply_steer.sh").read_text()
        assert nodes[0][0] in kwargs["stdin_data"]


def test_failed_deployment_reports_the_router_messages(tmp_path, caplog):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))), \
            patch("proxy_sites.ui.dashboard.RouterClient") as client:
        client.return_value.exec_command.return_value = (
            1, "Waiting for Steer: 10s\nRestoring the previous Steer servers\n",
            "PSC_ERROR: Steer did not apply the new servers: the panel reported a failure while applying\n"
            "PSC_LOG: ОШИБКА: ядро steer не приняло настройки\nPSC_ERROR: The previous servers were restored.\n")
        with caplog.at_level("INFO", logger="ProxySiteChecker"):
            assert not asyncio.run(dashboard.run_pipeline_async())
        text = caplog.text
        assert "Steer did not apply the new servers" in text
        assert "ядро steer не приняло настройки" in text
        assert "The previous servers were restored." in text
        caplog.clear()
        client.return_value.exec_command.return_value = (
            0, "PSC_NOTE: Steer accepted the servers, but its VPN tunnel is not up yet. Check the panel.\nPSC_OK: Steer main servers replaced: 2 servers\n", "")
        with caplog.at_level("INFO", logger="ProxySiteChecker"):
            assert dashboard.deploy_steer()
        assert "its VPN tunnel is not up yet" in caplog.text
        assert "[+] Steer main servers replaced: 2 servers" in caplog.text
        # A clean exit without the router's confirmation is not a success.
        caplog.clear()
        client.return_value.exec_command.return_value = (0, "Waiting for Steer: 10s\n", "")
        with caplog.at_level("INFO", logger="ProxySiteChecker"):
            assert not dashboard.deploy_steer()
        assert "The router did not confirm the change" in caplog.text


def test_interrupted_scan_cannot_deploy_previous_results(tmp_path):
    config = config_for(tmp_path)
    script = tmp_path / "apply_steer.sh"
    script.write_text("old deployment script")
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(side_effect=RuntimeError("scan interrupted"))):
        try:
            asyncio.run(dashboard.run_pipeline_async(check_only=True))
        except RuntimeError:
            pass
    assert not script.exists()


def test_report_does_not_export_raw_alias_of_normalized_survivor(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    raw_alias = nodes[0][0].replace("security=tls", "security=tls&encryption=incorrect")
    metadata[raw_alias] = metadata[nodes[0][0]]
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))):
        assert asyncio.run(dashboard.run_pipeline_async(check_only=True))
    assert "encryption=incorrect" not in (tmp_path / "apply_steer.sh").read_text()


def test_steer_scan_never_stages_mihomo_on_router(tmp_path):
    config = config_for(tmp_path)
    config.update(workers=1, tcp_workers=1, enable_router_validation=True)
    dashboard = VPNDashboard(config)
    node = candidate("only")
    tester = MagicMock(test_node_full=AsyncMock(return_value=(node, 10, node)))
    with patch.object(dashboard, "_get_real_ip", AsyncMock(return_value=None)), \
            patch.object(dashboard, "filter_tcp", AsyncMock(return_value=[node])), \
            patch("proxy_sites.ui.dashboard.ResourceLimits.get_max_safe_workers", return_value=(4, 8192)), \
            patch("proxy_sites.ui.dashboard.NodeFetcher.fetch_all", AsyncMock(return_value=([node], {}))), \
            patch("proxy_sites.ui.dashboard.MihomoManager.setup"), \
            patch("proxy_sites.ui.dashboard.NodeTester", return_value=tester), \
            patch("proxy_sites.core.router_validator.RouterValidator") as router_validator:
        nodes, used_tester = asyncio.run(dashboard.fetch_and_verify_candidates_async())
    assert nodes == [(node, 10, node)]
    assert used_tester is tester
    router_validator.assert_not_called()


def test_router_exec_streams_script_over_stdin():
    router = RouterClient()
    ssh, stdin, stdout, stderr = [MagicMock() for _ in range(4)]
    ssh.exec_command.return_value = (stdin, stdout, stderr)
    stdout.read.return_value = b"ok"
    stderr.read.return_value = b""
    stdout.channel.recv_exit_status.return_value = 0
    with patch.object(router, "_create_ssh", return_value=ssh):
        assert router.exec_command("/bin/sh -s", stdin_data="echo ok\n") == (0, "ok", "")
    stdin.write.assert_called_once_with("echo ok\n")
    stdin.channel.shutdown_write.assert_called_once()
    ssh.close.assert_called_once()
