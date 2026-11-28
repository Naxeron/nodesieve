"""Subscription feed output, permissions, speed cutoffs, and feed_command."""

import asyncio
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import nodesieve.feed as feed_module
from nodesieve.feed import (
    BASE64_NAME,
    LINKS_NAME,
    feed_directory,
    feed_status,
    run_feed_command,
    write_feed,
)
from nodesieve.routing import normalize_routing
import nodesieve.ui.cli as cli_module
from nodesieve.ui.dashboard import VPNDashboard

VLESS = ("vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&sni=example.org&type=ws"
         "&path=%2Fws#%5BVLESS%3A%20First%5D%20%F0%9F%87%A9%F0%9F%87%AA%20Germany%20%7C%20203.0.113.1")
TROJAN = "trojan://private-password@192.0.2.2:443?security=tls&sni=example.org#Second"
SS = "ss://YWVzLTI1Ni1nY206c2VjcmV0@192.0.2.3:8388#Third"
VMESS = "vmess://eyJhZGQiOiIxOTIuMC4yLjUifQ==#vmess"
HYSTERIA = "hysteria2://secret@192.0.2.8:443#hysteria"
FILES = (LINKS_NAME, BASE64_NAME)


def feed_config(tmp_path, **settings):
    return {"feed_dir": str(tmp_path / "feed"), **settings}


def read(tmp_path, name):
    return (tmp_path / "feed" / name).read_text(encoding="utf-8")


def test_write_feed_formats_permissions_and_deduplication(tmp_path):
    result = write_feed([VLESS, VMESS, TROJAN, HYSTERIA, HYSTERIA.replace("hysteria2://", "hy2://")], feed_config(tmp_path))
    directory = tmp_path / "feed"
    assert result == {"written": True, "count": 3, "left_out": 1, "directory": str(directory)}
    links = read(tmp_path, LINKS_NAME)
    assert links == f"{VLESS}\n{TROJAN}\n{HYSTERIA}\n"
    assert base64.b64decode(read(tmp_path, BASE64_NAME)).decode() == links
    assert directory.stat().st_mode & 0o777 == 0o700
    assert {(directory / name).stat().st_mode & 0o777 for name in FILES} == {0o600}


def test_world_traversable_dir_writes_0644_for_uhttpd(tmp_path):
    (tmp_path / "feed").mkdir(mode=0o711)
    (tmp_path / "feed").chmod(0o711)
    write_feed([TROJAN], feed_config(tmp_path))
    assert {(tmp_path / "feed" / name).stat().st_mode & 0o777 for name in FILES} == {0o644}


@pytest.mark.parametrize("nodes", [[], [VMESS, "hy2://user@:443"], ["vless://unreadable"]])
def test_empty_or_invalid_scan_leaves_existing_feed_untouched(tmp_path, nodes):
    config = feed_config(tmp_path)
    assert not write_feed([VMESS], config)["written"] and not (tmp_path / "feed").exists()
    assert feed_status(config) is None

    write_feed([VLESS, TROJAN], config)
    before = {name: (tmp_path / "feed" / name).read_bytes() for name in FILES}
    result = write_feed(nodes, config)
    assert not result["written"] and result["count"] == 0
    assert {name: (tmp_path / "feed" / name).read_bytes() for name in FILES} == before
    assert feed_status(config)["count"] == 2


def test_malformed_and_duplicate_links_filtered(tmp_path):
    nodes = [
        TROJAN.replace("#Second", "#Second\nvless://injected@192.0.2.9:443#line"),
        "trojan://two words@192.0.2.4:443#Space",
        VMESS, "vless://unreadable", 42, None, TROJAN,
        TROJAN.replace("#Second", "#Duplicate"),
    ]
    result = write_feed(nodes, feed_config(tmp_path))
    assert (result["count"], result["left_out"]) == (1, 6)
    assert read(tmp_path, LINKS_NAME) == TROJAN + "\n"


def test_feed_directory_and_selected_formats_skip_unchanged_writes(tmp_path):
    project = Path(feed_module.PROJECT_ROOT)
    assert feed_directory({}) == (project / "feed").resolve()
    assert feed_directory({"feed_dir": "elsewhere/feed"}) == (project / "elsewhere" / "feed").resolve()
    assert feed_directory({"feed_dir": str(tmp_path)}) == tmp_path.resolve()

    config = feed_config(tmp_path, feed_formats=["links"])
    assert write_feed([VLESS, TROJAN], config)["written"]
    assert sorted(p.name for p in (tmp_path / "feed").iterdir()) == [LINKS_NAME]
    links_path = tmp_path / "feed" / LINKS_NAME
    inode_before = links_path.stat().st_ino
    assert write_feed([VLESS, TROJAN], config)["written"]
    assert links_path.stat().st_ino == inode_before


@pytest.mark.parametrize("settings,expected", [
    ({}, [VLESS, HYSTERIA, TROJAN]),
    ({"min_speed_percent": 0}, [VLESS, HYSTERIA, TROJAN, SS]),
    ({"min_speed_percent": 100}, [VLESS, HYSTERIA]),
])
def test_speed_cutoff_publishes_fastest_qualifying_nodes(tmp_path, settings, expected):
    dashboard = VPNDashboard(feed_config(tmp_path, **settings))
    verified = [(n, 5.0, n) for n in (SS, TROJAN, VLESS, HYSTERIA)]
    measured = [(VLESS, 2e6), (HYSTERIA, 2e6), (TROJAN, 1e6), (SS, 999_999)]
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(verified, None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=measured)):
        assert asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME).splitlines() == expected


def test_min_speed_percent_cli_override_and_speedtest_failure_fallback(tmp_path):
    cfg_path = tmp_path / "settings.json"
    cfg_path.write_text(json.dumps({"subscriptions": ["https://example.org/sub"], **feed_config(tmp_path), "min_speed_percent": 0}))
    measured = [(VLESS, 2_000_000), (SS, 1_510_000), (TROJAN, 1_250_000)]
    verified = [(n, 5.0, n) for n, _ in measured]
    with patch.object(VPNDashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(verified, None))), \
            patch.object(VPNDashboard, "run_speedtest_nodes_async", AsyncMock(return_value=measured)):
        cli_module.main(["check", "--config-file", str(cfg_path), "--min-speed-percent", "75.5"])
    assert read(tmp_path, LINKS_NAME).splitlines() == [VLESS, SS]
    assert json.loads(cfg_path.read_text())["min_speed_percent"] == 0

    dashboard = VPNDashboard(feed_config(tmp_path))
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([(SS, 5.0, SS), (TROJAN, 9.0, TROJAN)], None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=[])):
        assert asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME).splitlines() == [SS, TROJAN]


def test_speedtest_phase_runs_sequentially_with_shared_batches(tmp_path):
    from nodesieve.core.tester import NodeTester

    dashboard = VPNDashboard(feed_config(tmp_path, workers=64))
    tester = NodeTester(dashboard.config, total_nodes=50)
    candidates = [(VLESS, 10.0, VLESS), (TROJAN, 20.0, TROJAN), (SS, 30.0, SS)]
    captured = {}

    async def fake_run(jobs, links, check, on_result, **kwargs):
        captured["kwargs"] = kwargs
        for idx, node in jobs:
            on_result(idx, node, (node, float(idx * 1_000_000)))

    with patch("nodesieve.ui.dashboard.setup_core"), patch("nodesieve.ui.dashboard.run_in_batches", side_effect=fake_run):
        results = asyncio.run(dashboard.run_speedtest_nodes_async(candidates, tester=tester))
    assert (captured["kwargs"]["workers"], captured["kwargs"]["nodes_per_instance"], tester.total_nodes) == (1, 3, 3)
    assert [node for node, _ in results] == [SS, TROJAN, VLESS]


def test_scan_without_survivors_and_write_error(tmp_path, caplog):
    config = feed_config(tmp_path)
    write_feed([VLESS, TROJAN], config)
    before = read(tmp_path, LINKS_NAME)
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([], None))):
        assert not asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME) == before and "keeps the 2 nodes of the scan from" in caplog.text

    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([(TROJAN, 9.0, TROJAN)], None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=[(TROJAN, 1e6)])), \
            patch("nodesieve.ui.dashboard.write_feed", side_effect=PermissionError("read-only")):
        assert not asyncio.run(dashboard.run_pipeline_async())
    assert "Cannot write the subscription feed: read-only" in caplog.text


def test_feed_command_execution_dry_run_and_unchanged_order_skip(tmp_path, caplog):
    assert run_feed_command({}) is None
    assert run_feed_command({"feed_command": "true"}) is True
    assert run_feed_command({"feed_command": "echo first >&2; echo boom >&2; exit 3"}) is False
    assert "feed_command failed with exit code 3: boom" in caplog.text
    assert run_feed_command({"feed_command": "sleep 5"}, timeout=0.2) is False

    marker = tmp_path / "ran"
    config = {**feed_config(tmp_path), "feed_command": f"echo ran >> '{marker}'"}
    write_feed([VLESS + "1", TROJAN + "1"], config)
    dashboard = VPNDashboard(config)
    # Only labels changed -> skip feed_command; reordering -> runs feed_command.
    assert dashboard.publish_feed([VLESS + "2", TROJAN + "2"]) and not marker.exists()
    assert dashboard.publish_feed([TROJAN + "2", VLESS + "2"]) and marker.read_text().count("ran") == 1
    # dry_run skips feed_command.
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([(SS, 5.0, SS)], None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=[(SS, 1e6)])):
        assert asyncio.run(dashboard.run_pipeline_async(dry_run=True))
    assert marker.read_text().count("ran") == 1


def test_steer_check_publishes_ranked_main_pool(tmp_path):
    summary = {"country": "DE", "score": 1.0, "votes": 3, "total": 3, "counts": {"DE": 3}}
    loc = {**summary, "source": "geoip", "status": "ok", "tested_families": ["ipv4"], "families": {"ipv4": dict(summary)}}
    slow = "vless://12345678-1234-1234-1234-123456789012@slow.example:443?security=tls#slow"
    fast = "trojan://password@fast.example:443?security=tls#fast"
    meta = {slow: {"location": loc, "latency_ms": 7}, fast: {"location": loc, "latency_ms": 5}}
    config = {**feed_config(tmp_path), "routing": normalize_routing({"enabled": True}),
              "routing_output_dir": str(tmp_path / "steer")}
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async",
                      AsyncMock(return_value=([(slow, 7, slow), (fast, 5, fast)], MagicMock(node_metadata=meta)))):
        assert asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME) == f"{fast}\n{slow}\n"
    assert json.loads((tmp_path / "steer" / "routing-report.json").read_text())["ready"]
