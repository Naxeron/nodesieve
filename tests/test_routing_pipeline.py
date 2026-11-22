"""A Steer scan ranks the main pool and writes its report and subscription feed locally."""

import asyncio
import copy
import json
from unittest.mock import AsyncMock, MagicMock, patch

from nodesieve.feed import LINKS_NAME, feed_directory
from nodesieve.routing import normalize_routing
from nodesieve.ui.dashboard import VPNDashboard


def config_for(directory):
    return {
        "routing": normalize_routing({"enabled": True}),
        "routing_output_dir": str(directory),
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
    return {**summary, "source": "geoip", "status": "ok", "tested_families": ["ipv4"],
            "families": {"ipv4": copy.deepcopy(summary)}}


def scan(config, nodes, metadata):
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async",
                      AsyncMock(return_value=(nodes, MagicMock(node_metadata=metadata)))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock()) as throughput:
        result = asyncio.run(dashboard.run_pipeline_async())
    throughput.assert_not_called()
    return result


def feed_links(config):
    return (feed_directory(config) / LINKS_NAME).read_text().splitlines()


def test_check_ranks_the_main_pool_into_the_report_and_the_feed(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    assert scan(config, nodes, metadata)
    assert feed_links(config) == [nodes[0][0], nodes[1][0]]
    report = json.loads((tmp_path / "routing-report.json").read_text())
    assert report["ready"]
    assert [node["country"] for node in report["main"]["eligible"]] == ["DE", "DE"]
    assert "12345678-1234" not in json.dumps(report)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["routing-report.json"]


def test_steer_publishes_hysteria2_and_redacts_its_credentials(tmp_path):
    config = config_for(tmp_path)
    node = "hy2://private-password@node.example/?obfs=salamander&obfs-password=private-obfs#Game"
    assert scan(config, [(node, 5, node)], {node: {"location": location(), "latency_ms": 5}})
    assert feed_links(config) == [node]
    report = (tmp_path / "routing-report.json").read_text()
    assert len(json.loads(report)["main"]["eligible"]) == 1
    assert all(secret not in report for secret in ("private-password", "node.example", "private-obfs"))


def test_nodes_failing_the_location_policy_are_reported_as_exclusions(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    rejected = candidate("rejected")
    metadata[rejected] = {"dropped": True, "reason": "Location country excluded: RU", "location": location("RU")}
    metadata[candidate("dead")] = {"dropped": True, "reason": "Proxy leaks real IP"}
    assert scan(config, nodes, metadata)
    report = json.loads((tmp_path / "routing-report.json").read_text())
    assert len(report["main"]["eligible"]) == 2
    assert [item["reason"] for item in report["main"]["excluded"]] == ["Location country is excluded or not allowed"]
    assert not any("rejected" in link for link in feed_links(config))


def test_a_scan_with_no_qualifying_proxy_fails_and_leaves_the_feed(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    assert scan(config, nodes, metadata)
    for node, _, _ in nodes:
        metadata[node]["location"] = location("RU")
    assert not scan(config, nodes, metadata)
    assert feed_links(config) == [nodes[0][0], nodes[1][0]]
    assert not json.loads((tmp_path / "routing-report.json").read_text())["ready"]


def test_report_does_not_export_raw_alias_of_normalized_survivor(tmp_path):
    config = config_for(tmp_path)
    nodes, metadata = evidence()
    raw_alias = nodes[0][0].replace("security=tls", "security=tls&encryption=incorrect")
    metadata[raw_alias] = metadata[nodes[0][0]]
    assert scan(config, nodes, metadata)
    assert not any("encryption=incorrect" in link for link in feed_links(config))
