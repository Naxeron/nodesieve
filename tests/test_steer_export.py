"""Steer main pool: its ranking, its redacted report, and what qualifies for the feed."""

import json
from pathlib import Path

import pytest

from nodesieve.router.steer import write_routing_report
from nodesieve.routing import normalize_routing


NODE = "vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&sni=example.org#First%20server"
OTHER = "trojan://private-password@192.0.2.2:443?security=tls#Second"


def config(tmp_path, **overrides):
    return {"routing_output_dir": str(tmp_path / "output"), "routing": normalize_routing(), **overrides}


def export(route, options):
    # Most cases focus on the report: derive matching preferences explicitly.
    # Contract mismatch tests below call the production function directly.
    options["routing"] = normalize_routing({"main": route["policy"]})
    return write_routing_report(route, options)


def location(counts=None):
    counts = counts or {"DE": 3}
    country = max(counts, key=counts.get)
    total = sum(counts.values())
    consensus = {"country": country, "score": counts[country] / total, "votes": counts[country], "total": total, "counts": counts}
    return {"source": "geoip", "status": "ok", **consensus, "tested_families": ["ipv4"], "families": {"ipv4": dict(consensus)}}


def main_route(node=NODE, evidence=None, **policy):
    return {"policy": normalize_routing({"main": policy})["main"],
            "eligible": [{"node": node, "evidence": location() if evidence is None else evidence}], "excluded": []}


def two_servers():
    route = main_route()
    route["eligible"].append(main_route(OTHER)["eligible"][0])
    return route


def test_ranks_the_pool_and_writes_only_a_redacted_report(tmp_path):
    result = export(two_servers(), config(tmp_path))
    assert result["ready"], result["errors"]
    assert result["servers"] == [NODE, OTHER]
    report_text = Path(result["report_path"]).read_text()
    report = json.loads(report_text)
    assert set(report) == {"ready", "created_at", "main", "errors", "warnings"}
    assert [node["country"] for node in report["main"]["eligible"]] == ["DE", "DE"]
    for secret in ("11111111", "192.0.2.1", "private-password", "First", "vless://"):
        assert secret not in report_text
    assert report["created_at"].endswith("+00:00")
    assert Path(result["report_path"]).stat().st_mode & 0o777 == 0o600
    assert [path.name for path in (tmp_path / "output").iterdir()] == ["routing-report.json"]


def test_a_pool_without_a_qualifying_proxy_is_not_ready(tmp_path):
    failed = export({"policy": normalize_routing()["main"], "eligible": [],
                     "excluded": [{"node": NODE, "reason": "failed vless://secret-password@server"}]}, config(tmp_path))
    assert not failed["ready"] and failed["servers"] == []
    assert "main: no supported proxy satisfies the location policy" in failed["errors"]
    assert "secret-password" not in Path(failed["report_path"]).read_text()


@pytest.mark.parametrize("node", ["mihomo://secret", "socks5://user:password@example.org:1080", "vless://bad",
                                  NODE + "\nmalicious", "http://example.org:8080", "vmess://eyJhZGQiOiIxOTIuMC4yLjEifQ=="])
def test_unsupported_or_malformed_uri_cannot_make_empty_pool_ready(tmp_path, node):
    result = export(main_route(node), config(tmp_path))
    assert not result["ready"] and result["servers"] == []


def test_missing_route_and_policy_drift_refuse_export(tmp_path):
    options = config(tmp_path)
    for missing in ({}, None):
        result = write_routing_report(missing, options)
        assert not result["ready"]
        assert result["errors"] == ["Missing main route"]
    drifted = write_routing_report(main_route(min_votes=2), options)
    assert not drifted["ready"]
    assert drifted["errors"] == ["main: route policy does not match the configured policy"]


@pytest.mark.parametrize("reason,expected", [
    ("Location country excluded: RU private-host", "Location country is excluded or not allowed"),
    ("IPV4: Location agreement below threshold private-url", "Location agreement is below the required threshold"),
    ("Location probe failed: GeoIP providers did not answer in time private-response", "Location evidence is unavailable or incomplete"),
    ("Location probe detected an IP leak 198.51.100.7 private-ip", "Location probe detected an IP leak"),
    ("Something unexpected private-cookie", "Location evidence did not satisfy this policy"),
])
def test_report_keeps_safe_failure_categories_and_policy(tmp_path, reason, expected):
    candidate = main_route(allowed_countries=["DE"])
    candidate["excluded"] = [{"node": OTHER, "reason": reason}]
    result = export(candidate, config(tmp_path))
    report = json.loads(Path(result["report_path"]).read_text())
    assert report["main"]["excluded"][0]["reason"] == expected
    assert report["main"]["allowed_countries"] == ["DE"]
    assert report["main"]["min_agreement"] == 0.6
    assert "private-" not in Path(result["report_path"]).read_text()


def test_main_report_retains_and_ranks_all_qualified_nodes_and_redacts_evidence(tmp_path):
    best = location({"DE": 8, "US": 2})
    best["ip"] = "198.51.100.100"
    best["private_response"] = "private-location-secret"
    best["latency_ms"] = 50
    smaller_sample = "trojan://smaller-sample@192.0.2.3:443"
    lower_score = "trojan://lower-score@192.0.2.4:443"
    unknown_latency = "trojan://unknown-latency@192.0.2.5:443"
    blocked = "trojan://blocked-country@192.0.2.6:443"
    insufficient = "trojan://low-agreement@192.0.2.7:443"
    candidate = main_route(evidence=best)
    candidate["eligible"].extend([
        {"node": smaller_sample, "evidence": {**location({"DE": 4, "US": 1}), "latency_ms": 1}},
        {"node": OTHER, "evidence": {**location({"DE": 8, "US": 2}), "latency_ms": 10}},
        {"node": lower_score, "evidence": {**location({"DE": 3, "US": 2}), "latency_ms": 0.5}},
        {"node": unknown_latency, "evidence": location({"DE": 8, "US": 2})},
        {"node": blocked, "evidence": location({"RU": 3})},
        {"node": insufficient, "evidence": location({"DE": 2, "US": 1, "FR": 1})},
        {"node": OTHER + "-renamed-duplicate", "evidence": {**location({"DE": 9, "US": 1}), "latency_ms": 5}},
    ])
    result = export(candidate, config(tmp_path))
    assert result["ready"], result["errors"]
    # Best agreement first, then more reports, then lower latency: Steer's "first working" follows this order.
    assert result["servers"] == [OTHER, NODE, unknown_latency, smaller_sample, lower_score]
    report_text = Path(result["report_path"]).read_text()
    report = json.loads(report_text)["main"]
    assert report["excluded_countries"] == ["RU", "BY", "CN", "IR", "KP", "SY", "CU"]
    assert report["eligible"][0]["counts"] == {"DE": 8, "US": 2}
    assert report["eligible"][0]["score"] == 0.8
    assert [(node["score"], node["total"], node["latency_ms"]) for node in report["eligible"]] == [
        (0.8, 10, 10), (0.8, 10, 50), (0.8, 10, None), (0.8, 5, 1), (0.6, 5, 0.5)]
    assert [node["reason"] for node in report["excluded"]] == [
        "Location country is excluded or not allowed", "Location agreement is below the required threshold"]
    for secret in ("198.51.100.100", "private-location-secret", "192.0.2.1", "private-password", "smaller-sample", "lower-score", "blocked-country"):
        assert secret not in report_text
    assert any("its own server selection setting" in warning for warning in result["warnings"])


@pytest.mark.parametrize("evidence", [None, {"source": "node-label", "country": "DE"}, location({"RU": 3}), location({"DE": 2})])
def test_invalid_or_missing_main_location_qualifies_nothing(tmp_path, evidence):
    result = export(main_route(evidence=evidence or {}), config(tmp_path))
    assert not result["ready"] and result["servers"] == []
