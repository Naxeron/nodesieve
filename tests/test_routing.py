"""Location routing policy, pool selection, redacted Steer report, and pipeline integration."""

import asyncio
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nodesieve.feed import LINKS_NAME, feed_directory
from nodesieve.routing import (
    DEFAULT_ROUTING,
    main_location_rank,
    main_policy_failure,
    normalize_routing,
    select_main_pool,
    write_routing_report,
)
from nodesieve.ui.dashboard import VPNDashboard

NODE = "vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&sni=example.org#First%20server"
OTHER = "trojan://private-password@192.0.2.2:443?security=tls#Second"


def consensus(counts):
    total, votes = sum(counts.values()), max(counts.values(), default=0)
    winners = [c for c, n in counts.items() if n == votes]
    return {"country": winners[0] if len(winners) == 1 else None,
            "score": votes / total if total else 0, "votes": votes, "total": total, "counts": counts}


def location(v4=None, v6=None):
    if v4 is None and v6 is None:
        v4 = {"DE": 3}
    families = {name: consensus(c) for name, c in (("ipv4", v4), ("ipv6", v6)) if c is not None}
    counts = {}
    for fam in families.values():
        for code, n in fam["counts"].items():
            counts[code] = counts.get(code, 0) + n
    return {**consensus(counts), "source": "geoip", "status": "ok",
            "families": families, "tested_families": list(families)}


def main_route(node=NODE, ev=None, **policy):
    return {"policy": normalize_routing({"main": policy})["main"],
            "eligible": [{"node": node, "evidence": location() if ev is None else ev}], "excluded": []}


def export(tmp_path, route):
    cfg = {"routing_output_dir": str(tmp_path / "output"), "routing": normalize_routing({"main": route["policy"]})}
    return write_routing_report(route, cfg)


# Policy validation and pool selection

def test_default_main_policy_selects_and_ranks_on_location_evidence_only():
    cfg = normalize_routing({"enabled": True})
    assert set(cfg["main"]["excluded_countries"]) == {"RU", "BY", "CN", "IR", "KP", "SY", "CU"}
    nodes = ["vless://good", "vless://restricted", "vless://label-only", "vless://unprobed", "vmess://high"]
    meta = {
        nodes[0]: {"location": location({"DE": 4})},
        nodes[1]: {"location": location({"RU": 8})},
        nodes[2]: {"country_code": "US", "location": None},
        nodes[4]: {"location": location({"DE": 10})},
    }
    pool = select_main_pool(nodes, meta, cfg)
    assert [i["node"] for i in pool["eligible"]] == [nodes[0]]
    reasons = {i["node"]: i["reason"] for i in pool["excluded"]}
    assert reasons[nodes[1]] == "Location country excluded: RU"
    assert reasons[nodes[2]] == reasons[nodes[3]] == "Location evidence missing"
    assert "unsupported" in reasons[nodes[4]]


@pytest.mark.parametrize("ev,reason", [
    ({}, "missing"),
    (location({"DE": 2}), "Too few"),
    (location({"DE": 3, "US": 3}), "tied"),
    (location({"DE": 3, "US": 2, "GB": 2}), "agreement"),
    (location({"RU": 3}), "excluded"),
    (location({"DE": 15}, {"RU": 3}), "IPV6: Location country excluded"),
    (location({"DE": 15}, {}), "IPV6: Location country unknown"),
    (location({"DE": 15}, {"DE": 1}), "IPV6: Too few"),
    ({**location({"DE": 3}), "ip_leak": True}, "IP leak"),
    ({**location({"DE": 3}), "score": 0.99}, "inconsistent"),
    ({**location({"DE": 3}), "votes": True}, "inconsistent"),
    ({**location({"DE": 3}), "status": "failed"}, "failed"),
    ({**location({"DE": 3}), "tested_families": []}, "IP-family"),
    (location({"AA": 3}), "unknown"),
    ({**location({"DE": 3}), "score": 1.0000000005}, "inconsistent"),
])
def test_main_policy_rejects_weak_missing_or_inconsistent_evidence(ev, reason):
    assert reason in main_policy_failure(normalize_routing()["main"], ev)


def test_allowlist_family_consistency_and_vote_ranking():
    policy = normalize_routing({"main": {"allowed_countries": ["us"], "min_agreement": 0.8}})["main"]
    assert main_policy_failure(policy, location({"US": 4, "DE": 1})) is None
    assert "outside allowlist" in main_policy_failure(policy, location({"DE": 3}))
    assert "agreement" in main_policy_failure(policy, location({"US": 3, "DE": 2}))

    inconsistent = location({"US": 3})
    inconsistent["families"]["ipv4"] = consensus({"US": 4})
    assert "inconsistent" in main_policy_failure(policy, inconsistent)

    unlisted = location({"DE": 8})
    unlisted["families"]["ipv6"] = consensus({"RU": 3})
    assert "observed IP family" in main_policy_failure(normalize_routing()["main"], unlisted)

    ev = location({"DE": 7, "US": 3})
    ev["score"] += 1e-10
    assert main_location_rank(ev) == (0.7, 10)
    assert "agreement" in main_policy_failure(normalize_routing({"main": {"min_agreement": 0.70000000001}})["main"], ev)


def test_pool_ranking_deduplication_and_no_mutation():
    evs = [location({"DE": 9, "RU": 1}), location({"DE": 3}), location({"US": 6}), location({"NL": 6})]
    nodes = [f"vless://node{i}" for i in range(len(evs))]
    meta = {n: {"location": item, "latency_ms": [1, 2, 40, 20][i]} for i, (n, item) in enumerate(zip(nodes, evs))}
    pool = select_main_pool(nodes, meta, {})
    assert [i["node"] for i in pool["eligible"]] == [nodes[3], nodes[2], nodes[1], nodes[0]]
    pool["eligible"][0]["evidence"]["counts"]["NL"] = 0
    assert meta[nodes[3]]["location"]["counts"]["NL"] == 6

    orig, renamed = "vless://one#src", "vless://one#measured"
    obs = {orig: {"location": location({"DE": 3}), "latency_ms": 12}}
    pool = select_main_pool([(renamed, 500, orig), orig], obs, None)
    assert [i["node"] for i in pool["eligible"]] == [renamed] and pool["eligible"][0]["evidence"]["latency_ms"] == 12


@pytest.mark.parametrize("bad", [
    [], "steer", {"enabled": "true"}, {"enabled": 1}, {"target": "mihomo"}, {"target": "forkozz"},
    {"default_policy": "direct"}, {"services": {}}, {"main": "location"}, {"main": {"mode": "fast"}},
    {"main": {"excluded_countries": ["ZZ"]}}, {"main": {"allowed_countries": ["RU"]}},
    {"main": {"min_agreement": 0}}, {"main": {"min_agreement": 1.1}}, {"main": {"min_agreement": float("nan")}},
    {"main": {"min_agreement": True}}, {"main": {"min_votes": 0}}, {"main": {"min_votes": True}},
])
def test_normalize_routing_rejects_invalid_and_preserves_defaults(bad):
    saved = deepcopy(DEFAULT_ROUTING)
    with pytest.raises(ValueError):
        normalize_routing(bad)
    assert normalize_routing(None) == normalize_routing({}) == saved
    supplied = {"main": {"excluded_countries": [" ru ", "CN", "RU"]}}
    orig = deepcopy(supplied)
    norm = normalize_routing(supplied)
    assert norm["main"]["excluded_countries"] == ["RU", "CN"]
    norm["main"]["excluded_countries"].clear()
    assert supplied == orig and DEFAULT_ROUTING == saved


# Redacted Steer routing report

def test_write_routing_report_ranks_and_redacts_all_secrets(tmp_path):
    best = {**location({"DE": 8, "US": 2}), "ip": "198.51.100.100", "private_response": "secret-body", "latency_ms": 50}
    smaller = "trojan://smaller@192.0.2.3:443"
    lower = "trojan://lower@192.0.2.4:443"
    no_lat = "trojan://nolat@192.0.2.5:443"
    blocked = "trojan://blocked@192.0.2.6:443"
    route = main_route(ev=best)
    route["eligible"].extend([
        {"node": smaller, "evidence": {**location({"DE": 4, "US": 1}), "latency_ms": 1}},
        {"node": OTHER, "evidence": {**location({"DE": 8, "US": 2}), "latency_ms": 10}},
        {"node": lower, "evidence": {**location({"DE": 3, "US": 2}), "latency_ms": 0.5}},
        {"node": no_lat, "evidence": location({"DE": 8, "US": 2})},
        {"node": blocked, "evidence": location({"RU": 3})},
        {"node": OTHER + "-dup", "evidence": {**location({"DE": 9, "US": 1}), "latency_ms": 5}},
    ])
    res = export(tmp_path, route)
    assert res["ready"] and res["servers"] == [OTHER, NODE, no_lat, smaller, lower]
    text = Path(res["report_path"]).read_text()
    report = json.loads(text)
    assert Path(res["report_path"]).stat().st_mode & 0o777 == 0o600
    assert report["created_at"].endswith("+00:00")
    assert [(n["score"], n["total"], n["latency_ms"]) for n in report["main"]["eligible"]] == [
        (0.8, 10, 10), (0.8, 10, 50), (0.8, 10, None), (0.8, 5, 1), (0.6, 5, 0.5)]
    for secret in ("11111111", "192.0.2.1", "198.51.100.100", "secret-body", "private-password", "smaller", "blocked"):
        assert secret not in text


def test_report_refuses_bad_uris_policy_drift_and_redacts_failure_reasons(tmp_path):
    # Xray-only httpupgrade link with trailing slash is accepted.
    hu = "vless://11111111-1111-4111-8111-111111111111@192.0.2.10:443/?type=httpupgrade&security=tls&sni=example.org#HU"
    assert export(tmp_path, main_route(hu))["servers"] == [hu]

    for bad in ("socks5://u:p@example.org:1080", "vless://bad", NODE + "\nmalicious", "vmess://e30="):
        res = export(tmp_path, main_route(bad))
        assert not res["ready"] and res["servers"] == []

    cfg = {"routing_output_dir": str(tmp_path / "output"), "routing": normalize_routing()}
    assert write_routing_report({}, cfg)["errors"] == ["Missing main route"]
    assert write_routing_report(main_route(min_votes=2), cfg)["errors"] == [
        "main: route policy does not match the configured policy"]

    route = main_route(allowed_countries=["DE"])
    route["excluded"] = [
        {"node": OTHER, "reason": "Location country excluded: RU private-host"},
        {"node": OTHER, "reason": "Location probe detected an IP leak 198.51.100.7"},
        {"node": OTHER, "reason": "Unexpected private-cookie"},
    ]
    res = export(tmp_path, route)
    text = Path(res["report_path"]).read_text()
    assert [e["reason"] for e in json.loads(text)["main"]["excluded"]] == [
        "Location country is excluded or not allowed",
        "Location probe detected an IP leak",
        "Location evidence did not satisfy this policy",
    ]
    assert "private-" not in text and "198.51.100.7" not in text


# Routing pipeline integration

def test_routing_pipeline_writes_report_and_feed_and_keeps_feed_on_failure(tmp_path):
    cfg = {"routing": normalize_routing({"enabled": True}), "routing_output_dir": str(tmp_path)}
    first = "vless://12345678-1234-1234-1234-123456789012@first.example:443?security=tls#first"
    hy2 = "hy2://private-password@node.example/?obfs=salamander&obfs-password=private-obfs#Game"
    rejected = "vless://12345678-1234-1234-1234-123456789012@rejected.example:443?security=tls#rejected"
    meta = {
        first: {"location": location(), "latency_ms": 5},
        hy2: {"location": location(), "latency_ms": 7},
        rejected: {"dropped": True, "reason": "Location country excluded: RU", "location": location({"RU": 3})},
        first.replace("security=tls", "security=tls&encryption=bad"): {"location": location(), "latency_ms": 5},
    }

    def run_scan(cands, md):
        dash = VPNDashboard(cfg)
        with patch.object(dash, "fetch_and_verify_candidates_async", AsyncMock(return_value=(cands, MagicMock(node_metadata=md)))), \
                patch.object(dash, "run_speedtest_nodes_async", AsyncMock()) as speed:
            ok = asyncio.run(dash.run_pipeline_async())
        speed.assert_not_called()
        return ok

    assert run_scan([(first, 5, first), (hy2, 7, hy2)], meta)
    links = (feed_directory(cfg) / LINKS_NAME).read_text().splitlines()
    assert links == [first, hy2]
    report_text = (tmp_path / "routing-report.json").read_text()
    assert all(s not in report_text for s in ("12345678", "private-password", "private-obfs", "node.example"))
    assert len(json.loads(report_text)["main"]["excluded"]) == 1

    # Failed scan leaves existing feed intact.
    assert not run_scan([(first, 5, first)], {first: {"location": location({"RU": 3}), "latency_ms": 5}})
    assert (feed_directory(cfg) / LINKS_NAME).read_text().splitlines() == [first, hy2]
    assert not json.loads((tmp_path / "routing-report.json").read_text())["ready"]
