"""Country consensus alone decides which nodes join the main pool."""

from copy import deepcopy

import pytest

from nodesieve.routing import DEFAULT_ROUTING, main_location_rank, main_policy_failure, normalize_routing, select_main_pool


def consensus(counts):
    total, votes = sum(counts.values()), max(counts.values(), default=0)
    winners = [code for code, count in counts.items() if count == votes]
    return {"country": winners[0] if len(winners) == 1 else None,
            "score": votes / total if total else 0, "votes": votes, "total": total, "counts": counts}


def location(v4=None, v6=None):
    families = {name: consensus(counts) for name, counts in (("ipv4", v4), ("ipv6", v6)) if counts is not None}
    counts = {}
    for family in families.values():
        for code, number in family["counts"].items():
            counts[code] = counts.get(code, 0) + number
    return {**consensus(counts), "source": "ipregion", "status": "ok",
            "families": families, "tested_families": list(families)}


def test_default_main_policy_selects_on_location_evidence_only():
    config = normalize_routing({"enabled": True})
    assert set(config["main"]["excluded_countries"]) == {"RU", "BY", "CN", "IR", "KP", "SY", "CU"}
    nodes = ["vless://good", "vless://restricted", "vless://label-only", "vless://unprobed"]
    meta = {
        nodes[0]: {"location": location({"DE": 4})},
        nodes[1]: {"location": location({"RU": 8})},
        nodes[2]: {"country_code": "US", "location": None},
    }
    pool = select_main_pool(nodes, meta, config)
    assert pool["policy"] == config["main"]
    assert [item["node"] for item in pool["eligible"]] == [nodes[0]]
    assert {item["node"]: item["reason"] for item in pool["excluded"]} == {
        nodes[1]: "Location country excluded: RU",
        nodes[2]: "Location evidence missing",
        nodes[3]: "Location evidence missing",
    }


@pytest.mark.parametrize("evidence,reason", [
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
def test_main_never_infers_country_from_missing_conflicting_or_weak_evidence(evidence, reason):
    assert reason in main_policy_failure(normalize_routing()["main"], evidence)


def test_allowlist_confidence_threshold_and_family_consistency():
    policy = normalize_routing({"main": {"allowed_countries": ["us"], "min_agreement": 0.8}})["main"]
    assert main_policy_failure(policy, location({"US": 4, "DE": 1})) is None
    assert "outside allowlist" in main_policy_failure(policy, location({"DE": 3}))
    assert "agreement" in main_policy_failure(policy, location({"US": 3, "DE": 2}))
    evidence = location({"US": 3})
    evidence["families"]["ipv4"] = consensus({"US": 4})
    assert "inconsistent" in main_policy_failure(policy, evidence)


def test_unlisted_observed_family_is_not_ignored():
    evidence = location({"DE": 8})
    evidence["families"]["ipv6"] = consensus({"RU": 3})
    assert "observed IP family" in main_policy_failure(normalize_routing()["main"], evidence)


def test_rank_and_threshold_use_votes_instead_of_rounded_score():
    evidence = location({"DE": 7, "US": 3})
    evidence["score"] += 1e-10
    assert main_location_rank(evidence) == (0.7, 10)
    policy = normalize_routing({"main": {"min_agreement": 0.70000000001}})["main"]
    assert "agreement" in main_policy_failure(policy, evidence)


def test_main_rank_keeps_all_qualifying_nodes_in_agreement_report_latency_order():
    evidence = [location({"DE": 9, "RU": 1}), location({"DE": 3}), location({"US": 6}), location({"NL": 6})]
    nodes = [f"vless://node{i}" for i in range(len(evidence))]
    meta = {node: {"location": item, "latency_ms": [1, 2, 40, 20][index]}
            for index, (node, item) in enumerate(zip(nodes, evidence))}
    pool = select_main_pool(nodes, meta, {})
    assert [item["node"] for item in pool["eligible"]] == [nodes[3], nodes[2], nodes[1], nodes[0]]
    assert pool["excluded"] == []
    pool["eligible"][0]["evidence"]["counts"]["NL"] = 0
    assert meta[nodes[3]]["location"]["counts"]["NL"] == 6


def test_unsupported_protocol_cannot_displace_a_supported_main_candidate():
    pool = select_main_pool(["vmess://high", "trojan://eligible"], {
        "vmess://high": {"location": location({"DE": 10})},
        "trojan://eligible": {"location": location({"DE": 4, "US": 1})},
    }, {})
    assert [item["node"] for item in pool["eligible"]] == ["trojan://eligible"]
    assert "unsupported" in pool["excluded"][0]["reason"]


def test_renamed_nodes_recover_original_evidence_and_duplicate_uris_are_removed():
    original = "vless://one#source-name"
    renamed = "vless://one#measured-name"
    observations = {original: {"location": location({"DE": 3}), "latency_ms": 12}}
    pool = select_main_pool([(renamed, 500, original), original], observations, None)
    assert [item["node"] for item in pool["eligible"]] == [renamed]
    assert pool["eligible"][0]["evidence"]["latency_ms"] == 12
    pool["eligible"][0]["evidence"]["counts"]["DE"] = 999
    assert observations[original]["location"]["counts"]["DE"] == 3


def test_settings_saved_by_earlier_versions_are_migrated_or_refused():
    legacy = {"enabled": True, "target": "forkozz", "main": {"mode": "location", "min_votes": 4}, "services": {
        "twitter": {"mode": "country", "countries": ["US"], "country_source": "edge"},
        "discord": {"mode": "latency"}, "no-longer-validated": "anything",
    }}
    saved = deepcopy(legacy)
    normalized = normalize_routing(legacy)
    assert legacy == saved
    assert normalized == {**deepcopy(DEFAULT_ROUTING), "enabled": True,
                          "main": {**DEFAULT_ROUTING["main"], "min_votes": 4}}
    assert normalize_routing(normalized) == normalized
    # "preserve" asked for main to be left alone: never turn that into a managed pool.
    for enabled in (True, False):
        with pytest.raises(ValueError, match="preserve"):
            normalize_routing({"enabled": enabled, "main": {"mode": "preserve"}})


@pytest.mark.parametrize("routing", [
    [], "steer", {"enabled": "true"}, {"enabled": 1}, {"target": "mihomo"}, {"target": "netshift"},
    {"default_policy": "direct"}, {"servcies": {}}, {"main": "location"},
])
def test_malformed_routing_preferences_raise_readable_value_errors(routing):
    with pytest.raises(ValueError):
        normalize_routing(routing)


def test_normalization_is_consistent_and_cannot_mutate_defaults():
    saved_defaults = deepcopy(DEFAULT_ROUTING)
    normalized = normalize_routing(None)
    assert normalized == normalize_routing({}) == saved_defaults
    normalized["main"]["excluded_countries"].append("GB")
    assert DEFAULT_ROUTING == saved_defaults


@pytest.mark.parametrize("main", [
    [], {"mode": "fast"}, {"mode": []}, {"mode": "preserve"}, {"allow_countries": ["US"]},
    {"excluded_countries": "RU"}, {"excluded_countries": ["ZZ"]},
    {"allowed_countries": ["USA"]}, {"allowed_countries": ["RU"]},
    {"min_agreement": 0}, {"min_agreement": 1.1}, {"min_agreement": float("nan")},
    {"min_agreement": True}, {"min_votes": 0}, {"min_votes": True}, {"min_votes": 3.1},
])
def test_invalid_main_preferences_are_rejected(main):
    with pytest.raises(ValueError):
        normalize_routing({"main": main})


def test_normalization_cannot_mutate_country_lists():
    supplied = {"main": {"excluded_countries": [" ru ", "CN", "RU"]}}
    original = deepcopy(supplied)
    normalized = normalize_routing(supplied)
    assert normalized["main"]["excluded_countries"] == ["RU", "CN"]
    normalized["main"]["excluded_countries"].clear()
    assert supplied == original
