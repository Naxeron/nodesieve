"""Main-pool routing preferences and evidence-based candidate selection."""

import copy
import math

from nodesieve.location import COUNTRIES


DEFAULT_ROUTING = {
    "enabled": False,
    "target": "steer",
    "default_policy": "preserve",
    "main": {
        "excluded_countries": ["RU", "BY", "CN", "IR", "KP", "SY", "CU"],
        "allowed_countries": [],
        "min_agreement": 0.6,
        "min_votes": 3,
    },
}


def normalize_routing(value=None):
    """Merge defaults, rejecting invalid policy settings instead of weakening them."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("routing must be an object")
    unknown = set(value) - set(DEFAULT_ROUTING)
    if unknown:
        raise ValueError(f"Unknown routing setting: {', '.join(sorted(map(str, unknown)))}")
    result = copy.deepcopy(DEFAULT_ROUTING)
    result.update({k: v for k, v in value.items() if k != "main"})
    if not isinstance(result["enabled"], bool):
        raise ValueError("routing.enabled must be true or false")
    if result["target"] != "steer" or result["default_policy"] != "preserve":
        raise ValueError("Routing supports target 'steer' and default_policy 'preserve' only")
    main = value.get("main", {})
    if not isinstance(main, dict):
        raise ValueError("routing.main must be an object")
    if set(main) - set(DEFAULT_ROUTING["main"]):
        raise ValueError("routing.main must contain only excluded_countries, allowed_countries, min_agreement and min_votes")
    result["main"].update(copy.deepcopy(main))
    main = result["main"]
    for key in ("excluded_countries", "allowed_countries"):
        countries = main[key]
        if not isinstance(countries, list) or any(
            not isinstance(c, str) or c.strip().upper() not in COUNTRIES for c in countries
        ):
            raise ValueError(f"routing.main.{key} must be a list of two-letter country codes")
        main[key] = list(dict.fromkeys(c.strip().upper() for c in countries))
    if set(main["allowed_countries"]) & set(main["excluded_countries"]):
        raise ValueError("A main-pool country cannot be both allowed and excluded")
    agreement = main["min_agreement"]
    if isinstance(agreement, bool) or not isinstance(agreement, (int, float)) or not math.isfinite(agreement) or not 0 < agreement <= 1:
        raise ValueError("routing.main.min_agreement must be greater than 0 and at most 1")
    votes = main["min_votes"]
    if isinstance(votes, bool) or not isinstance(votes, int) or not 1 <= votes <= 100:
        raise ValueError("routing.main.min_votes must be an integer from 1 to 100")
    return result


def _consensus_failure(policy, result):
    """Validate the recorded votes rather than trusting a label or cached score."""
    if not isinstance(result, dict):
        return "Location evidence missing"
    counts = result.get("counts")
    if not isinstance(counts, dict) or not counts or any(
        not isinstance(code, str) or code not in COUNTRIES
        or isinstance(count, bool) or not isinstance(count, int) or count <= 0
        for code, count in counts.items()
    ):
        return "Location country unknown"
    total, votes = sum(counts.values()), max(counts.values())
    winners = [code for code, count in counts.items() if count == votes]
    if len(winners) != 1:
        return "Location country tied"
    country = winners[0]
    score = result.get("score")
    if (result.get("country") != country or type(result.get("total")) is not int or result["total"] != total
            or type(result.get("votes")) is not int or result["votes"] != votes
            or isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1
            or not math.isclose(score, votes / total, rel_tol=1e-9, abs_tol=1e-9)):
        return "Location evidence inconsistent"
    if total < policy["min_votes"]:
        return "Too few location reports"
    if votes / total < policy["min_agreement"]:
        return "Location agreement below threshold"
    if country in policy["excluded_countries"]:
        return "Location country excluded: " + country
    if policy["allowed_countries"] and country not in policy["allowed_countries"]:
        return "Location country outside allowlist: " + country
    return None


def main_policy_failure(policy, evidence):
    """Require usable GeoIP consensus in every observed/required IP family."""
    # "geoip": evidence from nodesieve.location.
    if not isinstance(evidence, dict) or evidence.get("source") != "geoip":
        return "Location evidence missing"
    if evidence.get("ip_leak"):
        return "Location probe detected an IP leak"
    if evidence.get("status") == "failed":
        return "Location probe failed"
    failure = _consensus_failure(policy, evidence)
    if failure:
        return failure
    tested = evidence.get("tested_families")
    families = evidence.get("families")
    if (not isinstance(tested, list) or not tested or any(f not in ("ipv4", "ipv6") for f in tested)
            or len(set(tested)) != len(tested) or not isinstance(families, dict)):
        return "Location IP-family evidence missing"
    for family, result in families.items():
        if family not in ("ipv4", "ipv6") or not isinstance(result, dict):
            return "Location IP-family evidence inconsistent"
        if family not in tested and (result.get("counts") or result.get("country") or result.get("total")):
            return "Location observed IP family was not tested"
    combined = {}
    for family in tested:
        result = families.get(family)
        failure = _consensus_failure(policy, result)
        if failure:
            return family.upper() + ": " + failure
        for code, votes in result["counts"].items():
            combined[code] = combined.get(code, 0) + votes
    if combined != evidence["counts"] or evidence.get("status") != "ok":
        return "Location evidence inconsistent"
    return None


def main_location_rank(evidence):
    """Agreement first, then amount of evidence; call only on validated evidence."""
    counts = evidence["counts"]
    return max(counts.values()) / sum(counts.values()), sum(counts.values())


def select_main_pool(candidates, metadata, routing):
    """Qualify every tested node for the main pool, retaining exclusion reasons."""
    policy = normalize_routing(routing)["main"]
    eligible, excluded, seen = [], [], set()
    for candidate in candidates:
        node = candidate[0] if isinstance(candidate, (tuple, list)) else candidate
        original = candidate[2] if isinstance(candidate, (tuple, list)) and len(candidate) > 2 else node
        core = node.split("#", 1)[0]
        if core in seen:
            continue
        seen.add(core)
        meta = metadata.get(node, metadata.get(original, {}))
        evidence = copy.deepcopy(meta.get("location", {}))
        reason = main_policy_failure(policy, evidence)
        if not reason and node.split("://", 1)[0] not in {"vless", "trojan", "ss"}:
            reason = "Proxy URI is unsupported by this exporter (VLESS, Trojan and Shadowsocks only)"
        if reason:
            excluded.append({"node": node, "reason": reason})
        else:
            evidence["latency_ms"] = meta.get("latency_ms")
            eligible.append({"node": node, "evidence": evidence})

    def order(item):
        score, reports = main_location_rank(item["evidence"])
        value = item["evidence"].get("latency_ms")
        latency = value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0 else float("inf")
        return -score, -reports, latency

    # Ranking orders the pool; it must not discard nodes that passed
    # the configured country and evidence requirements.
    eligible.sort(key=order)
    return {"policy": policy, "eligible": eligible, "excluded": excluded}
