"""Main-pool location policy, candidate ranking, and redacted Steer routing report."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

from nodesieve.files import write_atomic
from nodesieve.location import COUNTRIES
from nodesieve.parsers.base import SHARE_SCHEMES, node_key, normalize_share_link
from nodesieve.parsers.xray import node_url_to_xray_outbound

OUTPUT_DIR = "steer-output"
REPORT_NAME = "routing-report.json"

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

_REASON_LABELS = (
    (("ip leak",), "Location probe detected an IP leak"),
    (("excluded", "not allowed", "not permitted", "outside allowlist"), "Location country is excluded or not allowed"),
    (("agreement", "score"), "Location agreement is below the required threshold"),
    (("votes", "reports"), "Too few valid location reports"),
    (("unknown", "missing", "unavailable", "failed"), "Location evidence is unavailable or incomplete"),
    (("inconsistent", "tied"), "Location evidence is inconsistent or tied"),
)


def _valid_latency(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0:
        return value
    return None


def _is_int(v: object) -> bool:
    return type(v) is int


def normalize_routing(value=None) -> dict:
    """Merge defaults and reject invalid routing settings."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("routing must be an object")
    if unknown := set(value) - set(DEFAULT_ROUTING):
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
        if not isinstance(countries, list) or any(not isinstance(c, str) or c.strip().upper() not in COUNTRIES for c in countries):
            raise ValueError(f"routing.main.{key} must be a list of two-letter country codes")
        main[key] = list(dict.fromkeys(c.strip().upper() for c in countries))
    if set(main["allowed_countries"]) & set(main["excluded_countries"]):
        raise ValueError("A main-pool country cannot be both allowed and excluded")
    agreement = main["min_agreement"]
    if isinstance(agreement, bool) or not isinstance(agreement, (int, float)) or not math.isfinite(agreement) or not 0 < agreement <= 1:
        raise ValueError("routing.main.min_agreement must be greater than 0 and at most 1")
    votes = main["min_votes"]
    if not _is_int(votes) or not 1 <= votes <= 100:
        raise ValueError("routing.main.min_votes must be an integer from 1 to 100")
    return result


def _consensus_failure(policy: dict, result: object) -> str | None:
    if not isinstance(result, dict):
        return "Location evidence missing"
    counts = result.get("counts")
    if not isinstance(counts, dict) or not counts or any(
        not isinstance(code, str) or code not in COUNTRIES or not _is_int(n) or n <= 0
        for code, n in counts.items()
    ):
        return "Location country unknown"
    total, votes = sum(counts.values()), max(counts.values())
    winners = [c for c, n in counts.items() if n == votes]
    if len(winners) != 1:
        return "Location country tied"
    country = winners[0]
    score = result.get("score")
    if (result.get("country") != country or not _is_int(result.get("total")) or result["total"] != total
            or not _is_int(result.get("votes")) or result["votes"] != votes
            or isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score)
            or not 0 <= score <= 1 or not math.isclose(score, votes / total, rel_tol=1e-9, abs_tol=1e-9)):
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


def main_policy_failure(policy: dict, evidence: object) -> str | None:
    """Require valid GeoIP consensus in every observed/tested IP family."""
    if not isinstance(evidence, dict) or evidence.get("source") != "geoip":
        return "Location evidence missing"
    if evidence.get("ip_leak"):
        return "Location probe detected an IP leak"
    if evidence.get("status") == "failed":
        return "Location probe failed"
    if failure := _consensus_failure(policy, evidence):
        return failure
    tested, families = evidence.get("tested_families"), evidence.get("families")
    if (not isinstance(tested, list) or not tested or any(f not in ("ipv4", "ipv6") for f in tested)
            or len(set(tested)) != len(tested) or not isinstance(families, dict)):
        return "Location IP-family evidence missing"
    for f, res in families.items():
        if f not in ("ipv4", "ipv6") or not isinstance(res, dict):
            return "Location IP-family evidence inconsistent"
        if f not in tested and (res.get("counts") or res.get("country") or res.get("total")):
            return "Location observed IP family was not tested"
    combined: dict[str, int] = {}
    for f in tested:
        res = families.get(f)
        if failure := _consensus_failure(policy, res):
            return f.upper() + ": " + failure
        for code, n in res["counts"].items():
            combined[code] = combined.get(code, 0) + n
    if combined != evidence["counts"] or evidence.get("status") != "ok":
        return "Location evidence inconsistent"
    return None


def main_location_rank(evidence: dict) -> tuple[float, int]:
    counts = evidence["counts"]
    return max(counts.values()) / sum(counts.values()), sum(counts.values())


def select_main_pool(candidates, metadata: dict, routing) -> dict:
    """Qualify every tested node for the main pool, retaining exclusion reasons."""
    policy = normalize_routing(routing)["main"]
    eligible, excluded, seen = [], [], set()
    for candidate in candidates:
        node = candidate[0] if isinstance(candidate, (tuple, list)) else candidate
        original = candidate[2] if isinstance(candidate, (tuple, list)) and len(candidate) > 2 else node
        core = node_key(node)
        if core in seen:
            continue
        seen.add(core)
        meta = metadata.get(node, metadata.get(original, {}))
        evidence = copy.deepcopy(meta.get("location", {}))
        reason = main_policy_failure(policy, evidence)
        if not reason and node.partition("://")[0].lower() not in SHARE_SCHEMES:
            reason = "Proxy URI is unsupported by this exporter"
        if reason:
            excluded.append({"node": node, "reason": reason})
        else:
            evidence["latency_ms"] = meta.get("latency_ms")
            eligible.append({"node": node, "evidence": evidence})

    eligible.sort(key=lambda item: (
        -main_location_rank(item["evidence"])[0],
        -main_location_rank(item["evidence"])[1],
        _valid_latency(item["evidence"].get("latency_ms")) or float("inf"),
    ))
    return {"policy": policy, "eligible": eligible, "excluded": excluded}


def _node_id(node: str) -> str:
    return hashlib.sha256(str(node).split("#", 1)[0].encode()).hexdigest()[:16]


def _location_reason(reason: object) -> str:
    text = str(reason or "").lower()
    for needles, label in _REASON_LABELS:
        if any(n in text for n in needles):
            return label
    return "Location evidence did not satisfy this policy"


def _public_location(ev: dict) -> dict:
    cc = ev.get("country")
    score = ev.get("score")
    counts = ev.get("counts", {})
    return {
        "country": cc if isinstance(cc, str) and re.fullmatch(r"[A-Z]{2}", cc) else None,
        "score": score if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 1 else None,
        "votes": ev.get("votes") if _is_int(ev.get("votes")) and ev["votes"] >= 0 else None,
        "total": ev.get("total") if _is_int(ev.get("total")) and ev["total"] >= 0 else None,
        "counts": {c: v for c, v in counts.items() if isinstance(c, str) and re.fullmatch(r"[A-Z]{2}", c) and _is_int(v) and v >= 0}
        if isinstance(counts, dict) else {},
    }


def write_routing_report(route: dict, config: dict) -> dict:
    """Validate and rank the main pool, write its redacted report, and return links for the feed."""
    directory = Path(config.get("routing_output_dir") or OUTPUT_DIR).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    report_path = directory / REPORT_NAME
    warnings = [
        "Eligibility reflects the last scan. Run a fresh scan when proxy locations change.",
        "Latency is measured from the scan host.",
        "The list keeps every proxy passing the country and evidence thresholds, ranked by location agreement, "
        "valid reports and latency. Steer chooses among them by its own server selection setting; it does not verify location again.",
    ]
    report: dict = {"ready": False, "created_at": datetime.now(timezone.utc).isoformat(),
                    "main": None, "errors": [], "warnings": warnings}
    policy = normalize_routing(config.get("routing"))["main"]
    servers: list[str] = []

    if not route:
        report["errors"].append("Missing main route")
    elif normalize_routing({"main": route.get("policy", {})})["main"] != policy:
        report["errors"].append("main: route policy does not match the configured policy")
    else:
        eligible, seen = [], set()
        excluded = [{"id": _node_id(c.get("node", "")), "reason": _location_reason(c.get("reason"))}
                    for c in route.get("excluded", [])]
        for cand in route.get("eligible", []):
            node, ev = cand.get("node", ""), cand.get("evidence", {})
            reason = main_policy_failure(policy, ev)
            uri = normalize_share_link(node)
            if uri and node_url_to_xray_outbound(uri.partition("#")[0]) is None:
                uri = None
            if reason or uri is None:
                excluded.append({"id": _node_id(node), "reason": _location_reason(reason) if reason else
                                 "Proxy URI is unsupported by this exporter"})
                continue
            core = node_key(uri)
            if core in seen:
                continue
            seen.add(core)
            public = {
                "id": _node_id(node), "source": "geoip", **_public_location(ev),
                "tested_families": [f for f in ev.get("tested_families", []) if f in ("ipv4", "ipv6")],
                "families": {f: _public_location(v) for f, v in ev.get("families", {}).items()
                             if f in ("ipv4", "ipv6") and isinstance(v, dict)},
                "score": main_location_rank(ev)[0],
                "latency_ms": _valid_latency(ev.get("latency_ms")),
            }
            eligible.append((uri, public))
        eligible.sort(key=lambda item: (
            -item[1]["score"], -item[1]["total"],
            item[1]["latency_ms"] if item[1]["latency_ms"] is not None else float("inf"),
        ))
        servers = [uri for uri, _ in eligible]
        report["main"] = {**policy, "eligible": [pub for _, pub in eligible], "excluded": excluded}
        if not servers:
            report["errors"].append("main: no supported proxy satisfies the location policy")

    report["ready"] = not report["errors"]
    write_atomic(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return {"ready": report["ready"], "report_path": str(report_path),
            "servers": servers if report["ready"] else [], "warnings": warnings, "errors": report["errors"]}
