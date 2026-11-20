"""Rank the Steer main pool and write its report.

Every node that passes the location policy joins the pool, ranked by location agreement,
valid reports and latency. The ranked links go to the subscription feed (feed.py), which
Steer's main section subscribes to; the report says, without credentials, why each node
was excluded and what qualified the rest.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from urllib.parse import quote, unquote

from nodesieve.files import write_private
from nodesieve.parsers.mihomo import node_url_to_mihomo_dict
from nodesieve.routing import main_location_rank, main_policy_failure, normalize_routing

OUTPUT_DIR = "steer-output"
REPORT_NAME = "routing-report.json"


def output_directory(config: dict) -> Path:
    return Path(config.get("routing_output_dir") or OUTPUT_DIR).expanduser().resolve()


def _node_id(node: str) -> str:
    return hashlib.sha256(str(node).split("#", 1)[0].encode()).hexdigest()[:16]


def _uri(node: str) -> str | None:
    if not isinstance(node, str) or any(ord(c) < 32 or ord(c) == 127 for c in node):
        return None
    core, separator, fragment = node.strip().partition("#")
    if any(c.isspace() for c in core) or core.split("://", 1)[0] not in {"vless", "trojan", "ss"}:
        return None
    if node_url_to_mihomo_dict(core) is None:
        return None
    return core + ("#" + quote(unquote(fragment), safe="") if separator else "")


def _location_reason(reason: object) -> str:
    """Keep useful location failures without echoing untrusted probe contents."""
    text = str(reason or "").lower()
    for needles, label in (
        (("ip leak",), "Location probe detected an IP leak"),
        (("excluded", "not allowed", "not permitted", "outside allowlist"), "Location country is excluded or not allowed"),
        (("agreement", "score"), "Location agreement is below the required threshold"),
        (("votes", "reports"), "Too few valid location reports"),
        (("unknown", "missing", "unavailable", "failed"), "Location evidence is unavailable or incomplete"),
        (("inconsistent", "tied"), "Location evidence is inconsistent or tied"),
    ):
        if any(needle in text for needle in needles):
            return label
    return "Location evidence did not satisfy this policy"


def _public_location(evidence: dict) -> dict:
    """Include country consensus only; IPs, URLs and probe bodies never leave here."""
    result = {}
    country = evidence.get("country")
    result["country"] = country if isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country) else None
    score = evidence.get("score")
    result["score"] = score if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 1 else None
    for key in ("votes", "total"):
        value = evidence.get(key)
        result[key] = value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
    counts = evidence.get("counts", {})
    result["counts"] = {code: value for code, value in counts.items()
                        if isinstance(code, str) and re.fullmatch(r"[A-Z]{2}", code)
                        and isinstance(value, int) and not isinstance(value, bool) and value >= 0} if isinstance(counts, dict) else {}
    return result


def _main_route(route: dict, policy: dict) -> tuple[list[str], dict]:
    """Re-validate every candidate; return the ranked server links and a redacted report."""
    eligible, excluded, seen = [], [], set()
    for candidate in route.get("excluded", []):
        excluded.append({"id": _node_id(candidate.get("node", "")), "reason": _location_reason(candidate.get("reason"))})
    for candidate in route.get("eligible", []):
        node, evidence = candidate.get("node", ""), candidate.get("evidence", {})
        reason = main_policy_failure(policy, evidence)
        uri = _uri(node)
        if reason or uri is None:
            excluded.append({"id": _node_id(node), "reason": _location_reason(reason) if reason else
                             "Proxy URI is unsupported by this exporter (VLESS, Trojan and Shadowsocks only)"})
            continue
        core = uri.split("#", 1)[0]
        if core in seen:
            continue
        seen.add(core)
        public = {"id": _node_id(node), "source": "geoip", **_public_location(evidence),
                  "tested_families": [family for family in evidence.get("tested_families", []) if family in {"ipv4", "ipv6"}],
                  "families": {family: _public_location(values) for family, values in evidence.get("families", {}).items()
                               if family in {"ipv4", "ipv6"} and isinstance(values, dict)}}
        public["score"] = main_location_rank(evidence)[0]
        latency = evidence.get("latency_ms")
        public["latency_ms"] = latency if isinstance(latency, (int, float)) and not isinstance(latency, bool) and math.isfinite(latency) and latency > 0 else None
        eligible.append((uri, public))
    # Rank every qualifying candidate: Steer's "first working" selection follows this order.
    eligible.sort(key=lambda item: (
        -item[1]["score"], -item[1]["total"],
        item[1]["latency_ms"] if item[1]["latency_ms"] is not None else float("inf"),
    ))
    report = {**policy, "eligible": [public for _, public in eligible], "excluded": excluded}
    return [uri for uri, _ in eligible], report


def write_routing_report(route: dict, config: dict) -> dict:
    """Rank the main pool and write its redacted report; the ranked links are returned for the feed.

    The report holds no proxy credentials: why each node was excluded, and the country
    evidence and latency of each one that qualified. ready says that one did.
    """
    directory = output_directory(config)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    report_path = directory / REPORT_NAME
    report = {"ready": False, "created_at": datetime.now(timezone.utc).isoformat(),
              "main": None, "errors": [], "warnings": [
                  "Eligibility reflects the last scan. Run a fresh scan when proxy locations change.",
                  "Latency is measured from the scan host.",
                  "The list keeps every proxy passing the country and evidence thresholds, ranked by location agreement, valid reports and latency. Steer chooses among them by its own server selection setting; it does not verify location again."]}
    policy = normalize_routing(config.get("routing"))["main"]
    servers: list[str] = []
    if not route:
        report["errors"].append("Missing main route")
    elif normalize_routing({"main": route.get("policy", {})})["main"] != policy:
        report["errors"].append("main: route policy does not match the configured policy")
    else:
        servers, report["main"] = _main_route(route, policy)
        if not servers:
            report["errors"].append("main: no supported proxy satisfies the location policy")
    report["ready"] = not report["errors"]
    write_private(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return {"ready": report["ready"], "report_path": str(report_path),
            "servers": servers if report["ready"] else [],
            "warnings": report["warnings"], "errors": report["errors"]}
