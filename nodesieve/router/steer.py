"""Export the location-ranked main server list for Steer (Zapret Manager).

Steer keeps its settings under /etc/zm-steer and is driven by the panel's own
backend. Behaviour verified against the upstream installer, v5.085, commit 1ff3f5a:
https://github.com/StressOzz/Zapret-Manager/blob/1ff3f5aa01e85125548eccc0a1dd6229a99123fb/ZapretManager_LuCI.sh
The apply script only talks to that backend (`steer_action sub_status`,
`sub_links_get`, `sub_set`, `job_status`, `log_tail`); it never edits Steer's
files, so validation, plugin installation and applying stay the panel's job.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import quote, unquote

from nodesieve.parsers.mihomo import node_url_to_mihomo_dict
from nodesieve.routing import main_location_rank, main_policy_failure, normalize_routing

OUTPUT_DIR = "steer-output"
SCRIPT_NAME = "apply_steer.sh"
SERVERS_NAME = "steer-servers.txt"
REPORT_NAME = "routing-report.json"
# PSC_ comes from the project's former name, Proxy Site Checker. It prefixes the lines the
# script prints for dashboard.py (PSC_OK, PSC_ERROR, PSC_LOG, PSC_NOTE) and the documented
# PSC_CHECK_ONLY switch. It stays: deploy runs the script an earlier check saved, which may
# predate the rename.
# Closes the quoted here-document that carries the links; a link can never be this line.
_SERVERS_END = "PSC_SERVERS_END"


def output_directory(config: dict) -> Path:
    return Path(config.get("routing_output_dir") or OUTPUT_DIR).expanduser().resolve()


def routing_fingerprint(config: dict) -> str:
    """Bind an export to its policy and intended router, without exposing either."""
    routing = normalize_routing(config.get("routing"))
    material = {"routing": routing, "router_host": config.get("router_host", ""),
                "main_pool_selection": "all_qualified_v1"}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _write_private(path: Path, text: str, mode: int = 0o600) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".psc-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


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
        public = {"id": _node_id(node), "source": "ipregion", **_public_location(evidence),
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


def _script(servers: list[str]) -> str:
    """Shell for the router: hand the list to the panel backend, wait, verify, restore on failure.

    The script is streamed to `sh -s`. Its whole body is one function, so the shell
    has read all of it before anything runs: a script cut short in transit, or a
    child process draining stdin, cannot leave it half executed. Success is only
    ever reported through a PSC_OK line.
    """
    if not servers or any(server == _SERVERS_END or "\n" in server or "\r" in server for server in servers):
        raise ValueError("Server links cannot be embedded safely")
    count = f"{len(servers)} server" + ("" if len(servers) == 1 else "s")
    return r"""#!/bin/sh
# Generated for Steer (Zapret Manager). Run on the router only after reviewing.
# PSC_CHECK_ONLY=1 stops after the read-only checks, before anything is changed.
set -eu
umask 077
psc_main() {
fail() { printf 'PSC_ERROR: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Run this script as root on the router.'
backend=/opt/zapret-manager-luci/backend.sh
[ -x "$backend" ] || fail 'Zapret Manager is not installed: its panel backend was not found.'
command -v jsonfilter >/dev/null 2>&1 || fail 'Required command missing: jsonfilter'
field() { printf '%s' "$1" | jsonfilter -e "$2" 2>/dev/null || :; }
panel() { "$backend" "$@" </dev/null 2>/dev/null || :; }
problem=''
# The list Steer uses now, exactly as the panel can take it back: a subscription link or its own links.
servers_now() {
    case "$(field "$1" '@.kind')" in
        url) field "$1" '@.url';;
        links) field "$(panel steer_action sub_links_get)" '@.links';;
    esac
}
status=$(panel steer_action sub_status)
route=$(field "$status" '@.exit')
case "$route" in
    vpn) :;;
    warp|iface|none) fail "The main section of Steer is not connected through VPN (now: $route). Connect it to VPN in the panel once, then apply again.";;
    *) fail 'Steer did not report its main connection. Install Steer in Zapret Manager, or update the panel.';;
esac
kind=$(field "$status" '@.kind')
previous=$(servers_now "$status")
[ -n "$previous" ] || fail 'The server list Steer uses now could not be read, so it could not be restored after a failure. Nothing was changed.'
if [ "${PSC_CHECK_ONLY:-}" = 1 ]; then
    case "$kind" in url) printf '%s\n' 'PSC_OK: Steer is ready: its main section uses VPN with a subscription link. Nothing was changed.';;
        *) printf '%s\n' 'PSC_OK: Steer is ready: its main section uses VPN with its own server list. Nothing was changed.';; esac
    exit 0
fi
# Hands the text on stdin to the panel as the main section's servers and waits until it is applied.
# Returns 1 when the panel refused, 2 when it is still working, 3 when applying failed.
submit() {
    reply=$("$backend" steer_action sub_set @stdin 2>/dev/null || :)
    problem=$(field "$reply" '@.error')
    [ -z "$problem" ] || return 1
    [ "$(field "$reply" '@.started')" = true ] || { problem='the panel did not start the operation'; return 1; }
    waited=0
    while :; do
        job=$(panel job_status steer)
        [ "$(field "$job" '@.done')" != true ] || break
        [ "$waited" -lt 300 ] || { problem='the panel is still working after 5 minutes'; return 2; }
        sleep 2
        waited=$((waited + 2))
        [ $((waited % 10)) -ne 0 ] || printf 'Waiting for Steer: %ss\n' "$waited"
    done
    [ "$(field "$job" '@.rc')" = 0 ] || { problem='the panel reported a failure while applying'; return 3; }
}
outcome=0
submit <<'""" + _SERVERS_END + r"""' || outcome=$?
""" + "\n".join(servers) + "\n" + _SERVERS_END + r"""
if [ "$outcome" = 0 ]; then
    after=$(panel steer_action sub_status)
    if [ "$(field "$after" '@.kind')" = links ] && [ "$(field "$after" '@.exit')" = vpn ]; then
        attempt=0
        while [ "$(field "$after" '@.vpn.up')" != true ] && [ "$attempt" -lt 10 ]; do
            attempt=$((attempt + 1))
            sleep 2
            after=$(panel steer_action sub_status)
        done
        [ "$(field "$after" '@.vpn.up')" = true ] || printf 'PSC_NOTE: %s\n' 'Steer accepted the servers, but its VPN tunnel is not up yet. Check the panel.'
        printf 'PSC_OK: Steer main servers replaced: %s\n' '""" + count + r"""'
        exit 0
    fi
    outcome=3
    problem='Steer does not show the new server list'
fi
printf 'PSC_ERROR: Steer did not apply the new servers: %s\n' "$problem" >&2
field "$(panel log_tail steer)" '@.lines' | tail -n 8 | sed 's/^/PSC_LOG: /' >&2
# The panel runs one operation at a time: while it is still busy, nothing can be restored.
[ "$outcome" != 2 ] || fail 'The previous servers were not restored because the panel is still busy. Check Steer in the panel.'
current=$(panel steer_action sub_status)
if [ "$(field "$current" '@.exit')" = vpn ] && [ "$(field "$current" '@.kind')" = "$kind" ] && [ "$(servers_now "$current")" = "$previous" ]; then
    fail 'The previous servers are still in place.'
fi
printf '%s\n' 'Restoring the previous Steer servers'
outcome=0
submit <<PSC_PREVIOUS_END || outcome=$?
$previous
PSC_PREVIOUS_END
[ "$outcome" = 0 ] || fail "The previous servers could not be restored ($problem). Set them again in the panel: Steer, Connection tab."
fail 'The previous servers were restored.'
}
psc_main
"""


def write_steer_artifacts(route: dict, config: dict) -> dict:
    """Write a redacted report and, for a non-empty pool, the server list and guarded router script.

Nothing is sent to the router. A main pool without a qualifying proxy prevents
export of an apply script; previous scripts are removed before attempting export.
"""
    directory = output_directory(config)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    report_path = directory / REPORT_NAME
    script_path = directory / SCRIPT_NAME
    servers_path = directory / SERVERS_NAME
    for stale in (script_path, servers_path):
        stale.unlink(missing_ok=True)
    report = {"ready": False, "created_at": datetime.now(timezone.utc).isoformat(),
              "config_fingerprint": routing_fingerprint(config), "script_sha256": None,
              "main": None, "errors": [], "warnings": [
                  "Eligibility reflects the last scan. Run a fresh scan when proxy locations change.",
                  "Latency is measured from the scan host.",
                  "The server list keeps every proxy passing the country and evidence thresholds, ranked by location agreement, valid reports and latency. Steer chooses among them by its own server selection setting; it does not verify location again.",
                  "Applying replaces the servers of Steer's main section, including a subscription connected there. Services, devices and other sections are not touched.",
                  "Live router compatibility and routing require verification after applying."]}
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
    if not report["errors"]:
        script = _script(servers)
        _write_private(servers_path, "\n".join(servers) + "\n")
        _write_private(script_path, script, 0o700)
        report["script_sha256"] = hashlib.sha256(script.encode()).hexdigest()
        report["ready"] = True
    _write_private(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return {"ready": report["ready"], "report_path": str(report_path),
            "script_path": str(script_path) if report["ready"] else None,
            "servers_path": str(servers_path) if report["ready"] else None,
            "warnings": report["warnings"], "errors": report["errors"]}
