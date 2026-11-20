"""Country consensus from ipregion's GeoIP reports through a node proxy."""

import asyncio
from collections import Counter, defaultdict
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal


# ISO 3166-1 alpha-2. A two-letter error/placeholder is not country evidence.
COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM
IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK
LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW
MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR
PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())
FAMILIES = ("ipv4", "ipv6")
DEPENDENCIES = ("bash", "jq", "curl")
# The bundled ipregion.sh prints this JSON report version; its GeoIP databases
# are the "geoip" group. Version 1 called that group "primary" and used plain
# strings where version 2 has objects.
REPORT_VERSION = 2
GEOIP_GROUP = "geoip"
# Seconds each ipregion request may take through the node, its TLS handshakes included;
# ipregion's own default. With two, good nodes failed on mobile data, where the first
# requests through a freshly started node often take longer.
REQUEST_TIMEOUT = 5


def _consensus(counts):
    counts = dict(sorted(counts.items()))
    total = sum(counts.values())
    votes = max(counts.values(), default=0)
    winners = [country for country, count in counts.items() if count == votes]
    return {"country": winners[0] if len(winners) == 1 else None,
            "score": votes / total if total else 0.0,
            "votes": votes, "total": total, "counts": counts}


def empty_location(status="unknown", reason=None, families=()):
    evidence = {"source": "ipregion", **_consensus({}),
                "families": {family: _consensus({}) for family in families},
                "tested_families": list(families), "status": status, "ip_leak": False}
    if reason:
        evidence["reason"] = reason
    return evidence


def _exit_address(payload, family):
    """The exit address ipregion found for a family, or None if it found none."""
    details = payload.get(family)
    value = details.get("ip") if isinstance(details, dict) else None
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return address if address.version == (4 if family == "ipv4" else 6) else None


def parse_ipregion(payload, families=None, real_ip=None):
    """Count each GeoIP provider once per family, excluding conflicting repeats.

    Platform, CDN, availability and AI checks never affect GeoIP consensus.
    ``families`` are known reachable families and remain required even if their
    report is missing. Additional discovered families are included automatically.
    Exit addresses are only examined for leaks and are omitted from the result.
    """
    required = tuple(family for family in (families or ()) if family in FAMILIES)
    requested = FAMILIES
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return empty_location("failed", "Invalid ipregion JSON", requested)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        return empty_location("failed", "Invalid ipregion report", requested)
    if payload.get("version") != REPORT_VERSION:
        return empty_location(
            "failed", f"Unsupported ipregion report version (expected {REPORT_VERSION})", requested)
    records = payload["results"].get(GEOIP_GROUP)
    if not isinstance(records, list):
        return empty_location("failed", "Missing GeoIP reports", requested)

    exits = {family: _exit_address(payload, family) for family in FAMILIES}
    discovered = set(required) | {family for family, address in exits.items() if address is not None}

    observations = {family: defaultdict(set) for family in requested}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            continue
        provider = record["id"].strip().casefold()
        if not provider:
            continue
        for family in requested:
            # A failed lookup has no country, only a reason. A family that was
            # not checked is null, as is one the proxy did not use for a request.
            answer = record.get(family)
            value = answer.get("country") if isinstance(answer, dict) else None
            country = value.strip().upper() if isinstance(value, str) else None
            if country in COUNTRIES:
                discovered.add(family)
                observations[family][provider].add(country)
    evidence = empty_location(families=requested)
    aggregate = Counter()
    for family, providers in observations.items():
        counts = Counter(next(iter(values)) for values in providers.values() if len(values) == 1)
        evidence["families"][family] = _consensus(counts)
        aggregate.update(counts)
    evidence["tested_families"] = [family for family in FAMILIES if family in discovered]
    evidence.update(_consensus(aggregate))
    evidence["status"] = "ok" if evidence["country"] else "unknown"
    try:
        direct = ipaddress.ip_address(real_ip) if real_ip else None
    except (ValueError, TypeError):
        direct = None
    if direct is not None and direct in exits.values():
        evidence["ip_leak"] = True
        evidence["status"] = "failed"
        evidence["reason"] = "Proxy leaks real IP"
    return evidence


def _ipregion_error(stderr):
    """The reason for a probe that ended without a report: ipregion's last error line."""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", (stderr or b"").decode("utf-8", "replace"))
    lines = ["".join(c for c in line if c.isprintable()).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        return "ipregion failed without a report"
    return "ipregion: " + lines[-1].removeprefix("Error: ")[:160]


async def _stop_process_group(process, communication):
    """Bound cleanup of bash and all its curl/process-substitution children."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(asyncio.shield(communication), timeout=0.3)
            if sig == signal.SIGKILL:
                return
        except Exception:
            pass
        # Kill the group even if its leader exited after SIGTERM: descendants
        # may ignore TERM and close their inherited output before exiting.
    if not communication.done():
        communication.cancel()
    try:
        await asyncio.wait_for(process.wait(), timeout=0.3)
    except (asyncio.TimeoutError, ProcessLookupError):
        pass


async def probe_ipregion(script_path, proxy_address, families=None, real_ip=None, timeout=180):
    """Run the bundled script non-interactively; the caller limits concurrency."""
    families = tuple(family for family in (families or ()) if family in FAMILIES)
    missing = [name for name in DEPENDENCIES if not shutil.which(name)]
    if missing:
        return empty_location("failed", "Missing dependencies: " + ", ".join(missing), families)
    if not Path(script_path).is_file():
        return empty_location("failed", "ipregion script not found", families)
    command = [shutil.which("bash"), str(script_path), "-p", proxy_address, "-j", "-g", GEOIP_GROUP,
               "-t", str(REQUEST_TIMEOUT)]
    # Always discover both; known reachable families remain required even when
    # the script cannot discover them. Never hide a failed IPv6 report.
    # Explicit SOCKS5 must not be bypassed by inherited no_proxy settings.
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    environment.update({"NO_PROXY": "", "no_proxy": ""})
    process = None
    communication = None
    launch = None
    try:
        launch = asyncio.create_task(asyncio.create_subprocess_exec(
            *command, cwd=str(Path(script_path).resolve().parent), env=environment,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        ))
        process = await asyncio.shield(launch)
        communication = asyncio.create_task(process.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), timeout=timeout)
        # ipregion's JSON is authoritative even if a final optional cleanup
        # function exits nonzero; malformed/absent output fails closed.
        if process.returncode and not stdout.strip():
            # It stopped before reporting, for example when no exit IP answered through the proxy.
            return empty_location("failed", _ipregion_error(stderr), families)
        return parse_ipregion(stdout, families=families, real_ip=real_ip)
    except asyncio.CancelledError:
        # Do not lose the child if cancellation arrives during subprocess setup.
        if process is None and launch is not None:
            try:
                process = await asyncio.shield(launch)
                communication = asyncio.create_task(process.communicate())
            except (OSError, ValueError):
                pass
        if process is not None and communication is not None:
            await _stop_process_group(process, communication)
        raise
    except asyncio.TimeoutError:
        if process is not None and communication is not None:
            await _stop_process_group(process, communication)
        return empty_location("failed", "ipregion timed out", families)
    except (OSError, ValueError):
        if process is not None and communication is not None:
            await _stop_process_group(process, communication)
        return empty_location("failed", "ipregion could not run", families)
