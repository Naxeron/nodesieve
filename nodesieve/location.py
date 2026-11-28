"""Country consensus from 14 GeoIP providers asked through a node's proxy.

Providers adapted from the "geoip" group of ipregion (MIT, see THIRD_PARTY_NOTICES.md).
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import ipaddress
import json
import re
import ssl
from typing import Iterable, Optional

import aiohttp

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
SOURCE = "geoip"
REQUEST_TIMEOUT = 5
PROBE_TIMEOUT = 60
REQUESTS_PER_NODE = 16
USER_AGENT = "curl/8.11.1"


@dataclass(frozen=True)
class Lookup:
    name: str
    url: str
    path: Optional[tuple] = None
    headers: dict = field(default_factory=dict)
    ipv6_url: Optional[str] = None


LOOKUPS = (
    Lookup("RIPE", "https://rdap.db.ripe.net/ip/{ip}", ("country",)),
    Lookup("ipinfo.io", "https://ipinfo.io/widget/demo/{ip}", ("data", "country"),
           ipv6_url="https://v6.ipinfo.io/widget/demo/{ip}"),
    Lookup("ipregistry.co", "https://api.ipregistry.co/{ip}?hostname=true&key=sb69ksjcajfs4c",
           ("location", "country", "code"), {"Origin": "https://ipregistry.co"}),
    Lookup("ipapi.co", "https://ipapi.co/{ip}/json", ("country",), {"Referer": "https://ipapi.co/"}),
    Lookup("ifconfig.co", "https://ifconfig.co/country-iso?ip={ip}"),
    Lookup("ip2location.io", "https://api.ip2location.io/?ip={ip}", ("country_code",)),
    Lookup("country.is", "https://api.country.is/{ip}", ("country",)),
    Lookup("geoapify.com", "https://api.geoapify.com/v1/ipinfo?ip={ip}&apiKey=b8568cb9afc64fad861a69edbddb2658",
           ("country", "iso_code")),
    Lookup("geojs.io", "https://get.geojs.io/v1/ip/country.json?ip={ip}", (0, "country")),
    Lookup("ipbase.com", "https://api.ipbase.com/v2/info?ip={ip}", ("data", "location", "country", "alpha2")),
    Lookup("ipquery.io", "https://api.ipquery.io/{ip}", ("location", "country_code")),
    Lookup("ipwho.is", "https://ipwho.is/{ip}", ("country_code",)),
    Lookup("ip-api.com", "https://demo.ip-api.com/json/{ip}?fields=countryCode", ("countryCode",),
           {"Origin": "https://ip-api.com"}),
)
PROVIDERS = ("Cloudflare", *(lookup.name for lookup in LOOKUPS))
CLOUDFLARE_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
IDENTITY_URLS = {
    "ipv4": ("https://ipv4.icanhazip.com", "https://api.ipify.org", "https://ipv4.seeip.org",
             "https://ipv4.wtfismyip.com/text"),
    "ipv6": ("https://ipv6.icanhazip.com", "https://api6.ipify.org", "https://ipv6.seeip.org",
             "https://ipv6.wtfismyip.com/text"),
}
_COUNTRY_CODE = re.compile(r"[A-Z]{2}")
_REQUEST_ERRORS = (asyncio.TimeoutError, aiohttp.ClientError, OSError, ValueError, LookupError)
_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def _ssl_context() -> ssl.SSLContext:
    global _SSL_CONTEXT
    if _SSL_CONTEXT is None:
        _SSL_CONTEXT = ssl.create_default_context()
    return _SSL_CONTEXT


def _consensus(counts: dict) -> dict:
    counts = dict(sorted(counts.items()))
    total = sum(counts.values())
    votes = max(counts.values(), default=0)
    winners = [c for c, n in counts.items() if n == votes]
    return {"country": winners[0] if len(winners) == 1 else None,
            "score": votes / total if total else 0.0, "votes": votes, "total": total, "counts": counts}


def empty_location(status: str = "unknown", reason: Optional[str] = None, families: Iterable[str] = ()) -> dict:
    ev = {"source": SOURCE, **_consensus({}),
          "families": {f: _consensus({}) for f in families},
          "tested_families": list(families), "status": status, "ip_leak": False}
    if reason:
        ev["reason"] = reason
    return ev


def _address(value: object, family: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(addr) if addr.version == (4 if family == "ipv4" else 6) else None


def location_evidence(reports: Iterable[dict], exits: Optional[dict] = None, families: Iterable[str] = (),
                      real_ip: Optional[str] = None) -> dict:
    """Compute per-family and aggregate country consensus from provider reports."""
    exits = exits or {}
    discovered = {f for f in families if f in FAMILIES} | {f for f, a in exits.items() if f in FAMILIES and a}
    observations = {f: defaultdict(set) for f in FAMILIES}
    for r in reports:
        f, p, c = r.get("family"), r.get("provider"), r.get("country")
        if f in FAMILIES and isinstance(p, str) and p.strip() and c in COUNTRIES:
            discovered.add(f)
            observations[f][p.strip().casefold()].add(c)
    ev = empty_location(families=FAMILIES)
    aggregate: Counter = Counter()
    for f, providers in observations.items():
        counts = Counter(next(iter(vals)) for vals in providers.values() if len(vals) == 1)
        ev["families"][f] = _consensus(counts)
        aggregate.update(counts)
    ev["tested_families"] = [f for f in FAMILIES if f in discovered]
    ev.update(_consensus(aggregate))
    ev["status"] = "ok" if ev["country"] else "unknown"
    own = _address(real_ip, "ipv4") or _address(real_ip, "ipv6")
    if own is not None and own in {_address(a, f) for f, a in exits.items()}:
        ev.update(ip_leak=True, status="failed", reason="Proxy leaks real IP")
    return ev


class ProxyClient:
    """Bounded concurrent HTTP requester routed through one local proxy."""

    def __init__(self, session: aiohttp.ClientSession, proxy: str):
        self.session = session
        self.proxy = proxy
        self.slots = asyncio.Semaphore(REQUESTS_PER_NODE)

    async def request(self, method: str, url: str, headers: Optional[dict] = None,
                      data: Optional[dict] = None) -> tuple[int, str]:
        async with self.slots:
            async with self.session.request(method, url, proxy=self.proxy, headers=headers, data=data,
                                            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as resp:
                return resp.status, await resp.text(errors="replace")


def _report(provider: str, family: str, country: Optional[str] = None, reason: Optional[str] = None) -> dict:
    return {"provider": provider, "family": family, "country": country, "reason": reason}


def _failure(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, aiohttp.ClientSSLError):
        return "TLS failed"
    return "connection failed"


def _verdict(status: int, body: str, path: Optional[tuple]) -> tuple[Optional[str], Optional[str]]:
    if status == 403:
        return None, "forbidden (403)"
    if status == 429:
        return None, "rate limited (429)"
    if 500 <= status <= 599:
        return None, f"server error ({status})"
    value: object = body
    if path is not None:
        try:
            value = json.loads(body)
            for key in path:
                value = value[key]
        except (ValueError, KeyError, IndexError, TypeError):
            value = None
    if isinstance(value, str) and _COUNTRY_CODE.fullmatch(value.strip()):
        return value.strip(), None
    return None, f"unexpected response ({status})"


async def _safe_get(client, url: str, headers: Optional[dict] = None) -> tuple[Optional[int], Optional[str], Optional[str]]:
    try:
        status, body = await client.request("GET", url, headers=headers)
        return status, body, None
    except _REQUEST_ERRORS as exc:
        return None, None, _failure(exc)


async def _ask(client, lookup: Lookup, family: str, ip: str) -> dict:
    url = (lookup.ipv6_url if family == "ipv6" and lookup.ipv6_url else lookup.url).format(ip=ip)
    status, body, err = await _safe_get(client, url, headers=lookup.headers or None)
    if err is not None:
        return _report(lookup.name, family, reason=err)
    return _report(lookup.name, family, *_verdict(status, body, lookup.path))


def _cloudflare_reports(exits: dict, fetched: tuple[Optional[int], Optional[str], Optional[str]]) -> list[dict]:
    if not exits:
        return []
    status, body, err = fetched
    if err is not None:
        return [_report("Cloudflare", f, reason=err) for f in exits]
    seen = re.search(r"(?:^|\n)ip=([^\n]+)", body or "")
    seen_ip = seen.group(1).strip() if seen else ""
    loc = re.search(r"(?:^|\n)loc=([^\n]*)", body or "")
    loc_val = loc.group(1) if loc else ""
    reports = []
    for family in exits:
        other_fam = "ipv6" if family == "ipv4" else "ipv4"
        other_ip = exits.get(other_fam)
        if other_ip and _address(seen_ip, other_fam) == other_ip:
            reports.append(_report("Cloudflare", family, reason="the node used its other family"))
        else:
            reports.append(_report("Cloudflare", family, *_verdict(status, loc_val, None)))
    return reports


async def _exit_address(client, family: str) -> Optional[str]:
    async def ask(url: str) -> Optional[str]:
        status, body, err = await _safe_get(client, url)
        return _address(body, family) if err is None and status == 200 else None

    tasks = [asyncio.ensure_future(ask(url)) for url in IDENTITY_URLS[family]]
    try:
        for answer in asyncio.as_completed(tasks):
            if addr := await answer:
                return addr
        return None
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def query_providers(client) -> tuple[list[dict], dict]:
    """Discover per-family exit addresses and query all 14 GeoIP providers concurrently."""
    discoveries = {f: asyncio.ensure_future(_exit_address(client, f)) for f in FAMILIES}
    cf_task: Optional[asyncio.Future] = None

    def start_cloudflare() -> asyncio.Future:
        nonlocal cf_task
        if cf_task is None:
            cf_task = asyncio.ensure_future(_safe_get(client, CLOUDFLARE_TRACE))
        return cf_task

    async def lookups(family: str) -> list[dict]:
        addr = await discoveries[family]
        if not addr:
            return []
        start_cloudflare()
        return list(await asyncio.gather(*(_ask(client, lk, family, addr) for lk in LOOKUPS)))

    async def cloudflare() -> list[dict]:
        found = await asyncio.gather(*discoveries.values())
        exits = {f: a for f, a in zip(discoveries, found) if a}
        return _cloudflare_reports(exits, await start_cloudflare()) if exits else []

    try:
        results = await asyncio.gather(lookups("ipv4"), lookups("ipv6"), cloudflare())
    finally:
        tasks = [*discoveries.values(), *([cf_task] if cf_task else [])]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    exits = {f: t.result() for f, t in discoveries.items() if t.result()}
    return [r for group in results for r in group], exits


async def probe_location(proxy: str, families: Iterable[str] = (), real_ip: Optional[str] = None,
                         timeout: float = PROBE_TIMEOUT, client=None) -> dict:
    """Collect GeoIP consensus through proxy (http://127.0.0.1:<port>)."""
    fam_list = [f for f in FAMILIES if f in tuple(families)]
    try:
        if client is not None:
            reports, exits = await asyncio.wait_for(query_providers(client), timeout)
        else:
            connector = aiohttp.TCPConnector(limit=REQUESTS_PER_NODE, ssl=_ssl_context())
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as session:
                reports, exits = await asyncio.wait_for(query_providers(ProxyClient(session, proxy)), timeout)
    except asyncio.TimeoutError:
        return empty_location("failed", "GeoIP providers did not answer in time", fam_list)
    if not exits:
        return empty_location("failed", "No exit address answered through the proxy", fam_list)
    return location_evidence(reports, exits, fam_list, real_ip)
