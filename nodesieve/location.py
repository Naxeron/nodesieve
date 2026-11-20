"""Country consensus from GeoIP providers, asked through a node's proxy.

Each provider names the country it places the node's exit address in, for IPv4 and IPv6
separately. Every provider counts once per family, and the consensus is the country
most of them name; routing.py decides what qualifies.

The providers, and how each is asked, are those of the "geoip" group of ipregion
(https://github.com/vernette/ipregion, MIT License, see THIRD_PARTY_NOTICES.md), which
nodesieve ran as a bash script before:

- Every request goes through the node, which resolves the provider's name, so each
  provider sees the node's exit address and applies its rate limits to it.
- The exit address of each family is what identity services, on hosts with one family
  each, see a request come from. Most providers then look up that address, given in the
  URL. Cloudflare reports the address a request comes from and its country; its country
  counts in a family unless the node reached it through the other family's address.
- Some nodes leave through different addresses for different destinations: their
  provider sends some traffic out directly from the server, the rest abroad. The
  address identity services see then decides, as it did with ipregion, even where the
  Cloudflare trace of the IP check saw another one.
- A request may take REQUEST_TIMEOUT seconds. A 403, 429 or 5xx answer, a request that
  fails, or an answer without a two-letter country is not a vote.
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import ipaddress
import json
import re
from typing import Iterable, Optional

import aiohttp


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
# The evidence's "source", which routing.py requires.
SOURCE = "geoip"
# Seconds each request may take through the node, its TLS handshakes included; ipregion's
# default. With two, good nodes failed on mobile data, where the first requests through a
# freshly started node often take longer.
REQUEST_TIMEOUT = 5
# A probe's requests take at most three of those in a row (MaxMind's); this only bounds a
# node that stalls connections in a way no single request's timeout catches.
PROBE_TIMEOUT = 60
# Requests in flight through one node, as ipregion ran its parallel jobs.
REQUESTS_PER_NODE = 16
# The client ipregion's requests named; some providers answer other clients differently.
USER_AGENT = "curl/8.11.1"


@dataclass(frozen=True)
class Lookup:
    """A provider asked for the country of the address in its URL ({ip})."""
    name: str
    url: str
    # Keys and list indexes that lead to the country in the JSON answer; None when the
    # answer is the country code itself.
    path: Optional[tuple] = None
    headers: dict = field(default_factory=dict)
    # A separate URL for IPv6 addresses, on a host that has only an IPv6 address.
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
# The rest take more than one request: see _maxmind, _ip2location and _cloudflare.
PROVIDERS = ("MaxMind", "Cloudflare", "ip2location.com", *(lookup.name for lookup in LOOKUPS))

MAXMIND_PAGE = "https://www.maxmind.com/en/geoip-web-services-demo"
MAXMIND_TOKEN = "https://www.maxmind.com/en/geoip2/demo/token"
MAXMIND_CITY = "https://geoip.maxmind.com/geoip/v2.1/city/{ip}?demo=1"
_MAXMIND_CSRF = re.compile(r'value="([0-9a-f]+)" name="csrf_token"')
IP2LOCATION_PAGE = "https://www.ip2location.com"
IP2LOCATION_QUERY = "https://api.ip2location.io/query/"
_IP2LOCATION_TOKEN = re.compile(r"(?:^|\n)\s*t: ([0-9]+),\s*token: '([0-9a-f]+)'")
CLOUDFLARE_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
# Services that report the address a request comes from, on hosts with one family each.
IDENTITY_URLS = {
    "ipv4": ("https://ipv4.icanhazip.com", "https://api.ipify.org", "https://ipv4.seeip.org",
             "https://ipv4.wtfismyip.com/text"),
    "ipv6": ("https://ipv6.icanhazip.com", "https://api6.ipify.org", "https://ipv6.seeip.org",
             "https://ipv6.wtfismyip.com/text"),
}
_COUNTRY_CODE = re.compile(r"[A-Z]{2}")


def _consensus(counts):
    counts = dict(sorted(counts.items()))
    total = sum(counts.values())
    votes = max(counts.values(), default=0)
    winners = [country for country, count in counts.items() if count == votes]
    return {"country": winners[0] if len(winners) == 1 else None,
            "score": votes / total if total else 0.0,
            "votes": votes, "total": total, "counts": counts}


def empty_location(status="unknown", reason=None, families=()):
    evidence = {"source": SOURCE, **_consensus({}),
                "families": {family: _consensus({}) for family in families},
                "tested_families": list(families), "status": status, "ip_leak": False}
    if reason:
        evidence["reason"] = reason
    return evidence


def _address(value: object, family: str) -> Optional[str]:
    """value as an address of this family, written the standard way, or None."""
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(address) if address.version == (4 if family == "ipv4" else 6) else None


def location_evidence(reports: Iterable[dict], exits: Optional[dict] = None, families: Iterable[str] = (),
                      real_ip: Optional[str] = None) -> dict:
    """The consensus of the providers' reports ({"provider", "family", "country", "reason"}).

    Each provider counts once per family, and not at all in a family it named two
    countries for. ``families`` need a consensus even when no provider answered for them,
    as does every family with an exit address or a vote. Exit addresses are only
    compared with this computer's own address, to find a leak, and are left out of the
    result.
    """
    exits = exits or {}
    discovered = {family for family in families if family in FAMILIES}
    discovered |= {family for family, address in exits.items() if family in FAMILIES and address}
    observations = {family: defaultdict(set) for family in FAMILIES}
    for report in reports:
        family, provider, country = report.get("family"), report.get("provider"), report.get("country")
        if family in FAMILIES and isinstance(provider, str) and provider.strip() and country in COUNTRIES:
            discovered.add(family)
            observations[family][provider.strip().casefold()].add(country)
    evidence = empty_location(families=FAMILIES)
    aggregate = Counter()
    for family, providers in observations.items():
        counts = Counter(next(iter(values)) for values in providers.values() if len(values) == 1)
        evidence["families"][family] = _consensus(counts)
        aggregate.update(counts)
    evidence["tested_families"] = [family for family in FAMILIES if family in discovered]
    evidence.update(_consensus(aggregate))
    evidence["status"] = "ok" if evidence["country"] else "unknown"
    own = _address(real_ip, "ipv4") or _address(real_ip, "ipv6")
    if own is not None and own in {_address(address, family) for family, address in exits.items()}:
        evidence["ip_leak"] = True
        evidence["status"] = "failed"
        evidence["reason"] = "Proxy leaks real IP"
    return evidence


class ProxyClient:
    """The requests of one probe, all through the node's proxy, REQUESTS_PER_NODE at a time."""

    def __init__(self, session: aiohttp.ClientSession, proxy: str):
        self.session = session
        self.proxy = proxy
        self.slots = asyncio.Semaphore(REQUESTS_PER_NODE)

    async def request(self, method: str, url: str, headers: Optional[dict] = None,
                      data: Optional[dict] = None) -> tuple[int, str]:
        async with self.slots:
            async with self.session.request(method, url, proxy=self.proxy, headers=headers, data=data,
                                            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as response:
                return response.status, await response.text(errors="replace")


def _report(provider: str, family: str, country: Optional[str] = None, reason: Optional[str] = None) -> dict:
    return {"provider": provider, "family": family, "country": country, "reason": reason}


def _failure(exc: BaseException) -> str:
    """Why a request failed, for an exception the request may raise."""
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, aiohttp.ClientSSLError):
        return "TLS failed"
    return "connection failed"


# What a request can fail with (LookupError: an answer in an unknown character set);
# anything else is a bug to surface, not a missing vote.
_REQUEST_ERRORS = (asyncio.TimeoutError, aiohttp.ClientError, OSError, ValueError, LookupError)


def _http_failure(status: int) -> Optional[str]:
    if status == 403:
        return "forbidden (403)"
    if status == 429:
        return "rate limited (429)"
    if 500 <= status <= 599:
        return f"server error ({status})"
    return None


def _verdict(status: int, body: str, path: Optional[tuple]) -> tuple[Optional[str], Optional[str]]:
    """(country, None) from an answer that names one, or (None, why not)."""
    failure = _http_failure(status)
    if failure:
        return None, failure
    if path is None:
        value: object = body
    else:
        try:
            value = json.loads(body)
            for key in path:
                value = value[key]
        except (ValueError, KeyError, IndexError, TypeError):
            value = None
    if isinstance(value, str) and _COUNTRY_CODE.fullmatch(value.strip()):
        return value.strip(), None
    return None, f"unexpected response ({status})"


async def _ask(client, lookup: Lookup, family: str, ip: str) -> dict:
    url = (lookup.ipv6_url if family == "ipv6" and lookup.ipv6_url else lookup.url).format(ip=ip)
    try:
        status, body = await client.request("GET", url, headers=lookup.headers or None)
    except _REQUEST_ERRORS as exc:
        return _report(lookup.name, family, reason=_failure(exc))
    return _report(lookup.name, family, *_verdict(status, body, lookup.path))


async def _maxmind_token(client) -> tuple[Optional[str], Optional[str]]:
    """MaxMind's demo token, fetched as its demo page does: (token, None) or (None, why not)."""
    try:
        status, page = await client.request("GET", MAXMIND_PAGE)
        match = _MAXMIND_CSRF.search(page)
        if not match:
            return None, _http_failure(status) or f"unexpected response ({status})"
        status, body = await client.request("POST", MAXMIND_TOKEN, headers={"X-CSRF-Token": match.group(1)})
    except _REQUEST_ERRORS as exc:
        return None, _failure(exc)
    if status != 201:
        return None, _http_failure(status) or f"unexpected response ({status})"
    try:
        token = json.loads(body).get("token")
    except (ValueError, AttributeError):
        token = None
    return (token, None) if isinstance(token, str) and token else (None, "unexpected response (201)")


async def _maxmind(client, token: asyncio.Future, family: str, ip: str) -> dict:
    value, reason = await token
    if not value:
        return _report("MaxMind", family, reason=reason)
    try:
        status, body = await client.request("GET", MAXMIND_CITY.format(ip=ip),
                                            headers={"Authorization": f"Bearer {value}"})
    except _REQUEST_ERRORS as exc:
        return _report("MaxMind", family, reason=_failure(exc))
    if status == 402:
        return _report("MaxMind", family, reason="daily limit (402)")
    return _report("MaxMind", family, *_verdict(status, body, ("country", "iso_code")))


async def _ip2location_token(client) -> tuple[Optional[tuple[str, str]], Optional[str]]:
    """The timestamp and token ip2location.com's page queries with, or (None, why not)."""
    try:
        status, page = await client.request("GET", IP2LOCATION_PAGE)
    except _REQUEST_ERRORS as exc:
        return None, _failure(exc)
    match = _IP2LOCATION_TOKEN.search(page)
    if not match:
        return None, _http_failure(status) or f"unexpected response ({status})"
    return (match.group(1), match.group(2)), None


async def _ip2location(client, token: asyncio.Future, family: str, ip: str) -> dict:
    found, reason = await token
    if not found:
        return _report("ip2location.com", family, reason=reason)
    timestamp, value = found
    try:
        status, body = await client.request("POST", IP2LOCATION_QUERY, data={"ip": ip, "t": timestamp, "token": value})
    except _REQUEST_ERRORS as exc:
        return _report("ip2location.com", family, reason=_failure(exc))
    return _report("ip2location.com", family, *_verdict(status, body, ("countryCode",)))


async def _cloudflare(client, exits: dict) -> list[dict]:
    """Cloudflare's vote in each family with an exit address, from one trace through the node.

    The node picks the family it reaches Cloudflare in. The country counts in every
    family except one whose exit Cloudflare did not see while it saw the other family's,
    as ipregion counts it: a node leaving through another address for Cloudflare still
    gets Cloudflare's vote.
    """
    if not exits:
        return []
    try:
        status, body = await client.request("GET", CLOUDFLARE_TRACE)
    except _REQUEST_ERRORS as exc:
        return [_report("Cloudflare", family, reason=_failure(exc)) for family in exits]
    seen = re.search(r"(?:^|\n)ip=([^\n]+)", body)
    seen_address = seen.group(1).strip() if seen else ""
    country = re.search(r"(?:^|\n)loc=([^\n]*)", body)
    reports = []
    for family, address in exits.items():
        other = exits.get("ipv6" if family == "ipv4" else "ipv4")
        if other and _address(seen_address, "ipv6" if family == "ipv4" else "ipv4") == other:
            reports.append(_report("Cloudflare", family, reason="the node used its other family"))
        else:
            reports.append(_report("Cloudflare", family, *_verdict(status, country.group(1) if country else "", None)))
    return reports


async def _exit_address(client, family: str) -> Optional[str]:
    """The node's exit address in this family, from the first identity service to name one."""
    async def ask(url):
        try:
            status, body = await client.request("GET", url)
        except _REQUEST_ERRORS:
            return None
        return _address(body, family) if status == 200 else None

    tasks = [asyncio.ensure_future(ask(url)) for url in IDENTITY_URLS[family]]
    try:
        for answer in asyncio.as_completed(tasks):
            address = await answer
            if address:
                return address
        return None
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def query_providers(client) -> tuple[list[dict], dict]:
    """Every provider's report for each family the node has an exit address in, and those addresses.

    A family's lookups start as soon as its address is known; MaxMind's and
    ip2location.com's tokens are fetched once, meanwhile, for both.
    """
    discoveries = {family: asyncio.ensure_future(_exit_address(client, family)) for family in FAMILIES}
    maxmind_token = asyncio.ensure_future(_maxmind_token(client))
    ip2location_token = asyncio.ensure_future(_ip2location_token(client))

    async def lookups(family):
        address = await discoveries[family]
        if not address:
            return []
        return await asyncio.gather(
            _maxmind(client, maxmind_token, family, address),
            _ip2location(client, ip2location_token, family, address),
            *(_ask(client, lookup, family, address) for lookup in LOOKUPS),
        )

    async def cloudflare():
        found = await asyncio.gather(*discoveries.values())
        return await _cloudflare(client, {family: address for family, address in zip(discoveries, found) if address})

    tasks = [*discoveries.values(), maxmind_token, ip2location_token]
    try:
        results = await asyncio.gather(lookups("ipv4"), lookups("ipv6"), cloudflare())
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    exits = {family: task.result() for family, task in discoveries.items() if task.result()}
    return [report for result in results for report in result], exits


async def probe_location(proxy: str, families: Iterable[str] = (), real_ip: Optional[str] = None,
                         timeout: float = PROBE_TIMEOUT, client=None) -> dict:
    """GeoIP evidence for the node behind ``proxy`` (http://127.0.0.1:<port>); the caller limits concurrency.

    ``families`` are the ones the IP check found the node reachable in: they need a
    consensus even when no identity service answers in them here. ``client`` stands in
    for the requests in tests.
    """
    families = [family for family in FAMILIES if family in tuple(families)]
    try:
        if client is not None:
            reports, exits = await asyncio.wait_for(query_providers(client), timeout)
        else:
            connector = aiohttp.TCPConnector(limit=REQUESTS_PER_NODE)
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as session:
                reports, exits = await asyncio.wait_for(query_providers(ProxyClient(session, proxy)), timeout)
    except asyncio.TimeoutError:
        return empty_location("failed", "GeoIP providers did not answer in time", families)
    if not exits:
        return empty_location("failed", "No exit address answered through the proxy", families)
    return location_evidence(reports, exits, families, real_ip)
