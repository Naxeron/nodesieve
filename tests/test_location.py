"""Location evidence: 14 GeoIP providers asked through the node and consensus scoring."""

import asyncio
import re
import unittest
import urllib.parse
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
import pytest

from nodesieve import location
from nodesieve.core.tester import NodeTester
from nodesieve.location import LOOKUPS, PROVIDERS, ProxyClient, empty_location, location_evidence, probe_location
from nodesieve.routing import main_policy_failure, normalize_routing

IPV4, IPV6 = "192.0.2.5", "2001:db8::5"
POLICY = normalize_routing()["main"]


def reports(v4=("DE", "DE", "DE", "US"), v6=()):
    return [
        {"provider": f"provider_{i}", "family": fam, "country": c, "reason": None if c else "timeout"}
        for fam, cs in (("ipv4", v4), ("ipv6", v6)) for i, c in enumerate(cs)
    ]


def evidence(v4=("DE", "DE", "DE", "US"), v6=(), exits=None, families=None, real_ip=None):
    exits = exits if exits is not None else {**({"ipv4": IPV4} if v4 else {}), **({"ipv6": IPV6} if v6 else {})}
    return location_evidence(reports(v4, v6), exits, families if families is not None else list(exits), real_ip)


def test_consensus_majority_ties_duplicates_families_and_leaks():
    res = evidence()
    assert (res["source"], res["country"], res["score"], res["votes"], res["total"], res["status"]) == (
        "geoip", "DE", 0.75, 3, 4, "ok")
    assert res["counts"] == {"DE": 3, "US": 1} and res["tested_families"] == ["ipv4"]
    assert IPV4 not in repr(res) and main_policy_failure(POLICY, res) is None

    assert (evidence(("DE", "US"))["country"], evidence(("DE", "US"))["status"]) == (None, "unknown")
    assert evidence(("DE", "DE", "DE", None, "XX", "T1", "de", "Germany"))["counts"] == {"DE": 3}

    doubled = reports(("DE", "DE", "DE")) + [
        {"provider": "provider_0", "family": "ipv4", "country": "DE"},
        {"provider": "Provider_1", "family": "ipv4", "country": "US"},
    ]
    assert location_evidence(doubled, {"ipv4": IPV4}, ["ipv4"])["counts"] == {"DE": 2}

    dual = evidence(("DE",) * 3, ("US",) * 3)
    assert (dual["families"]["ipv4"]["country"], dual["families"]["ipv6"]["country"], dual["country"]) == ("DE", "US", None)

    for ev in (evidence(("DE",) * 3, exits={"ipv4": IPV4}, families=["ipv4", "ipv6"]),
               evidence(("DE",) * 3, exits={"ipv4": IPV4, "ipv6": IPV6}, families=["ipv4"])):
        assert ev["tested_families"] == ["ipv4", "ipv6"] and "IPV6" in main_policy_failure(POLICY, ev)

    leak = evidence(real_ip=IPV4)
    assert leak["ip_leak"] and (leak["status"], leak["reason"]) == ("failed", "Proxy leaks real IP")
    assert main_policy_failure(POLICY, leak) == "Location probe detected an IP leak"
    assert main_policy_failure(POLICY, {**evidence(("DE",) * 3), "source": "ipregion"}) == "Location evidence missing"


ANSWERS = {
    "ipv4.icanhazip.com": IPV4 + "\n",
    "www.cloudflare.com/cdn-cgi/trace": f"fl=1\nip={IPV4}\nloc=DE\n",
    "rdap.db.ripe.net/ip/": '{"country": "DE"}',
    "ipinfo.io/widget/demo/": '{"data": {"country": "DE"}}',
    "api.ipregistry.co/": '{"location": {"country": {"code": "DE"}}}',
    "ipapi.co/": '{"country": "DE"}',
    "ifconfig.co/country-iso": "DE\n",
    "api.ip2location.io/?ip=": '{"country_code": "DE"}',
    "api.country.is/": '{"country": "DE"}',
    "api.geoapify.com/v1/ipinfo": '{"country": {"iso_code": "DE"}}',
    "get.geojs.io/": '[{"country": "DE"}]',
    "api.ipbase.com/": '{"data": {"location": {"country": {"alpha2": "DE"}}}}',
    "api.ipquery.io/": '{"location": {"country_code": "DE"}}',
    "ipwho.is/": '{"country_code": "DE"}',
    "demo.ip-api.com/": '{"countryCode": "DE"}',
}


class FakeNode:
    def __init__(self, **overrides):
        self.answers = {**ANSWERS, **overrides}
        self.requests = []

    async def request(self, method, url, headers=None, data=None):
        self.requests.append({"method": method, "url": url, "headers": headers or {}, "data": data})
        for key in sorted(self.answers, key=len, reverse=True):
            if key in url:
                ans = self.answers[key]
                if isinstance(ans, BaseException):
                    raise ans
                return ans(url) if callable(ans) else (ans if isinstance(ans, tuple) else (200, ans))
        raise aiohttp.ClientConnectionError("no such host")

    def urls(self, part):
        return [r["url"] for r in self.requests if part in r["url"]]


def probe(node, families=("ipv4",), **options):
    return asyncio.run(probe_location("http://127.0.0.1:1", families=families, client=node, **options))


def votes(node):
    reps, _ = asyncio.run(location.query_providers(node))
    res = {}
    for r in reps:
        res.setdefault(r["family"], {})[r["provider"]] = r["country"] or r["reason"]
    return res


def dual_stack(**answers):
    return FakeNode(**{"ipv6.icanhazip.com": IPV6 + "\n", **answers})


def test_all_14_providers_asked_once_per_family_and_make_consensus():
    assert len(LOOKUPS) == 13 and len(set(PROVIDERS)) == 14
    assert all(lk.url.startswith("https://") and "{ip}" in lk.url for lk in LOOKUPS)

    node = dual_stack()
    found = votes(node)
    assert set(found) == {"ipv4", "ipv6"}
    for fam in found:
        assert set(found[fam]) == set(PROVIDERS)
    assert (found["ipv4"]["Cloudflare"], found["ipv6"]["Cloudflare"]) == ("DE", "the node used its other family")
    assert len(node.urls("www.cloudflare.com")) == 1
    assert node.urls("v6.ipinfo.io") == [f"https://v6.ipinfo.io/widget/demo/{IPV6}"]
    assert f"https://ipwho.is/{IPV6}" in node.urls("ipwho.is")
    assert next(r for r in node.requests if "ipapi.co" in r["url"])["headers"] == {"Referer": "https://ipapi.co/"}
    assert next(r for r in node.requests if "ip-api.com" in r["url"])["headers"] == {"Origin": "https://ip-api.com"}

    result = probe(dual_stack(), families=("ipv4", "ipv6"))
    assert (result["country"], result["votes"], result["total"]) == ("DE", 27, 27)
    assert {f: v["total"] for f, v in result["families"].items()} == {"ipv4": 14, "ipv6": 13}
    assert main_policy_failure(POLICY, result) is None


def test_identity_fallback_required_families_and_cloudflare_family_rules():
    node = FakeNode(**{"ipv4.icanhazip.com": (500, ""), "api.ipify.org": "2001:db8::99",
                       "ipv4.seeip.org": "192.0.2.77\n", "ipv6.icanhazip.com": "2001:db8::7\n",
                       "api6.ipify.org": "192.0.2.99", "ipv6.wtfismyip.com": aiohttp.ClientConnectionError()})
    _, exits = asyncio.run(location.query_providers(node))
    assert exits == {"ipv4": "192.0.2.77", "ipv6": "2001:db8::7"}

    res = probe(FakeNode(), families=("ipv4", "ipv6"))
    assert res["tested_families"] == ["ipv4", "ipv6"] and main_policy_failure(POLICY, res).startswith("IPV6:")

    assert votes(FakeNode(**{"www.cloudflare.com/cdn-cgi/trace": "ip=203.0.113.9\nloc=NL\n"}))["ipv4"]["Cloudflare"] == "NL"
    over_v6 = votes(dual_stack(**{"www.cloudflare.com/cdn-cgi/trace": f"ip={IPV6}\nloc=NL\n"}))
    assert (over_v6["ipv4"]["Cloudflare"], over_v6["ipv6"]["Cloudflare"]) == ("the node used its other family", "NL")
    assert votes(FakeNode(**{"www.cloudflare.com/cdn-cgi/trace": (429, "")}))["ipv4"]["Cloudflare"] == "rate limited (429)"


@pytest.mark.parametrize("answer,reason", [
    ((403, '{"country": "DE"}'), "forbidden (403)"),
    ((429, ""), "rate limited (429)"),
    ((503, ""), "server error (503)"),
    (asyncio.TimeoutError(), "timeout"),
    (aiohttp.ClientConnectionError(), "connection failed"),
    (aiohttp.ClientSSLError(MagicMock(), OSError()), "TLS failed"),
    ((200, "<html>"), "unexpected response (200)"),
    ((200, '{"country_code": "Germany"}'), "unexpected response (200)"),
    ((404, '{"country": null}'), "unexpected response (404)"),
])
def test_an_answer_without_a_country_is_no_vote(answer, reason):
    assert votes(FakeNode(**{"ipwho.is/": answer}))["ipv4"]["ipwho.is"] == reason


def test_dead_node_skips_cloudflare_and_slow_ipv6_does_not_block_cloudflare():
    dead = FakeNode(**{"ipv4.icanhazip.com": (502, "")})
    res = probe(dead, families=())
    assert (res["status"], res["reason"], res["tested_families"]) == ("failed", "No exit address answered through the proxy", [])
    assert dead.urls("www.cloudflare.com") == []

    events, release_v6 = [], asyncio.Event()

    class SlowV6Node(FakeNode):
        async def request(self, method, url, headers=None, data=None):
            if any(h in url for h in ("ipv6.", "api6.")):
                await release_v6.wait()
                raise aiohttp.ClientConnectionError("no ipv6")
            if "www.cloudflare.com" in url:
                events.append("cloudflare")
                release_v6.set()
            return await super().request(method, url, headers=headers, data=data)

    reps, exits = asyncio.run(asyncio.wait_for(location.query_providers(SlowV6Node()), timeout=2.0))
    assert exits == {"ipv4": IPV4} and events == ["cloudflare"]
    assert any(r["provider"] == "Cloudflare" and r["country"] == "DE" for r in reps)

    class Stalling(FakeNode):
        async def request(self, method, url, headers=None, data=None):
            await asyncio.sleep(10)

    timed = probe(Stalling(), timeout=0.05)
    assert (timed["status"], timed["reason"], timed["tested_families"]) == ("failed", "GeoIP providers did not answer in time", ["ipv4"])


def test_proxy_client_routes_through_proxy_and_times_out(monkeypatch):
    seen = []

    async def proxy(request):
        seen.append((request.method, str(request.url), request.headers.get("User-Agent")))
        if request.path == "/slow":
            await asyncio.sleep(1)
        return web.Response(text="DE")

    async def run():
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", proxy)
        async with TestServer(app) as server:
            async with aiohttp.ClientSession(headers={"User-Agent": location.USER_AGENT}) as session:
                client = ProxyClient(session, f"http://127.0.0.1:{server.port}")
                ans = await client.request("GET", "http://provider.invalid/lookup?ip=192.0.2.5")
                monkeypatch.setattr(location, "REQUEST_TIMEOUT", 0.2)
                with pytest.raises(asyncio.TimeoutError):
                    await client.request("GET", "http://provider.invalid/slow")
                return ans

    assert asyncio.run(run()) == (200, "DE")
    assert seen[0] == ("GET", "http://provider.invalid/lookup?ip=192.0.2.5", location.USER_AGENT)


class TestMainLocationIntegration(unittest.IsolatedAsyncioTestCase):
    async def _run(self, loc_ev, trace=(None, None, float("inf"))):
        tester = NodeTester({"routing": {"enabled": True}}, real_ip="198.51.100.1")
        node = "vless://abc@192.0.2.1:443?encryption=foo#original"
        runner = MagicMock(proxy_url="http://127.0.0.1:23456", port=23456, ensure_alive=AsyncMock())
        with patch("nodesieve.core.tester.CoreRunner") as runner_cls, \
                patch("nodesieve.core.tester.aiohttp.ClientSession") as session_cls, \
                patch("nodesieve.core.tester.aiohttp.TCPConnector") as conn_cls, \
                patch.object(tester, "_fetch_ip", new=AsyncMock(return_value=trace)), \
                patch.object(tester, "fetch_location", new=AsyncMock(return_value=loc_ev)) as loc_probe, \
                patch("nodesieve.core.tester.GeolocationService.get_country_name", new=AsyncMock(return_value="Germany")):
            runner_cls.return_value.__aenter__ = AsyncMock(return_value=runner)
            runner_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            session_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await tester.test_node_full(1, node)
        conn_cls.assert_called_once_with(ssl=True, limit=10)
        return result, tester.node_metadata[node], loc_probe

    async def test_qualifies_and_renames_with_consensus(self):
        found = evidence()
        result, meta, probe_ = await self._run(found)
        self.assertIsNotNone(result)
        self.assertEqual((meta["country_code"], meta["location"]), ("DE", found))
        probe_.assert_awaited_once_with(23456, None, None)

        result, meta, _ = await self._run(found, trace=("192.0.2.5", "US", 10))
        survivor, latency, tested = result
        self.assertEqual((latency, tested), (10, "vless://abc@192.0.2.1:443?encryption=none#original"))
        self.assertEqual(urllib.parse.unquote(survivor.split("#", 1)[1]),
                         "[VLESS: original] 🇩🇪 Germany | 192.0.2.5 | Location DE 75% (3/4 votes)")

    async def test_drops_excluded_weak_tied_failed_or_leaking_nodes(self):
        cases = [
            (evidence(("RU",) * 3), "Location country excluded: RU"),
            (evidence(("DE", "DE")), "Too few location reports"),
            (evidence(("DE", "FI")), "tied"),
            (empty_location("failed", "GeoIP providers did not answer in time", ("ipv4",)),
             "Location probe failed: GeoIP providers did not answer in time"),
            (evidence(real_ip=IPV4), "Proxy leaks real IP"),
        ]
        for ev, expected in cases:
            result, meta, _ = await self._run(ev, trace=("192.0.2.5", "DE", 10))
            self.assertIsNone(result)
            self.assertIn(expected, meta["reason"])

    async def test_fetch_location_asks_through_nodes_listener(self):
        tester = NodeTester({}, real_ip="198.51.100.1")
        with patch("nodesieve.core.tester.probe_location", new=AsyncMock(return_value=evidence())) as probe_:
            await tester.fetch_location(23456, "192.0.2.5", None)
        probe_.assert_awaited_once_with("http://127.0.0.1:23456", families=["ipv4"], real_ip="198.51.100.1")


def test_no_subprocess_is_started_for_location():
    source = open(location.__file__, encoding="utf-8").read()
    assert not re.search(r"\bsubprocess\b|create_subprocess|os\.system|Popen", source)
