"""Location evidence: GeoIP providers asked through the node, and the consensus of their answers."""

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
from nodesieve.location import (
    LOOKUPS,
    PROVIDERS,
    ProxyClient,
    empty_location,
    location_evidence,
    probe_location,
)
from nodesieve.routing import main_policy_failure, normalize_routing

IPV4, IPV6 = "192.0.2.5", "2001:db8::5"
POLICY = normalize_routing()["main"]


def reports(v4=("DE", "DE", "DE", "US"), v6=()):
    """One report per provider and family, as query_providers gives them; None: a failed lookup."""
    result = []
    for family, countries in (("ipv4", v4), ("ipv6", v6)):
        for index, country in enumerate(countries):
            result.append({"provider": f"provider_{index}", "family": family, "country": country,
                           "reason": None if country else "timeout"})
    return result


def evidence(v4=("DE", "DE", "DE", "US"), v6=(), exits=None, families=None, real_ip=None):
    exits = exits if exits is not None else {**({"ipv4": IPV4} if v4 else {}), **({"ipv6": IPV6} if v6 else {})}
    return location_evidence(reports(v4, v6), exits, families if families is not None else list(exits), real_ip)


# The consensus

class TestLocationConsensus(unittest.TestCase):
    def test_majority_and_private_summary(self):
        result = evidence()
        self.assertEqual((result["source"], result["country"], result["score"], result["votes"], result["total"]),
                         ("geoip", "DE", .75, 3, 4))
        self.assertEqual(result["counts"], {"DE": 3, "US": 1})
        self.assertEqual(result["tested_families"], ["ipv4"])
        self.assertEqual(result["status"], "ok")
        self.assertNotIn(IPV4, repr(result))
        self.assertIsNone(main_policy_failure(POLICY, result))

    def test_ties_are_unknown(self):
        result = evidence(("DE", "US"))
        self.assertIsNone(result["country"])
        self.assertEqual(result["status"], "unknown")

    def test_failed_lookups_and_non_countries_do_not_vote(self):
        result = evidence(("DE", "DE", "DE", None, "XX", "T1", "de", "Germany"))
        self.assertEqual(result["counts"], {"DE": 3})

    def test_duplicates_count_once_and_conflicting_duplicates_are_excluded(self):
        doubled = reports(("DE", "DE", "DE")) + [
            {"provider": "provider_0", "family": "ipv4", "country": "DE"},
            {"provider": "Provider_1", "family": "ipv4", "country": "US"},
        ]
        result = location_evidence(doubled, {"ipv4": IPV4}, ["ipv4"])
        self.assertEqual(result["counts"], {"DE": 2})

    def test_each_family_remains_independent(self):
        result = evidence(("DE",) * 3, ("US",) * 3)
        self.assertEqual(result["families"]["ipv4"]["country"], "DE")
        self.assertEqual(result["families"]["ipv6"]["country"], "US")
        self.assertIsNone(result["country"])

    def test_a_family_the_trace_found_cannot_be_hidden(self):
        result = evidence(("DE",) * 3, exits={"ipv4": IPV4}, families=["ipv4", "ipv6"])
        self.assertEqual(result["tested_families"], ["ipv4", "ipv6"])
        self.assertIn("IPV6", main_policy_failure(POLICY, result))

    def test_a_discovered_family_without_votes_is_still_required(self):
        result = evidence(("DE",) * 3, exits={"ipv4": IPV4, "ipv6": IPV6}, families=["ipv4"])
        self.assertEqual(result["tested_families"], ["ipv4", "ipv6"])
        self.assertIn("IPV6", main_policy_failure(POLICY, result))

    def test_an_exit_at_this_computers_address_is_a_leak(self):
        result = evidence(real_ip="192.0.2.5")
        self.assertTrue(result["ip_leak"])
        self.assertEqual((result["status"], result["reason"]), ("failed", "Proxy leaks real IP"))
        self.assertEqual(main_policy_failure(POLICY, result), "Location probe detected an IP leak")

    def test_evidence_from_elsewhere_does_not_qualify(self):
        result = {**evidence(("DE",) * 3), "source": "ipregion"}
        self.assertEqual(main_policy_failure(POLICY, result), "Location evidence missing")


# Asking the providers

ANSWERS = {
    # The node's IPv4 exit; it has no IPv6 unless a test answers for ipv6.icanhazip.com.
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
    "www.maxmind.com/en/geoip-web-services-demo": '<input type="hidden" value="c0ffee" name="csrf_token">',
    "www.maxmind.com/en/geoip2/demo/token": (201, '{"token": "demo-token"}'),
    "geoip.maxmind.com/geoip/v2.1/city/": '{"country": {"iso_code": "DE"}}',
    "www.ip2location.com": "<script>\n  t: 1700000000,\n  token: 'beef42'\n</script>",
    "api.ip2location.io/query/": '{"countryCode": "DE"}',
}


class FakeNode:
    """Stands in for the requests through a node: answers by URL, records every request."""

    def __init__(self, **overrides):
        self.answers = {**ANSWERS, **overrides}
        self.requests = []

    async def request(self, method, url, headers=None, data=None):
        self.requests.append({"method": method, "url": url, "headers": headers or {}, "data": data})
        for key in sorted(self.answers, key=len, reverse=True):
            if key in url:
                answer = self.answers[key]
                if isinstance(answer, BaseException):
                    raise answer
                if callable(answer):
                    return answer(url)
                return answer if isinstance(answer, tuple) else (200, answer)
        raise aiohttp.ClientConnectionError("no such host")

    def urls(self, part):
        return [request["url"] for request in self.requests if part in request["url"]]


def probe(node, families=("ipv4",), **options):
    return asyncio.run(probe_location("http://127.0.0.1:1", families=families, client=node, **options))


def votes(node):
    """What each provider reported, per family: its country, or why it has none."""
    reports, _ = asyncio.run(location.query_providers(node))
    result = {}
    for report in reports:
        result.setdefault(report["family"], {})[report["provider"]] = report["country"] or report["reason"]
    return result


def dual_stack(**answers):
    return FakeNode(**{"ipv6.icanhazip.com": IPV6 + "\n", **answers})


def test_every_provider_is_asked_once_per_family_about_the_address_identity_services_see():
    node = dual_stack()
    found = votes(node)
    assert set(found) == {"ipv4", "ipv6"}
    for family in found:
        assert set(found[family]) == set(PROVIDERS) and len(PROVIDERS) == 16
    # The node reached Cloudflare over IPv4, so it counts there only.
    assert (found["ipv4"]["Cloudflare"], found["ipv6"]["Cloudflare"]) == ("DE", "the node used its other family")
    assert len(node.urls("www.cloudflare.com")) == 1
    # Lookups name the exit address; ipinfo.io has a host of its own for IPv6.
    assert node.urls("v6.ipinfo.io") == [f"https://v6.ipinfo.io/widget/demo/{IPV6}"]
    assert f"https://ipwho.is/{IPV6}" in node.urls("ipwho.is")
    # MaxMind's and ip2location.com's tokens are fetched once and used by both families.
    assert len(node.urls("geoip-web-services-demo")) == len(node.urls("demo/token")) == 1
    assert len(node.urls("www.ip2location.com")) == 1
    cities = [request for request in node.requests if "geoip.maxmind.com" in request["url"]]
    assert {request["headers"]["Authorization"] for request in cities} == {"Bearer demo-token"}
    token_request = next(request for request in node.requests if "demo/token" in request["url"])
    assert token_request["method"] == "POST" and token_request["headers"] == {"X-CSRF-Token": "c0ffee"}
    queries = [request for request in node.requests if "ip2location.io/query" in request["url"]]
    assert sorted(request["data"]["ip"] for request in queries) == sorted([IPV4, IPV6])
    assert {(request["method"], request["data"]["t"], request["data"]["token"]) for request in queries} == {
        ("POST", "1700000000", "beef42")}
    assert next(r for r in node.requests if "ipapi.co" in r["url"])["headers"] == {"Referer": "https://ipapi.co/"}
    assert next(r for r in node.requests if "ip-api.com" in r["url"])["headers"] == {"Origin": "https://ip-api.com"}


def test_all_answers_make_one_consensus_per_family():
    result = probe(dual_stack(), families=("ipv4", "ipv6"))
    assert (result["country"], result["votes"], result["total"]) == ("DE", 31, 31)
    assert {family: values["total"] for family, values in result["families"].items()} == {"ipv4": 16, "ipv6": 15}
    assert main_policy_failure(POLICY, result) is None


def test_the_first_identity_service_to_name_an_address_of_the_family_decides():
    node = FakeNode(**{"ipv4.icanhazip.com": (500, ""), "api.ipify.org": "2001:db8::99",
                       "ipv4.seeip.org": "192.0.2.77\n", "ipv6.icanhazip.com": "2001:db8::7\n",
                       "api6.ipify.org": "192.0.2.99", "ipv6.wtfismyip.com": aiohttp.ClientConnectionError()})
    _, exits = asyncio.run(location.query_providers(node))
    assert exits == {"ipv4": "192.0.2.77", "ipv6": "2001:db8::7"}
    assert "https://ipwho.is/2001:db8::7" in node.urls("ipwho.is")


def test_a_family_the_ip_check_found_stays_required_without_an_identity_answer():
    result = probe(FakeNode(), families=("ipv4", "ipv6"))
    assert result["tested_families"] == ["ipv4", "ipv6"]
    assert main_policy_failure(POLICY, result).startswith("IPV6:")


def test_cloudflare_counts_unless_the_node_reached_it_through_the_other_family():
    # A node that leaves through another address for Cloudflare still gets its vote,
    # as with ipregion: only an address of the other family rules it out.
    elsewhere = FakeNode(**{"www.cloudflare.com/cdn-cgi/trace": "ip=203.0.113.9\nloc=NL\n"})
    assert votes(elsewhere)["ipv4"]["Cloudflare"] == "NL"
    over_ipv6 = dual_stack(**{"www.cloudflare.com/cdn-cgi/trace": f"ip={IPV6}\nloc=NL\n"})
    found = votes(over_ipv6)
    assert (found["ipv4"]["Cloudflare"], found["ipv6"]["Cloudflare"]) == ("the node used its other family", "NL")
    failing = FakeNode(**{"www.cloudflare.com/cdn-cgi/trace": (429, "")})
    assert votes(failing)["ipv4"]["Cloudflare"] == "rate limited (429)"


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


def test_maxmind_without_a_token_or_over_its_limit_is_no_vote():
    no_token = FakeNode(**{"www.maxmind.com/en/geoip-web-services-demo": "<html>no form</html>"})
    assert votes(no_token)["ipv4"]["MaxMind"] == "unexpected response (200)"
    assert no_token.urls("geoip.maxmind.com") == []
    limited = FakeNode(**{"geoip.maxmind.com/geoip/v2.1/city/": (402, "")})
    assert votes(limited)["ipv4"]["MaxMind"] == "daily limit (402)"
    refused = FakeNode(**{"www.maxmind.com/en/geoip2/demo/token": (403, "")})
    assert votes(refused)["ipv4"]["MaxMind"] == "forbidden (403)"


def test_ip2location_without_its_token_is_no_vote():
    node = FakeNode(**{"www.ip2location.com": "<html></html>"})
    assert votes(node)["ipv4"]["ip2location.com"] == "unexpected response (200)"
    assert node.urls("ip2location.io/query") == []


def test_a_node_without_any_exit_address_fails():
    result = probe(FakeNode(**{"ipv4.icanhazip.com": (502, "")}), families=())
    assert (result["status"], result["reason"]) == ("failed", "No exit address answered through the proxy")
    assert result["tested_families"] == []


def test_a_probe_that_stalls_fails_in_time():
    class Stalling(FakeNode):
        async def request(self, method, url, headers=None, data=None):
            await asyncio.sleep(10)

    result = probe(Stalling(), timeout=0.05)
    assert (result["status"], result["reason"]) == ("failed", "GeoIP providers did not answer in time")
    assert result["tested_families"] == ["ipv4"]


def test_providers_match_ipregions_geoip_group():
    assert len(LOOKUPS) == 13 and len(set(PROVIDERS)) == 16
    assert all(lookup.url.startswith("https://") and "{ip}" in lookup.url for lookup in LOOKUPS)


# The requests themselves

def test_requests_go_through_the_proxy_and_time_out(monkeypatch):
    seen = []

    async def proxy(request):
        # A proxy gets the whole URL; this one answers by itself.
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
                answer = await client.request("GET", "http://provider.invalid/lookup?ip=192.0.2.5")
                monkeypatch.setattr(location, "REQUEST_TIMEOUT", 0.2)
                with pytest.raises(asyncio.TimeoutError):
                    await client.request("GET", "http://provider.invalid/slow")
                return answer

    assert asyncio.run(run()) == (200, "DE")
    assert seen[0] == ("GET", "http://provider.invalid/lookup?ip=192.0.2.5", location.USER_AGENT)


# The IP check

class TestMainLocationIntegration(unittest.IsolatedAsyncioTestCase):
    async def _run(self, location_evidence_, trace=(None, None, float("inf"))):
        tester = NodeTester({"routing": {"enabled": True}}, real_ip="198.51.100.1")
        node = "vless://abc@192.0.2.1:443?encryption=foo#original"
        runner = MagicMock(proxy_url="http://127.0.0.1:23456", port=23456, ensure_alive=AsyncMock())
        with patch("nodesieve.core.tester.MihomoRunner") as runner_cls, \
                patch("nodesieve.core.tester.aiohttp.ClientSession") as session_cls, \
                patch("nodesieve.core.tester.aiohttp.TCPConnector") as connector_cls, \
                patch.object(tester, "_fetch_ip", new=AsyncMock(return_value=trace)), \
                patch.object(tester, "fetch_location", new=AsyncMock(return_value=location_evidence_)) as location_probe, \
                patch("nodesieve.core.tester.GeolocationService.get_country_name", new=AsyncMock(return_value="Germany")):
            runner_cls.return_value.__aenter__ = AsyncMock(return_value=runner)
            runner_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            session_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await tester.test_node_full(1, node)
        connector_cls.assert_called_once_with(ssl=True, limit=10)
        return result, tester.node_metadata[node], location_probe

    async def test_main_qualifies_when_cloudflare_trace_fails(self):
        found = evidence()
        result, metadata, probe_ = await self._run(found)
        self.assertIsNotNone(result)
        self.assertEqual(metadata["loc_score"], .75)
        self.assertEqual(metadata["location"], found)
        self.assertEqual(metadata["country_code"], "DE")
        probe_.assert_awaited_once_with(23456, None, None)

    async def test_survivor_is_renamed_with_consensus_and_keeps_shared_metadata(self):
        result, metadata, _ = await self._run(evidence(), trace=("192.0.2.5", "US", 10))
        survivor, latency, tested = result
        self.assertEqual(latency, 10)
        self.assertEqual(tested, "vless://abc@192.0.2.1:443?encryption=none#original")
        self.assertEqual(
            urllib.parse.unquote(survivor.split("#", 1)[1]),
            "[VLESS: original] \U0001F1E9\U0001F1EA Germany | 192.0.2.5 | Location DE 75% (3/4 votes)",
        )
        self.assertEqual(metadata["latency_ms"], 10)

    async def test_restricted_or_weak_location_is_dropped_with_its_evidence(self):
        for found, reason in (
            (evidence(("RU",) * 3), "Location country excluded: RU"),
            (evidence(("DE", "DE")), "Too few location reports"),
        ):
            with self.subTest(reason=reason):
                result, metadata, _ = await self._run(found, trace=("192.0.2.5", "DE", 10))
                self.assertIsNone(result)
                self.assertTrue(metadata["dropped"])
                self.assertEqual(metadata["reason"], reason)
                self.assertEqual(metadata["location"], found)

    async def test_tied_consensus_does_not_fall_back_to_single_provider_country_label(self):
        result, metadata, _ = await self._run(evidence(("DE", "FI")), trace=("192.0.2.5", "DE", 10))
        self.assertIsNone(result)
        self.assertIsNone(metadata["country_code"])
        self.assertIn("tied", metadata["reason"])

    async def test_failed_probe_reports_why_location_is_unknown(self):
        failed = empty_location("failed", "GeoIP providers did not answer in time", ("ipv4",))
        result, metadata, _ = await self._run(failed)
        self.assertIsNone(result)
        self.assertEqual(metadata["reason"], "Location probe failed: GeoIP providers did not answer in time")

    async def test_leaked_ip_found_by_the_probe_drops_the_node(self):
        result, metadata, _ = await self._run(evidence(real_ip="192.0.2.5"))
        self.assertIsNone(result)
        self.assertEqual(metadata["reason"], "Proxy leaks real IP")

    async def test_fetch_location_asks_through_the_nodes_listener(self):
        tester = NodeTester({}, real_ip="198.51.100.1")
        with patch("nodesieve.core.tester.probe_location", new=AsyncMock(return_value=evidence())) as probe_:
            await tester.fetch_location(23456, "192.0.2.5", None)
        probe_.assert_awaited_once_with("http://127.0.0.1:23456", families=["ipv4"], real_ip="198.51.100.1")

    async def test_legacy_score_api_uses_allowed_country_votes(self):
        tester = NodeTester({})
        with patch.object(tester, "fetch_location", new=AsyncMock(return_value=evidence())):
            self.assertEqual(await tester.fetch_loc_score(23456, ["DE"]), .75)
            self.assertEqual(await tester.fetch_loc_score(23456, ["US"]), .25)
            self.assertEqual(await tester.fetch_loc_score(23456, []), 0)


def test_no_subprocess_is_started_for_location():
    source = open(location.__file__, encoding="utf-8").read()
    assert not re.search(r"\bsubprocess\b|create_subprocess|os\.system|Popen", source)
