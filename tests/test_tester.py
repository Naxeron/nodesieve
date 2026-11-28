"""Unit tests for NodeTester: TCP ping, IP trace resolution, Phase 1 check, and speedtest."""

import asyncio
import urllib.parse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nodesieve.core.tester import NodeTester


class _Ctx:
    def __init__(self, value, on_exit=None):
        self.value, self.on_exit = value, on_exit

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *args):
        if self.on_exit:
            self.on_exit()


def _tester(**overrides):
    return NodeTester({"allowed_countries": ["US", "DE"], "speedtest_timeout": 5, **overrides}, total_nodes=1)


def _run_speedtest(stream, timeout=45, clock=None, on_close=None):
    node = "vless://11111111-1111-4111-8111-111111111111@198.51.100.219:443?security=tls&sni=example.com#Speed"
    runner = AsyncMock(proxy_url="http://127.0.0.1:12345", port=12345)
    session = MagicMock()
    session.get.return_value = _Ctx(MagicMock(status=200, content=stream), on_exit=on_close)

    async def run():
        patches = [
            patch("nodesieve.core.tester.CoreRunner", return_value=_Ctx(runner)),
            patch("aiohttp.ClientSession", return_value=_Ctx(session)),
        ]
        if clock is not None:
            patches.append(patch("nodesieve.core.tester.time.perf_counter", side_effect=lambda: clock[0]))
        with patches[0], patches[1]:
            if len(patches) == 3:
                with patches[2]:
                    return await _tester().speedtest_node(1, node, timeout=timeout)
            return await _tester().speedtest_node(1, node, timeout=timeout)

    return asyncio.run(run()), runner, session


def _full_check(node, traces, tester=None, country_name="United States"):
    tester = tester or _tester()

    async def run():
        runner = AsyncMock(proxy_url="http://127.0.0.1:12345", port=12345)
        with patch("nodesieve.core.tester.CoreRunner", return_value=_Ctx(runner)), \
                patch.object(tester, "_fetch_ip", new=AsyncMock(side_effect=list(traces))), \
                patch("nodesieve.core.tester.GeolocationService.get_country_name", new=AsyncMock(return_value=country_name)):
            return await tester.test_node_full(1, node)

    return asyncio.run(run()), tester


def test_tcp_ping_rejects_headers_and_invalid_uris():
    t = _tester()
    assert asyncio.run(t.async_check_tcp_node("vless://uuid@1.2.3.4:443#Авто_Node")) is None
    assert asyncio.run(t.async_check_tcp_node("invalid://node")) is None


def test_fetch_ip_ipv4_ipv6_fidelity_and_retry():
    t = _tester()

    def session_for(responses):
        s = MagicMock()
        s.get.side_effect = [
            r if isinstance(r, BaseException) else _Ctx(MagicMock(status=200, text=AsyncMock(return_value=r)))
            for r in responses
        ]
        return s

    async def run():
        v4 = await t._fetch_ip("https://1.1.1.1/cdn-cgi/trace", "http://127.0.0.1:8080",
                               session=session_for(["ip=203.0.113.10\nloc=US\n"]))
        assert v4[:2] == ("203.0.113.10", "US") and v4[2] > 0

        v6 = await t._fetch_ip("https://[2606:4700:4700::1111]/cdn-cgi/trace", "http://127.0.0.1:8080",
                               session=session_for(["ip=2001:db8::1\nloc=DE\n"]))
        assert v6[:2] == ("2001:db8::1", "DE")

        # IPv6 URL must reject IPv4 trace response.
        bad = await t._fetch_ip("https://[2606:4700:4700::1111]/cdn-cgi/trace", "http://127.0.0.1:8080",
                                session=session_for(["ip=203.0.113.10\nloc=US\n"]))
        assert bad[0] is None

        # Retry resets latency on fallback URL.
        retry = await t._fetch_ip("https://1.1.1.1/cdn-cgi/trace", "http://127.0.0.1:8080",
                                  session=session_for([Exception("timeout"), "ip=203.0.113.10\nloc=US\n"]))
        assert retry[:2] == ("203.0.113.10", "US") and retry[2] < 5000.0

    asyncio.run(run())


def test_speedtest_sustained_warmup_early_stop_and_stall_penalty():
    chunk = b"0" * 131072  # 128 KiB

    class BasicStream:
        async def iter_chunked(self, size):
            for _ in range(20):
                yield chunk
                await asyncio.sleep(0.005)

    res, _, _ = _run_speedtest(BasicStream(), timeout=5)
    assert res and res[1] > 0 and "⚡" in urllib.parse.unquote(res[0])

    # Excludes 0.5 s warmup and 0.5 s teardown; measures 20 MiB over 1.0 s -> 20 MiB/s.
    clock = [0.0]

    class RampStream:
        async def iter_chunked(self, size):
            yield chunk
            clock[0] = 0.25
            yield chunk
            clock[0] = 0.50
            yield chunk
            for i in range(1, 161):
                clock[0] = 0.50 + i / 160.0
                yield chunk

    res, _, sess = _run_speedtest(RampStream(), clock=clock, on_close=lambda: clock.__setitem__(0, clock[0] + 0.5))
    assert res[1] / 1048576 == pytest.approx(20.0, abs=0.1)
    assert sess.get.call_args.args[0] == "https://speed.cloudflare.com/__down?bytes=100000000"
    assert sess.get.call_args.kwargs["timeout"].sock_read == 4.0

    # Early stop after 2.5 s steady-state sample at 25 MiB/s.
    clock = [0.0]

    class FastStream:
        async def iter_chunked(self, size):
            yield chunk
            while True:
                clock[0] += 0.005
                yield chunk

    res, _, _ = _run_speedtest(FastStream(), clock=clock)
    assert res[1] / 1048576 == pytest.approx(25.0, abs=0.2) and clock[0] < 3.5

    # Mid-stream stall penalized by wall-clock timeout and triggers ensure_alive().
    clock = [0.0]

    class StallingStream:
        async def iter_chunked(self, size):
            yield chunk
            for _ in range(4):
                clock[0] += 0.05
                yield chunk
            clock[0] += 4.0
            raise asyncio.TimeoutError()

    res, runner, _ = _run_speedtest(StallingStream(), clock=clock)
    assert res[1] / 1048576 == pytest.approx(0.5 / 4.2, abs=0.02)
    runner.ensure_alive.assert_awaited()


def test_full_check_qualifies_dual_stack_and_drops_dead_leaks_and_blocked():
    node = "vless://uuid@198.51.100.7:443#Primary"
    res, t = _full_check(node, [("203.0.113.10", "US", 25.0), (None, None, 99999.0)])
    survivor, latency, orig = res
    assert (latency, orig) == (25.0, node)
    assert urllib.parse.unquote(survivor.split("#", 1)[1]) == "[VLESS: Primary] 🇺🇸 United-States | 203.0.113.10"
    assert t.node_metadata[survivor] == {"country_code": "US", "country_name": "United States",
                                         "latency_ms": 25.0, "location": None}

    res, _ = _full_check(node, [("203.0.113.10", "DE", 40.0), ("2001:db8::1", "DE", 30.0)], country_name="Germany")
    assert res[1] == 30.0 and urllib.parse.unquote(res[0]).endswith("Germany | 203.0.113.10 | 2001:db8::1")

    # Dead node aborts without location probe.
    dead, t = _full_check(node, [(None, None, 99999.0), (None, None, 99999.0)])
    assert dead is None and t.node_metadata[node]["reason"] == "No outbound internet connectivity"

    # Leak drops node.
    leak_res, t_leak = _full_check(node, [("203.0.113.10", "US", 25.0), (None, None, 99999.0)],
                                   tester=NodeTester({"allowed_countries": ["US"]}, 1, "203.0.113.10"))
    assert leak_res is None and t_leak.node_metadata[node]["reason"] == "Proxy leaks real IP"

    # Blocked or disallowed countries (including IPv6 blocked behind allowed IPv4).
    for traces, reason in (
        ([("203.0.113.10", "RU", 25.0), (None, None, 99999.0)], "Geo-blocked region (RU)"),
        ([("203.0.113.10", "FR", 25.0), (None, None, 99999.0)], "Location not allowed (FR)"),
        ([("203.0.113.10", "US", 25.0), ("2001:db8::1", "CN", 30.0)], "Geo-blocked region (CN)"),
        ([("198.51.100.1", None, 25.0), (None, None, 99999.0)], "Could not determine node location"),
    ):
        r, t = _full_check(node, traces)
        assert r is None and t.node_metadata[node]["reason"] == reason
