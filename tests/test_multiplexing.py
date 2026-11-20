"""Multiplexing (use_mux) is kept only on nodes whose server answers through it.

A link does not say whether its server supports sing-mux, and a server without it
drops every multiplexed connection. A node is therefore checked without
multiplexing, and keeps it on the router only after answering a request through it.
"""

import asyncio
import base64
import copy
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

import proxy_sites.ui.dashboard as dashboard_module
from proxy_sites.core.router_validator import RouterValidator
from proxy_sites.core.tester import TRACE_URL_IPV4, TRACE_URL_IPV6, NodeTester
from proxy_sites.parsers.mihomo import node_url_to_mihomo_dict, without_mux
from proxy_sites.ui.dashboard import VPNDashboard

VISION = (
    "vless://uuid@vision.example:443?security=reality&flow=xtls-rprx-vision"
    "&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sni=example.com#vision.example"
)


def ws_node(host):
    """A WebSocket node as the fetcher hands it over while use_mux is on."""
    return f"vless://uuid@{host}:443?smux=1&type=ws&path=%2Fws&security=tls&sni={host}#{host}"


def multiplexed(link):
    return "smux" in node_url_to_mihomo_dict(link, use_mux=True)


class _Instance:
    """A started Mihomo: its proxy URL says which server it connects to, and how."""

    port = 12345

    def __init__(self, proxy_url, starts=True):
        self.proxy_url, self.starts = proxy_url, starts

    async def __aenter__(self):
        if not self.starts:
            raise RuntimeError("Mihomo failed to initialize")
        return self

    async def __aexit__(self, *exc):
        return False


class _Servers:
    """Stands in for Mihomo and the servers behind the nodes.

    Like real servers, they answer a multiplexed connection only if they support sing-mux.
    """

    def __init__(self):
        self.with_mux = set()        # hosts whose server supports sing-mux
        self.dead = set()            # hosts whose server answers nothing
        self.ipv6_only = set()       # hosts whose exit has no IPv4
        self.mux_crashes = set()     # hosts Mihomo cannot start a multiplexed instance for
        self.started = []            # (host, multiplexed) of every instance, in order
        self.mux_traces = []         # trace URL of every request through a multiplexed instance

    def mihomo(self, node, config, **_):
        proxy = node_url_to_mihomo_dict(node, use_mux=config.get("use_mux", True))
        host, mux = proxy["server"], "smux" in proxy
        self.started.append((host, mux))
        return _Instance(f"http://{host}/{'mux' if mux else 'plain'}", starts=not (mux and host in self.mux_crashes))

    async def trace(self, url, proxy_url, session=None):
        host, mode = proxy_url.removeprefix("http://").split("/")
        if mode == "mux":
            self.mux_traces.append(url)
        if host in self.dead or (mode == "mux" and host not in self.with_mux):
            return None, None, 99999.0
        if host in self.ipv6_only:
            return ("2001:db8::1", "US", 30.0) if url == TRACE_URL_IPV6 else (None, None, 99999.0)
        return ("203.0.113.10", "US", 25.0) if url == TRACE_URL_IPV4 else (None, None, 99999.0)


@pytest.fixture
def servers():
    farm = _Servers()
    with patch("proxy_sites.core.tester.MihomoRunner", farm.mihomo), \
            patch.object(NodeTester, "_fetch_ip", farm.trace), \
            patch("proxy_sites.core.tester.GeolocationService.get_country_name",
                  AsyncMock(return_value="United States")):
        yield farm


def check(node, **config):
    tester = NodeTester({"use_mux": True, **config}, total_nodes=1)
    return tester, asyncio.run(tester.test_node_full(1, node))


def test_link_marked_smux_0_gets_no_multiplexing():
    link = "vless://uuid@plain.example:443?type=ws&security=tls&sni=plain.example#Tag"
    assert multiplexed(link)
    assert multiplexed(link.replace("?", "?smux=1&"))
    assert not multiplexed(link.replace("?", "?smux=0&"))
    assert "smux" not in node_url_to_mihomo_dict(link, use_mux=False)


@pytest.mark.parametrize("link, marked", [
    ("vless://u@h.example:443?smux=1&type=ws#Tag #1", "vless://u@h.example:443?smux=0&type=ws#Tag #1"),
    ("vless://u@h.example:443?type=ws&smux=1#Tag", "vless://u@h.example:443?type=ws&smux=0#Tag"),
    ("vless://u@h.example:443?type=ws#Tag?smux=1", "vless://u@h.example:443?type=ws&smux=0#Tag?smux=1"),
    ("vless://u@h.example:443#Tag", "vless://u@h.example:443?smux=0#Tag"),
    ("vless://u@h.example:443", "vless://u@h.example:443?smux=0"),
])
def test_without_mux_marks_the_link_and_keeps_the_rest(link, marked):
    assert without_mux(link) == marked
    assert without_mux(marked) == marked
    assert not multiplexed(marked)


def test_node_on_a_server_without_multiplexing_qualifies_and_goes_on_without_it(servers):
    node = ws_node("plain.example")
    tester, (survivor, latency, tested) = check(node)
    # Checked without multiplexing, then offered it once.
    assert servers.started == [("plain.example", False), ("plain.example", True)]
    assert (latency, tested) == (25.0, node)
    assert survivor.split("#")[0] == without_mux(node).split("#")[0]
    assert not multiplexed(survivor)
    assert tester.node_metadata[survivor] is tester.node_metadata[node]
    assert (tester.mux_offered, tester.mux_supported) == (1, 0)


def test_node_on_a_server_with_multiplexing_keeps_it(servers):
    servers.with_mux.add("mux.example")
    node = ws_node("mux.example")
    tester, (survivor, _, _) = check(node)
    assert servers.started == [("mux.example", False), ("mux.example", True)]
    assert survivor.split("#")[0] == node.split("#")[0]
    assert multiplexed(survivor)
    assert (tester.mux_offered, tester.mux_supported) == (1, 1)


def test_node_goes_on_without_multiplexing_when_mihomo_cannot_start_with_it(servers):
    servers.with_mux.add("crash.example")
    servers.mux_crashes.add("crash.example")
    tester, (survivor, _, _) = check(ws_node("crash.example"))
    assert not multiplexed(survivor)
    assert (tester.mux_offered, tester.mux_supported) == (1, 0)


def test_multiplexing_is_probed_over_the_ip_family_the_node_has(servers):
    servers.with_mux.update({"dual.example", "six.example"})
    servers.ipv6_only.add("six.example")
    check(ws_node("dual.example"))
    _, (survivor, _, _) = check(ws_node("six.example"))
    assert servers.mux_traces == [TRACE_URL_IPV4, TRACE_URL_IPV6]
    assert multiplexed(survivor)


def test_dead_node_is_dropped_without_a_multiplexing_probe(servers):
    servers.dead.add("dead.example")
    node = ws_node("dead.example")
    tester, result = check(node)
    assert result is None
    assert servers.started == [("dead.example", False)]
    assert tester.node_metadata[node]["reason"] == "No outbound internet connectivity"
    assert tester.mux_offered == 0


@pytest.mark.parametrize("node, config", [
    (VISION, {}),                                    # Vision carries no multiplexing
    (ws_node("plain.example"), {"use_mux": False}),  # switched off
])
def test_no_multiplexing_probe_where_multiplexing_does_not_apply(servers, node, config):
    tester, (survivor, _, _) = check(node, **config)
    assert servers.started == [(node_url_to_mihomo_dict(node)["server"], False)]
    assert survivor.split("#")[0] == node.split("#")[0]
    assert tester.mux_offered == 0


def test_steer_node_is_checked_without_multiplexing_and_never_probed(servers):
    """Steer connects with its own core, so the checker neither needs nor decides multiplexing for it."""
    summary = {"country": "DE", "score": 1.0, "votes": 3, "total": 3, "counts": {"DE": 3}}
    location = {**summary, "source": "ipregion", "status": "ok", "tested_families": ["ipv4"],
                "families": {"ipv4": copy.deepcopy(summary)}}
    node = ws_node("plain.example")
    with patch.object(NodeTester, "fetch_location", AsyncMock(return_value=location)), \
            patch("proxy_sites.core.tester.aiohttp.TCPConnector"), \
            patch("proxy_sites.core.tester.aiohttp.ClientSession") as session:
        session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        session.return_value.__aexit__ = AsyncMock(return_value=False)
        tester, (survivor, _, _) = check(node, routing={"enabled": True})
    assert servers.started == [("plain.example", False)]
    assert survivor.split("#")[0] == node.split("#")[0]
    assert tester.mux_offered == 0


def test_router_validation_stages_each_node_the_way_it_was_verified():
    validator = RouterValidator(router_client=MagicMock(), config={"use_mux": True})
    staged, _ = validator.build_candidate_sub_yaml([
        (ws_node("mux.example"), 10.0, "original"),
        (without_mux(ws_node("plain.example")), 12.0, "original"),
    ])
    proxies = yaml.safe_load(staged)["proxies"]
    assert {proxy["server"]: "smux" in proxy for proxy in proxies} == {"mux.example": True, "plain.example": False}


def test_scan_reports_multiplexing_and_deploys_it_only_where_it_works(servers, caplog):
    servers.with_mux.add("mux.example")
    nodes = [ws_node("mux.example"), ws_node("plain.example"), VISION]
    dashboard = VPNDashboard({
        "subscriptions": [], "use_mux": True, "workers": 2, "tcp_workers": 2, "enable_router_validation": False,
    })

    async def speedtest(candidates, tester=None):
        return [(candidate[0], 1_000_000.0, 0.0) for candidate in candidates]

    with patch.object(dashboard, "_get_real_ip", AsyncMock(return_value=None)), \
            patch.object(dashboard, "filter_tcp", AsyncMock(return_value=nodes)), \
            patch.object(dashboard, "run_speedtest_nodes_async", speedtest), \
            patch("proxy_sites.ui.dashboard.ResourceLimits.get_max_safe_workers", return_value=(2, 8192)), \
            patch("proxy_sites.ui.dashboard.NodeFetcher.fetch_all", AsyncMock(return_value=(nodes, {}))), \
            patch("proxy_sites.ui.dashboard.MihomoManager.setup"), \
            caplog.at_level("INFO", logger="ProxySiteChecker"):
        assert asyncio.run(dashboard.run_pipeline_async(check_only=True))

    assert "Multiplexing: 1 of 2 eligible working nodes support it; the rest are used without it." in caplog.text
    script = (Path(dashboard_module.PROJECT_ROOT) / "apply_to_router.sh").read_text(encoding="utf-8")
    provider = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d > /etc/mihomo/proxy-providers/sub\.yaml\.tmp", script)
    proxies = yaml.safe_load(base64.b64decode(provider.group(1)))["proxies"]
    assert {proxy["server"]: "smux" in proxy for proxy in proxies} == {
        "mux.example": True, "plain.example": False, "vision.example": False,
    }
