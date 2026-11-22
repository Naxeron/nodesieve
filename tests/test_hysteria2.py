"""Hysteria 2 share links through subscription filtering, scan preparation and both core parsers."""

import asyncio
import json
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import pytest

from nodesieve.core.fetcher import NodeFetcher
from nodesieve.core.tester import NodeTester
from nodesieve.parsers import extract_host_port, extract_node_protocol, node_url_to_mihomo_dict, node_url_to_xray_outbound


def test_both_cores_keep_credentials_port_ranges_and_tls_options():
    pin = ":".join(["AB"] * 32)
    q = urlencode({"sni": "cert.example", "pinSHA256": pin, "insecure": "1", "ech": "abc+123=",
                   "obfs": "gecko", "obfs-password": "key&+", "alpn": "h3", "up": "25", "down": "100 Mbps",
                   "fm": json.dumps({"quicParams": {"debug": True}})})
    node = f"hysteria2://user:p%40ss%253A+@[2001:db8::1]:8443,9000-9010/?{q}#Two%20ports"
    assert extract_host_port(node) == ("2001:db8::1", 8443)
    assert node_url_to_mihomo_dict(node) == {
        "name": "Two ports", "type": "hysteria2", "server": "2001:db8::1", "port": 8443, "ports": "8443,9000-9010",
        "password": "user:p@ss%3A+", "udp": True, "sni": "cert.example", "alpn": ["h3"], "skip-cert-verify": True,
        "fingerprint": "ab" * 32, "ech-opts": {"enable": True, "config": "abc+123="},
        "obfs": "gecko", "obfs-password": "key&+", "up": "25", "down": "100 Mbps",
    }
    outbound = node_url_to_xray_outbound(node)
    assert outbound["protocol"] == "hysteria"
    assert outbound["settings"] == {"version": 2, "address": "2001:db8::1", "port": 8443}
    stream = outbound["streamSettings"]
    assert stream["hysteriaSettings"] == {"version": 2, "auth": "user:p@ss%3A+"}
    assert stream["tlsSettings"] == {"alpn": ["h3"], "serverName": "cert.example", "pinnedPeerCertSha256": "ab" * 32,
                                     "echConfigList": "abc+123="}
    assert stream["finalmask"]["udp"] == [
        {"type": "salamander", "settings": {"password": "key&+", "packetSize": "512-1200"}},
        {"type": "udphop", "settings": {"mode": "intervallocal,intervalremote", "remotePorts": "8443,9000-9010", "interval": 30}},
    ]
    assert stream["finalmask"]["quicParams"] == {"debug": True, "brutalUp": "25 mbps", "brutalDown": "100 Mbps"}


@pytest.mark.parametrize("scheme", ["hy2", "hysteria2"])
def test_minimal_link_uses_default_port_and_tls(scheme):
    node = f"{scheme}://node.example/"
    assert extract_host_port(node) == ("node.example", 443)
    assert extract_node_protocol(node) == "HYSTERIA2"
    assert node_url_to_mihomo_dict(node) == {
        "name": "hysteria2_node.example_443", "type": "hysteria2",
        "server": "node.example", "port": 443, "password": "", "udp": True,
    }
    assert node_url_to_xray_outbound(node)["streamSettings"] == {
        "network": "hysteria", "hysteriaSettings": {"version": 2, "auth": ""}, "security": "tls",
        "tlsSettings": {"alpn": ["h3"]},
    }


@pytest.mark.parametrize("endpoint", [
    ":443", "host:", "host:0", "host:443,65536", "host:8443-443", "host:443,,80", "host:noport",
    "[::1", "[::1]extra:123", "host/invalid", "two hosts", "host:443?mport=65536",
    "host?obfs=unknown", "host?obfs=salamander", "host?insecure=1&pinSHA256=bad",
])
def test_malformed_links_are_excluded(endpoint):
    node = "hy2://pw@" + endpoint
    assert node_url_to_mihomo_dict(node) is None
    assert node_url_to_xray_outbound(node) is None
    assert NodeFetcher({})._parse_subscription(node) == []


def test_quic_skips_tcp_and_sing_mux_but_preserves_scan_filters(monkeypatch):
    connect = AsyncMock()
    monkeypatch.setattr(asyncio, "open_connection", connect)
    tester = NodeTester({"core": "mihomo", "use_mux": True})
    node = "hy2://pw@host:443/"
    assert asyncio.run(tester.async_check_tcp_node(node)) == node
    assert asyncio.run(tester.async_check_tcp_node(node + "#⬇")) is None
    assert asyncio.run(tester.async_check_tcp_node("hy2://@host:0/")) is None
    connect.assert_not_called()
    assert tester.check_links(node) == (node, None)
    assert tester.speedtest_links(node) == (node, None)


def test_fetch_keeps_first_alias_and_source(monkeypatch):
    first = "hy2://pw@host/#First"
    second = "hysteria2://pw@host/#Second"
    fetcher = NodeFetcher({"subscriptions": ["https://one.test", "https://two.test"]})
    monkeypatch.setattr(fetcher, "_process_url", AsyncMock(side_effect=[[first], [second]]))
    nodes, sources = asyncio.run(fetcher.fetch_all())
    assert nodes == [first]
    assert sources[first] == "https://one.test"
