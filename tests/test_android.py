"""Android (Termux) DNS host resolution passed into Xray's dns.hosts."""

import asyncio
import json
import socket
from unittest.mock import AsyncMock, patch

import pytest

from nodesieve.core import batch as core_batch
from nodesieve.core.batch import BatchNode, CoreBatch, CoreRunner, android_resolved_hosts
from nodesieve.core.xray import render_xray_config

NODE = "vless://11111111-2222-3333-4444-555555555555@Node.Example:443?security=tls&sni=node.example&type=tcp#Test"


def addrinfo(*addresses):
    return [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (a, 0, 0, 0)) if ":" in a
        else (socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
        for a in addresses
    ]


def lookup(result):
    mock = AsyncMock(side_effect=result) if isinstance(result, BaseException) else AsyncMock(return_value=result)
    return patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=mock)


@pytest.fixture
def android(monkeypatch):
    monkeypatch.setattr(core_batch, "IS_ANDROID", True)


def test_xray_resolves_for_itself_outside_android(monkeypatch):
    monkeypatch.setattr(core_batch, "IS_ANDROID", False)
    with lookup(addrinfo("203.0.113.7")) as resolver:
        assert asyncio.run(android_resolved_hosts("node.example")) == {}
    resolver.assert_not_called()


def test_android_resolves_the_server_name(android):
    with lookup(addrinfo("203.0.113.7", "203.0.113.7", "2001:db8::7")) as resolver:
        assert asyncio.run(android_resolved_hosts("Node.Example")) == {"node.example": ["203.0.113.7", "2001:db8::7"]}
    assert resolver.call_args.args[0] == "Node.Example"


@pytest.mark.parametrize("server", ["203.0.113.7", "2001:db8::7", "[2001:db8::7]", "", None])
def test_android_leaves_addresses_alone(android, server):
    with lookup(addrinfo("198.51.100.1")) as resolver:
        assert asyncio.run(android_resolved_hosts(server)) == {}
    resolver.assert_not_called()


def test_android_lookup_failure_and_scoped_link_local(android):
    with lookup(socket.gaierror(socket.EAI_NONAME, "Name or service not known")):
        assert asyncio.run(android_resolved_hosts("missing.example")) == {}
    with lookup(addrinfo("fe80::1%wlan0", "203.0.113.7")):
        assert asyncio.run(android_resolved_hosts("node.example")) == {"node.example": ["203.0.113.7"]}


def test_batch_and_runner_on_android_pass_resolved_hosts_to_xray(android):
    answers = {"a.example": ("203.0.113.1", "2001:db8::1"), "b.example": ("203.0.113.2",), "node.example": ("203.0.113.7",)}
    written = {}

    async def resolve(self, host, port, **kwargs):
        return addrinfo(*answers[host.lower()])

    async def launch(*command, **kwargs):
        with open(command[command.index("-c") + 1], encoding="utf-8") as f:
            written["config"] = json.load(f)
        raise OSError("not starting Xray in this test")

    def link(server, tag):
        return f"vless://11111111-2222-3333-4444-555555555555@{server}:443?security=tls&type=tcp#{tag}"

    nodes = [BatchNode(link("A.example", "one")), BatchNode(link("b.example", "two")),
             BatchNode(link("a.example", "three")), BatchNode(link("203.0.113.9", "by-ip"))]

    async def run_batch():
        async with CoreBatch(nodes, {}) as instance:
            return instance.endpoints

    with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
            patch.object(core_batch.asyncio, "create_subprocess_exec", new=launch):
        endpoints = asyncio.run(run_batch())
    assert written["config"]["dns"] == {"hosts": {"a.example": ["203.0.113.1", "2001:db8::1"], "b.example": ["203.0.113.2"]}}
    assert all(isinstance(ep.exception, OSError) for ep in endpoints)

    async def run_runner():
        async with CoreRunner(node=NODE, config={}):
            pass

    with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
            patch.object(core_batch.asyncio, "create_subprocess_exec", new=launch):
        with pytest.raises(OSError):
            asyncio.run(run_runner())
    assert written["config"]["dns"] == {"hosts": {"node.example": ["203.0.113.7"]}}
    # Also verify plain render_xray_config has no dns section when hosts is omitted.
    outbound = {"tag": "node-0", "protocol": "shadowsocks", "settings": {"address": "node.example", "port": 8388}}
    assert "dns" not in json.loads(render_xray_config([(outbound, 7890)]))
