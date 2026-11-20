"""Android (Termux): how a node's server name reaches Mihomo.

Mihomo finds no /etc/resolv.conf on Android and then asks 114.114.114.114 and 8.8.8.8
itself, bypassing Android's DNS. So on Android nodesieve resolves the server through
Android's resolver and passes the addresses to Mihomo in its `hosts` section: one section
for every node a Mihomo serves.
"""

import asyncio
import os
import socket
import threading
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from nodesieve.constants import MIHOMO_PATH
from nodesieve.core import mihomo
from nodesieve.core.mihomo import (
    BatchNode,
    MihomoBatch,
    MihomoRunner,
    android_resolved_hosts,
    render_batch_config,
)

NODE = "vless://11111111-2222-3333-4444-555555555555@Node.Example:443?security=tls&sni=node.example&type=tcp#Test"


def addrinfo(*addresses):
    """getaddrinfo results for these addresses."""
    infos = []
    for address in addresses:
        if ":" in address:
            infos.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0)))
        else:
            infos.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)))
    return infos


def lookup(result):
    """Stands in for the event loop's getaddrinfo, which goes to the system resolver."""
    mock = AsyncMock(side_effect=result) if isinstance(result, BaseException) else AsyncMock(return_value=result)
    return patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=mock)


@pytest.fixture
def android(monkeypatch):
    monkeypatch.setattr(mihomo, "IS_ANDROID", True)


def test_mihomo_resolves_for_itself_outside_android(monkeypatch):
    monkeypatch.setattr(mihomo, "IS_ANDROID", False)
    with lookup(addrinfo("203.0.113.7")) as resolver:
        assert asyncio.run(android_resolved_hosts("node.example")) == {}
    resolver.assert_not_called()


def test_android_resolves_the_server_name(android):
    with lookup(addrinfo("203.0.113.7", "203.0.113.7", "2001:db8::7")) as resolver:
        assert asyncio.run(android_resolved_hosts("Node.Example")) == {
            "node.example": ["203.0.113.7", "2001:db8::7"],
        }
    assert resolver.call_args.args[0] == "Node.Example"


@pytest.mark.parametrize("server", ["203.0.113.7", "2001:db8::7", "[2001:db8::7]", "", None])
def test_android_leaves_addresses_alone(android, server):
    with lookup(addrinfo("198.51.100.1")) as resolver:
        assert asyncio.run(android_resolved_hosts(server)) == {}
    resolver.assert_not_called()


def test_android_lookup_failure_leaves_the_name_to_mihomo(android):
    with lookup(socket.gaierror(socket.EAI_NONAME, "Name or service not known")):
        assert asyncio.run(android_resolved_hosts("missing.example")) == {}


def test_android_drops_link_local_addresses_with_a_scope(android):
    with lookup(addrinfo("fe80::1%wlan0", "203.0.113.7")):
        assert asyncio.run(android_resolved_hosts("node.example")) == {"node.example": ["203.0.113.7"]}


def test_batch_config_gains_a_hosts_section_only_when_given_one():
    proxy = {"name": "node-0", "type": "http", "server": "node.example", "port": 8080}
    plain = yaml.safe_load(render_batch_config([(proxy, 7890)]))
    assert "hosts" not in plain
    assert plain["listeners"] == [
        {"name": "in-node-0", "type": "mixed", "listen": "127.0.0.1", "port": 7890, "proxy": "node-0"},
    ]

    hosts = {"node.example": ["203.0.113.7", "2001:0:0:1"]}
    with_hosts = yaml.safe_load(render_batch_config([(proxy, 7890)], hosts))
    assert with_hosts["hosts"] == hosts
    assert {key: value for key, value in with_hosts.items() if key != "hosts"} == plain


def test_batch_on_android_hands_every_servers_addresses_to_its_mihomo(android):
    """The nodes of one Mihomo share its hosts section: each server once, with all its addresses."""
    answers = {"a.example": ("203.0.113.1", "2001:db8::1"), "b.example": ("203.0.113.2",)}
    asked = []

    async def resolve(self, host, port, **kwargs):
        asked.append(host)
        return addrinfo(*answers[host.lower()])

    written = {}

    async def launch(*command, **kwargs):
        with open(command[command.index("-f") + 1], encoding="utf-8") as config:
            written["config"] = yaml.safe_load(config)
        raise OSError("not starting Mihomo in this test")

    def link(server, tag):
        return f"vless://11111111-2222-3333-4444-555555555555@{server}:443?security=tls&type=tcp#{tag}"

    nodes = [BatchNode(link("A.example", "one"), mux_link=link("A.example", "one-mux")),
             BatchNode(link("b.example", "two")), BatchNode(link("a.example", "three")),
             BatchNode(link("203.0.113.9", "by-address"))]

    async def run():
        async with MihomoBatch(nodes, {"use_mux": False}) as batch:
            return batch.endpoints

    with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
            patch.object(mihomo.asyncio, "create_subprocess_exec", new=launch):
        endpoints = asyncio.run(run())
    assert written["config"]["hosts"] == {
        "a.example": ["203.0.113.1", "2001:db8::1"], "b.example": ["203.0.113.2"],
    }
    assert sorted(asked) == ["A.example", "a.example", "b.example"]
    # A listener for each node and for the mux twin, besides the one telling when Mihomo is ready.
    assert len([listener for listener in written["config"]["listeners"] if listener["proxy"].startswith("node-")]) == 5
    # Mihomo could not be run at all: every node is told why.
    assert all(isinstance(endpoint.exception, OSError) for endpoint in endpoints)


def test_runner_on_android_hands_the_resolved_server_to_mihomo(android):
    written = {}

    async def launch(*command, **kwargs):
        with open(command[command.index("-f") + 1], encoding="utf-8") as config:
            written["config"] = yaml.safe_load(config)
        raise OSError("not starting Mihomo in this test")

    async def run():
        async with MihomoRunner(node=NODE, config={"use_mux": False}):
            pass

    with lookup(addrinfo("203.0.113.7")), patch.object(mihomo.asyncio, "create_subprocess_exec", new=launch):
        with pytest.raises(OSError):
            asyncio.run(run())
    assert written["config"]["hosts"] == {"node.example": ["203.0.113.7"]}


def test_mihomo_reaches_a_node_through_its_hosts_entry(android):
    """The real binary connects to a server whose name only Android's resolver knows."""
    if not (os.path.isfile(MIHOMO_PATH) and os.access(MIHOMO_PATH, os.X_OK)):
        pytest.skip(f"Mihomo binary not executable at {MIHOMO_PATH}")

    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream.settimeout(10)
    received = []

    def accept():
        try:
            connection, _ = upstream.accept()
            with connection:
                connection.settimeout(5)
                received.append(connection.recv(4096))
        except OSError:
            pass

    accepting = threading.Thread(target=accept, daemon=True)
    accepting.start()

    # .invalid never resolves through DNS, so only the hosts entry can lead Mihomo there.
    proxy = {"type": "http", "server": "upstream.nodesieve.invalid", "port": upstream.getsockname()[1]}

    async def resolve(self, host, port, **kwargs):
        assert host == "upstream.nodesieve.invalid"
        return addrinfo("127.0.0.1")

    async def run():
        async with MihomoBatch([BatchNode("http://upstream.nodesieve.invalid#Node", idx=1, total=1)], {}) as batch:
            endpoint = batch.endpoints[0]
            assert endpoint.error is None
            reader, writer = await asyncio.open_connection("127.0.0.1", endpoint.port)
            writer.write(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
            await writer.drain()
            await asyncio.get_running_loop().run_in_executor(None, accepting.join, 10)
            writer.close()

    try:
        with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
                patch.object(mihomo, "mihomo_proxy", return_value=proxy):
            asyncio.run(run())
        assert received and received[0].startswith(b"CONNECT example.invalid:443 ")
    finally:
        upstream.close()
