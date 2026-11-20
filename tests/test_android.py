"""Android (Termux): how a node's server name reaches Mihomo.

Mihomo finds no /etc/resolv.conf on Android and then asks 114.114.114.114 and 8.8.8.8
itself, bypassing Android's DNS. So on Android nodesieve resolves the server through
Android's resolver and passes the addresses to Mihomo in its `hosts` section.
"""

import asyncio
import os
import socket
import subprocess
import threading
import time
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from nodesieve.constants import MIHOMO_PATH
from nodesieve.core import mihomo
from nodesieve.core.mihomo import MihomoManager, MihomoRunner, android_resolved_hosts, render_test_config

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


def test_test_config_gains_a_hosts_section_only_when_given_one():
    plain = yaml.safe_load(render_test_config(7890, "/work/node.txt"))
    assert "hosts" not in plain
    assert plain["mixed-port"] == 7890
    assert plain["proxy-providers"]["test_sub"]["path"] == "/work/node.txt"

    hosts = {"node.example": ["203.0.113.7", "2001:0:0:1"]}
    with_hosts = yaml.safe_load(render_test_config(7890, "/work/node.txt", hosts))
    assert with_hosts["hosts"] == hosts
    assert {key: value for key, value in with_hosts.items() if key != "hosts"} == plain


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


def test_mihomo_reaches_a_node_through_its_hosts_entry(tmp_path):
    """The real binary connects to a server whose name only the hosts section knows."""
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
    node_file = tmp_path / "node.txt"
    node_file.write_text(yaml.dump({"proxies": [{
        "name": "node", "type": "http", "server": "upstream.nodesieve.invalid",
        "port": upstream.getsockname()[1],
    }]}))
    port = MihomoManager.get_free_port()
    config_file = tmp_path / "config.yaml"
    config_file.write_text(render_test_config(port, str(node_file), {"upstream.nodesieve.invalid": ["127.0.0.1"]}))
    process = subprocess.Popen(
        [MIHOMO_PATH, "-d", str(tmp_path), "-f", str(config_file)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if process.poll() is not None or time.monotonic() > deadline:
                    pytest.fail("Mihomo did not open its port")
                time.sleep(0.05)
        with client:
            client.sendall(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
            accepting.join(10)
        assert received and received[0].startswith(b"CONNECT example.invalid:443 ")
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
        upstream.close()
        MihomoManager.release_port(port)
