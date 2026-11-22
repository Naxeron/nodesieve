"""Xray as the core nodes are checked through.

Links go to Xray with every option they carry. One Xray serves a batch of nodes, each
through a mixed listener with a routing rule to its outbound. Most tests run a stand-in for
the binary that behaves as nodesieve relies on Xray to: it refuses a whole configuration over
one outbound it can't build, naming its tag; it fails to start when a listener's port is
taken, naming the port; and its HTTP outbound dials only once the client has sent data,
dropping whatever came with the answer to its CONNECT. The other tests run the real binary,
from the project directory or PATH, when there is one.
"""

import asyncio
import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from nodesieve.config import ConfigManager
from nodesieve.constants import MIHOMO_PATH, XRAY_PATH
from nodesieve.core import batch as core_batch
from nodesieve.core import xray
from nodesieve.core.batch import BatchNode, CoreBatch, CoreRunner, PortManager, core_for
from nodesieve.core.xray import XrayCore, render_xray_config, xray_asset
from nodesieve.parsers.xray import node_url_to_xray_outbound

CONFIG = {"use_mux": False, "core": "xray"}
PASSWORD = "nodesieve-test-password"
PBK = "vpmWvtTfqGiWK_mQey9hK41fgWez3GVX07_h6uLWrS4"
FRAGMENT = {"tcp": [{"type": "fragment", "settings": {"delay": "0", "length": "10-20", "packets": "tlshello"}}]}


def ss(server, tag, cipher="aes-128-gcm", port=8388, password=PASSWORD):
    return f"ss://{cipher}:{password}@{server}:{port}#{tag}"


def fm(value):
    return json.dumps(value, separators=(",", ":")).replace("{", "%7B").replace("}", "%7D").replace('"', "%22")


# Links to outbounds.


def test_reality_vision_link_keeps_every_option_and_its_fragmenting():
    link = (f"vless://11111111-2222-3333-4444-555555555555@node.example:443?encryption=none&type=tcp"
            f"&security=reality&sni=www.example.com&fp=firefox&pbk={PBK}&sid=ab12&spx=%2F"
            f"&flow=xtls-rprx-vision&fm={fm(FRAGMENT)}&smux=1#Node")
    assert node_url_to_xray_outbound(link) == {
        "protocol": "vless",
        "settings": {"address": "node.example", "port": 443, "id": "11111111-2222-3333-4444-555555555555",
                     "encryption": "none", "flow": "xtls-rprx-vision"},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {"serverName": "www.example.com", "fingerprint": "firefox", "publicKey": PBK,
                                "shortId": "ab12", "spiderX": "/"},
            "finalmask": FRAGMENT,
        },
    }


def test_websocket_link_checks_the_certificate_against_its_vcn():
    link = ("vless://u@203.0.113.7:443?type=ws&path=%2Fa%2Fb%3Fed%3D2048&host=203.0.113.7&security=tls"
            "&sni=203.0.113.7&fp=edge&alpn=http%2F1.1&vcn=cert.example&insecure=1#WS")
    stream = node_url_to_xray_outbound(link)["streamSettings"]
    assert stream["wsSettings"] == {"path": "/a/b?ed=2048", "host": "203.0.113.7"}
    # Xray 26 removed allowInsecure; vcn is what replaced it.
    assert stream["tlsSettings"] == {"serverName": "203.0.113.7", "fingerprint": "edge", "alpn": ["http/1.1"],
                                     "verifyPeerCertByName": "cert.example"}


def test_grpc_and_xhttp_links_keep_their_settings():
    grpc = node_url_to_xray_outbound("vless://u@g.example:443?type=grpc&serviceName=gs&mode=multi&authority=a.example"
                                     f"&security=reality&sni=a.example&pbk={PBK}&sid=01#G")["streamSettings"]
    assert grpc["grpcSettings"] == {"serviceName": "gs", "multiMode": True, "authority": "a.example"}
    assert grpc["realitySettings"]["fingerprint"] == "chrome"
    extra = {"xPaddingBytes": "100-1000", "xmux": {"maxConcurrency": "8-32", "cMaxLifetimeMs": 0}, "noSSEHeader": True}
    xhttp = node_url_to_xray_outbound(f"vless://u@x.example:443?type=xhttp&path=%2Fx&host=h.example&mode=packet-up"
                                      f"&extra={fm(extra)}&security=tls&sni=x.example#X")["streamSettings"]
    assert xhttp["xhttpSettings"] == {"path": "/x", "mode": "packet-up", "host": "h.example", "extra": extra}


def test_trojan_and_shadowsocks_links():
    trojan = node_url_to_xray_outbound("trojan://secret@t.example:443?type=ws&path=%2Fws&sni=t.example#T")
    assert trojan["settings"] == {"address": "t.example", "port": 443, "password": "secret"}
    assert trojan["streamSettings"]["security"] == "tls"
    expected = {"protocol": "shadowsocks",
                "settings": {"address": "s.example", "port": 8388, "method": "aes-128-gcm", "password": "pw"}}
    userinfo = "YWVzLTEyOC1nY206cHc"  # base64 of aes-128-gcm:pw
    assert node_url_to_xray_outbound("ss://aes-128-gcm:pw@s.example:8388#S") == expected
    assert node_url_to_xray_outbound(f"ss://{userinfo}@s.example:8388#S") == expected
    assert node_url_to_xray_outbound("ss://YWVzLTEyOC1nY206cHdAcy5leGFtcGxlOjgzODg#S") == expected
    assert node_url_to_xray_outbound("vless://u@[2001:db8::1]:443?security=none#V6")["settings"]["address"] == "2001:db8::1"


@pytest.mark.parametrize("link", [
    "vless://u@h.example:443?type=h2&security=tls#HTTP/2, replaced by XHTTP",
    "vless://u@h.example:443?type=kcp#mKCP",
    "vless://u@h.example:443?security=xtls#Old XTLS",
    f"ss://{'YWVzLTEyOC1nY206cHc'}@s.example:8388?plugin=obfs-local#Plugin",
    "vmess://eyJhZGQiOiIxOTIuMC4yLjUifQ==#VMess",
    "vless://no-server#Broken",
    "vless://u@h.example#No port",
])
def test_links_xray_cannot_use_give_no_outbound(link):
    assert node_url_to_xray_outbound(link) is None


# Configuration and log.


def test_config_pins_a_listener_to_each_outbound_and_refuses_anything_else():
    a = {"tag": "node-0", "protocol": "shadowsocks", "settings": {"address": "10.0.0.1", "port": 8388}}
    b = {"tag": "node-1", "protocol": "shadowsocks", "settings": {"address": "s.example", "port": 8388}}
    config = json.loads(render_xray_config([(a, 20001), (b, 20002)]))
    assert config["inbounds"] == [
        {"tag": "in-node-0", "listen": "127.0.0.1", "port": 20001, "protocol": "mixed", "settings": {}},
        {"tag": "in-node-1", "listen": "127.0.0.1", "port": 20002, "protocol": "mixed", "settings": {}},
    ]
    assert config["routing"]["rules"] == [
        {"type": "field", "inboundTag": ["in-node-0"], "outboundTag": "node-0"},
        {"type": "field", "inboundTag": ["in-node-1"], "outboundTag": "node-1"},
    ]
    # What no rule names goes to the first outbound: nowhere.
    assert config["outbounds"] == [{"tag": "refuse", "protocol": "blackhole"}, a, b]
    assert config["log"]["access"] == "none" and "dns" not in config

    hosts = {"s.example": ["203.0.113.7"]}
    with_hosts = json.loads(render_xray_config([(a, 20001), (b, 20002)], hosts))
    assert with_hosts["dns"] == {"hosts": hosts}
    # Only the outbound whose server the hosts name looks it up there.
    assert "streamSettings" not in with_hosts["outbounds"][1]
    assert with_hosts["outbounds"][2]["streamSettings"] == {"sockopt": {"domainStrategy": "UseIP"}}
    assert "streamSettings" not in b


def test_xray_log_names_the_refused_outbound_the_taken_port_and_what_failed():
    core = XrayCore()
    lines = ["Xray 26.11.9 (Xray, Penetrates Everything.)",
             "2026/11/21 00:00:00.000000 [Warning] common/errors: The feature gRPC transport is deprecated",
             "Failed to start: main: failed to load config files: [config.json] > infra/conf: failed to build "
             "outbound config with tag node-4 > infra/conf: unknown cipher method"]
    assert core.refused(lines, ["node-3", "node-4"]) == (1, "Failed to build outbound: infra/conf: unknown cipher method")
    assert core.refused(lines, ["node-3"]) is None
    assert core.detail(lines).startswith("Failed to start: main: failed to load config files")
    assert core.detail(lines[:2]) == ""
    busy = ["Failed to start: app/proxyman/inbound: failed to listen TCP on 20002 > transport/internet: "
            "failed to listen on address: 127.0.0.1:20002 > bind: address already in use"]
    assert list(core.busy(busy, [("node-0", 20001), ("node-1", 20002)])) == [1]
    assert core.detail(["panic: runtime error: index out of range", "goroutine 1 [running]:"]) == (
        "panic: runtime error: index out of range")


def test_the_core_setting_picks_the_core():
    assert core_for({}).name == "xray"
    assert core_for({"core": "Mihomo"}).name == "mihomo"
    assert core_for({"core": "sing-box"}).name == "xray"
    assert ConfigManager.load("/nonexistent/settings.json")["core"] == "xray"


def test_settings_keep_a_known_core_and_replace_another(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"core": " MIHOMO "}), encoding="utf-8")
    assert ConfigManager.load(str(path))["core"] == "mihomo"
    path.write_text(json.dumps({"core": "v2ray"}), encoding="utf-8")
    assert ConfigManager.load(str(path))["core"] == "xray"


def test_core_option_applies_to_this_run(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"subscriptions": ["https://sub.example/x"]}), encoding="utf-8")
    from nodesieve.ui.cli import main
    with patch("nodesieve.ui.cli.VPNDashboard") as dashboard:
        dashboard.return_value.run_pipeline_async = AsyncMock(return_value=True)
        main(["--config-file", str(settings), "--core", "mihomo"])
    assert dashboard.call_args.kwargs["config"]["core"] == "mihomo"
    assert "core" not in json.loads(settings.read_text(encoding="utf-8"))


# The binary.


@pytest.mark.parametrize("machine, android, system, asset", [
    ("x86_64", False, "linux", "Xray-linux-64.zip"),
    ("aarch64", False, "linux", "Xray-linux-arm64-v8a.zip"),
    ("aarch64", True, "linux", "Xray-android-arm64-v8a.zip"),
    ("armv7l", False, "linux", "Xray-linux-arm32-v7a.zip"),
    ("armv7l", True, "linux", "Xray-linux-arm32-v7a.zip"),
    ("AMD64", False, "windows", "Xray-windows-64.zip"),
    ("arm64", False, "macos", "Xray-macos-arm64-v8a.zip"),
    ("mips", False, "linux", None),
])
def test_release_archive_for_each_platform(machine, android, system, asset):
    assert xray_asset(machine, android, system) == asset


def _release(binary=b"#!/bin/sh\necho xray\n", digest=None):
    """A release's archive and its .dgst file."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("xray", binary)
        bundle.writestr("geoip.dat", b"geo")
    archive = buffer.getvalue()
    digest = digest or hashlib.sha256(archive).hexdigest()
    return archive, f"MD5= 0\nSHA1= 0\nSHA2-256= {digest}\nSHA2-512= 0\n".encode()


def _serve_release(monkeypatch, tmp_path, archive, dgst):
    path = tmp_path / "xray"
    asset = xray_asset()
    monkeypatch.setattr(xray, "XRAY_PATH", str(path))
    monkeypatch.setattr(xray, "release_assets", lambda url: {asset: "https://x/a.zip", f"{asset}.dgst": "https://x/a.dgst"})
    monkeypatch.setattr(xray, "download", lambda url, timeout=0: archive if url.endswith(".zip") else dgst)
    return path


@pytest.mark.skipif(xray_asset() is None, reason="Xray has no release for this platform")
def test_setup_installs_the_release_binary_once_its_sha256_matches(monkeypatch, tmp_path):
    archive, dgst = _release()
    path = _serve_release(monkeypatch, tmp_path, archive, dgst)
    XrayCore().setup()
    assert path.read_bytes() == b"#!/bin/sh\necho xray\n"
    assert os.name == "nt" or os.access(path, os.X_OK)
    assert sorted(os.listdir(tmp_path)) == ["xray"]


@pytest.mark.skipif(xray_asset() is None, reason="Xray has no release for this platform")
def test_setup_refuses_an_archive_that_does_not_match_its_sha256(monkeypatch, tmp_path):
    archive, dgst = _release(digest="0" * 64)
    path = _serve_release(monkeypatch, tmp_path, archive, dgst)
    with pytest.raises(SystemExit):
        XrayCore().setup()
    assert not path.exists() and os.listdir(tmp_path) == []


# Batches, through a stand-in for Xray.


FAKE_XRAY = r'''
import asyncio
import json
import os
import sys

args = sys.argv[1:]
with open(args[args.index("-c") + 1], encoding="utf-8") as f:
    config = json.load(f)
outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
routes = {rule["inboundTag"][0]: rule["outboundTag"] for rule in config["routing"]["rules"]}
print("Xray 26.11.9 (Xray, Penetrates Everything.)", flush=True)
for outbound in config["outbounds"]:
    if (outbound.get("settings") or {}).get("method") == "not-a-cipher":
        print("Failed to start: main: failed to load config files: [config.json] > infra/conf: failed to build "
              f"outbound config with tag {outbound['tag']} > infra/conf: failed to build outbound handler for "
              "protocol shadowsocks > infra/conf: unknown cipher method", flush=True)
        sys.exit(23)
servers = {(outbound.get("settings") or {}).get("address") for outbound in config["outbounds"]}
marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "port-was-busy")


async def hold(reader, writer):
    await reader.read()
    writer.close()


async def ready(reader, writer):
    """Like Xray's HTTP outbound: dials once the client sent data, and drops what comes with the answer."""
    await reader.readuntil(b"\r\n\r\n")
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()
    line = await reader.readline()
    server = outbounds[routes["in-nodesieve-ready"]]["settings"]["servers"][0]
    far_reader, far_writer = await asyncio.open_connection(server["address"], server["port"])
    far_writer.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
    await far_writer.drain()
    answer = await far_reader.read(65536)
    while b"\r\n\r\n" not in answer:
        answer += await far_reader.read(65536)
    far_writer.write(line)
    await far_writer.drain()
    writer.write(await far_reader.read(4096))
    await writer.drain()
    far_writer.close()
    writer.close()


async def main():
    for inbound in config["inbounds"]:
        busy = (not os.path.exists(marker) and inbound["tag"] != "in-nodesieve-ready"
                and outbounds[routes[inbound["tag"]]]["settings"].get("address") == "busy-once.invalid")
        try:
            if busy:
                open(marker, "w").close()
                raise OSError("bind: address already in use")
            handler = ready if inbound["tag"] == "in-nodesieve-ready" else hold
            await asyncio.start_server(handler, inbound["listen"], inbound["port"])
        except OSError as exc:
            print(f"Failed to start: app/proxyman/inbound: failed to listen TCP on {inbound['port']} > {exc}",
                  flush=True)
            sys.exit(255)
    print("2026/11/21 00:00:00.000000 [Warning] core: Xray 26.11.9 started", flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
'''


@pytest.fixture
def fake_xray(tmp_path, monkeypatch):
    """Runs the stand-in for Xray, and counts how often it is started."""
    path = tmp_path / "fake-xray"
    path.write_text(f"#!{sys.executable}\n{FAKE_XRAY}", encoding="utf-8")
    path.chmod(0o755)
    monkeypatch.setattr(xray, "XRAY_PATH", str(path))
    starts = []
    launch = asyncio.create_subprocess_exec

    async def counted(*command, **kwargs):
        starts.append(command)
        return await launch(*command, **kwargs)

    monkeypatch.setattr(core_batch.asyncio, "create_subprocess_exec", counted)
    return starts


def serve(nodes, inspect, config=CONFIG):
    async def run():
        async with CoreBatch(nodes, config) as instance:
            return await inspect(instance)
    return asyncio.run(run())


def crash_log():
    path = Path(core_batch.PROJECT_ROOT) / "crashed_nodes.txt"
    return path.read_text(encoding="utf-8") if path.exists() else ""


REFUSED = ("crashed with code 23 [Failed to build outbound: infra/conf: failed to build outbound handler for "
           "protocol shadowsocks > infra/conf: unknown cipher method]")


def test_nodes_of_a_batch_share_one_xray_that_relays(fake_xray):
    nodes = [BatchNode(ss(f"10.0.0.{n}", f"node{n}"), idx=n, total=3) for n in (1, 2, 3)]

    async def inspect(instance):
        assert all(endpoint.error is None for endpoint in instance.endpoints)
        assert all([await core_batch._accepts(endpoint.port) for endpoint in instance.endpoints])
        return [endpoint.port for endpoint in instance.endpoints]

    ports = serve(nodes, inspect)
    assert len(set(ports)) == 3
    assert len(fake_xray) == 1 and fake_xray[0][1:3] == ("run", "-c")
    assert not set(ports) & PortManager._allocated_ports


def test_a_node_xray_refuses_is_set_aside_and_the_rest_share_one_xray(fake_xray, capsys):
    nodes = [BatchNode(ss("10.0.0.1", "one"), idx=1, total=3),
             BatchNode(ss("10.0.0.9", "broken", cipher="not-a-cipher"), idx=2, total=3),
             BatchNode(ss("10.0.0.3", "three"), idx=3, total=3)]

    async def inspect(instance):
        return [endpoint.error for endpoint in instance.endpoints], len(instance._processes)

    errors, processes = serve(nodes, inspect)
    assert errors == [None, REFUSED, None]
    assert (processes, len(fake_xray)) == (1, 2)
    assert crash_log() == f"[broken] (10.0.0.9:8388) ERROR: {REFUSED}\n{nodes[1].link}\n\n"
    assert f"[-] Node 2/3 [broken] (10.0.0.9:8388) -> ERROR: xray {REFUSED}" in capsys.readouterr().out


def test_a_listener_whose_port_was_taken_meanwhile_gets_another(fake_xray):
    nodes = [BatchNode(ss("10.0.0.1", "one")), BatchNode(ss("busy-once.invalid", "two"))]

    async def inspect(instance):
        return [endpoint.error for endpoint in instance.endpoints]

    assert serve(nodes, inspect) == [None, None]
    assert len(fake_xray) == 2
    assert crash_log() == ""


def test_a_link_without_an_xray_outbound_starts_nothing(fake_xray):
    async def inspect(instance):
        return [str(endpoint.exception) for endpoint in instance.endpoints]

    nodes = [BatchNode("vless://u@h.example:443?type=h2&security=tls#h2"), BatchNode("vmess://e30=#other")]
    assert serve(nodes, inspect) == ["The link does not convert to an Xray outbound"] * 2
    assert fake_xray == []


def test_runner_raises_why_xray_refused_its_node(fake_xray):
    async def run():
        async with CoreRunner(node=ss("10.0.0.9", "broken", cipher="not-a-cipher"), config=CONFIG):
            pass

    with pytest.raises(RuntimeError, match="unknown cipher method"):
        asyncio.run(run())


def test_batch_on_android_hands_the_resolved_servers_to_xray(monkeypatch):
    monkeypatch.setattr(core_batch, "IS_ANDROID", True)
    written = {}

    async def launch(*command, **kwargs):
        with open(command[command.index("-c") + 1], encoding="utf-8") as config:
            written["config"] = json.load(config)
        raise OSError("not starting Xray in this test")

    async def resolve(self, host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", 0))]

    nodes = [BatchNode(ss("node.example", "named")), BatchNode(ss("198.51.100.9", "by-address"))]
    with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
            patch.object(core_batch.asyncio, "create_subprocess_exec", new=launch):
        endpoints = serve(nodes, lambda instance: asyncio.sleep(0, instance.endpoints))
    assert written["config"]["dns"] == {"hosts": {"node.example": ["203.0.113.7"]}}
    by_tag = {outbound["tag"]: outbound for outbound in written["config"]["outbounds"]}
    assert by_tag["node-0"]["streamSettings"] == {"sockopt": {"domainStrategy": "UseIP"}}
    assert "streamSettings" not in by_tag["node-1"]
    assert all(isinstance(endpoint.exception, OSError) for endpoint in endpoints)


# The real binary.


def _real_xray():
    for path in (XRAY_PATH, shutil.which("xray")):
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


@pytest.fixture
def real_xray(monkeypatch):
    path = _real_xray()
    if path is None:
        pytest.skip("no Xray binary in the project directory or on PATH")
    monkeypatch.setattr(xray, "XRAY_PATH", path)
    return path


async def _answer(reader, writer, hits):
    await reader.readuntil(b"\r\n\r\n")
    hits.append(1)
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
    await writer.drain()
    writer.close()


async def socks5_get(port, target_port):
    """GET / from 127.0.0.1:target_port through a SOCKS5 proxy, as a SOCKS client asks a node."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x00"
        writer.write(b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + target_port.to_bytes(2, "big"))
        await writer.drain()
        reply = await reader.readexactly(4)
        assert reply[1] == 0
        await reader.readexactly({1: 4, 4: 16}[reply[3]] + 2)
        writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return await asyncio.wait_for(reader.read(), timeout=5)
    finally:
        writer.close()


@contextlib.asynccontextmanager
async def xray_server(binary, tmp_path, inbound, socket_type=socket.SOCK_STREAM):
    """Run the far end of a test node on a kernel-allocated port."""
    with socket.socket(socket.AF_INET, socket_type) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        ready_port = PortManager.get_free_port()
    ready_server = await asyncio.start_server(core_batch._serve_ready, "127.0.0.1", 0)
    config = {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {**inbound, "listen": "127.0.0.1", "port": port},
            {"tag": "ready-in", "listen": "127.0.0.1", "port": ready_port, "protocol": "mixed", "settings": {}},
        ],
        "outbounds": [
            # Xray 26 blackholes private targets of what its proxy inbounds receive, and the
            # tests' target is on 127.0.0.1.
            {"tag": "direct", "protocol": "freedom",
             "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"tag": "ready", "protocol": "http", "settings": {"servers": [
                {"address": "127.0.0.1", "port": ready_server.sockets[0].getsockname()[1]}]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["ready-in"], "outboundTag": "ready"}]},
    }
    directory = tmp_path / "far-end"
    directory.mkdir()
    (directory / "config.json").write_text(json.dumps(config), encoding="utf-8")
    process = await asyncio.create_subprocess_exec(
        binary, "run", "-c", str(directory / "config.json"),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        for _ in range(500):
            if await core_batch._relays(ready_port):
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail(f"The {inbound['protocol']} server did not start")
        yield port
    finally:
        ready_server.close()
        if process.returncode is None:
            process.terminate()
        await process.wait()
        PortManager.release_port(ready_port)


def test_real_xray_serves_each_node_through_its_own_listener(real_xray, tmp_path):
    async def run():
        hits, recorded = [], []

        async def record(reader, writer):
            recorded.append(await reader.read(64))
            writer.close()

        target = await asyncio.start_server(lambda r, w: _answer(r, w, hits), "127.0.0.1", 0)
        recorder = await asyncio.start_server(record, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{target.sockets[0].getsockname()[1]}/"
        inbound = {"protocol": "shadowsocks", "settings": {"method": "aes-128-gcm", "password": PASSWORD, "network": "tcp"}}
        async with xray_server(real_xray, tmp_path, inbound) as ss_port:
            nodes = [BatchNode(ss("127.0.0.1", "A", port=ss_port)),
                     BatchNode(ss("127.0.0.1", "B", port=recorder.sockets[0].getsockname()[1])),
                     BatchNode(ss("10.0.0.9", "C", cipher="not-a-cipher"))]
            async with CoreBatch(nodes, CONFIG) as instance:
                a, b, c = instance.endpoints
                assert len(instance._processes) == 1
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                    async with session.get(url, proxy=a.proxy_url) as response:
                        assert await response.text() == "hello"
                    # Each listener also speaks SOCKS5, for SOCKS clients.
                    assert (await socks5_get(a.port, target.sockets[0].getsockname()[1])).endswith(b"hello")
                    # B's server is no Shadowsocks server: the request fails.
                    try:
                        async with session.get(url, proxy=b.proxy_url) as response:
                            assert response.status != 200
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass
                assert c.error is not None and "unknown cipher method" in c.error
        target.close()
        recorder.close()
        # B's listener led only to B's server, though nothing else goes anywhere.
        assert len(hits) == 2 and len(recorded) == 1

    asyncio.run(run())


@pytest.mark.parametrize("core", ["xray", "mihomo"])
@pytest.mark.parametrize("obfs", ["salamander", "gecko"])
def test_real_core_relays_through_a_udp_only_hysteria2_server(real_xray, tmp_path, core, obfs):
    if core == "mihomo" and not os.access(MIHOMO_PATH, os.X_OK):
        pytest.skip("no Mihomo binary in the project directory")
    cert = json.loads(subprocess.check_output([real_xray, "tls", "cert", "-domain=hy2.test", "-json"], cwd=tmp_path))
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert("\n".join(cert["certificate"]))).hexdigest()
    obfs_settings = {"password": "test-obfs"}
    if obfs == "gecko":
        obfs_settings["packetSize"] = "512-1200"
    inbound = {"protocol": "hysteria", "settings": {"version": 2},
               "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"certificates": [cert]},
                                  "hysteriaSettings": {"version": 2, "auth": PASSWORD},
                                  "finalmask": {"udp": [{"type": "salamander", "settings": obfs_settings}]}}}

    async def run():
        hits = []
        target = await asyncio.start_server(lambda r, w: _answer(r, w, hits), "127.0.0.1", 0)
        async with target, xray_server(real_xray, tmp_path, inbound, socket.SOCK_DGRAM) as port:
            # Only the hopping port has a server. This also detects cores silently ignoring mport.
            link = (f"hy2://{PASSWORD}@127.0.0.1:1/?mport={port}&sni=hy2.test&pinSHA256={pin}"
                    f"&obfs={obfs}&obfs-password=test-obfs&insecure=1#Local")
            url = f"http://127.0.0.1:{target.sockets[0].getsockname()[1]}/"
            async with CoreBatch([BatchNode(link), BatchNode(link.replace(pin, "00" * 32))], {"core": core}) as batch:
                endpoint, wrong_pin = batch.endpoints
                assert not endpoint.error and not wrong_pin.error
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                    async with session.get(url, proxy=endpoint.proxy_url) as response:
                        assert await response.text() == "hello"
                    try:
                        async with session.get(url, proxy=wrong_pin.proxy_url) as response:
                            assert response.status != 200
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass
            assert hits == [1]

    asyncio.run(run())


def test_real_xray_reaches_a_node_through_its_hosts_entry(real_xray, monkeypatch):
    """On Android, Xray connects to a server whose name only Android's resolver knows."""
    monkeypatch.setattr(core_batch, "IS_ANDROID", True)
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
    # .invalid never resolves through DNS, so only the hosts entry can lead Xray there.
    outbound = {"protocol": "http", "settings": {"servers": [
        {"address": "upstream.nodesieve.invalid", "port": upstream.getsockname()[1]}]}}

    async def resolve(self, host, port, **kwargs):
        assert host == "upstream.nodesieve.invalid"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    async def run():
        async with CoreBatch([BatchNode("http://upstream.nodesieve.invalid#Node", idx=1, total=1)], CONFIG) as instance:
            endpoint = instance.endpoints[0]
            assert endpoint.error is None
            reader, writer = await asyncio.open_connection("127.0.0.1", endpoint.port)
            writer.write(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\nhello")
            await writer.drain()
            await asyncio.get_running_loop().run_in_executor(None, accepting.join, 10)
            writer.close()

    try:
        with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
                patch.object(XrayCore, "proxy", return_value=outbound):
            asyncio.run(run())
        assert received and received[0].startswith(b"CONNECT example.invalid:443 ")
    finally:
        upstream.close()
