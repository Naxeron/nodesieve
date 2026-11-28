"""Xray outbound parsing, binary download, batch orchestration, resource limits, and real-binary relay tests."""

import asyncio
import contextlib
import hashlib
import io
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

import aiohttp
import pytest

from nodesieve.constants import XRAY_PATH
from nodesieve.core import batch as core_batch, limits, xray
from nodesieve.core.batch import (
    BatchNode,
    CoreBatch,
    CoreInstanceLost,
    CoreRunner,
    PortManager,
    run_in_batches,
)
from nodesieve.core.limits import ResourceLimits
from nodesieve.core.xray import XrayCore, render_xray_config, xray_asset
from nodesieve.parsers.xray import node_url_to_xray_outbound

PASSWORD = "nodesieve-test-password"
PBK = "vpmWvtTfqGiWK_mQey9hK41fgWez3GVX07_h6uLWrS4"
FRAGMENT = {"tcp": [{"type": "fragment", "settings": {"delay": "0", "length": "10-20", "packets": "tlshello"}}]}


def ss(server, tag, cipher="aes-128-gcm", port=8388, password=PASSWORD):
    return f"ss://{cipher}:{password}@{server}:{port}#{tag}"


def fm(value):
    return json.dumps(value, separators=(",", ":")).replace("{", "%7B").replace("}", "%7D").replace('"', "%22")


# --- Share links to Xray outbounds ---

def test_xray_outbound_conversion_for_vless_trojan_and_ss():
    link = (f"vless://11111111-2222-3333-4444-555555555555@node.example:443?encryption=none&type=tcp"
            f"&security=reality&sni=www.example.com&fp=firefox&pbk={PBK}&sid=ab12&spx=%2F"
            f"&flow=xtls-rprx-vision&fm={fm(FRAGMENT)}#Node")
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

    ws = node_url_to_xray_outbound(
        "vless://u@203.0.113.7:443?type=ws&path=%2Fa%2Fb%3Fed%3D2048&host=203.0.113.7&security=tls"
        "&sni=203.0.113.7&fp=edge&alpn=http%2F1.1&vcn=cert.example&insecure=1#WS")["streamSettings"]
    assert ws["wsSettings"] == {"path": "/a/b?ed=2048", "host": "203.0.113.7"}
    assert ws["tlsSettings"] == {"serverName": "203.0.113.7", "fingerprint": "edge", "alpn": ["http/1.1"],
                                 "verifyPeerCertByName": "cert.example"}

    grpc = node_url_to_xray_outbound(
        f"vless://u@g.example:443?type=grpc&serviceName=gs&mode=multi&authority=a.example&security=reality&sni=a.example&pbk={PBK}&sid=01#G"
    )["streamSettings"]
    assert grpc["grpcSettings"] == {"serviceName": "gs", "multiMode": True, "authority": "a.example"}
    assert grpc["realitySettings"]["fingerprint"] == "chrome"

    extra = {"xPaddingBytes": "100-1000", "xmux": {"maxConcurrency": "8-32", "cMaxLifetimeMs": 0}, "noSSEHeader": True}
    xhttp = node_url_to_xray_outbound(
        f"vless://u@x.example:443?type=xhttp&path=%2Fx&host=h.example&mode=packet-up&extra={fm(extra)}&security=tls&sni=x.example#X"
    )["streamSettings"]
    assert xhttp["xhttpSettings"] == {"path": "/x", "mode": "packet-up", "host": "h.example", "extra": extra}

    trojan = node_url_to_xray_outbound("trojan://secret@t.example:443?type=ws&path=%2Fws&sni=t.example#T")
    assert trojan["settings"] == {"address": "t.example", "port": 443, "password": "secret"}
    assert trojan["streamSettings"]["security"] == "tls"

    expected_ss = {"protocol": "shadowsocks",
                   "settings": {"address": "s.example", "port": 8388, "method": "aes-128-gcm", "password": "pw"}}
    for link in ("ss://aes-128-gcm:pw@s.example:8388#S",
                 "ss://YWVzLTEyOC1nY206cHc@s.example:8388#S",
                 "ss://YWVzLTEyOC1nY206cHdAcy5leGFtcGxlOjgzODg#S"):
        assert node_url_to_xray_outbound(link) == expected_ss
    assert node_url_to_xray_outbound("vless://u@[2001:db8::1]:443?security=none#V6")["settings"]["address"] == "2001:db8::1"


@pytest.mark.parametrize("link", [
    "vless://u@h.example:443?type=h2&security=tls#h2",
    "vless://u@h.example:443?type=kcp#kcp",
    "vless://u@h.example:443?security=xtls#xtls",
    "ss://YWVzLTEyOC1nY206cHc@s.example:8388?plugin=obfs-local#Plugin",
    "vmess://eyJhZGQiOiIxOTIuMC4yLjUifQ==#VMess",
    "vless://no-server#Broken",
    "vless://u@h.example#NoPort",
])
def test_unsupported_links_return_none(link):
    assert node_url_to_xray_outbound(link) is None


# --- Config rendering, log parsing, and binary download ---

def test_render_config_and_log_parsing():
    a = {"tag": "node-0", "protocol": "shadowsocks", "settings": {"address": "10.0.0.1", "port": 8388}}
    b = {"tag": "node-1", "protocol": "shadowsocks", "settings": {"address": "s.example", "port": 8388}}
    cfg = json.loads(render_xray_config([(a, 20001), (b, 20002)]))
    assert cfg["outbounds"] == [{"tag": "refuse", "protocol": "blackhole"}, a, b]
    assert cfg["routing"]["rules"] == [
        {"type": "field", "inboundTag": ["in-node-0"], "outboundTag": "node-0"},
        {"type": "field", "inboundTag": ["in-node-1"], "outboundTag": "node-1"},
    ]
    assert cfg["log"]["access"] == "none" and "dns" not in cfg

    with_hosts = json.loads(render_xray_config([(a, 20001), (b, 20002)], {"s.example": ["203.0.113.7"]}))
    assert with_hosts["dns"] == {"hosts": {"s.example": ["203.0.113.7"]}}
    assert "streamSettings" not in with_hosts["outbounds"][1]
    assert with_hosts["outbounds"][2]["streamSettings"] == {"sockopt": {"domainStrategy": "UseIP"}}
    assert "streamSettings" not in b

    core = XrayCore()
    lines = ["Xray 26.11.9", "2026/11/21 00:00:00 [Warning] deprecated",
             "Failed to start: main: failed to build outbound config with tag node-4 > unknown cipher method"]
    assert core.refused(lines, ["node-3", "node-4"]) == (1, "Failed to build outbound: unknown cipher method")
    assert core.refused(lines, ["node-3"]) is None
    assert core.detail(lines).startswith("Failed to start:") and core.detail(lines[:2]) == ""
    assert list(core.busy(["Failed to start: failed to listen TCP on 20002 > bind"], [("node-0", 20001), ("node-1", 20002)])) == [1]
    assert core.detail(["panic: runtime error", "goroutine 1"]) == "panic: runtime error"

    # Per-outbound [Info] log diagnostics isolate tags and summarize concrete failure causes.
    info_lines = [
        "2026/11/28 22:52:06 [Info] [100] app/dispatcher: taking detour [node-0] for [tcp:1.1.1.1:443]",
        "2026/11/28 22:52:11 [Info] [100] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/hysteria: failed to find an available destination > timeout: no recent network activity",
        "2026/11/28 22:52:06 [Info] [101] app/dispatcher: taking detour [node-1] for [tcp:1.1.1.1:443]",
        "2026/11/28 22:52:06 [Info] [101] app/proxyman/outbound: failed to process outbound traffic > proxy/hysteria: failed to find an available destination > INTERNAL_ERROR (local): tls: failed to verify certificate: x509: certificate signed by unknown authority",
        "2026/11/28 22:52:06 [Info] [102] app/dispatcher: taking detour [node-2] for [tcp:1.1.1.1:443]",
        "2026/11/28 22:52:06 [Info] [102] app/proxyman/outbound: failed to process outbound traffic > proxy/hysteria: failed to find an available destination > transport/internet/hysteria: auth failed code 404",
        "2026/11/28 22:52:06 [Info] [103] app/dispatcher: taking detour [node-3] for [tcp:1.1.1.1:443]",
        "2026/11/28 22:52:08 [Info] [103] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: [transport/internet/tcp: failed to dial to dest > dial tcp 1.2.3.4:443: connect: connection refused transport/internet/tcp: failed to dial to dest > dial tcp 1.2.3.4:443: connect: connection refused] > common/retry: all retry attempts failed",
        "2026/11/28 22:52:06 [Info] [104] app/dispatcher: taking detour [node-4] for [tcp:1.1.1.1:443]",
        "2026/11/28 22:52:06 [Info] [104] proxy/hysteria: tunneling request to tcp:1.1.1.1:443 via TCP:127.0.0.1:443",
        "2026/11/28 22:52:06 [Info] [105] app/dispatcher: taking detour [node-5] for [tcp:1.1.1.1:443]",
    ]
    assert core.outbound_status(info_lines, "node-0") == ("error", "QUIC handshake timeout (no UDP response)")
    assert core.outbound_status(info_lines, "node-1") == ("error", "TLS certificate error: certificate signed by unknown authority")
    assert core.outbound_status(info_lines, "node-2") == ("error", "Hysteria 2 auth failed code 404")
    assert core.outbound_status(info_lines, "node-3") == ("error", "Proxy connection refused")
    assert core.outbound_status(info_lines, "node-4") == ("tunneled", None)
    assert core.outbound_status(info_lines, "node-5") == ("dialing", None)
    assert core.outbound_status(info_lines, "node-99") == ("none", None)


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


@pytest.mark.skipif(xray_asset() is None, reason="Xray has no release for this platform")
def test_setup_verifies_sha256_before_installing(monkeypatch, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as bundle:
        bundle.writestr("xray.exe" if os.name == "nt" else "xray", b"#!/bin/sh\necho xray\n")
    archive = buf.getvalue()
    asset = xray_asset()
    path = tmp_path / "xray"
    monkeypatch.setattr(xray, "XRAY_PATH", str(path))
    monkeypatch.setattr(xray, "release_assets", lambda url: {asset: "https://x/a.zip", f"{asset}.dgst": "https://x/a.dgst"})

    # Bad SHA-256 refuses to install.
    monkeypatch.setattr(xray, "download", lambda url, timeout=0: archive if url.endswith(".zip") else f"SHA2-256= {'0' * 64}\n".encode())
    with pytest.raises(SystemExit):
        XrayCore().setup()
    assert not path.exists() and os.listdir(tmp_path) == []

    # Good SHA-256 installs atomically.
    dgst = f"SHA2-256= {hashlib.sha256(archive).hexdigest()}\n".encode()
    monkeypatch.setattr(xray, "download", lambda url, timeout=0: archive if url.endswith(".zip") else dgst)
    XrayCore().setup()
    assert path.read_bytes() == b"#!/bin/sh\necho xray\n" and (os.name == "nt" or os.access(path, os.X_OK))


# --- Resource limits ---

@pytest.mark.parametrize("workers, plan", [
    (1, (1, 2)), (8, (8, 2)), (29, (29, 2)), (32, (32, 2)), (33, (32, 3)), (64, (32, 3)), (256, (32, 9)),
])
def test_core_instances_plan(workers, plan):
    assert ResourceLimits.core_instances(workers) == plan


def test_resource_limits_router_memory_android_cap_and_bad_budget(monkeypatch):
    monkeypatch.setattr(limits, "get_free_memory_mb", lambda: 787.0)
    workers, _ = ResourceLimits.get_max_safe_workers({"mem_per_worker": 8})
    assert workers == 29 and ResourceLimits.core_instances(workers)[1] == 2
    assert ResourceLimits.memory_needed_mb(workers, 8) <= 787 - limits.RESERVED_MB
    assert ResourceLimits.memory_needed_mb(workers + 1, 8) > 787 - limits.RESERVED_MB
    assert ResourceLimits.get_max_safe_workers({"mem_per_worker": 0})[0] == 29
    assert ResourceLimits.get_max_safe_workers({"mem_per_worker": "lots"})[0] == 29

    monkeypatch.setattr(limits, "get_free_memory_mb", lambda: 6000.0)
    monkeypatch.setattr(limits, "IS_ANDROID", True)
    assert ResourceLimits.get_max_safe_workers({})[0] == 64


# --- Batches and run_in_batches with stand-in Xray ---

FAKE_XRAY = r'''
import asyncio, json, os, sys
args = sys.argv[1:]
with open(args[args.index("-c") + 1], encoding="utf-8") as f:
    config = json.load(f)
outbounds = {o["tag"]: o for o in config["outbounds"]}
routes = {r["inboundTag"][0]: r["outboundTag"] for r in config["routing"]["rules"]}
servers = {(o.get("settings") or {}).get("address") for o in config["outbounds"]}
print("Xray 26.11.9", flush=True)
for o in config["outbounds"]:
    if (o.get("settings") or {}).get("method") == "not-a-cipher":
        print(f"Failed to start: failed to build outbound config with tag {o['tag']} > unknown cipher method", flush=True)
        sys.exit(23)
if "panic.invalid" in servers:
    print("panic: runtime error: invalid memory address", file=sys.stderr, flush=True)
    sys.exit(2)
marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "port-was-busy")
relaying = False

async def hold(r, w):
    await r.read()
    w.close()

async def ready(r, w):
    await r.readuntil(b"\r\n\r\n")
    w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await w.drain()
    if relaying:
        line = await r.readline()
        srv = outbounds[routes["in-nodesieve-ready"]]["settings"]["servers"][0]
        fr, fw = await asyncio.open_connection(srv["address"], srv["port"])
        fw.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        await fw.drain()
        ans = await fr.read(65536)
        while b"\r\n\r\n" not in ans:
            ans += await fr.read(65536)
        fw.write(line)
        await fw.drain()
        w.write(await fr.read(4096))
        await w.drain()
        fw.close()
    w.close()

async def main():
    global relaying
    for inb in config["inbounds"]:
        busy = (not os.path.exists(marker) and inb["tag"] != "in-nodesieve-ready"
                and outbounds[routes[inb["tag"]]]["settings"].get("address") == "busy-once.invalid")
        try:
            if busy:
                open(marker, "w").close()
                raise OSError("bind: address already in use")
            await asyncio.start_server(ready if inb["tag"] == "in-nodesieve-ready" else hold, inb["listen"], inb["port"])
        except OSError as exc:
            print(f"Failed to start: failed to listen TCP on {inb['port']} > {exc}", flush=True)
            sys.exit(255)
    await asyncio.sleep(0.15)
    if "never-ready.invalid" not in servers:
        relaying = True
    if "crash.invalid" in servers:
        await asyncio.sleep(0.4)
        print("panic: crashed while serving", file=sys.stderr, flush=True)
        os._exit(2)
    await asyncio.Event().wait()

asyncio.run(main())
'''


@pytest.fixture
def fake_xray(tmp_path, monkeypatch):
    path = tmp_path / "fake-xray"
    path.write_text(f"#!{sys.executable}\n{FAKE_XRAY}", encoding="utf-8")
    path.chmod(0o755)
    monkeypatch.setattr(xray, "XRAY_PATH", str(path))
    starts, launch = [], asyncio.create_subprocess_exec

    async def counted(*command, **kwargs):
        starts.append(command)
        return await launch(*command, **kwargs)

    monkeypatch.setattr(core_batch.asyncio, "create_subprocess_exec", counted)
    return starts


def serve(nodes, inspect):
    async def run():
        async with CoreBatch(nodes, {}) as instance:
            return await inspect(instance)
    return asyncio.run(run())


def crash_log():
    p = Path(core_batch.PROJECT_ROOT) / "crashed_nodes.txt"
    return p.read_text(encoding="utf-8") if p.exists() else ""


def test_batch_sharing_ready_wait_refused_halving_busy_timeout_and_missing(fake_xray, monkeypatch, capsys, tmp_path):
    # Shared batch + ready delay.
    started = time.monotonic()
    nodes = [BatchNode(ss(f"10.0.0.{n}", f"n{n}"), idx=n, total=3) for n in (1, 2, 3)]

    async def inspect_shared(inst):
        assert all(ep.error is None and ep.shared for ep in inst.endpoints)
        for ep in inst.endpoints:
            assert await core_batch._accepts(ep.port)
            await ep.ensure_alive()
        return [ep.port for ep in inst.endpoints], time.monotonic()

    ports, ready_at = serve(nodes, inspect_shared)
    assert len(set(ports)) == 3 and len(fake_xray) == 1 and ready_at >= started + 0.15
    assert not set(ports) & PortManager._allocated_ports

    # Refused node set aside, rest share one process.
    fake_xray.clear()
    refused_nodes = [BatchNode(ss("10.0.0.1", "one"), 1, 3),
                     BatchNode(ss("10.0.0.9", "broken", cipher="not-a-cipher"), 2, 3),
                     BatchNode(ss("10.0.0.3", "three"), 3, 3)]
    errors, procs = serve(refused_nodes, lambda inst: asyncio.sleep(0, ([e.error for e in inst.endpoints], len(inst._processes))))
    assert errors[0] is None and errors[2] is None and "unknown cipher method" in errors[1]
    assert (procs, len(fake_xray)) == (1, 2)
    assert "[broken] (10.0.0.9:8388)" in crash_log() and "ERROR: xray" in capsys.readouterr().out

    # Unnamed crash found by binary halving.
    halving = [BatchNode(ss(s, t), n, 4) for n, (s, t) in enumerate(
        [("10.0.0.1", "a"), ("10.0.0.2", "b"), ("panic.invalid", "culprit"), ("10.0.0.4", "d")], 1)]
    errors, procs = serve(halving, lambda inst: asyncio.sleep(0, ([e.error for e in inst.endpoints], len(inst._processes))))
    assert errors[0] is None and errors[1] is None and errors[3] is None and "panic:" in errors[2] and procs == 2

    # Busy port retries with fresh ports.
    fake_xray.clear()
    busy_nodes = [BatchNode(ss("10.0.0.1", "one")), BatchNode(ss("busy-once.invalid", "two"))]
    assert serve(busy_nodes, lambda inst: asyncio.sleep(0, [e.error for e in inst.endpoints])) == [None, None]
    assert len(fake_xray) == 2

    # Timed-out core is not split up.
    fake_xray.clear()
    monkeypatch.setattr(core_batch, "START_TIMEOUT", 0.4)
    to_nodes = [BatchNode(ss("10.0.0.1", "one")), BatchNode(ss("never-ready.invalid", "two"))]
    assert serve(to_nodes, lambda inst: asyncio.sleep(0, [e.error for e in inst.endpoints])) == ["timed out opening port"] * 2
    assert len(fake_xray) == 1

    # Unsupported links start nothing.
    fake_xray.clear()
    bad = [BatchNode("vless://u@h.example:443?type=h2&security=tls#h2"), BatchNode("vmess://e30=#v")]
    assert serve(bad, lambda inst: asyncio.sleep(0, [str(e.exception) for e in inst.endpoints])) == [
        "The link does not convert to an Xray outbound"] * 2
    assert fake_xray == []

    # Missing binary fails all nodes with FileNotFoundError.
    monkeypatch.setattr(xray, "XRAY_PATH", str(tmp_path / "missing"))
    excs = serve([BatchNode(ss("10.0.0.1", "a"))], lambda inst: asyncio.sleep(0, [type(e.exception) for e in inst.endpoints]))
    assert excs == [FileNotFoundError]


def test_runner_mid_check_exit_and_retry_isolation(fake_xray, capsys):
    # Runner standalone, shared endpoint, and refused node.
    async def run_runner():
        async with CoreRunner(ss("10.0.0.1", "node"), {}) as r:
            port = r.port
            assert r.proxy_url == f"http://127.0.0.1:{port}" and await core_batch._accepts(port)
            await r.ensure_alive()
        assert not await core_batch._accepts(port)
        async with CoreBatch([BatchNode(ss("10.0.0.1", "a")), BatchNode(ss("10.0.0.2", "b"))], {}) as b:
            async with CoreRunner(b.endpoints[0].link, {}, endpoint=b.endpoints[0]) as r:
                assert r.port == b.endpoints[0].port
            assert await core_batch._accepts(b.endpoints[0].port)
        with pytest.raises(RuntimeError, match="unknown cipher method"):
            async with CoreRunner(ss("10.0.0.9", "broken", cipher="not-a-cipher"), {}):
                pass

    asyncio.run(run_runner())

    # Mid-check exit triggers retry on shared batch, fails directly alone, and run_in_batches isolates culprit.
    fake_xray.clear()
    jobs = [(1, ss("10.0.0.1", "one")), (2, ss("crash.invalid", "culprit")), (3, ss("10.0.0.3", "three"))]
    results = {}

    async def check(idx, node, ep):
        await asyncio.sleep(0.8)
        await ep.ensure_alive()
        return f"ok {idx}"

    asyncio.run(run_in_batches(jobs, lambda n: n, check, lambda i, n, r: results.setdefault(i, []).append(r),
                               config={}, workers=3, total_nodes=3))
    assert results == {1: ["ok 1"], 2: [None], 3: ["ok 3"]} and len(fake_xray) == 4
    assert "[culprit] (crash.invalid:8388)" in crash_log()
    assert "An Xray serving 3 nodes crashed with code 2" in capsys.readouterr().out


class _FakeBatch:
    sizes, live, peak = [], 0, 0

    def __init__(self, nodes, config, temp_prefix="core_"):
        _FakeBatch.sizes.append(len(nodes))
        self.endpoints = [object() for _ in nodes]

    async def __aenter__(self):
        _FakeBatch.live += 1
        _FakeBatch.peak = max(_FakeBatch.peak, _FakeBatch.live)
        return self

    async def __aexit__(self, *exc):
        _FakeBatch.live -= 1

    def exited(self):
        return []


def test_run_in_batches_concurrency_errors_and_sequential_retry(monkeypatch):
    monkeypatch.setattr(core_batch, "CoreBatch", _FakeBatch)
    monkeypatch.setattr(_FakeBatch, "sizes", [])
    monkeypatch.setattr(_FakeBatch, "peak", 0)
    checking = {"now": 0, "peak": 0}
    delivered, eps = [], {}

    async def check(idx, node, ep):
        checking["now"] += 1
        checking["peak"] = max(checking["peak"], checking["now"])
        eps[idx] = ep
        await asyncio.sleep(0.001 * (idx % 5))
        checking["now"] -= 1
        if idx == 2:
            raise ValueError("bad")
        return idx

    jobs = [(i, f"node{i}") for i in range(1, 101)]
    asyncio.run(run_in_batches(jobs, lambda n: None if n.endswith("0") else n, check,
                               lambda i, n, r: delivered.append((i, r)), config={}, workers=40))
    assert len(delivered) == 100 and (2, None) in delivered and checking["peak"] <= 40
    assert _FakeBatch.peak <= 3 and max(_FakeBatch.sizes) == 32 and sum(_FakeBatch.sizes) == 90
    assert all(eps[i] is None for i in range(10, 101, 10))

    # Sequential mode (workers=1, nodes_per_instance=4) retries only affected job alone and requeues remaining.
    _FakeBatch.sizes, _FakeBatch.peak = [], 0
    calls, seq_out = [], []

    async def seq_check(idx, node, ep):
        calls.append(idx)
        if idx == 2 and calls.count(2) == 1:
            raise CoreInstanceLost("crashed", retry=True)
        return idx

    asyncio.run(run_in_batches([(i, f"n{i}") for i in range(1, 5)], lambda n: n, seq_check,
                               lambda i, n, r: seq_out.append(r), config={}, workers=1, nodes_per_instance=4))
    assert (seq_out, _FakeBatch.sizes, calls) == ([1, 2, 3, 4], [4, 1, 2], [1, 2, 2, 3, 4])


# --- Real Xray binary integration tests ---

@pytest.fixture
def real_xray(monkeypatch):
    path = next((p for p in (XRAY_PATH, shutil.which("xray")) if p and os.path.isfile(p) and os.access(p, os.X_OK)), None)
    if path is None:
        pytest.skip("no Xray binary in project directory or on PATH")
    monkeypatch.setattr(xray, "XRAY_PATH", path)
    return path


async def _answer(reader, writer, hits):
    await reader.readuntil(b"\r\n\r\n")
    hits.append(1)
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
    await writer.drain()
    writer.close()


async def _socks5_get(port, target_port):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    try:
        w.write(b"\x05\x01\x00")
        await w.drain()
        assert await r.readexactly(2) == b"\x05\x00"
        w.write(b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + target_port.to_bytes(2, "big"))
        await w.drain()
        rep = await r.readexactly(4)
        assert rep[1] == 0
        await r.readexactly({1: 4, 4: 16}[rep[3]] + 2)
        w.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        await w.drain()
        return await asyncio.wait_for(r.read(), timeout=5)
    finally:
        w.close()


@contextlib.asynccontextmanager
async def _xray_server(binary, tmp_path, inbound, sock_type=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, sock_type) as res:
        res.bind(("127.0.0.1", 0))
        port = res.getsockname()[1]
        ready_port = PortManager.get_free_port()
    ready_srv = await asyncio.start_server(core_batch._serve_ready, "127.0.0.1", 0)
    cfg = {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {**inbound, "listen": "127.0.0.1", "port": port},
            {"tag": "ready-in", "listen": "127.0.0.1", "port": ready_port, "protocol": "mixed", "settings": {}},
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"tag": "ready", "protocol": "http", "settings": {"servers": [
                {"address": "127.0.0.1", "port": ready_srv.sockets[0].getsockname()[1]}]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["ready-in"], "outboundTag": "ready"}]},
    }
    d = tmp_path / "far-end"
    d.mkdir()
    (d / "config.json").write_text(json.dumps(cfg))
    proc = await asyncio.create_subprocess_exec(binary, "run", "-c", str(d / "config.json"),
                                                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    try:
        for _ in range(500):
            if await core_batch._relays(ready_port):
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail(f"The {inbound['protocol']} server did not start")
        yield port
    finally:
        ready_srv.close()
        if proc.returncode is None:
            proc.terminate()
        await proc.wait()
        PortManager.release_port(ready_port)


def test_real_xray_serves_http_socks5_and_detects_sigkill(real_xray, tmp_path):
    async def run():
        hits, recorded = [], []

        async def record(r, w):
            recorded.append(await r.read(64))
            w.close()

        target = await asyncio.start_server(lambda r, w: _answer(r, w, hits), "127.0.0.1", 0)
        recorder = await asyncio.start_server(record, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{target.sockets[0].getsockname()[1]}/"
        inbound = {"protocol": "shadowsocks", "settings": {"method": "aes-128-gcm", "password": PASSWORD, "network": "tcp"}}
        async with _xray_server(real_xray, tmp_path, inbound) as ss_port:
            nodes = [BatchNode(ss("127.0.0.1", "A", port=ss_port)),
                     BatchNode(ss("127.0.0.1", "B", port=recorder.sockets[0].getsockname()[1])),
                     BatchNode(ss("10.0.0.9", "C", cipher="not-a-cipher"))]
            async with CoreBatch(nodes, {}) as inst:
                a, b, c = inst.endpoints
                assert len(inst._processes) == 1 and c.error and "unknown cipher method" in c.error
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as s:
                    async with s.get(url, proxy=a.proxy_url) as resp:
                        assert await resp.text() == "hello"
                    assert (await _socks5_get(a.port, target.sockets[0].getsockname()[1])).endswith(b"hello")
                    try:
                        async with s.get(url, proxy=b.proxy_url) as resp:
                            assert resp.status != 200
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass
                # Killing the real process mid-check is detected.
                proc = inst._processes[0].proc
                os.kill(proc.pid, signal.SIGKILL)
                await proc.wait()
                with pytest.raises(CoreInstanceLost) as lost:
                    await a.ensure_alive()
                assert lost.value.retry and lost.value.reason.startswith("crashed with code -9")
        target.close()
        recorder.close()
        assert len(hits) == 2 and len(recorded) == 1

    asyncio.run(run())


@pytest.mark.parametrize("obfs", ["salamander", "gecko"])
def test_real_xray_relays_through_udp_hysteria2_server(real_xray, tmp_path, obfs):
    cert = json.loads(subprocess.check_output([real_xray, "tls", "cert", "-domain=hy2.test", "-json"], cwd=tmp_path))
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert("\n".join(cert["certificate"]))).hexdigest()
    obfs_cfg = {"password": "test-obfs", **({"packetSize": "512-1200"} if obfs == "gecko" else {})}
    inbound = {"protocol": "hysteria", "settings": {"version": 2},
               "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"certificates": [cert]},
                                  "hysteriaSettings": {"version": 2, "auth": PASSWORD},
                                  "finalmask": {"udp": [{"type": "salamander", "settings": obfs_cfg}]}}}

    async def run():
        hits = []
        target = await asyncio.start_server(lambda r, w: _answer(r, w, hits), "127.0.0.1", 0)
        async with target, _xray_server(real_xray, tmp_path, inbound, socket.SOCK_DGRAM) as port:
            link = f"hy2://{PASSWORD}@127.0.0.1:1/?mport={port}&sni=hy2.test&pinSHA256={pin}&obfs={obfs}&obfs-password=test-obfs#Local"
            url = f"http://127.0.0.1:{target.sockets[0].getsockname()[1]}/"
            async with CoreBatch([BatchNode(link), BatchNode(link.replace(pin, "00" * 32)),
                                  BatchNode(link.replace(PASSWORD, "wrong-password"))], {}) as batch:
                good, bad_pin, bad_auth = batch.endpoints
                assert not good.error and not bad_pin.error and not bad_auth.error
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as s:
                    async with s.get(url, proxy=good.proxy_url) as resp:
                        assert await resp.text() == "hello"
                    for broken in (bad_pin, bad_auth):
                        try:
                            async with s.get(url, proxy=broken.proxy_url) as resp:
                                assert resp.status != 200
                        except (aiohttp.ClientError, asyncio.TimeoutError):
                            pass
                assert good.outbound_status() == ("tunneled", None)
                pin_state, pin_err = bad_pin.outbound_status()
                assert pin_state == "error" and pin_err and "TLS" in pin_err
                auth_state, auth_err = bad_auth.outbound_status()
                assert auth_state == "error" and auth_err and "auth failed" in auth_err
            assert hits == [1]

    asyncio.run(run())


def test_real_xray_reaches_node_through_android_hosts_entry(real_xray, monkeypatch):
    monkeypatch.setattr(core_batch, "IS_ANDROID", True)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream.settimeout(10)
    received = []

    def accept():
        try:
            conn, _ = upstream.accept()
            with conn:
                conn.settimeout(5)
                received.append(conn.recv(4096))
        except OSError:
            pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    outbound = {"protocol": "http", "settings": {"servers": [{"address": "upstream.nodesieve.invalid", "port": upstream.getsockname()[1]}]}}

    async def resolve(self, host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    async def run():
        async with CoreBatch([BatchNode("http://upstream.nodesieve.invalid#Node", 1, 1)], {}) as inst:
            ep = inst.endpoints[0]
            assert ep.error is None
            _, w = await asyncio.open_connection("127.0.0.1", ep.port)
            w.write(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\nhello")
            await w.drain()
            await asyncio.get_running_loop().run_in_executor(None, t.join, 10)
            w.close()

    try:
        with patch("asyncio.base_events.BaseEventLoop.getaddrinfo", new=resolve), \
                patch.object(XrayCore, "proxy", return_value=outbound):
            asyncio.run(run())
        assert received and received[0].startswith(b"CONNECT example.invalid:443 ")
    finally:
        upstream.close()
