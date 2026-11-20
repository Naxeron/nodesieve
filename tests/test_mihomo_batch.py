"""One local Mihomo serves a batch of nodes, each through a listener of its own.

Most tests run a stand-in for the Mihomo binary that behaves as nodesieve relies on Mihomo
to: it refuses a whole configuration over one proxy it can't use, naming it "proxy N"; it
can crash without naming anything; it opens its listeners a moment before it relays, and
answers an HTTP CONNECT in between all the same; and it can exit while it serves. The
other tests run the real binary, when the project has one.
"""

import asyncio
import contextlib
import os
import signal
import sys
import time
from pathlib import Path

import aiohttp
import pytest
import yaml

from nodesieve.constants import MIHOMO_PATH
from nodesieve.core import limits, mihomo
from nodesieve.core.limits import ResourceLimits
from nodesieve.core.mihomo import (
    BatchNode,
    MihomoBatch,
    MihomoInstanceLost,
    MihomoManager,
    MihomoRunner,
    run_in_batches,
)

CONFIG = {"use_mux": False}
PASSWORD = "nodesieve-test-password"

FAKE_MIHOMO = r'''
import asyncio
import os
import sys

import yaml

args = sys.argv[1:]
with open(args[args.index("-f") + 1], encoding="utf-8") as f:
    config = yaml.safe_load(f)
proxies = config.get("proxies", [])
by_name = {proxy["name"]: proxy for proxy in proxies}
servers = {proxy.get("server") for proxy in proxies}


def say(level, message):
    print(f'time="2026-11-20T00:00:00Z" level={level} msg="{message}"', flush=True)


say("info", "Start initial configuration in progress")
for number, proxy in enumerate(proxies):
    if proxy.get("cipher") == "not-a-cipher":
        say("fatal", f"Parse config error: proxy {number}: ss {proxy['server']}:{proxy['port']} "
                     "cipher: not-a-cipher initialize error: unknown method: not-a-cipher")
        sys.exit(1)
if "panic.invalid" in servers:
    print("panic: runtime error: invalid memory address or nil pointer dereference", file=sys.stderr, flush=True)
    sys.exit(2)

# The first start with a busy-once.invalid node finds its listener's port taken.
marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "port-was-busy")
busy = set()
if "busy-once.invalid" in servers and not os.path.exists(marker):
    open(marker, "w").close()
    busy = {listener["name"] for listener in config["listeners"]
            if by_name[listener["proxy"]].get("server") == "busy-once.invalid"}
relaying = False


async def hold(reader, writer):
    await reader.read()
    writer.close()


async def ready(reader, writer):
    await reader.readuntil(b"\r\n\r\n")
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    if relaying:
        proxy = by_name["nodesieve-ready"]
        far_reader, far_writer = await asyncio.open_connection(proxy["server"], proxy["port"])
        far_writer.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n")
        await far_reader.readuntil(b"\r\n\r\n")
        writer.write(await far_reader.read(4096))
        far_writer.close()
    await writer.drain()
    writer.close()


async def main():
    global relaying
    for listener in config.get("listeners", []):
        if listener["name"] in busy:
            say("error", f"Listener {listener['name']} listen err: listen tcp {listener['listen']}:"
                         f"{listener['port']}: bind: address already in use")
            continue
        handler = ready if listener["proxy"] == "nodesieve-ready" else hold
        await asyncio.start_server(handler, listener["listen"], listener["port"])
    await asyncio.sleep(0.2)
    if "never-ready.invalid" not in servers:
        relaying = True
    if "crash.invalid" in servers:
        await asyncio.sleep(0.5)
        print("panic: crashed while serving", file=sys.stderr, flush=True)
        os._exit(2)
    await asyncio.Event().wait()


asyncio.run(main())
'''


@pytest.fixture
def fake_mihomo(tmp_path, monkeypatch):
    """Runs the stand-in for Mihomo, and counts how often it is started."""
    path = tmp_path / "fake-mihomo"
    path.write_text(f"#!{sys.executable}\n{FAKE_MIHOMO}", encoding="utf-8")
    path.chmod(0o755)
    monkeypatch.setattr(mihomo, "MIHOMO_PATH", str(path))
    starts = []
    launch = asyncio.create_subprocess_exec

    async def counted(*command, **kwargs):
        starts.append(command)
        return await launch(*command, **kwargs)

    monkeypatch.setattr(mihomo.asyncio, "create_subprocess_exec", counted)
    return starts


needs_mihomo = pytest.mark.skipif(
    not (os.path.isfile(MIHOMO_PATH) and os.access(MIHOMO_PATH, os.X_OK)),
    reason=f"Mihomo binary not executable at {MIHOMO_PATH}",
)


def ss(server, tag, cipher="aes-128-gcm", port=8388, password=PASSWORD):
    return f"ss://{cipher}:{password}@{server}:{port}#{tag}"


def crash_log():
    path = Path(mihomo.PROJECT_ROOT) / "crashed_nodes.txt"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def serve(nodes, inspect, config=CONFIG):
    """Starts a batch for these nodes and returns what inspect(batch) finds while it runs."""
    async def run():
        async with MihomoBatch(nodes, config) as batch:
            return await inspect(batch)
    return asyncio.run(run())


REFUSED = ("crashed with code 1 [Parse config error: ss 10.0.0.9:8388 cipher: not-a-cipher "
           "initialize error: unknown method: not-a-cipher]")


def test_config_pins_a_listener_to_each_proxy_and_refuses_anything_else():
    config = yaml.safe_load(mihomo.render_batch_config([
        ({"name": "node-0", "type": "ss", "server": "10.0.0.1", "port": 8388}, 20001),
        ({"name": "node-1", "type": "ss", "server": "10.0.0.2", "port": 8388}, 20002),
    ]))
    assert [proxy["name"] for proxy in config["proxies"]] == ["node-0", "node-1"]
    assert config["listeners"] == [
        {"name": "in-node-0", "type": "mixed", "listen": "127.0.0.1", "port": 20001, "proxy": "node-0"},
        {"name": "in-node-1", "type": "mixed", "listen": "127.0.0.1", "port": 20002, "proxy": "node-1"},
    ]
    assert config["rules"] == ["MATCH,REJECT"]
    assert "mixed-port" not in config and "proxy-providers" not in config
    assert config["allow-lan"] is False


def test_nodes_of_a_batch_share_one_mihomo(fake_mihomo):
    nodes = [BatchNode(ss(f"10.0.0.{n}", f"node{n}"), idx=n, total=3) for n in (1, 2, 3)]

    async def inspect(batch):
        assert all(endpoint.error is None for endpoint in batch.endpoints)
        ports = [endpoint.port for endpoint in batch.endpoints]
        assert len(set(ports)) == 3
        assert [endpoint.proxy_url for endpoint in batch.endpoints] == [f"http://127.0.0.1:{port}" for port in ports]
        assert all([await mihomo._accepts(port) for port in ports])
        assert all(endpoint.shared for endpoint in batch.endpoints)
        for endpoint in batch.endpoints:
            await endpoint.ensure_alive()
        return ports

    ports = serve(nodes, inspect)
    assert len(fake_mihomo) == 1
    # Stopped: its ports are free and no longer reserved.
    assert not set(ports) & MihomoManager._allocated_ports
    assert not any(asyncio.run(mihomo._accepts(port)) for port in ports)


def test_a_batch_is_ready_only_once_mihomo_relays(fake_mihomo, monkeypatch):
    """The stand-in, like Mihomo, accepts connections 0.2 s before it relays them."""
    reached = []
    serve_ready = mihomo._serve_ready

    async def counted(reader, writer):
        reached.append(time.monotonic())
        await serve_ready(reader, writer)

    monkeypatch.setattr(mihomo, "_serve_ready", counted)
    started = time.monotonic()

    async def inspect(batch):
        return time.monotonic()

    ready = serve([BatchNode(ss("10.0.0.1", "node"))], inspect)
    # Only a Mihomo that relays takes the ready probe on to the ready server.
    assert reached and started + 0.2 <= reached[0] <= ready


def test_a_node_mihomo_refuses_is_set_aside_and_the_rest_share_one_mihomo(fake_mihomo, capsys):
    nodes = [BatchNode(ss("10.0.0.1", "one"), idx=1, total=4),
             BatchNode(ss("10.0.0.9", "broken", cipher="not-a-cipher"), idx=2, total=4),
             BatchNode(ss("10.0.0.3", "three"), idx=3, total=4),
             BatchNode(ss("10.0.0.4", "four"), idx=4, total=4)]

    async def inspect(batch):
        return [(endpoint.port is not None, endpoint.error) for endpoint in batch.endpoints], len(batch._processes)

    served, processes = serve(nodes, inspect)
    assert served == [(True, None), (False, REFUSED), (True, None), (True, None)]
    assert (processes, len(fake_mihomo)) == (1, 2)
    assert crash_log() == f"[broken] (10.0.0.9:8388) ERROR: {REFUSED}\n{nodes[1].link}\n\n"
    assert f"[-] Node 2/4 [broken] (10.0.0.9:8388) -> ERROR: mihomo {REFUSED}" in capsys.readouterr().out


def test_a_node_that_crashes_mihomo_without_naming_itself_is_found_by_halving(fake_mihomo):
    servers = [("10.0.0.1", "a"), ("10.0.0.2", "b"), ("panic.invalid", "culprit"), ("10.0.0.4", "d")]
    nodes = [BatchNode(ss(server, tag), idx=n, total=4) for n, (server, tag) in enumerate(servers, 1)]

    async def inspect(batch):
        return [endpoint.error for endpoint in batch.endpoints], len(batch._processes)

    errors, processes = serve(nodes, inspect)
    crash = "crashed with code 2 [panic: runtime error: invalid memory address or nil pointer dereference]"
    assert errors == [None, None, crash, None]
    assert processes == 2
    assert crash_log().count("ERROR") == 1 and "[culprit] (panic.invalid:8388)" in crash_log()


def test_a_refused_multiplexing_twin_leaves_the_node_served_without_it(fake_mihomo, capsys):
    node = BatchNode(ss("10.0.0.1", "node"), mux_link=ss("10.0.0.9", "twin", cipher="not-a-cipher"), idx=1, total=1)

    async def inspect(batch):
        endpoint = batch.endpoints[0]
        return endpoint.error, endpoint.port is not None, endpoint.mux.error, endpoint.mux.port

    assert serve([node], inspect) == (None, True, REFUSED, None)
    # Recorded, but not shown: the node itself goes on and is reported by its check.
    assert "[twin]" in crash_log()
    assert "ERROR" not in capsys.readouterr().out


def test_a_multiplexing_twin_gets_a_listener_of_its_own(fake_mihomo):
    node = BatchNode(ss("10.0.0.1", "node"), mux_link=ss("10.0.0.1", "twin"))

    async def inspect(batch):
        endpoint = batch.endpoints[0]
        # One node, so its Mihomo is not shared, twin or not.
        return endpoint.port != endpoint.mux.port, endpoint.mux.link, endpoint.shared

    assert serve([node], inspect) == (True, node.mux_link, False)
    assert len(fake_mihomo) == 1


def test_a_listener_whose_port_was_taken_meanwhile_gets_another(fake_mihomo):
    nodes = [BatchNode(ss("10.0.0.1", "one")), BatchNode(ss("busy-once.invalid", "two"))]

    async def inspect(batch):
        return [endpoint.error for endpoint in batch.endpoints]

    assert serve(nodes, inspect) == [None, None]
    assert len(fake_mihomo) == 2
    assert crash_log() == ""


def test_a_mihomo_that_runs_but_never_relays_is_not_split_up(fake_mihomo, monkeypatch):
    monkeypatch.setattr(mihomo, "START_TIMEOUT", 0.6)
    nodes = [BatchNode(ss("10.0.0.1", "one")), BatchNode(ss("never-ready.invalid", "two"))]

    async def inspect(batch):
        return [endpoint.error for endpoint in batch.endpoints]

    assert serve(nodes, inspect) == ["timed out opening port", "timed out opening port"]
    assert len(fake_mihomo) == 1


def test_a_mihomo_that_cannot_be_run_fails_every_node_with_why(monkeypatch, tmp_path):
    monkeypatch.setattr(mihomo, "MIHOMO_PATH", str(tmp_path / "missing"))

    async def inspect(batch):
        return [type(endpoint.exception) for endpoint in batch.endpoints]

    assert serve([BatchNode(ss("10.0.0.1", "one")), BatchNode(ss("10.0.0.2", "two"))], inspect) == [
        FileNotFoundError, FileNotFoundError]
    assert crash_log() == ""


def test_a_link_without_a_mihomo_proxy_starts_nothing(fake_mihomo):
    async def inspect(batch):
        return [str(endpoint.exception) for endpoint in batch.endpoints]

    nodes = [BatchNode("vless://no-server#broken"), BatchNode("vmess://eyJhZGQiOiIxOTIuMC4yLjUifQ==#other")]
    assert serve(nodes, inspect) == ["The link does not convert to a Mihomo proxy"] * 2
    assert fake_mihomo == []


def test_a_mihomo_that_exits_while_serving_is_noticed(fake_mihomo):
    async def run():
        shared = MihomoBatch([BatchNode(ss("crash.invalid", "a")), BatchNode(ss("10.0.0.2", "b"))], CONFIG)
        alone = MihomoBatch([BatchNode(ss("crash.invalid", "c"), idx=1, total=1)], CONFIG)
        async with shared, alone:
            await asyncio.sleep(1.0)
            for endpoint in shared.endpoints:
                with pytest.raises(MihomoInstanceLost) as lost:
                    await endpoint.ensure_alive()
                assert lost.value.retry
            with pytest.raises(MihomoInstanceLost) as lost:
                await alone.endpoints[0].ensure_alive()
            assert not lost.value.retry
            assert shared.exited() == ["crashed with code 2 [panic: crashed while serving]"]
        # Stopped on purpose: no longer a reason to suspect the node.
        await shared.endpoints[0].ensure_alive()

    asyncio.run(run())
    log = crash_log()
    assert "[c] (crash.invalid:8388) ERROR: crashed with code 2 during the check [panic: crashed while serving]" in log
    assert "[a]" not in log and "[b]" not in log


def test_runner_starts_and_stops_a_mihomo_for_one_node(fake_mihomo):
    async def run():
        async with MihomoRunner(node=ss("10.0.0.1", "node"), config=CONFIG) as runner:
            port = runner.port
            assert runner.proxy_url == f"http://127.0.0.1:{port}"
            assert await mihomo._accepts(port)
            await runner.ensure_alive()
        return port, runner.port

    port, after = asyncio.run(run())
    assert after is None
    assert not asyncio.run(mihomo._accepts(port))


def test_runner_on_a_batch_endpoint_leaves_the_batch_running(fake_mihomo):
    async def run():
        async with MihomoBatch([BatchNode(ss("10.0.0.1", "a")), BatchNode(ss("10.0.0.2", "b"))], CONFIG) as batch:
            endpoint = batch.endpoints[0]
            async with MihomoRunner(node=endpoint.link, config=CONFIG, endpoint=endpoint) as runner:
                assert runner.port == endpoint.port
            return await mihomo._accepts(endpoint.port)

    assert asyncio.run(run())
    assert len(fake_mihomo) == 1


def test_runner_raises_why_mihomo_refused_its_node(fake_mihomo):
    async def run():
        async with MihomoRunner(node=ss("10.0.0.9", "broken", cipher="not-a-cipher"), config=CONFIG):
            pass

    with pytest.raises(RuntimeError, match="unknown method: not-a-cipher"):
        asyncio.run(run())


def test_scan_checks_the_nodes_of_a_crashed_mihomo_again_and_finds_the_one_that_crashed_it(fake_mihomo, capsys):
    jobs = [(1, ss("10.0.0.1", "one")), (2, ss("crash.invalid", "culprit")), (3, ss("10.0.0.3", "three"))]
    results = {}

    async def check(idx, node, endpoint):
        await asyncio.sleep(1.0)  # the culprit's Mihomo crashes meanwhile
        await endpoint.ensure_alive()
        return f"ok {idx}"

    def record(idx, node, result):
        results.setdefault(idx, []).append(result)

    asyncio.run(run_in_batches(jobs, lambda node: (node, None), check, record, config=CONFIG, workers=3,
                               total_nodes=3))
    assert results == {1: ["ok 1"], 2: [None], 3: ["ok 3"]}
    log = crash_log()
    assert log.count("ERROR") == 1 and "[culprit] (crash.invalid:8388)" in log
    out = capsys.readouterr().out
    assert "A Mihomo serving 3 nodes crashed with code 2 [panic: crashed while serving]; checking 3 of them" in out
    assert "[-] Node 2/3 [culprit] (crash.invalid:8388) -> ERROR: mihomo crashed with code 2 during the check" in out
    # One shared Mihomo, then one for each node.
    assert len(fake_mihomo) == 4


class _Batch:
    """A MihomoBatch that starts nothing, and keeps count."""

    sizes = []
    live = 0
    peak = 0

    def __init__(self, nodes, config, temp_prefix="mihomo_"):
        _Batch.sizes.append(len(nodes))
        self.endpoints = [object() for _ in nodes]

    async def __aenter__(self):
        _Batch.live += 1
        _Batch.peak = max(_Batch.peak, _Batch.live)
        return self

    async def __aexit__(self, *exc):
        _Batch.live -= 1

    def exited(self):
        return []


def test_scan_keeps_to_its_workers_and_mihomo_instances(monkeypatch):
    monkeypatch.setattr(mihomo, "MihomoBatch", _Batch)
    monkeypatch.setattr(_Batch, "sizes", [])
    monkeypatch.setattr(_Batch, "peak", 0)
    checking = {"now": 0, "peak": 0}
    endpoints = {}

    async def check(idx, node, endpoint):
        checking["now"] += 1
        checking["peak"] = max(checking["peak"], checking["now"])
        endpoints[idx] = endpoint
        await asyncio.sleep(0.001 * (idx % 7))
        checking["now"] -= 1
        return idx

    delivered = []
    jobs = [(idx, f"node{idx}") for idx in range(1, 101)]
    # Every tenth node is turned away before any Mihomo is needed.
    asyncio.run(run_in_batches(jobs, lambda node: None if node.endswith("0") else (node, None), check,
                               lambda idx, node, result: delivered.append(result), config={}, workers=40))
    assert sorted(delivered) == list(range(1, 101))
    assert checking["peak"] <= 40
    assert _Batch.peak <= 3 and max(_Batch.sizes) == 32 and sum(_Batch.sizes) == 90
    assert all(endpoints[idx] is None for idx in range(10, 101, 10))
    assert all(endpoints[idx] is not None for idx in range(1, 101) if idx % 10)


def test_scan_hands_on_a_result_for_a_check_that_raised(monkeypatch):
    monkeypatch.setattr(mihomo, "MihomoBatch", _Batch)

    async def check(idx, node, endpoint):
        if idx == 2:
            raise ValueError("bad node")
        return idx

    delivered = []
    asyncio.run(run_in_batches([(1, "a"), (2, "b")], lambda node: (node, None), check,
                               lambda idx, node, result: delivered.append((idx, result)), config={}, workers=2))
    assert sorted(delivered) == [(1, 1), (2, None)]


@pytest.mark.parametrize("workers, plan", [
    (1, (1, 2)), (8, (8, 2)), (29, (29, 2)), (32, (32, 2)), (33, (32, 3)), (64, (32, 3)), (256, (32, 9)),
])
def test_nodes_per_mihomo_and_mihomos_at_once(workers, plan):
    assert ResourceLimits.mihomo_instances(workers) == plan


def test_a_router_checks_what_fits_its_memory_with_two_mihomos(monkeypatch):
    """The GL-MT6000 with Steer has about 787 MB available."""
    monkeypatch.setattr(limits, "get_free_memory_mb", lambda: 787.0)
    workers, _ = ResourceLimits.get_max_safe_workers({"mem_per_worker": 8})
    assert workers == 29
    assert ResourceLimits.mihomo_instances(workers)[1] == 2
    assert ResourceLimits.memory_needed_mb(workers, 8) <= 787 - limits.RESERVED_MB
    assert ResourceLimits.memory_needed_mb(workers + 1, 8) > 787 - limits.RESERVED_MB


def test_android_checks_at_most_64_nodes_through_three_mihomos(monkeypatch):
    monkeypatch.setattr(limits, "get_free_memory_mb", lambda: 6000.0)
    monkeypatch.setattr(limits, "IS_ANDROID", True)
    workers, _ = ResourceLimits.get_max_safe_workers({})
    assert workers == 64
    assert ResourceLimits.mihomo_instances(workers)[1] == 3


def test_a_nonsensical_memory_budget_per_node_falls_back_to_the_default(monkeypatch):
    monkeypatch.setattr(limits, "get_free_memory_mb", lambda: 787.0)
    assert ResourceLimits.get_max_safe_workers({"mem_per_worker": 0})[0] == 29
    assert ResourceLimits.get_max_safe_workers({"mem_per_worker": "lots"})[0] == 29


# The real binary.


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
async def shadowsocks_server(tmp_path):
    """A real Mihomo serving Shadowsocks, which goes out directly: the far end of the test nodes."""
    port, ready_port = MihomoManager.get_free_port(), MihomoManager.get_free_port()
    ready_server = await asyncio.start_server(mihomo._serve_ready, "127.0.0.1", 0)
    config = {
        "allow-lan": False, "log-level": "error", "mode": "rule",
        "proxies": [{"name": "nodesieve-ready", "type": "http", "server": "127.0.0.1",
                     "port": ready_server.sockets[0].getsockname()[1]}],
        "listeners": [
            {"name": "ss-in", "type": "shadowsocks", "listen": "127.0.0.1", "port": port,
             "cipher": "aes-128-gcm", "password": PASSWORD},
            {"name": "ready-in", "type": "mixed", "listen": "127.0.0.1", "port": ready_port,
             "proxy": "nodesieve-ready"},
        ],
        "rules": ["MATCH,DIRECT"],
    }
    directory = tmp_path / "far-end"
    directory.mkdir()
    (directory / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    process = await asyncio.create_subprocess_exec(
        MIHOMO_PATH, "-d", str(directory), "-f", str(directory / "config.yaml"),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        for _ in range(500):
            if await mihomo._relays(ready_port):
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail("The Shadowsocks Mihomo did not start")
        yield port, process.pid
    finally:
        ready_server.close()
        process.terminate()
        await process.wait()
        MihomoManager.release_port(port)
        MihomoManager.release_port(ready_port)


@needs_mihomo
def test_real_mihomo_serves_each_node_through_its_own_listener(tmp_path):
    async def run():
        hits, recorded = [], []

        async def record(reader, writer):
            recorded.append(await reader.read(64))
            writer.close()

        target = await asyncio.start_server(lambda r, w: _answer(r, w, hits), "127.0.0.1", 0)
        recorder = await asyncio.start_server(record, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{target.sockets[0].getsockname()[1]}/"
        async with shadowsocks_server(tmp_path) as (ss_port, _):
            nodes = [BatchNode(ss("127.0.0.1", "A", port=ss_port)),
                     BatchNode(ss("127.0.0.1", "B", port=recorder.sockets[0].getsockname()[1])),
                     BatchNode(ss("10.0.0.9", "C", cipher="not-a-cipher"))]
            async with MihomoBatch(nodes, CONFIG) as batch:
                a, b, c = batch.endpoints
                assert len(batch._processes) == 1
                timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, proxy=a.proxy_url) as response:
                        assert await response.text() == "hello"
                    # Each listener also speaks SOCKS5, for SOCKS clients.
                    assert (await socks5_get(a.port, target.sockets[0].getsockname()[1])).endswith(b"hello")
                    # B's server is no Shadowsocks server: Mihomo answers 502 or drops the request.
                    try:
                        async with session.get(url, proxy=b.proxy_url) as response:
                            assert response.status == 502
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass
                assert c.error == REFUSED
        target.close()
        recorder.close()
        # B's listener led only to B's server, though the rules refuse everything.
        assert len(hits) == 2 and len(recorded) == 1

    asyncio.run(run())


@needs_mihomo
def test_real_scan_runs_only_a_few_mihomo_processes(tmp_path):
    # Counts Mihomo processes; nodesieve itself does not need psutil.
    psutil = pytest.importorskip("psutil")

    async def run():
        hits, peak = [], []
        target = await asyncio.start_server(lambda r, w: _answer(r, w, hits), "127.0.0.1", 0)
        url = f"http://127.0.0.1:{target.sockets[0].getsockname()[1]}/"
        async with shadowsocks_server(tmp_path) as (ss_port, far_end):
            async def check(idx, node, endpoint):
                running = [child for child in psutil.Process().children(recursive=True)
                           if child.pid != far_end and child.name() == os.path.basename(MIHOMO_PATH)]
                peak.append(len(running))
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    async with session.get(url, proxy=endpoint.proxy_url) as response:
                        return await response.text()

            results = {}
            jobs = [(idx, ss("127.0.0.1", f"node{idx}", port=ss_port)) for idx in range(1, 41)]
            await run_in_batches(jobs, lambda node: (node, None), check,
                                 lambda idx, node, result: results.update({idx: result}),
                                 config=CONFIG, workers=40)
        target.close()
        return results, max(peak)

    results, peak = asyncio.run(run())
    assert results == {idx: "hello" for idx in range(1, 41)}
    # 40 nodes at once: one Mihomo for 32 of them, one for the other 8.
    assert peak <= 3


@needs_mihomo
def test_real_mihomo_killed_mid_check_is_noticed():
    async def run():
        nodes = [BatchNode(ss("10.0.0.1", "a")), BatchNode(ss("10.0.0.2", "b"))]
        async with MihomoBatch(nodes, CONFIG) as batch:
            process = batch._processes[0].proc
            os.kill(process.pid, signal.SIGKILL)
            await process.wait()
            with pytest.raises(MihomoInstanceLost) as lost:
                await batch.endpoints[0].ensure_alive()
            return lost.value

    lost = asyncio.run(run())
    assert lost.retry and lost.reason.startswith("crashed with code -9")
