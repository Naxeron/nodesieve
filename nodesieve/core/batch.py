"""The local core instances nodes are checked through, ephemeral ports, and run_in_batches.

One instance of the core (Xray or Mihomo, the `core` setting) serves a batch of nodes. Each
node is a proxy of its own in the instance's configuration and gets a mixed (HTTP and SOCKS5)
listener on 127.0.0.1 that is pinned to it, so a check reaches one node through one local
port, as it would with an instance of its own, while a scan runs only a few core processes at
a time. What differs between the cores is in core/xray.py and core/mihomo.py.
"""

import asyncio
import ipaddress
import os
import socket
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple

from nodesieve.constants import (
    CRASHED_LOG_FILE,
    DEFAULT_CONFIG,
    IS_ANDROID,
    PROJECT_ROOT,
)
from nodesieve.core.base import LISTEN_HOST, ProxyCore
from nodesieve.core.limits import ResourceLimits
from nodesieve.core.mihomo import MihomoCore
from nodesieve.core.xray import XrayCore
from nodesieve.logging import ErrorTracker, log, safe_close_writer, safe_print
from nodesieve.parsers.base import extract_host_port, get_node_name

# Seconds a starting core has to open all its listeners.
START_TIMEOUT = 10.0
# How often a batch is started again with new ports when something else took one meanwhile.
_PORT_RETRIES = 2
# The proxy of the listener that tells when a starting core relays (see _relays).
_READY_PROXY = "nodesieve-ready"
_READY_PROBE = b"nodesieve: relaying?\n"
_READY_TOKEN = b"nodesieve: the core relays\n"

CORES: Dict[str, ProxyCore] = {core.name: core for core in (XrayCore(), MihomoCore())}


def core_for(config: Optional[dict]) -> ProxyCore:
    """The core the `core` setting names; the default one for a setting nodesieve doesn't know."""
    name = str((config or {}).get("core") or DEFAULT_CONFIG["core"]).strip().lower()
    return CORES.get(name) or CORES[DEFAULT_CONFIG["core"]]


class PortManager:
    """Ephemeral port reservations for the local listeners."""

    _port_lock = threading.Lock()
    _allocated_ports: Set[int] = set()

    @classmethod
    def get_free_port(cls) -> int:
        """Dynamically requests an available free port from the OS kernel using socket binding."""
        with cls._port_lock:
            for _ in range(100):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
                s.close()
                if port not in cls._allocated_ports:
                    cls._allocated_ports.add(port)
                    return port
            raise RuntimeError("Failed to allocate an available free port after 100 attempts")

    @classmethod
    def release_port(cls, port: int) -> None:
        """Releases a reserved port back to the pool."""
        with cls._port_lock:
            cls._allocated_ports.discard(port)


async def android_resolved_hosts(server: Optional[str], timeout: float = 5.0) -> Dict[str, List[str]]:
    """Addresses Android's resolver gives a node's server, as a `hosts` entry for the core.

    The cores look host names up through the servers in /etc/resolv.conf. Android has no
    such file, so they ask public DNS servers directly instead (Mihomo 114.114.114.114 and
    8.8.8.8), bypassing Android's own DNS (Private DNS, a VPN's DNS, the carrier's). Where those can't be
    reached, no node addressed by host name would connect, although the TCP check, which
    resolves through Android, reached it. So on Android the server's name is resolved here
    and handed to the core. Elsewhere the core uses the system's resolver itself.
    """
    if not IS_ANDROID or not isinstance(server, str):
        return {}
    host = server.strip().strip("[]")
    if not host:
        return {}
    try:
        ipaddress.ip_address(host)
        return {}
    except ValueError:
        pass
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout
        )
    except Exception:
        # The core then tries its own resolvers, and the node fails as it would have.
        return {}
    addresses = [address for address in dict.fromkeys(str(info[4][0]) for info in infos) if "%" not in address]
    return {host.lower(): addresses} if addresses else {}


async def _accepts(port: Optional[int], timeout: float = 0.25) -> bool:
    """Whether something accepts connections on 127.0.0.1:port."""
    if not port:
        return False
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(LISTEN_HOST, port), timeout=timeout)
    except Exception:
        return False
    await safe_close_writer(writer)
    return True


async def _serve_ready(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """The far end of a starting core's ready proxy: answers its CONNECT, then the probe with the token.

    Xray and Mihomo 1.19 dial an HTTP proxy only once the client has sent something, and read
    the answer to their CONNECT through a buffer of their own, dropping what came with it. So
    the token goes back only once the probe's line came through the tunnel. A socket closed
    with data unread sends a reset, which can overtake the token: this reads on until the core
    closes the connection.
    """
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
        writer.write(_READY_TOKEN)
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=2.0)
    except Exception:
        pass
    finally:
        await safe_close_writer(writer)


async def _relays(port: int) -> bool:
    """Whether the core relays connections yet, through the ready listener at this port.

    Mihomo opens its listeners before it relays and closes what arrives in between, after
    answering an HTTP CONNECT all the same. Only a core that relays takes the connection on to
    _serve_ready, and with it the probe's line, which _serve_ready answers with the token.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(LISTEN_HOST, port), timeout=0.5)
    except Exception:
        return False
    received = b""
    try:
        writer.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n" + _READY_PROBE)
        await writer.drain()

        async def read() -> None:
            nonlocal received
            while _READY_TOKEN not in received:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                received += chunk

        await asyncio.wait_for(read(), timeout=2.0)
    except Exception:
        pass
    finally:
        await safe_close_writer(writer)
    return _READY_TOKEN in received


class CoreInstanceLost(RuntimeError):
    """The core instance serving a node exited while the node was being checked.

    retry: that instance also served other nodes, any of which may have ended it, so the node
    is to be checked again with an instance of its own. Without retry the node ended it, and
    that is already recorded as its crash.
    """

    def __init__(self, reason: str, retry: bool, core: str = "The core"):
        super().__init__(f"{core} exited during the check: {reason}")
        self.reason = reason
        self.retry = retry


@dataclass
class BatchNode:
    """A node for a CoreBatch to serve.

    link is what the node is checked with; mux_link, when given, the same node with
    multiplexing, for the multiplexing probe. idx and total number the node in the scan's
    output; with total 0, a crash goes only to crashed_nodes.txt.
    """

    link: str
    mux_link: Optional[str] = None
    idx: int = 0
    total: int = 0


class _Entry:
    """One link a batch serves: its proxy and its listener's port, or why the core can't serve it."""

    def __init__(self, core: ProxyCore, link: str, node: int, idx: int, total: int):
        self.core = core
        self.link = link
        self.node = node
        self.idx = idx
        self.total = total
        self.name = ""
        self.proxy: Any = None
        self.host_key: Optional[str] = None
        self.port: Optional[int] = None
        self.process: Optional["_Process"] = None
        self.error: Optional[str] = None
        self.exception: Optional[BaseException] = None

    def fail(self, error: str, exception: Optional[BaseException] = None) -> None:
        self.error = error
        self.exception = exception or RuntimeError(f"{self.core.display} failed to initialize: {error}")
        self.port = None
        self.process = None

    def record_crash(self, error: str) -> None:
        """Puts a failure of the core down to this link: in crashed_nodes.txt and, for a numbered node, on screen."""
        host, port = extract_host_port(self.link)
        node_name = get_node_name(self.link)
        if self.total > 0:
            safe_print(f"[-] Node {self.idx}/{self.total} [{node_name}] ({host}:{port}) -> ERROR: {self.core.name} {error}")
        try:
            crashed_log_path = os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE)
            with open(crashed_log_path, "a", encoding="utf-8") as f:
                f.write(f"[{node_name}] ({host}:{port}) ERROR: {error}\n{self.link}\n\n")
        except Exception:
            pass


class _Process:
    """One core process and the entries it serves."""

    def __init__(self, core: ProxyCore, entries: Sequence[_Entry], temp_prefix: str):
        self.core = core
        self.entries = list(entries)
        self.temp_prefix = temp_prefix
        # Whether it serves more than one node; a node's mux entry is the same node.
        self.shared = len({entry.node for entry in self.entries}) > 1
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.work_dir: Optional[tempfile.TemporaryDirectory] = None
        self.log_path: Optional[str] = None
        self.ports: List[int] = []
        self.ready_port: Optional[int] = None
        self.stopped = False
        self._crash_recorded = False

    async def start(self, hosts: Dict[str, List[str]]) -> Optional[str]:
        """Starts the core: None once it relays through every listener, otherwise why it did not start.

        Raises OSError when the core cannot be run at all.
        """
        for entry in self.entries:
            entry.port = PortManager.get_free_port()
            self.ports.append(entry.port)
        self.ready_port = PortManager.get_free_port()
        self.ports.append(self.ready_port)
        ready_server = await asyncio.start_server(_serve_ready, LISTEN_HOST, 0)
        try:
            ready_proxy = self.core.named(self.core.ready_proxy(ready_server.sockets[0].getsockname()[1]), _READY_PROXY)
            self.work_dir = tempfile.TemporaryDirectory(prefix=self.temp_prefix)
            work_path = self.work_dir.name
            config_file = os.path.join(work_path, self.core.config_name)
            self.log_path = os.path.join(work_path, "core.log")
            # The ready proxy comes last, so that Mihomo's "proxy N" still numbers the entries.
            served = [(entry.proxy, entry.port) for entry in self.entries] + [(ready_proxy, self.ready_port)]
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(self.core.render(served, hosts))
            # The core logs to stdout and a Go crash goes to stderr: both go to the log, which is
            # read only when something fails, so no pipe can fill up and stall the core.
            with open(self.log_path, "wb") as log_file:
                self.proc = await asyncio.create_subprocess_exec(
                    *self.core.command(work_path, config_file),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=asyncio.subprocess.STDOUT,
                )
            deadline = time.monotonic() + START_TIMEOUT
            while not await _relays(self.ready_port):
                if self.proc.returncode is not None or time.monotonic() >= deadline:
                    return self.failure()
                await asyncio.sleep(0.02)
        finally:
            ready_server.close()
            try:
                await asyncio.wait_for(ready_server.wait_closed(), timeout=0.2)
            except Exception:
                pass
        # The core opened every listener it could before relaying; one it couldn't is in busy().
        for entry in self.entries:
            if not await _accepts(entry.port):
                return self.failure()
        return None

    @property
    def timed_out(self) -> bool:
        """Whether a start failed with the core running, but not relaying through every listener."""
        return self.proc is not None and self.proc.returncode is None

    def output(self) -> List[str]:
        """The last lines the core wrote."""
        if not self.log_path:
            return []
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 65536))
                data = f.read()
        except OSError:
            return []
        return [line for line in data.decode("utf-8", "replace").splitlines() if line.strip()]

    def failure(self, during: str = "") -> str:
        """Why the process is not serving: its exit code, or that its listeners never opened."""
        code = self.proc.returncode if self.proc is not None else None
        reason = f"crashed with code {code}{during}" if code is not None else "timed out opening port"
        detail = self.core.detail(self.output())
        return f"{reason} [{detail}]" if detail else reason

    def refused(self) -> Optional[Tuple[_Entry, str]]:
        """The entry whose proxy the core refused, and the core's reason, when that is what stopped it."""
        found = self.core.refused(self.output(), [entry.name for entry in self.entries])
        if found is None:
            return None
        index, detail = found
        code = self.proc.returncode if self.proc is not None else None
        return self.entries[index], f"crashed with code {code} [{detail}]"

    def busy(self) -> Dict[int, str]:
        """Listeners, by entry index, that could not take their port, which something else took meanwhile.

        The ready listener's index is the number of entries.
        """
        listeners = [(entry.name, entry.port or 0) for entry in self.entries] + [(_READY_PROXY, self.ready_port or 0)]
        return self.core.busy(self.output(), listeners)

    async def serves(self, port: Optional[int]) -> bool:
        """Whether this core still runs; also True once it was stopped on purpose."""
        if self.stopped:
            return True
        if self.proc is None:
            return False
        if self.proc.returncode is None and await _accepts(port, timeout=1.0):
            return True
        # An exiting core closes its listeners before its exit is noticed here.
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            return True
        return False

    def record_crash(self, entry: _Entry, error: str) -> None:
        """Puts this process's exit down to one of its entries, once."""
        if not self._crash_recorded:
            self._crash_recorded = True
            entry.record_crash(error)

    async def stop(self) -> None:
        """Terminates the core, killing it if it does not exit, and frees its directory and ports."""
        self.stopped = True
        proc = self.proc
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=0.5)
            except Exception:
                try:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=0.5)
                except Exception:
                    pass
        if self.work_dir is not None:
            try:
                self.work_dir.cleanup()
            except Exception:
                pass
            self.work_dir = None
        for port in self.ports:
            PortManager.release_port(port)
        self.ports = []


class NodeEndpoint:
    """How a check reaches one link: a mixed (HTTP and SOCKS5) listener of a local core.

    error says why the core could not serve the link, and port is None then. mux, on the
    endpoint of the link a node is checked with, is the same node with multiplexing.
    """

    def __init__(self, entry: _Entry):
        self.link = entry.link
        self.port = entry.port
        self.error = entry.error
        self.exception = entry.exception
        self.mux: Optional["NodeEndpoint"] = None
        self._entry = entry
        self._process = entry.process

    @property
    def proxy_url(self) -> Optional[str]:
        return f"http://{LISTEN_HOST}:{self.port}" if self.port else None

    @property
    def shared(self) -> bool:
        """Whether the core serving this link serves other nodes too."""
        return bool(self._process is not None and self._process.shared)

    async def ensure_alive(self) -> None:
        """Raises CoreInstanceLost when the core serving this link has exited.

        A check calls this before it puts a failure down to the node, since a core that
        exited fails every check through it.
        """
        process = self._process
        if process is None or await process.serves(self.port):
            return
        reason = process.failure()
        if not process.shared:
            process.record_crash(self._entry, process.failure(" during the check"))
        raise CoreInstanceLost(reason, retry=process.shared, core=process.core.display)


class CoreBatch:
    """A local core serving a batch of nodes, each through a mixed listener of its own.

    Usually one process. The cores refuse a whole configuration over one proxy they can't use,
    so a node the core refuses, or one it can't start with, is set aside with the core's reason
    and recorded as that node's crash, and the rest start without it. `endpoints` has each
    node's endpoint, in order.
    """

    def __init__(self, nodes: Sequence[BatchNode], config: dict, temp_prefix: str = "core_"):
        self.nodes = list(nodes)
        self.config = config
        self.core = core_for(config)
        self.temp_prefix = temp_prefix
        self.endpoints: List[NodeEndpoint] = []
        self._processes: List[_Process] = []
        self._hosts: Dict[str, List[str]] = {}

    async def __aenter__(self) -> "CoreBatch":
        try:
            await self.start()
        except BaseException:
            await self.close()
            raise
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def start(self) -> None:
        """Starts the core for every node it accepts; the others' endpoints carry the reason."""
        pairs = []
        servable: List[_Entry] = []
        for number, node in enumerate(self.nodes):
            main = _Entry(self.core, node.link, number, node.idx, node.total)
            mux = _Entry(self.core, node.mux_link, number, node.idx, 0) if node.mux_link else None
            pairs.append((main, mux))
            for entry in (main, mux):
                if entry is None:
                    continue
                try:
                    proxy = self.core.proxy(entry.link, self.config)
                except Exception as exc:
                    entry.fail(str(exc), exc)
                    continue
                entry.name = f"node-{len(servable)}"
                entry.proxy = self.core.named(proxy, entry.name)
                server = self.core.server(proxy)
                entry.host_key = server.strip().strip("[]").lower() if isinstance(server, str) else None
                servable.append(entry)
        await self._resolve_hosts(servable)
        await self._launch(servable)
        self.endpoints = []
        for main, mux in pairs:
            endpoint = NodeEndpoint(main)
            endpoint.mux = NodeEndpoint(mux) if mux is not None else None
            self.endpoints.append(endpoint)

    async def _resolve_hosts(self, entries: Sequence[_Entry]) -> None:
        """On Android, each server's addresses from Android's resolver, for the core's hosts."""
        servers = list(dict.fromkeys(self.core.server(entry.proxy) for entry in entries if entry.proxy))
        found = await asyncio.gather(*(android_resolved_hosts(server) for server in servers))
        for hosts in found:
            for host, addresses in hosts.items():
                known = self._hosts.setdefault(host, [])
                known.extend(address for address in addresses if address not in known)

    def _hosts_for(self, entries: Sequence[_Entry]) -> Dict[str, List[str]]:
        keys = {entry.host_key for entry in entries}
        return {host: addresses for host, addresses in self._hosts.items() if host in keys}

    async def _launch(self, entries: List[_Entry]) -> None:
        """Starts the core for these entries, setting aside each one it refuses or fails with."""
        port_retries = 0
        while entries:
            process = _Process(self.core, entries, self.temp_prefix)
            try:
                failure = await process.start(self._hosts_for(entries))
            except OSError as exc:
                await process.stop()
                ErrorTracker.record_error(f"{self.core.display} Process Launch", exc)
                for entry in entries:
                    entry.fail(f"could not be started: {exc}", exc)
                return
            except BaseException:
                await process.stop()
                raise
            busy = process.busy()
            if failure is None and not busy:
                for entry in entries:
                    entry.process = process
                self._processes.append(process)
                return
            # Read before stopping, which removes the core's log and ends a core that runs.
            refused, timed_out = process.refused(), process.timed_out
            await process.stop()
            if busy and port_retries < _PORT_RETRIES:
                # Something else took a listener's port after it was picked: pick new ones.
                port_retries += 1
                continue
            culprit: Optional[_Entry] = None
            if refused is not None:
                culprit, error = refused
            elif busy:
                index = next((index for index in sorted(busy) if index < len(entries)), None)
                if index is not None:
                    culprit = entries[index]
                    error = f"could not open its port [{busy[index]}]"
            if culprit is None:
                if timed_out or len(entries) == 1:
                    # The core ran but never relayed, which no node's proxy is known to cause,
                    # or one node is left: each node is told what happened.
                    for entry in entries:
                        entry.record_crash(failure or "did not start")
                        entry.fail(failure or "did not start")
                    return
                # The core exited without saying which node stopped it: start each half on its own.
                half = len(entries) // 2
                await self._launch(entries[:half])
                await self._launch(entries[half:])
                return
            culprit.record_crash(error)
            culprit.fail(error)
            entries = [entry for entry in entries if entry is not culprit]

    def exited(self) -> List[str]:
        """Why each of its core processes that ended on its own did."""
        return [process.failure() for process in self._processes
                if not process.stopped and process.proc is not None and process.proc.returncode is not None]

    async def close(self) -> None:
        """Stops every core process of the batch."""
        processes, self._processes = self._processes, []
        await asyncio.gather(*(process.stop() for process in processes), return_exceptions=True)


class CoreRunner:
    """A node's local proxy for one check, at `port` and `proxy_url`.

    Given the node's endpoint from a CoreBatch, the batch's core serves the node, and goes on
    serving the batch's other nodes after this check. Without one, the runner starts a core
    for this node alone and stops it when the check is done.
    """

    def __init__(
        self,
        node: str,
        config: dict,
        temp_prefix: str = "core_",
        node_idx: int = 0,
        total_nodes: int = 0,
        endpoint: Optional[NodeEndpoint] = None,
    ):
        self.node = node
        self.config = config
        self.temp_prefix = temp_prefix
        self.node_idx = node_idx
        self.total_nodes = total_nodes
        self.endpoint = endpoint

        self.port: Optional[int] = None
        self.proxy_url: Optional[str] = None
        self._batch: Optional[CoreBatch] = None
        self._serving: Optional[NodeEndpoint] = None

    async def __aenter__(self) -> "CoreRunner":
        endpoint = self.endpoint
        if endpoint is None:
            self._batch = CoreBatch(
                [BatchNode(self.node, None, self.node_idx, self.total_nodes)], self.config, self.temp_prefix
            )
            try:
                await self._batch.start()
            except BaseException:
                await self._close()
                raise
            endpoint = self._batch.endpoints[0]
        if endpoint.error is not None:
            await self._close()
            raise endpoint.exception
        self._serving = endpoint
        self.port, self.proxy_url = endpoint.port, endpoint.proxy_url
        return self

    async def ensure_alive(self) -> None:
        """Raises CoreInstanceLost when the core serving the node has exited (see NodeEndpoint)."""
        if self._serving is not None:
            await self._serving.ensure_alive()

    async def _close(self) -> None:
        batch, self._batch = self._batch, None
        if batch is not None:
            await batch.close()
        self._serving = None
        self.port = self.proxy_url = None

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._close()


Links = Optional[Tuple[str, Optional[str]]]


async def run_in_batches(
    jobs: Sequence[Tuple[int, str]],
    links: Callable[[str], Links],
    check: Callable[[int, str, Optional[NodeEndpoint]], Awaitable[Any]],
    on_result: Callable[[int, str, Any], None],
    *,
    config: dict,
    workers: int,
    total_nodes: int = 0,
    temp_prefix: str = "core_",
    error_context: str = "Worker",
) -> None:
    """Checks every (idx, node) job through shared local core instances, `workers` nodes at a time.

    links(node) is what a job needs served: the link to check the node with and, or None,
    the same node with multiplexing. None instead of the pair marks a job turned away before
    any core is needed; its check runs with no endpoint. check(idx, node, endpoint) runs
    once per job and on_result(idx, node, result) receives the result, None if check raised.

    Consecutive jobs share an instance, up to ResourceLimits.NODES_PER_INSTANCE of them. When
    an instance exits mid-check, each job whose check noticed (CoreInstanceLost with retry)
    is checked again with an instance of its own, so a node that crashes the core is found.
    """
    workers = max(1, int(workers))
    per_instance, max_instances = ResourceLimits.core_instances(workers)
    node_slots = asyncio.Semaphore(workers)
    instance_slots = asyncio.Semaphore(max_instances)
    core = core_for(config)
    # (idx, node, links, alone): alone jobs get an instance of their own.
    pending: Deque[Tuple[int, str, Tuple[str, Optional[str]], bool]] = deque()
    running: Set[asyncio.Task] = set()

    def deliver(idx: int, node: str, result: Any) -> None:
        try:
            on_result(idx, node, result)
        except Exception as exc:
            ErrorTracker.record_error(error_context, exc)

    async def finish(idx: int, node: str, endpoint: Optional[NodeEndpoint]) -> bool:
        """Runs one check and hands on its result; True when it is to run again, alone."""
        try:
            result = await check(idx, node, endpoint)
        except CoreInstanceLost as lost:
            if lost.retry:
                return True
            ErrorTracker.record_error(error_context, lost)
            result = None
        except Exception as exc:
            ErrorTracker.record_error(error_context, exc)
            result = None
        deliver(idx, node, result)
        return False

    async def run_batch(batch: List[Tuple[int, str, Tuple[str, Optional[str]], bool]]) -> None:
        unfinished = list(batch)
        lost: List[Tuple[int, str, Tuple[str, Optional[str]], bool]] = []
        exits: List[str] = []
        try:
            nodes = [BatchNode(served[0], served[1], idx, total_nodes) for idx, _, served, _ in batch]
            async with CoreBatch(nodes, config, temp_prefix) as instance:

                async def run_job(job, endpoint: NodeEndpoint) -> None:
                    try:
                        if await finish(job[0], job[1], endpoint):
                            lost.append(job)
                    finally:
                        unfinished.remove(job)
                        node_slots.release()

                await asyncio.gather(*(run_job(job, endpoint) for job, endpoint in zip(batch, instance.endpoints)))
                if lost:
                    exits = instance.exited()
        except Exception as exc:
            # No instance to check these through: they fail as a check that raised does.
            ErrorTracker.record_error(error_context, exc)
            for idx, node, _, _ in unfinished:
                deliver(idx, node, None)
        finally:
            for _ in unfinished:
                node_slots.release()
            instance_slots.release()
        if lost:
            reason = "; ".join(exits) or "exited"
            ErrorTracker.record_error(f"{core.display} Instance", RuntimeError(reason))
            safe_print(f"[!] A {core.display} serving {len(batch)} nodes {reason}; checking {len(lost)} of them "
                       f"again, each with a {core.display} of its own.")
            for idx, node, served, _ in reversed(lost):
                pending.appendleft((idx, node, served, True))

    for idx, node in jobs:
        try:
            served = links(node)
        except Exception:
            served = None
        if served is None:
            await finish(idx, node, None)
        else:
            pending.append((idx, node, served, False))

    try:
        while pending or running:
            if not pending:
                await asyncio.wait(set(running), return_when=asyncio.FIRST_COMPLETED)
                continue
            await instance_slots.acquire()
            await node_slots.acquire()
            batch = [pending.popleft()]
            # A batch takes the jobs that have a slot now; an instance whose last nodes are
            # still being checked does not hold back the next one.
            while (not batch[0][3] and len(batch) < per_instance and pending and not pending[0][3]
                   and not node_slots.locked()):
                await node_slots.acquire()
                batch.append(pending.popleft())
            task = asyncio.create_task(run_batch(batch))
            running.add(task)
            task.add_done_callback(running.discard)
    finally:
        if running:
            for task in running:
                task.cancel()
            await asyncio.gather(*running, return_exceptions=True)


def setup_core(config: dict) -> ProxyCore:
    """The core a scan checks through, its binary in place (downloaded on first use)."""
    core = core_for(config)
    log.debug(f"Checking nodes through {core.display} at {core.path}")
    core.setup()
    return core
