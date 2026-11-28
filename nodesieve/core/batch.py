"""Batched local Xray instances, ephemeral port management, and run_in_batches."""

import asyncio
from collections import deque
from dataclasses import dataclass
import ipaddress
import math
import os
import socket
import tempfile
import threading
import time
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple

from nodesieve.constants import CRASHED_LOG_FILE, IS_ANDROID, PROJECT_ROOT
from nodesieve.core.limits import ResourceLimits
from nodesieve.core.xray import LISTEN_HOST, XrayCore
from nodesieve.logging import ErrorTracker, log, safe_close_writer, safe_print
from nodesieve.parsers.base import extract_host_port, get_node_name

START_TIMEOUT = 10.0
_PORT_RETRIES = 2
_READY_PROXY = "nodesieve-ready"
_READY_PROBE = b"nodesieve: relaying?\n"
_READY_TOKEN = b"nodesieve: the core relays\n"


class PortManager:
    """Dynamic kernel-allocated ephemeral port reservations."""

    _port_lock = threading.Lock()
    _allocated_ports: Set[int] = set()

    @classmethod
    def get_free_port(cls) -> int:
        with cls._port_lock:
            for _ in range(100):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((LISTEN_HOST, 0))
                port = s.getsockname()[1]
                s.close()
                if port not in cls._allocated_ports:
                    cls._allocated_ports.add(port)
                    return port
            raise RuntimeError("Failed to allocate an available free port after 100 attempts")

    @classmethod
    def release_port(cls, port: int) -> None:
        with cls._port_lock:
            cls._allocated_ports.discard(port)


async def android_resolved_hosts(server: Optional[str], timeout: float = 5.0) -> Dict[str, List[str]]:
    """Resolve a server hostname through Android's resolver for Xray's dns.hosts."""
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
        return {}
    addrs = [a for a in dict.fromkeys(str(info[4][0]) for info in infos) if "%" not in a]
    return {host.lower(): addrs} if addrs else {}


async def _accepts(port: Optional[int], timeout: float = 0.25) -> bool:
    if not port:
        return False
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(LISTEN_HOST, port), timeout=timeout)
    except Exception:
        return False
    await safe_close_writer(writer)
    return True


async def _serve_ready(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
    """Raised when the Xray instance serving a node exited mid-check."""

    def __init__(self, reason: str, retry: bool, core: str = "Xray"):
        super().__init__(f"{core} exited during the check: {reason}")
        self.reason = reason
        self.retry = retry


@dataclass
class BatchNode:
    link: str
    idx: int = 0
    total: int = 0


class NodeEndpoint:
    """One node's mixed listener on a local Xray instance, or the error preventing startup."""

    def __init__(self, core: XrayCore, link: str, idx: int = 0, total: int = 0):
        self.core = core
        self.link = link
        self.idx = idx
        self.total = total
        self.name = ""
        self.proxy: Any = None
        self.host_key: Optional[str] = None
        self.port: Optional[int] = None
        self.error: Optional[str] = None
        self.exception: Optional[BaseException] = None
        self._process: Optional["_Process"] = None

    @property
    def proxy_url(self) -> Optional[str]:
        return f"http://{LISTEN_HOST}:{self.port}" if self.port else None

    @property
    def shared(self) -> bool:
        return bool(self._process is not None and self._process.shared)

    def fail(self, error: str, exception: Optional[BaseException] = None) -> None:
        self.error = error
        self.exception = exception or RuntimeError(f"{self.core.display} failed to initialize: {error}")
        self.port = None
        self._process = None

    def record_crash(self, error: str) -> None:
        host, port = extract_host_port(self.link)
        name = get_node_name(self.link)
        if self.total > 0:
            safe_print(f"[-] Node {self.idx}/{self.total} [{name}] ({host}:{port}) -> ERROR: {self.core.name} {error}")
        try:
            with open(os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE), "a", encoding="utf-8") as f:
                f.write(f"[{name}] ({host}:{port}) ERROR: {error}\n{self.link}\n\n")
        except Exception:
            pass

    def outbound_status(self) -> Tuple[str, Optional[str]]:
        if self._process is None or not self.name:
            return "none", None
        return self.core.outbound_status(self._process.output(), self.name)

    async def ensure_alive(self) -> None:
        proc = self._process
        if proc is None or await proc.serves(self.port):
            return
        reason = proc.failure()
        if not proc.shared:
            proc.record_crash(self, proc.failure(" during the check"))
        raise CoreInstanceLost(reason, retry=proc.shared, core=proc.core.display)


class _Process:
    """One Xray subprocess and the endpoints it serves."""

    def __init__(self, core: XrayCore, entries: Sequence[NodeEndpoint], temp_prefix: str):
        self.core = core
        self.entries = list(entries)
        self.temp_prefix = temp_prefix
        self.shared = len(self.entries) > 1
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.work_dir: Optional[tempfile.TemporaryDirectory] = None
        self.log_path: Optional[str] = None
        self.ports: List[int] = []
        self.ready_port: Optional[int] = None
        self.stopped = False
        self._crash_recorded = False

    async def start(self, hosts: Dict[str, List[str]]) -> Optional[str]:
        ready_server = await asyncio.start_server(_serve_ready, LISTEN_HOST, 0)
        try:
            for entry in self.entries:
                entry.port = PortManager.get_free_port()
                self.ports.append(entry.port)
            self.ready_port = PortManager.get_free_port()
            self.ports.append(self.ready_port)
            ready_proxy = self.core.named(self.core.ready_proxy(ready_server.sockets[0].getsockname()[1]), _READY_PROXY)
            self.work_dir = tempfile.TemporaryDirectory(prefix=self.temp_prefix)
            work_path = self.work_dir.name
            config_file = os.path.join(work_path, self.core.config_name)
            self.log_path = os.path.join(work_path, "core.log")
            served = [(e.proxy, e.port) for e in self.entries] + [(ready_proxy, self.ready_port)]
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(self.core.render(served, hosts))
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
        for entry in self.entries:
            if not await _accepts(entry.port):
                return self.failure()
        return None

    @property
    def timed_out(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def output(self, max_bytes: int = 262144) -> List[str]:
        if not self.log_path:
            return []
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - max_bytes))
                data = f.read()
        except OSError:
            return []
        return [line for line in data.decode("utf-8", "replace").splitlines() if line.strip()]

    def failure(self, during: str = "") -> str:
        code = self.proc.returncode if self.proc is not None else None
        reason = f"crashed with code {code}{during}" if code is not None else "timed out opening port"
        detail = self.core.detail(self.output())
        return f"{reason} [{detail}]" if detail else reason

    def refused(self) -> Optional[Tuple[NodeEndpoint, str]]:
        found = self.core.refused(self.output(), [e.name for e in self.entries])
        if found is None:
            return None
        idx, detail = found
        code = self.proc.returncode if self.proc is not None else None
        return self.entries[idx], f"crashed with code {code} [{detail}]"

    def busy(self) -> Dict[int, str]:
        listeners = [(e.name, e.port or 0) for e in self.entries] + [(_READY_PROXY, self.ready_port or 0)]
        return self.core.busy(self.output(), listeners)

    async def serves(self, port: Optional[int]) -> bool:
        if self.stopped:
            return True
        if self.proc is None:
            return False
        if self.proc.returncode is None and await _accepts(port, timeout=1.0):
            return True
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            return True
        return False

    def record_crash(self, entry: NodeEndpoint, error: str) -> None:
        if not self._crash_recorded:
            self._crash_recorded = True
            entry.record_crash(error)

    async def stop(self) -> None:
        self.stopped = True
        proc = self.proc
        if proc is not None and proc.returncode is None:
            for action in (proc.terminate, proc.kill):
                try:
                    action()
                    await asyncio.wait_for(proc.wait(), timeout=0.5)
                    break
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


class CoreBatch:
    """One or more local Xray processes serving a batch of nodes with fault isolation."""

    def __init__(self, nodes: Sequence[BatchNode], config: dict, temp_prefix: str = "core_"):
        self.nodes = list(nodes)
        self.config = config
        self.core = XrayCore()
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
        self.endpoints = []
        servable: List[NodeEndpoint] = []
        for node in self.nodes:
            ep = NodeEndpoint(self.core, node.link, node.idx, node.total)
            self.endpoints.append(ep)
            try:
                proxy = self.core.proxy(ep.link, self.config)
            except Exception as exc:
                ep.fail(str(exc), exc)
                continue
            ep.name = f"node-{len(servable)}"
            ep.proxy = self.core.named(proxy, ep.name)
            server = self.core.server(proxy)
            ep.host_key = server.strip().strip("[]").lower() if isinstance(server, str) else None
            servable.append(ep)
        servers = list(dict.fromkeys(self.core.server(e.proxy) for e in servable if e.proxy))
        for resolved in await asyncio.gather(*(android_resolved_hosts(s) for s in servers)):
            for host, addrs in resolved.items():
                known = self._hosts.setdefault(host, [])
                known.extend(a for a in addrs if a not in known)
        await self._launch(servable)

    async def _launch(self, entries: List[NodeEndpoint]) -> None:
        port_retries = 0
        while entries:
            keys = {e.host_key for e in entries}
            hosts = {h: a for h, a in self._hosts.items() if h in keys}
            process = _Process(self.core, entries, self.temp_prefix)
            try:
                failure = await process.start(hosts)
            except OSError as exc:
                await process.stop()
                ErrorTracker.record_error(f"{self.core.display} Process Launch", exc)
                for e in entries:
                    e.fail(f"could not be started: {exc}", exc)
                return
            except BaseException:
                await process.stop()
                raise
            busy = process.busy()
            if failure is None and not busy:
                for e in entries:
                    e._process = process
                self._processes.append(process)
                return
            refused, timed_out = process.refused(), process.timed_out
            await process.stop()
            if busy and port_retries < _PORT_RETRIES:
                port_retries += 1
                continue
            culprit: Optional[NodeEndpoint] = None
            if refused is not None:
                culprit, error = refused
            elif busy:
                idx = next((i for i in sorted(busy) if i < len(entries)), None)
                if idx is not None:
                    culprit, error = entries[idx], f"could not open its port [{busy[idx]}]"
            if culprit is None:
                if timed_out or len(entries) == 1:
                    for e in entries:
                        e.record_crash(failure or "did not start")
                        e.fail(failure or "did not start")
                    return
                half = len(entries) // 2
                await self._launch(entries[:half])
                await self._launch(entries[half:])
                return
            culprit.record_crash(error)
            culprit.fail(error)
            entries = [e for e in entries if e is not culprit]

    def exited(self) -> List[str]:
        return [p.failure() for p in self._processes
                if not p.stopped and p.proc is not None and p.proc.returncode is not None]

    async def close(self) -> None:
        procs, self._processes = self._processes, []
        await asyncio.gather(*(p.stop() for p in procs), return_exceptions=True)


class CoreRunner:
    """Context manager providing a node's local proxy via a shared endpoint or a single-node batch."""

    def __init__(
        self, node: str, config: dict, temp_prefix: str = "core_",
        node_idx: int = 0, total_nodes: int = 0, endpoint: Optional[NodeEndpoint] = None,
    ):
        self.node, self.config, self.temp_prefix = node, config, temp_prefix
        self.node_idx, self.total_nodes, self.endpoint = node_idx, total_nodes, endpoint
        self.port: Optional[int] = None
        self.proxy_url: Optional[str] = None
        self._batch: Optional[CoreBatch] = None
        self._serving: Optional[NodeEndpoint] = None

    async def __aenter__(self) -> "CoreRunner":
        ep = self.endpoint
        if ep is None:
            self._batch = CoreBatch([BatchNode(self.node, self.node_idx, self.total_nodes)], self.config, self.temp_prefix)
            try:
                await self._batch.start()
            except BaseException:
                await self._close()
                raise
            ep = self._batch.endpoints[0]
        if ep.error is not None:
            await self._close()
            raise ep.exception
        self._serving = ep
        self.port, self.proxy_url = ep.port, ep.proxy_url
        return self

    async def outbound_status(self) -> Tuple[str, Optional[str]]:
        if self._serving is None:
            return "none", None
        return self._serving.outbound_status()

    async def ensure_alive(self) -> None:
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


async def run_in_batches(
    jobs: Sequence[Tuple[int, str]],
    links: Callable[[str], Optional[str]],
    check: Callable[[int, str, Optional[NodeEndpoint]], Awaitable[Any]],
    on_result: Callable[[int, str, Any], None],
    *,
    config: dict,
    workers: int,
    total_nodes: int = 0,
    temp_prefix: str = "core_",
    error_context: str = "Worker",
    nodes_per_instance: Optional[int] = None,
) -> None:
    """Run check(idx, node, endpoint) across jobs through shared local Xray instances."""
    workers = max(1, int(workers))
    per_instance, max_instances = ResourceLimits.core_instances(workers)
    if nodes_per_instance is not None:
        per_instance = max(1, int(nodes_per_instance))
    bounded = per_instance > workers
    if nodes_per_instance is not None:
        max_instances = 1 if bounded else math.ceil(workers / per_instance) + 1
    node_slots = asyncio.Semaphore(workers)
    instance_slots = asyncio.Semaphore(max_instances)
    pending: Deque[Tuple[int, str, str, bool]] = deque()
    running: Set[asyncio.Task] = set()

    def deliver(idx: int, node: str, result: Any) -> None:
        try:
            on_result(idx, node, result)
        except Exception as exc:
            ErrorTracker.record_error(error_context, exc)

    async def finish(idx: int, node: str, ep: Optional[NodeEndpoint]) -> bool:
        try:
            result = await check(idx, node, ep)
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

    async def run_batch(batch: List[Tuple[int, str, str, bool]]) -> None:
        unfinished = list(batch)
        lost: List[Tuple[int, str, str, bool]] = []
        requeue: List[Tuple[int, str, str, bool]] = []
        exits: List[str] = []
        try:
            nodes = [BatchNode(link, idx, total_nodes) for idx, _, link, _ in batch]
            async with CoreBatch(nodes, config, temp_prefix) as instance:

                async def run_job(job, ep: NodeEndpoint) -> None:
                    if bounded:
                        await node_slots.acquire()
                    try:
                        if bounded and lost:
                            requeue.append(job)
                        elif await finish(job[0], job[1], ep):
                            lost.append(job)
                    finally:
                        unfinished.remove(job)
                        node_slots.release()

                await asyncio.gather(*(run_job(job, ep) for job, ep in zip(batch, instance.endpoints)))
                if lost:
                    exits = instance.exited()
            for item in reversed(requeue):
                pending.appendleft(item)
            if lost:
                reason = "; ".join(exits) or "exited"
                ErrorTracker.record_error("Xray Instance", RuntimeError(reason))
                safe_print(f"[!] An Xray serving {len(batch)} nodes {reason}; checking {len(lost)} of them "
                           "again, each with an Xray of its own.")
                for idx, node, link, _ in reversed(lost):
                    pending.appendleft((idx, node, link, True))
        except Exception as exc:
            ErrorTracker.record_error(error_context, exc)
            for idx, node, _, _ in unfinished:
                deliver(idx, node, None)
        finally:
            if not bounded:
                for _ in unfinished:
                    node_slots.release()
            instance_slots.release()

    for idx, node in jobs:
        try:
            link = links(node)
        except Exception:
            link = None
        if link is None:
            await finish(idx, node, None)
        else:
            pending.append((idx, node, link, False))

    try:
        while pending or running:
            if not pending:
                await asyncio.wait(set(running), return_when=asyncio.FIRST_COMPLETED)
                continue
            await instance_slots.acquire()
            if not bounded:
                await node_slots.acquire()
            batch = [pending.popleft()]
            while not batch[0][3] and len(batch) < per_instance and pending and not pending[0][3]:
                if not bounded:
                    if node_slots.locked():
                        break
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


def setup_core(config: Optional[dict] = None) -> XrayCore:
    core = XrayCore()
    log.debug(f"Checking nodes through {core.display} at {core.path}")
    core.setup()
    return core
