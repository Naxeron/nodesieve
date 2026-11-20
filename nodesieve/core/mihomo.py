"""Mihomo binary provisioning, ephemeral ports, and the local Mihomo instances nodes are checked through.

One Mihomo instance serves a batch of nodes. Each node is a proxy of its own in the
instance's configuration and gets a mixed (HTTP and SOCKS5) listener on 127.0.0.1 that is
pinned to it, so a check reaches one node through one local port, as it would with an
instance of its own, while a scan runs only a few Mihomo processes at a time.
"""

import asyncio
import gzip
import io
import ipaddress
import json
import os
import platform
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple
import yaml

from nodesieve.constants import (
    CRASHED_LOG_FILE,
    IS_ANDROID,
    MIHOMO_PATH,
    PROJECT_ROOT,
)
from nodesieve.core.limits import ResourceLimits
from nodesieve.logging import ErrorTracker, log, safe_close_writer, safe_print
from nodesieve.parsers.base import extract_host_port, get_node_name
from nodesieve.parsers.mihomo import node_url_to_mihomo_dict

LISTEN_HOST = "127.0.0.1"
# Seconds a starting Mihomo has to open all its listeners.
START_TIMEOUT = 10.0
# How often a batch is started again with new ports when something else took one meanwhile.
_PORT_RETRIES = 2
# Mihomo's log lines (logrus text format), and the messages that say what stopped it.
_LOG_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_PROXY_REFUSED = re.compile(r"^Parse config error: proxy (\d+): (.+)$")
_LISTEN_FAILED = re.compile(r"^Listener (\S+) listen err")
# How the Go runtime starts the report of a crash.
_GO_CRASH = ("panic:", "fatal error:")
# The proxy of the listener that tells when a starting Mihomo relays (see _relays).
_READY_PROXY = "nodesieve-ready"
_READY_TOKEN = b"nodesieve: Mihomo relays\n"


class MihomoManager:
    """Manages Mihomo executable provisioning and ephemeral port reservations."""

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

    @classmethod
    def setup(cls) -> None:
        """Ensures the appropriate platform Mihomo binary exists, downloading it from GitHub if absent."""
        if os.path.exists(MIHOMO_PATH):
            return

        arch = platform.machine().lower()
        log.info(f"[*] Fetching latest alpha mihomo release for architecture {platform.machine()}...")

        if os.name == "nt":
            if arch in ["x86_64", "amd64"]:
                prefix, fallback_prefix = "mihomo-windows-amd64-compatible-alpha-", "mihomo-windows-amd64-alpha-"
            elif arch in ["aarch64", "arm64"]:
                prefix, fallback_prefix = "mihomo-windows-arm64-alpha-", "mihomo-windows-arm64-alpha-"
            elif "arm" in arch:
                prefix, fallback_prefix = "mihomo-windows-armv7-alpha-", "mihomo-windows-armv7-alpha-"
            else:
                prefix, fallback_prefix = "mihomo-windows-amd64-compatible-alpha-", "mihomo-windows-amd64-alpha-"
            ext = ".zip"
        else:
            if arch in ["x86_64", "amd64"]:
                prefix, fallback_prefix = "mihomo-linux-amd64-compatible-alpha-", "mihomo-linux-amd64-alpha-"
            elif arch in ["aarch64", "arm64"]:
                prefix, fallback_prefix = "mihomo-linux-arm64-alpha-", "mihomo-linux-arm64-alpha-"
            elif "arm" in arch:
                prefix, fallback_prefix = "mihomo-linux-armv7-alpha-", "mihomo-linux-armv7-alpha-"
            else:
                log.error(f"[-] Unsupported architecture: {arch}")
                sys.exit(1)
            ext = ".gz"

        url = None
        try:
            api_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha"
            req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req) as resp:
                rel_data = json.loads(resp.read().decode("utf-8"))

            assets = rel_data.get("assets", [])
            for a in assets:
                aname = a.get("name", "")
                if aname.startswith(prefix) and aname.endswith(ext):
                    url = a.get("browser_download_url")
                    break

            if not url:
                for a in assets:
                    aname = a.get("name", "")
                    if aname.startswith(fallback_prefix) and aname.endswith(ext):
                        url = a.get("browser_download_url")
                        break
        except Exception as e:
            log.warning(f"[!] Failed to fetch release info from GitHub API: {e}")

        if not url:
            log.error("[-] Could not find matching asset for latest alpha release.")
            sys.exit(1)

        log.info(f"[*] Downloading mihomo from {url}...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req) as response:
                data = response.read()

            if url.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for name in z.namelist():
                        if name.endswith(".exe"):
                            with open(MIHOMO_PATH, "wb") as f:
                                f.write(z.read(name))
                            break
            else:
                uncompressed_data = gzip.decompress(data)
                with open(MIHOMO_PATH, "wb") as f:
                    f.write(uncompressed_data)

            if os.name != "nt":
                os.chmod(MIHOMO_PATH, 0o755)
            log.info("[+] Mihomo alpha setup complete.")
        except Exception as e:
            log.error(f"[-] Failed to download mihomo: {e}")
            sys.exit(1)


async def android_resolved_hosts(server: Optional[str], timeout: float = 5.0) -> Dict[str, List[str]]:
    """Addresses Android's resolver gives a node's server, as a Mihomo `hosts` entry.

    Mihomo looks host names up through the servers in /etc/resolv.conf. Android has no
    such file, so Mihomo asks 114.114.114.114 and 8.8.8.8 directly instead, bypassing
    Android's own DNS (Private DNS, a VPN's DNS, the carrier's). Where those two can't be
    reached, no node addressed by host name would connect, although the TCP check, which
    resolves through Android, reached it. So on Android the server's name is resolved
    here and handed to Mihomo. Elsewhere Mihomo uses the system's resolver itself.
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
        # Mihomo then tries its own resolvers, and the node fails as it would have.
        return {}
    addresses = [address for address in dict.fromkeys(str(info[4][0]) for info in infos) if "%" not in address]
    return {host.lower(): addresses} if addresses else {}


def render_batch_config(
    proxies: Sequence[Tuple[dict, int]], hosts: Optional[Dict[str, List[str]]] = None
) -> str:
    """Mihomo configuration serving each proxy on a mixed listener of its own at 127.0.0.1:port.

    A listener pinned to a proxy sends everything it receives through that proxy, whatever
    the rules say. The rules refuse everything else, so no connection leaves directly.
    """
    config: Dict[str, Any] = {
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "ipv6": True,
        "proxies": [proxy for proxy, _ in proxies],
        "listeners": [
            {"name": f"in-{proxy['name']}", "type": "mixed", "listen": LISTEN_HOST, "port": port,
             "proxy": proxy["name"]}
            for proxy, port in proxies
        ],
        "rules": ["MATCH,REJECT"],
    }
    if hosts:
        config["hosts"] = hosts
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)


def mihomo_proxy(link: str, config: dict) -> dict:
    """The Mihomo proxy a link is checked through; ValueError for a link that gives none."""
    proxy = node_url_to_mihomo_dict(link, use_mux=config.get("use_mux", True))
    if not proxy:
        raise ValueError("The link does not convert to a Mihomo proxy")
    return proxy


def _log_record(line: str) -> Tuple[Optional[str], str]:
    """The level and message of one of Mihomo's log lines; (None, line) for other output."""
    fields = dict(_LOG_FIELD.findall(line))
    message = fields.get("msg")
    if message is None:
        return None, line.strip()
    if message.startswith('"'):
        try:
            message = json.loads(message)
        except ValueError:
            message = message[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return fields.get("level"), message


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
    """The far end of a starting Mihomo's ready proxy: answers its CONNECT, then says so."""
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n" + _READY_TOKEN)
        await writer.drain()
    except Exception:
        pass
    finally:
        await safe_close_writer(writer)


async def _relays(port: int) -> bool:
    """Whether Mihomo relays connections yet, through the ready listener at this port.

    Mihomo opens its listeners before it starts relaying and closes what arrives in
    between, after answering an HTTP CONNECT all the same. Only a Mihomo that relays takes
    the connection on to _serve_ready, whose token then comes back.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(LISTEN_HOST, port), timeout=0.5)
    except Exception:
        return False
    received = b""
    try:
        writer.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
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


class MihomoInstanceLost(RuntimeError):
    """The Mihomo serving a node exited while the node was being checked.

    retry: that Mihomo also served other nodes, any of which may have ended it, so the node
    is to be checked again with a Mihomo of its own. Without retry the node ended it, and
    that is already recorded as its crash.
    """

    def __init__(self, reason: str, retry: bool):
        super().__init__(f"Mihomo exited during the check: {reason}")
        self.reason = reason
        self.retry = retry


@dataclass
class BatchNode:
    """A node for a MihomoBatch to serve.

    link is what the node is checked with; mux_link, when given, the same node with
    multiplexing, for the multiplexing probe. idx and total number the node in the scan's
    output; with total 0, a crash goes only to crashed_nodes.txt.
    """

    link: str
    mux_link: Optional[str] = None
    idx: int = 0
    total: int = 0


class _Entry:
    """One link a batch serves: its proxy and its listener's port, or why Mihomo can't serve it."""

    def __init__(self, link: str, node: int, idx: int, total: int):
        self.link = link
        self.node = node
        self.idx = idx
        self.total = total
        self.name = ""
        self.proxy: Optional[dict] = None
        self.host_key: Optional[str] = None
        self.port: Optional[int] = None
        self.process: Optional["_Process"] = None
        self.error: Optional[str] = None
        self.exception: Optional[BaseException] = None

    def fail(self, error: str, exception: Optional[BaseException] = None) -> None:
        self.error = error
        self.exception = exception or RuntimeError(f"Mihomo failed to initialize: {error}")
        self.port = None
        self.process = None

    def record_crash(self, error: str) -> None:
        """Puts a failure of Mihomo down to this link: in crashed_nodes.txt and, for a numbered node, on screen."""
        host, port = extract_host_port(self.link)
        node_name = get_node_name(self.link)
        if self.total > 0:
            safe_print(f"[-] Node {self.idx}/{self.total} [{node_name}] ({host}:{port}) -> ERROR: mihomo {error}")
        try:
            crashed_log_path = os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE)
            with open(crashed_log_path, "a", encoding="utf-8") as f:
                f.write(f"[{node_name}] ({host}:{port}) ERROR: {error}\n{self.link}\n\n")
        except Exception:
            pass


class _Process:
    """One Mihomo process and the entries it serves."""

    def __init__(self, entries: Sequence[_Entry], temp_prefix: str):
        self.entries = list(entries)
        self.temp_prefix = temp_prefix
        # Whether it serves more than one node; a node's mux entry is the same node.
        self.shared = len({entry.node for entry in self.entries}) > 1
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.work_dir: Optional[tempfile.TemporaryDirectory] = None
        self.log_path: Optional[str] = None
        self.ports: List[int] = []
        self.stopped = False
        self._crash_recorded = False

    async def start(self, hosts: Dict[str, List[str]]) -> Optional[str]:
        """Starts Mihomo: None once it relays through every listener, otherwise why it did not start.

        Raises OSError when Mihomo cannot be run at all.
        """
        for entry in self.entries:
            entry.port = MihomoManager.get_free_port()
            self.ports.append(entry.port)
        ready_port = MihomoManager.get_free_port()
        self.ports.append(ready_port)
        ready_server = await asyncio.start_server(_serve_ready, LISTEN_HOST, 0)
        try:
            ready_proxy = {"name": _READY_PROXY, "type": "http", "server": LISTEN_HOST,
                           "port": ready_server.sockets[0].getsockname()[1]}
            self.work_dir = tempfile.TemporaryDirectory(prefix=self.temp_prefix)
            work_path = self.work_dir.name
            config_file = os.path.join(work_path, "config.yaml")
            self.log_path = os.path.join(work_path, "mihomo.log")
            # The ready proxy comes last, so that Mihomo's "proxy N" still numbers the entries.
            served = [(entry.proxy, entry.port) for entry in self.entries] + [(ready_proxy, ready_port)]
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(render_batch_config(served, hosts))
            # Mihomo logs to stdout and a Go crash goes to stderr: both go to the log, which is
            # read only when something fails, so no pipe can fill up and stall Mihomo.
            with open(self.log_path, "wb") as log_file:
                self.proc = await asyncio.create_subprocess_exec(
                    MIHOMO_PATH,
                    "-d",
                    work_path,
                    "-f",
                    config_file,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=asyncio.subprocess.STDOUT,
                )
            deadline = time.monotonic() + START_TIMEOUT
            while not await _relays(ready_port):
                if self.proc.returncode is not None or time.monotonic() >= deadline:
                    return self.failure()
                await asyncio.sleep(0.02)
        finally:
            ready_server.close()
            try:
                await asyncio.wait_for(ready_server.wait_closed(), timeout=0.2)
            except Exception:
                pass
        # Mihomo opened every listener it could before relaying; one it couldn't is in busy().
        for entry in self.entries:
            if not await _accepts(entry.port):
                return self.failure()
        return None

    @property
    def timed_out(self) -> bool:
        """Whether a start failed with Mihomo running, but not relaying through every listener."""
        return self.proc is not None and self.proc.returncode is None

    def output(self) -> List[str]:
        """The last lines Mihomo wrote."""
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

    def detail(self) -> str:
        """Mihomo's own account of a failure: a Go crash, or its last error."""
        lines = self.output()
        for line in lines:
            if line.startswith(_GO_CRASH):
                return line.strip()[:300]
        for line in reversed(lines):
            level, message = _log_record(line)
            if level is None or level in ("error", "fatal", "panic"):
                return message[:300]
        return ""

    def failure(self, during: str = "") -> str:
        """Why the process is not serving: its exit code, or that its listeners never opened."""
        code = self.proc.returncode if self.proc is not None else None
        reason = f"crashed with code {code}{during}" if code is not None else "timed out opening port"
        detail = self.detail()
        return f"{reason} [{detail}]" if detail else reason

    def refused(self) -> Optional[Tuple[_Entry, str]]:
        """The entry whose proxy Mihomo refused, and Mihomo's reason, when that is what stopped it."""
        for line in reversed(self.output()):
            match = _PROXY_REFUSED.match(_log_record(line)[1])
            if match and int(match.group(1)) < len(self.entries):
                code = self.proc.returncode if self.proc is not None else None
                return self.entries[int(match.group(1))], f"crashed with code {code} [Parse config error: {match.group(2)}]"
        return None

    def busy(self) -> Dict[str, str]:
        """Listeners that could not take their port, which something else took meanwhile, and why."""
        found = {}
        for line in self.output():
            message = _log_record(line)[1]
            match = _LISTEN_FAILED.match(message)
            if match:
                found[match.group(1)] = message[:300]
        return found

    async def serves(self, port: Optional[int]) -> bool:
        """Whether this Mihomo still runs; also True once it was stopped on purpose."""
        if self.stopped:
            return True
        if self.proc is None:
            return False
        if self.proc.returncode is None and await _accepts(port, timeout=1.0):
            return True
        # An exiting Mihomo closes its listeners before its exit is noticed here.
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
        """Terminates Mihomo, killing it if it does not exit, and frees its directory and ports."""
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
            MihomoManager.release_port(port)
        self.ports = []


class NodeEndpoint:
    """How a check reaches one link: a mixed (HTTP and SOCKS5) listener of a local Mihomo.

    error says why Mihomo could not serve the link, and port is None then. mux, on the
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
        """Whether the Mihomo serving this link serves other nodes too."""
        return bool(self._process is not None and self._process.shared)

    async def ensure_alive(self) -> None:
        """Raises MihomoInstanceLost when the Mihomo serving this link has exited.

        A check calls this before it puts a failure down to the node, since a Mihomo that
        exited fails every check through it.
        """
        process = self._process
        if process is None or await process.serves(self.port):
            return
        reason = process.failure()
        if not process.shared:
            process.record_crash(self._entry, process.failure(" during the check"))
        raise MihomoInstanceLost(reason, retry=process.shared)


class MihomoBatch:
    """Local Mihomo serving a batch of nodes, each through a mixed listener of its own.

    Usually one process. Mihomo refuses a whole configuration over one proxy it can't use,
    so a node it refuses, or one it can't start with, is set aside with Mihomo's reason and
    recorded as that node's crash, and the rest start without it. `endpoints` has each
    node's endpoint, in order.
    """

    def __init__(self, nodes: Sequence[BatchNode], config: dict, temp_prefix: str = "mihomo_"):
        self.nodes = list(nodes)
        self.config = config
        self.temp_prefix = temp_prefix
        self.endpoints: List[NodeEndpoint] = []
        self._processes: List[_Process] = []
        self._hosts: Dict[str, List[str]] = {}

    async def __aenter__(self) -> "MihomoBatch":
        try:
            await self.start()
        except BaseException:
            await self.close()
            raise
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def start(self) -> None:
        """Starts Mihomo for every node it accepts; the others' endpoints carry the reason."""
        pairs = []
        servable: List[_Entry] = []
        for number, node in enumerate(self.nodes):
            main = _Entry(node.link, number, node.idx, node.total)
            mux = _Entry(node.mux_link, number, node.idx, 0) if node.mux_link else None
            pairs.append((main, mux))
            for entry in (main, mux):
                if entry is None:
                    continue
                try:
                    proxy = mihomo_proxy(entry.link, self.config)
                except Exception as exc:
                    entry.fail(str(exc), exc)
                    continue
                entry.name = f"node-{len(servable)}"
                entry.proxy = {**proxy, "name": entry.name}
                server = proxy.get("server")
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
        """On Android, each server's addresses from Android's resolver, for Mihomo's hosts section."""
        servers = list(dict.fromkeys(entry.proxy.get("server") for entry in entries if entry.proxy))
        found = await asyncio.gather(*(android_resolved_hosts(server) for server in servers))
        for hosts in found:
            for host, addresses in hosts.items():
                known = self._hosts.setdefault(host, [])
                known.extend(address for address in addresses if address not in known)

    def _hosts_for(self, entries: Sequence[_Entry]) -> Dict[str, List[str]]:
        keys = {entry.host_key for entry in entries}
        return {host: addresses for host, addresses in self._hosts.items() if host in keys}

    async def _launch(self, entries: List[_Entry]) -> None:
        """Starts Mihomo for these entries, setting aside each one it refuses or fails with."""
        port_retries = 0
        while entries:
            process = _Process(entries, self.temp_prefix)
            try:
                failure = await process.start(self._hosts_for(entries))
            except OSError as exc:
                await process.stop()
                ErrorTracker.record_error("Mihomo Process Launch", exc)
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
            # Read before stopping, which removes Mihomo's log and ends a Mihomo that runs.
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
                culprit = next((entry for entry in entries if f"in-{entry.name}" in busy), None)
                if culprit is not None:
                    error = f"could not open its port [{busy[f'in-{culprit.name}']}]"
            if culprit is None:
                if timed_out or len(entries) == 1:
                    # Mihomo ran but never relayed, which no node's proxy is known to cause,
                    # or one node is left: each node is told what happened.
                    for entry in entries:
                        entry.record_crash(failure or "did not start")
                        entry.fail(failure or "did not start")
                    return
                # Mihomo exited without saying which node stopped it: start each half on its own.
                half = len(entries) // 2
                await self._launch(entries[:half])
                await self._launch(entries[half:])
                return
            culprit.record_crash(error)
            culprit.fail(error)
            entries = [entry for entry in entries if entry is not culprit]

    def exited(self) -> List[str]:
        """Why each of its Mihomo processes that ended on its own did."""
        return [process.failure() for process in self._processes
                if not process.stopped and process.proc is not None and process.proc.returncode is not None]

    async def close(self) -> None:
        """Stops every Mihomo of the batch."""
        processes, self._processes = self._processes, []
        await asyncio.gather(*(process.stop() for process in processes), return_exceptions=True)


class MihomoRunner:
    """A node's local proxy for one check, at `port` and `proxy_url`.

    Given the node's endpoint from a MihomoBatch, the batch's Mihomo serves the node, and
    goes on serving the batch's other nodes after this check. Without one, the runner starts
    a Mihomo for this node alone and stops it when the check is done.
    """

    def __init__(
        self,
        node: str,
        config: dict,
        temp_prefix: str = "mihomo_",
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
        self._batch: Optional[MihomoBatch] = None
        self._serving: Optional[NodeEndpoint] = None

    async def __aenter__(self) -> "MihomoRunner":
        endpoint = self.endpoint
        if endpoint is None:
            self._batch = MihomoBatch(
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
        """Raises MihomoInstanceLost when the Mihomo serving the node has exited (see NodeEndpoint)."""
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
    temp_prefix: str = "mihomo_",
    error_context: str = "Worker",
) -> None:
    """Checks every (idx, node) job through shared local Mihomo instances, `workers` nodes at a time.

    links(node) is what a job needs served: the link to check the node with and, or None,
    the same node with multiplexing. None instead of the pair marks a job turned away before
    any Mihomo is needed; its check runs with no endpoint. check(idx, node, endpoint) runs
    once per job and on_result(idx, node, result) receives the result, None if check raised.

    Consecutive jobs share an instance, up to ResourceLimits.NODES_PER_INSTANCE of them. When
    an instance exits mid-check, each job whose check noticed (MihomoInstanceLost with retry)
    is checked again with an instance of its own, so a node that crashes Mihomo is found.
    """
    workers = max(1, int(workers))
    per_instance, max_instances = ResourceLimits.mihomo_instances(workers)
    node_slots = asyncio.Semaphore(workers)
    instance_slots = asyncio.Semaphore(max_instances)
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
        except MihomoInstanceLost as lost:
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
            async with MihomoBatch(nodes, config, temp_prefix) as instance:

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
            ErrorTracker.record_error("Mihomo Instance", RuntimeError(reason))
            safe_print(f"[!] A Mihomo serving {len(batch)} nodes {reason}; checking {len(lost)} of them "
                       "again, each with a Mihomo of its own.")
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
