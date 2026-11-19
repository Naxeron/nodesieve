"""Mihomo binary lifecycle, dynamic port pool allocation, and safe subprocess runner."""

import asyncio
import gzip
import io
import json
import os
import platform
import socket
import sys
import tempfile
import threading
import urllib.request
import zipfile
from typing import Optional, Set
import yaml

from proxy_sites.constants import (
    CONFIG_YAML_TEMPLATE,
    CRASHED_LOG_FILE,
    MIHOMO_PATH,
    PROJECT_ROOT,
)
from proxy_sites.logging import ErrorTracker, log, safe_close_writer, safe_print
from proxy_sites.parsers.awg import generate_awg_proxy_yaml, parse_amnezia_conf
from proxy_sites.parsers.base import extract_host_port, get_node_name
from proxy_sites.parsers.mihomo import node_url_to_mihomo_dict
from proxy_sites.warp import WarpScanner


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


class MihomoRunner:
    """Async context manager encapsulating isolated Mihomo subprocess lifecycles, configuration generation, and port management."""

    def __init__(
        self,
        node: str,
        config: dict,
        temp_prefix: str = "mihomo_",
        node_idx: int = 0,
        total_nodes: int = 0,
    ):
        self.node = node
        self.config = config
        self.temp_prefix = temp_prefix
        self.node_idx = node_idx
        self.total_nodes = total_nodes

        self.port: Optional[int] = None
        self.proxy_url: Optional[str] = None
        self.work_dir: Optional[tempfile.TemporaryDirectory] = None
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.started = False

    async def _cleanup(self) -> None:
        """Cleans up all allocated resources: terminates process, cleans work directory, and releases port."""
        await self._terminate_process()
        if self.work_dir:
            try:
                self.work_dir.cleanup()
            except Exception:
                pass
            self.work_dir = None
        if self.port is not None:
            MihomoManager.release_port(self.port)
            self.port = None

    async def __aenter__(self) -> "MihomoRunner":
        try:
            self.port = MihomoManager.get_free_port()
            self.proxy_url = f"http://127.0.0.1:{self.port}"
            self.work_dir = tempfile.TemporaryDirectory(prefix=self.temp_prefix)

            work_path = self.work_dir.name
            node_file = os.path.join(work_path, "node.txt")
            config_file = os.path.join(work_path, "config.yaml")

            # Generate node configuration
            if self.node.startswith("warp://"):
                host_w, port_w = extract_host_port(self.node)
                proxy_dict = WarpScanner.generate_warp_proxy_dict(
                    host_w or "127.0.0.1", port_w or 2408, get_node_name(self.node), config=self.config
                )
                awg_yaml = generate_awg_proxy_yaml(proxy_dict)
                with open(node_file, "w", encoding="utf-8") as f:
                    f.write("proxies:\n" + awg_yaml + "\n")
            elif self.node.startswith("awg_conf:"):
                conf_file = self.node.split("awg_conf:", 1)[1].split("#", 1)[0]
                conf_path = os.path.join(PROJECT_ROOT, conf_file)
                if not os.path.exists(conf_path) and os.path.exists(conf_file):
                    conf_path = conf_file
                proxy_dict = parse_amnezia_conf(conf_path, proxy_name=get_node_name(self.node))
                if proxy_dict:
                    awg_yaml = generate_awg_proxy_yaml(proxy_dict)
                    with open(node_file, "w", encoding="utf-8") as f:
                        f.write("proxies:\n" + awg_yaml + "\n")
                else:
                    raise ValueError(f"Could not parse AWG config: {conf_file}")
            else:
                p_dict = node_url_to_mihomo_dict(self.node, use_mux=self.config.get("use_mux", True))
                if p_dict:
                    with open(node_file, "w", encoding="utf-8") as f:
                        f.write(yaml.dump({"proxies": [p_dict]}, allow_unicode=True, sort_keys=False))
                else:
                    with open(node_file, "w", encoding="utf-8") as f:
                        f.write(self.node + "\n")

            # Generate main Mihomo YAML
            config_content = CONFIG_YAML_TEMPLATE.replace("{PORT}", str(self.port)).replace("{NODE_FILE}", node_file)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Launch Mihomo process
            try:
                self.proc = await asyncio.create_subprocess_exec(
                    MIHOMO_PATH,
                    "-d",
                    work_path,
                    "-f",
                    config_file,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
            except OSError as e:
                ErrorTracker.record_error("Mihomo Process Launch", e)
                raise

            # Poll port until service is active with fast adaptive polling
            for _ in range(150):
                if self.proc.returncode is not None:
                    break
                try:
                    fut = asyncio.open_connection("127.0.0.1", self.port)
                    reader, writer = await asyncio.wait_for(fut, timeout=0.05)
                    await safe_close_writer(writer)
                    self.started = True
                    break
                except Exception:
                    await asyncio.sleep(0.01)

            initial_returncode = self.proc.returncode
            if not self.started or initial_returncode is not None:
                stderr_msg = ""
                if self.proc.stderr:
                    try:
                        stderr_data = await asyncio.wait_for(self.proc.stderr.read(), timeout=0.2)
                        stderr_text = stderr_data.decode(errors="ignore").strip()
                        if stderr_text:
                            stderr_msg = stderr_text.splitlines()[-1]
                    except Exception:
                        pass

                host, port = extract_host_port(self.node)
                node_name = get_node_name(self.node)
                err_msg = f"crashed with code {initial_returncode}" if initial_returncode is not None else "timed out opening port"
                if stderr_msg:
                    err_msg += f" [{stderr_msg}]"

                if self.proc.returncode != 2 and self.total_nodes > 0:
                    safe_print(
                        f"[-] Node {self.node_idx}/{self.total_nodes} [{node_name}] ({host}:{port}) -> ERROR: mihomo {err_msg}"
                    )

                try:
                    crashed_log_path = os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE)
                    with open(crashed_log_path, "a", encoding="utf-8") as f:
                        f.write(f"[{node_name}] ({host}:{port}) ERROR: {err_msg}\n{self.node}\n\n")
                except Exception:
                    pass

                raise RuntimeError(f"Mihomo failed to initialize: {err_msg}")

            return self
        except Exception:
            await self._cleanup()
            raise

    async def _terminate_process(self) -> None:
        """Gracefully terminates and forces kill if needed on Mihomo process."""
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=0.25)
            except Exception:
                try:
                    self.proc.kill()
                    await asyncio.wait_for(self.proc.wait(), timeout=0.15)
                except Exception:
                    pass

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._cleanup()
