"""Router communication client for Mihomo REST API and SSH operations."""

import os
import shlex
import socket
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple, Union

import aiohttp
import paramiko

from proxy_sites.logging import log


class RouterClient:
    """Client for interacting with OpenWrt router via REST API and SSH."""

    def __init__(
        self,
        host: str = "192.168.1.1",
        api_port: int = 9090,
        proxy_port: int = 7890,
        ssh_port: int = 22,
        ssh_user: str = "root",
        ssh_pass: str = "",
        ssh_key_path: Optional[str] = None,
        session: Optional[aiohttp.ClientSession] = None,
    ):
        self.host = host
        self.api_port = api_port
        self.proxy_port = proxy_port
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.ssh_key_path = ssh_key_path

        host_str = (
            f"[{host}]"
            if ":" in host and not host.startswith("[")
            else host
        )
        self.api_url = f"http://{host_str}:{api_port}"
        self.proxy_url = f"http://{host_str}:{proxy_port}"
        self.session = session
        self._owned_session = False

    async def __aenter__(self) -> "RouterClient":
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
            self._owned_session = True
        return self

    async def __aexit__(
        self, exc_type: Any, exc_val: Any, exc_tb: Any
    ) -> None:
        if (
            self._owned_session
            and self.session is not None
            and not self.session.closed
        ):
            await self.session.close()
            self.session = None
            self._owned_session = False

    async def _get_session(
        self, timeout_sec: float
    ) -> Tuple[aiohttp.ClientSession, bool]:
        if self.session is not None and not self.session.closed:
            return self.session, False
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        return aiohttp.ClientSession(timeout=timeout), True

    # --- REST API Operations (:9090) ---

    async def is_api_alive(self) -> bool:
        """Checks if Mihomo external controller REST API is reachable."""
        try:
            timeout_sec = 2.0
            req_timeout = aiohttp.ClientTimeout(total=timeout_sec)
            session, should_close = await self._get_session(
                timeout_sec=timeout_sec
            )
            try:
                async with session.get(
                    f"{self.api_url}/version", timeout=req_timeout
                ) as resp:
                    return resp.status == 200
            finally:
                if should_close:
                    await session.close()
        except Exception as e:
            log.debug(f"Router REST API not alive at {self.api_url}: {e}")
            return False

    async def reload_provider(
        self, provider_name: str = "Gemini_Nodes"
    ) -> bool:
        """Triggers dynamic reload of proxy provider from disk."""
        try:
            quoted_provider = urllib.parse.quote(provider_name, safe="")
            timeout_sec = 5.0
            req_timeout = aiohttp.ClientTimeout(total=timeout_sec)
            session, should_close = await self._get_session(
                timeout_sec=timeout_sec
            )
            try:
                url = f"{self.api_url}/providers/proxies/{quoted_provider}"
                async with session.put(url, timeout=req_timeout) as resp:
                    return resp.status in (200, 204)
            finally:
                if should_close:
                    await session.close()
        except Exception as e:
            log.error(
                f"Router reload_provider failed for '{provider_name}': {e}"
            )
            return False

    async def probe_group_delay(
        self,
        group_name: str = "Gemini_Auto",
        url: str = "https://www.gstatic.com/generate_204",
        timeout_ms: int = 3000,
    ) -> Dict[str, int]:
        """Probes proxy group delay concurrently through router WAN."""
        try:
            quoted_group = urllib.parse.quote(group_name, safe="")
            timeout_sec = (timeout_ms / 1000.0) + 2.0
            req_timeout = aiohttp.ClientTimeout(total=timeout_sec)
            params = {"url": url, "timeout": str(timeout_ms)}
            session, should_close = await self._get_session(
                timeout_sec=timeout_sec
            )
            try:
                req_url = f"{self.api_url}/group/{quoted_group}/delay"
                async with session.get(
                    req_url, params=params, timeout=req_timeout
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if isinstance(data, dict):
                            return data
                    log.warning(
                        f"probe_group_delay HTTP {resp.status} for "
                        f"'{group_name}'"
                    )
                    return {}
            finally:
                if should_close:
                    await session.close()
        except Exception as e:
            log.error(
                f"Router probe_group_delay failed for '{group_name}': {e}"
            )
            return {}

    async def get_proxies(self) -> Dict[str, Any]:
        """Queries /proxies endpoint and returns dictionary of all proxies/groups."""
        try:
            timeout_sec = 3.0
            req_timeout = aiohttp.ClientTimeout(total=timeout_sec)
            session, should_close = await self._get_session(
                timeout_sec=timeout_sec
            )
            try:
                async with session.get(
                    f"{self.api_url}/proxies", timeout=req_timeout
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if isinstance(data, dict):
                            return data.get("proxies", {})
                    return {}
            finally:
                if should_close:
                    await session.close()
        except Exception as e:
            log.debug(f"Failed to query /proxies from {self.api_url}: {e}")
            return {}

    async def has_proxy_group(self, group_name: str) -> bool:
        """Checks whether a specific proxy group exists on the router."""
        proxies = await self.get_proxies()
        return group_name in proxies

    # --- Paramiko SSH Operations (:22) ---

    def _create_ssh(self) -> paramiko.SSHClient:
        """Creates and connects a Paramiko SSH client."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {
            "hostname": self.host,
            "port": self.ssh_port,
            "username": self.ssh_user,
            "timeout": 5.0,
            "banner_timeout": 5.0,
        }
        if self.ssh_key_path and os.path.exists(self.ssh_key_path):
            connect_kwargs["key_filename"] = self.ssh_key_path
        elif self.ssh_pass:
            connect_kwargs["password"] = self.ssh_pass

        client.connect(**connect_kwargs)
        return client

    def exec_command(
        self, cmd: str, timeout: float = 15.0, stdin_data: Optional[str] = None
    ) -> Tuple[int, str, str]:
        """Executes command on router via SSH. Returns (code, out, err)."""
        client = None
        start_time = time.time()
        try:
            client = self._create_ssh()
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
                stdin.channel.shutdown_write()
            out = stdout.read().decode("utf-8", errors="ignore")
            err = stderr.read().decode("utf-8", errors="ignore")

            elapsed = time.time() - start_time
            remaining = max(0.1, timeout - elapsed)
            channel = stdout.channel
            if hasattr(channel, "status_event"):
                if not channel.status_event.wait(timeout=remaining):
                    raise TimeoutError(
                        f"Command timed out after {timeout}s"
                    )
            exit_code = channel.recv_exit_status()
            return exit_code, out, err
        except (TimeoutError, socket.timeout) as e:
            err_msg = str(e) if str(e) else "Command timed out"
            log.error(f"SSH exec_command timed out for '{cmd}': {err_msg}")
            return -1, "", err_msg
        except Exception as e:
            log.error(f"SSH exec_command failed for '{cmd}': {e}")
            return -1, "", str(e)
        finally:
            if client is not None:
                client.close()

    def stream_file_to_router(
        self, content: Union[str, bytes], remote_path: str, mode: str = "0644"
    ) -> bool:
        """Streams file content to remote router path via SSH stdin."""
        client = None
        try:
            client = self._create_ssh()
            quoted_path = shlex.quote(remote_path)
            quoted_mode = shlex.quote(mode)
            cmd = f"cat > {quoted_path} && chmod {quoted_mode} {quoted_path}"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=15.0)
            if isinstance(content, bytes):
                stdin.channel.sendall(content)
            elif isinstance(content, str):
                stdin.write(content)
            else:
                stdin.write(str(content))
            stdin.flush()
            stdin.channel.shutdown_write()
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                err = stderr.read().decode("utf-8", errors="ignore")
                log.error(
                    f"stream_file_to_router failed (code {exit_code}): {err}"
                )
                return False
            return True
        except Exception as e:
            log.error(f"stream_file_to_router failed: {e}")
            return False
        finally:
            if client is not None:
                client.close()
