"""SSH to the router, for install-router: commands, and files streamed to it."""

import os
import shlex
import socket
import time
from typing import Optional, Tuple, Union

from nodesieve.logging import log


class RouterClient:
    """Runs commands on the router and streams files to it over SSH (Paramiko)."""

    def __init__(
        self,
        host: str = "192.168.1.1",
        ssh_port: int = 22,
        ssh_user: str = "root",
        ssh_pass: str = "",
        ssh_key_path: Optional[str] = None,
    ):
        self.host = host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.ssh_key_path = ssh_key_path

    def _create_ssh(self) -> "paramiko.SSHClient":  # noqa: F821
        """Creates and connects a Paramiko SSH client.

        Paramiko is imported here, not with the module: nodesieve running on the router
        itself never connects over SSH, and in Termux it is an optional install, so both
        run without it.
        """
        try:
            import paramiko
        except ImportError:
            raise RuntimeError(
                "Reaching the router over SSH needs Paramiko: pip install paramiko "
                "(in Termux, first: pkg install python-cryptography python-bcrypt python-pynacl)"
            ) from None

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
