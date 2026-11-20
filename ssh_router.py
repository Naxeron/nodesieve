"""Router SSH execution helper script modernized with Paramiko."""

import sys
from typing import Any, Dict, Optional

import paramiko


def run_ssh(
    command: str,
    host: str = "192.168.1.1",
    user: str = "root",
    password: str = "",
    port: int = 22,
    timeout: float = 30.0,
    key_filename: Optional[str] = None,
) -> str:
    """Executes command on router via SSH, streams out, and propagates code.

    Without a password or key file, the SSH agent and default key files are used.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": 5.0,
            "banner_timeout": 5.0,
        }
        if key_filename:
            connect_kwargs["key_filename"] = key_filename
        elif password:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        status = stdout.channel.recv_exit_status()

        sys.stdout.write(out)
        sys.stdout.flush()
        if err:
            sys.stderr.write(err)
            sys.stderr.flush()

        if status != 0:
            sys.exit(status)
        return out
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write(f"SSH error: {e}\n")
        sys.stderr.flush()
        sys.exit(1)
    finally:
        client.close()


def saved_router_settings() -> Dict[str, Any]:
    """Router connection settings saved in nodesieve_config.json, as run_ssh arguments."""
    try:
        from nodesieve.config import ConfigManager
        from nodesieve.constants import PROJECT_ROOT

        config = ConfigManager.load(ConfigManager.default_path(PROJECT_ROOT))
    except Exception:
        return {}
    return {
        "host": config["router_host"],
        "user": config["router_ssh_user"],
        "password": config["router_ssh_pass"],
        "port": config["router_ssh_port"],
        "key_filename": config.get("router_ssh_key_path") or None,
    }


if __name__ == "__main__":
    cmd = (
        " ".join(sys.argv[1:])
        if len(sys.argv) > 1
        else "logread | grep zapret2"
    )
    run_ssh(cmd, **saved_router_settings())
