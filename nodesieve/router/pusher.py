"""Router deployment pusher using direct SSH streaming via RouterClient."""

import os
from typing import Optional

from nodesieve.config import ConfigManager
from nodesieve.constants import PROJECT_ROOT, ROUTER_SCRIPT_FILE
from nodesieve.logging import log
from nodesieve.router.client import RouterClient


def push_to_router(
    router_client: Optional[RouterClient] = None,
    config: Optional[dict] = None,
) -> bool:
    """Streams apply_to_router.sh to router via SSH and executes it."""
    script_path = ROUTER_SCRIPT_FILE
    if not os.path.isabs(script_path) and not os.path.exists(script_path):
        script_path = os.path.join(PROJECT_ROOT, ROUTER_SCRIPT_FILE)

    if not os.path.exists(script_path):
        log.info(
            f"[-] {ROUTER_SCRIPT_FILE} not found. Run check or pipeline first."
        )
        return False

    try:
        with open(script_path, "r", encoding="utf-8") as f:
            script_content = f.read()
    except Exception as e:
        log.error(f"[-] Failed to read {script_path}: {e}")
        return False

    if router_client is not None:
        client = router_client
    else:
        cfg = config if config is not None else ConfigManager.load()
        client = RouterClient(
            host=cfg.get("router_host", "192.168.1.1"),
            api_port=cfg.get("router_api_port", 9090),
            proxy_port=cfg.get("router_proxy_port", 7890),
            ssh_port=cfg.get("router_ssh_port", 22),
            ssh_user=cfg.get("router_ssh_user", "root"),
            ssh_pass=cfg.get("router_ssh_pass", ""),
        )
    log.info("[*] Uploading deployment script directly to router via SSH...")
    remote_path = "/tmp/apply_to_router.sh"
    if not client.stream_file_to_router(
        script_content, remote_path, mode="0755"
    ):
        log.error("[-] Failed to stream apply_to_router.sh to router.")
        return False

    log.info("[*] Executing deployment script on router...")
    exec_cmd = (
        f"/bin/sh {remote_path}; rc=$?; "
        f"rm -f {remote_path}; exit $rc"
    )
    code, out, err = client.exec_command(exec_cmd)
    if code != 0:
        log.error(
            f"[-] Router deployment failed with code {code}:\n{err or out}"
        )
        return False

    log.info("[+] Deployment script executed successfully.")
    return True
