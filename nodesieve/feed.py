"""Subscription feed output (links.txt and links-base64.txt) and post-update hook."""

from __future__ import annotations

import base64
from datetime import datetime
import os
from pathlib import Path
import stat
import subprocess
from typing import Iterable, Optional

from nodesieve.constants import PROJECT_ROOT
from nodesieve.files import write_atomic
from nodesieve.logging import log
from nodesieve.parsers.base import node_key, normalize_share_link
from nodesieve.parsers.xray import node_url_to_xray_outbound

FEED_DIR = "feed"
LINKS_NAME = "links.txt"
BASE64_NAME = "links-base64.txt"
FEED_FORMATS = ("links", "base64")


def feed_directory(config: dict) -> Path:
    configured = str(config.get("feed_dir") or "").strip()
    path = Path(configured).expanduser() if configured else Path(FEED_DIR)
    return (path if path.is_absolute() else Path(PROJECT_ROOT) / path).resolve()


def _feed_formats(config: dict) -> set[str]:
    configured = config.get("feed_formats")
    if isinstance(configured, (list, tuple, set)):
        selected = {str(item).strip().lower() for item in configured if isinstance(item, str)} & set(FEED_FORMATS)
        if selected:
            return selected
    return set(FEED_FORMATS)


def _write_if_changed(path: Path, text: str, mode: int) -> None:
    encoded = text.encode("utf-8")
    try:
        st = path.stat()
        if (os.name == "nt" or stat.S_IMODE(st.st_mode) == mode) and path.read_bytes() == encoded:
            return
    except OSError:
        pass
    write_atomic(path, text, mode)


def write_feed(nodes: Iterable, config: dict) -> dict:
    """Replace feed files with deduplicated Xray-supported share links; no-op when empty."""
    links: list[str] = []
    seen: set[str] = set()
    left_out = 0
    for node in nodes:
        link = normalize_share_link(node)
        if not link or node_url_to_xray_outbound(link.partition("#")[0]) is None:
            left_out += 1
            continue
        core = node_key(link)
        if core not in seen:
            seen.add(core)
            links.append(link)

    directory = feed_directory(config)
    result = {"written": False, "count": len(links), "left_out": left_out, "directory": str(directory)}
    if not links:
        return result

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Owner-only unless directory is world-traversable (e.g. OpenWrt uhttpd).
    mode = 0o644 if directory.stat().st_mode & 0o001 else 0o600
    payload = "".join(link + "\n" for link in links)
    formats = _feed_formats(config)
    if "base64" in formats:
        _write_if_changed(directory / BASE64_NAME, base64.b64encode(payload.encode("utf-8")).decode("ascii"), mode)
    if "links" in formats:
        _write_if_changed(directory / LINKS_NAME, payload, mode)
    result["written"] = True
    return result


def feed_server_keys(config: dict) -> Optional[list[str]]:
    """Ordered server keys currently in the feed, or None if no feed exists."""
    directory = feed_directory(config)
    try:
        text = (directory / LINKS_NAME).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        try:
            encoded = (directory / BASE64_NAME).read_text(encoding="ascii").strip()
            text = base64.b64decode(encoded).decode("utf-8")
        except (OSError, ValueError, UnicodeDecodeError):
            return None
    return [node_key(line.strip()) for line in text.splitlines() if line.strip()]


def run_feed_command(config: dict, timeout: float = 120.0) -> Optional[bool]:
    """Run configured feed_command after a feed update; None if unset."""
    command = str(config.get("feed_command") or "").strip()
    if not command:
        return None
    try:
        finished = subprocess.run(
            command, shell=True, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"[!] feed_command did not finish within {timeout:.0f} seconds.")
        return False
    except OSError as exc:
        log.warning(f"[!] feed_command could not run: {exc}")
        return False
    if finished.returncode != 0:
        output = (finished.stderr.strip() or finished.stdout.strip()).splitlines()
        log.warning(f"[!] feed_command failed with exit code {finished.returncode}"
                    + (f": {output[-1][:300]}" if output else "."))
        return False
    log.info("[*] Ran feed_command for the updated feed.")
    return True


def feed_status(config: dict) -> Optional[dict]:
    """Current feed link count and mtime, or None if missing."""
    path = feed_directory(config) / LINKS_NAME
    try:
        written_at = datetime.fromtimestamp(path.stat().st_mtime)
        count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except (OSError, UnicodeDecodeError):
        return None
    return {"count": count, "written_at": written_at}
