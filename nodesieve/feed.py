"""Subscription feed: a scan's results as files any VPN app can subscribe to.

Each scan that finds working nodes writes them to the feed directory, `feed/`
in the project directory unless the `feed_dir` setting names another one:

- links.txt: one share link per line. v2rayNG, Hiddify, NekoBox, Happ, v2RayTun and
  Steer subscribe to this.
- links-base64.txt: the same list, base64-encoded, for apps that only read that.
- clash.yaml: a complete Clash/Mihomo profile, for Clash Meta for Android, FlClash
  and other Clash apps.

A scan that finds nothing leaves the feed as it is, so apps keep their last good
servers. `python -m nodesieve serve` serves the files over HTTP.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
from typing import Iterable, Optional
from urllib.parse import quote, unquote

from aiohttp import web
try:
    import yaml
except ImportError:
    yaml = None  # Only needed when writing clash.yaml.

from nodesieve.constants import DEFAULT_CONFIG, GOOGLE_HEALTHCHECK_URL, PROJECT_ROOT
from nodesieve.files import write_private
from nodesieve.logging import log
from nodesieve.parsers.base import SHARE_SCHEMES, node_key
from nodesieve.parsers.mihomo import node_url_to_mihomo_dict
from nodesieve.parsers.xray import node_url_to_xray_outbound

FEED_DIR = "feed"
LINKS_NAME = "links.txt"
BASE64_NAME = "links-base64.txt"
CLASH_NAME = "clash.yaml"
FEED_FILES = (LINKS_NAME, BASE64_NAME, CLASH_NAME)
FEED_FORMATS = ("links", "base64", "clash")

SELECT_GROUP = "nodesieve"
AUTO_GROUP = "Auto"
# Names Mihomo resolves to its own policies or to the profile's groups; no proxy may take them.
_RESERVED_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", SELECT_GROUP, AUTO_GROUP}
_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")


def feed_directory(config: dict) -> Path:
    """Where the feed is written: feed_dir, relative to the project directory, or feed/ there."""
    configured = str(config.get("feed_dir") or "").strip()
    path = Path(configured).expanduser() if configured else Path(FEED_DIR)
    return (path if path.is_absolute() else Path(PROJECT_ROOT) / path).resolve()


def _without_mux_marker(core: str) -> str:
    """The link without smux, nodesieve's own marker for a node without multiplexing."""
    base, separator, query = core.partition("?")
    if not separator:
        return core
    kept = [part for part in query.split("&") if part and part.split("=", 1)[0] != "smux"]
    return base + ("?" + "&".join(kept) if kept else "")


def _share_link(node: object) -> Optional[str]:
    """The node as a share link other apps read, or None when it has none.

    Each link takes one line, so nothing that could split it gets through. Its name
    is encoded the way the Steer export encodes it, and the smux marker is dropped:
    no other app reads it.
    """
    if not isinstance(node, str) or any(ord(c) < 32 or ord(c) == 127 for c in node):
        return None
    core, separator, fragment = node.strip().partition("#")
    if any(c.isspace() for c in core) or core.partition("://")[0].lower() not in SHARE_SCHEMES:
        return None
    return _without_mux_marker(core) + ("#" + quote(unquote(fragment), safe="") if separator else "")


def _feed_formats(config: dict) -> set[str]:
    """Which feed files to write: any subset of links, base64, clash; all three by default."""
    configured = config.get("feed_formats")
    if isinstance(configured, (list, tuple, set)):
        selected = {str(item).strip().lower() for item in configured if isinstance(item, str)} & set(FEED_FORMATS)
        if selected:
            return selected
    return set(FEED_FORMATS)


def _entries(
    nodes: Iterable, use_mux: bool, include_clash: bool = True,
) -> tuple[list[tuple[str, Optional[dict]]], int]:
    """(share link, Mihomo proxy or None) of each node, in order and without repeats, and how many were left out.

    A link that neither Xray nor Mihomo can read stays out.
    """
    entries: list[tuple[str, Optional[dict]]] = []
    seen: set[str] = set()
    left_out = 0
    for node in nodes:
        link = _share_link(node)
        if not link:
            left_out += 1
            continue
        raw = node.strip()
        xray_ok = node_url_to_xray_outbound(raw) is not None
        # The proxy comes from the node as tested, so its smux marker still applies.
        proxy = node_url_to_mihomo_dict(raw, use_mux=use_mux) if (include_clash or not xray_ok) else None
        if not xray_ok and proxy is None:
            left_out += 1
            continue
        core = node_key(link)
        if core not in seen:
            seen.add(core)
            entries.append((link, proxy))
    return entries, left_out


def clash_profile(proxies: list[dict]) -> str:
    """A complete Clash/Mihomo profile: the proxies, a fallback group in their order, one rule.

    The fallback group uses the first proxy that answers, so the scan's ranking decides,
    and the select group in front of it lets a node be picked by hand.
    """
    if yaml is None:
        raise RuntimeError("PyYAML is required to build clash.yaml (install PyYAML or python3-yaml).")
    proxies = [dict(proxy) for proxy in proxies]
    used = set(_RESERVED_NAMES)
    for proxy in proxies:
        base = str(proxy.get("name") or "").strip() or f"{proxy['type']}_{proxy['server']}_{proxy['port']}"
        name, number = base, 2
        while name in used:
            name, number = f"{base} ({number})", number + 1
        used.add(name)
        proxy["name"] = name
    names = [proxy["name"] for proxy in proxies]
    profile = {
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {"name": SELECT_GROUP, "type": "select", "proxies": [AUTO_GROUP, *names]},
            {"name": AUTO_GROUP, "type": "fallback", "proxies": names,
             "url": GOOGLE_HEALTHCHECK_URL, "expected-status": "204", "interval": 300},
        ],
        "rules": [f"MATCH,{SELECT_GROUP}"],
    }
    return "# Written by nodesieve. Each scan replaces this profile.\n" + yaml.safe_dump(
        profile, allow_unicode=True, sort_keys=False)


def _write_if_changed(path: Path, text: str, mode: int) -> None:
    """Write text atomically unless path already has identical bytes and permissions."""
    encoded = text.encode("utf-8")
    try:
        st = path.stat()
        if (os.name == "nt" or stat.S_IMODE(st.st_mode) == mode) and path.read_bytes() == encoded:
            return
    except OSError:
        pass
    write_private(path, text, mode)


def write_feed(nodes: Iterable, config: dict) -> dict:
    """Replace the feed with the nodes that have a share link; with none, leave the feed as it is.

    Steer scans don't check multiplexing, so their profile never turns it on.
    """
    formats = _feed_formats(config)
    want_clash = "clash" in formats
    if want_clash and yaml is None:
        log.warning("[!] PyYAML is not installed; skipping clash.yaml in the subscription feed.")
        want_clash = False
    use_mux = bool(config.get("use_mux", True)) and not config.get("routing", {}).get("enabled", False)
    entries, left_out = _entries(nodes, use_mux, include_clash=want_clash)
    directory = feed_directory(config)
    result = {"written": False, "count": len(entries), "left_out": left_out, "directory": str(directory)}
    if not entries:
        return result
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # The files hold proxy credentials, so only their owner reads them, unless their directory
    # lets others in, as a web server's does: uhttpd serves only files that anyone may read.
    mode = 0o644 if directory.stat().st_mode & 0o001 else 0o600
    links = "".join(link + "\n" for link, _ in entries)
    wrote_any = False
    if want_clash:
        proxies = [proxy for _, proxy in entries if proxy is not None]
        if proxies:
            _write_if_changed(directory / CLASH_NAME, clash_profile(proxies), mode)
            wrote_any = True
    if "base64" in formats:
        _write_if_changed(directory / BASE64_NAME, base64.b64encode(links.encode("utf-8")).decode("ascii"), mode)
        wrote_any = True
    if "links" in formats:
        _write_if_changed(directory / LINKS_NAME, links, mode)
        wrote_any = True
    result["written"] = wrote_any
    return result


def feed_server_keys(config: dict) -> Optional[list[str]]:
    """Ordered server keys (ignoring display names) currently in the feed, or None without one."""
    directory = feed_directory(config)
    text: Optional[str] = None
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
    """Run the feed_command setting after the feed changed: True when it succeeded, None without one."""
    command = str(config.get("feed_command") or "").strip()
    if not command:
        return None
    try:
        finished = subprocess.run(command, shell=True, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, errors="replace", timeout=timeout)
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
    """The feed as apps get it now: how many links and when it was written, or None without one."""
    path = feed_directory(config) / LINKS_NAME
    try:
        written_at = datetime.fromtimestamp(path.stat().st_mtime)
        count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except (OSError, UnicodeDecodeError):
        return None
    return {"count": count, "written_at": written_at}


def new_token() -> str:
    """A random path segment that keeps the feed's address unguessable."""
    return secrets.token_urlsafe(18)


def valid_token(token: object) -> bool:
    return isinstance(token, str) and _TOKEN.fullmatch(token) is not None


def _update_hours(config: dict) -> int:
    hours = config.get("feed_update_hours", DEFAULT_CONFIG["feed_update_hours"])
    return hours if isinstance(hours, int) and not isinstance(hours, bool) and hours >= 1 \
        else DEFAULT_CONFIG["feed_update_hours"]


def build_app(config: dict, token: str) -> web.Application:
    """The feed's web app: GET /<token>/<file> for each feed file, 404 for anything else.

    Files are read on every request, so a scan's new feed is served without a restart.
    """
    directory = feed_directory(config)
    expected = token.encode("utf-8")
    headers = {
        "Cache-Control": "no-store",
        # How often subscribed apps refresh, in hours, and the name they show for it.
        "profile-update-interval": str(_update_hours(config)),
        "profile-title": "nodesieve",
    }

    async def handle(request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if name not in FEED_FILES or not hmac.compare_digest(request.match_info["token"].encode("utf-8"), expected):
            raise web.HTTPNotFound()
        try:
            body = (directory / name).read_bytes()
        except FileNotFoundError:
            return web.Response(status=503, text="No feed yet: run a scan first (python -m nodesieve check).\n")
        except OSError:
            return web.Response(status=500, text="The feed could not be read.\n")
        return web.Response(body=body, content_type="text/plain", charset="utf-8", headers=headers)

    app = web.Application()
    app.router.add_get("/{token}/{name}", handle)
    return app


def _base_url(host: str, port: int) -> str:
    if host in ("0.0.0.0", "::"):
        host = "<this device's address>"
    elif ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{port}"


async def serve_feed(config: dict, token: str, host: str, port: int) -> None:
    """Serve the feed on host:port until cancelled, as Ctrl+C does."""
    runner = web.AppRunner(build_app(config, token), access_log=None)
    await runner.setup()
    try:
        await web.TCPSite(runner, host, port).start()
        base = f"{_base_url(host, port)}/{token}"
        log.info(f"[+] Serving the subscription feed in {feed_directory(config)} on {_base_url(host, port)}")
        log.info("[*] Subscribe your VPN app to one of these addresses. Every scan updates what they return.")
        log.info(f"    Share links (v2rayNG, Hiddify, NekoBox, Happ, v2RayTun, Steer): {base}/{LINKS_NAME}")
        log.info(f"    Share links in base64, for apps that read only that: {base}/{BASE64_NAME}")
        log.info(f"    Clash/Mihomo profile (Clash Meta for Android, FlClash): {base}/{CLASH_NAME}")
        if feed_status(config) is None:
            log.warning("[!] There is no feed yet: these addresses answer 503 until a scan writes one (python -m nodesieve check).")
        log.info("[*] Press Ctrl+C to stop.")
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
