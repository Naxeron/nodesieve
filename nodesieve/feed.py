"""Subscription feed: a scan's results as files any VPN app can subscribe to.

Each scan that finds nodes to deploy also writes them to the feed directory, `feed/`
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
from pathlib import Path
import re
import secrets
from typing import Iterable, Optional
from urllib.parse import quote, unquote

from aiohttp import web
import yaml

from nodesieve.constants import DEFAULT_CONFIG, GOOGLE_HEALTHCHECK_URL, PROJECT_ROOT
from nodesieve.files import write_private
from nodesieve.logging import log
from nodesieve.parsers.mihomo import node_url_to_mihomo_dict

FEED_DIR = "feed"
LINKS_NAME = "links.txt"
BASE64_NAME = "links-base64.txt"
CLASH_NAME = "clash.yaml"
FEED_FILES = (LINKS_NAME, BASE64_NAME, CLASH_NAME)

# The link types nodesieve tests and other apps import.
SCHEMES = {"vless", "trojan", "ss"}
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
    if any(c.isspace() for c in core) or core.split("://", 1)[0] not in SCHEMES:
        return None
    return _without_mux_marker(core) + ("#" + quote(unquote(fragment), safe="") if separator else "")


def _entries(nodes: Iterable, use_mux: bool) -> tuple[list[tuple[str, dict]], int]:
    """(share link, Mihomo proxy) of each node, in order and without repeats, and how many were left out.

    WARP and AmneziaWG nodes (warp://, awg_conf:) use this computer's keys and files and
    have no share link, so they stay out, as does a link Mihomo can't read.
    """
    entries: list[tuple[str, dict]] = []
    seen: set[str] = set()
    left_out = 0
    for node in nodes:
        link = _share_link(node)
        # The proxy comes from the node as tested, so its smux marker still applies.
        proxy = node_url_to_mihomo_dict(node.strip(), use_mux=use_mux) if link else None
        if proxy is None:
            left_out += 1
            continue
        core = link.split("#", 1)[0]
        if core not in seen:
            seen.add(core)
            entries.append((link, proxy))
    return entries, left_out


def clash_profile(proxies: list[dict]) -> str:
    """A complete Clash/Mihomo profile: the proxies, a fallback group in their order, one rule.

    The fallback group uses the first proxy that answers, so the scan's ranking decides,
    and the select group in front of it lets a node be picked by hand.
    """
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


def write_feed(nodes: Iterable, config: dict) -> dict:
    """Replace the feed with the nodes that have a share link; with none, leave the feed as it is.

    Steer scans don't check multiplexing, so their profile never turns it on.
    """
    use_mux = bool(config.get("use_mux", True)) and not config.get("routing", {}).get("enabled", False)
    entries, left_out = _entries(nodes, use_mux)
    directory = feed_directory(config)
    result = {"written": False, "count": len(entries), "left_out": left_out, "directory": str(directory)}
    if not entries:
        return result
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    links = "".join(link + "\n" for link, _ in entries)
    write_private(directory / CLASH_NAME, clash_profile([proxy for _, proxy in entries]))
    write_private(directory / BASE64_NAME, base64.b64encode(links.encode("utf-8")).decode("ascii"))
    write_private(directory / LINKS_NAME, links)
    result["written"] = True
    return result


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
