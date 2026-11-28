"""Shared URI parsing, protocol detection, host/port extraction, and node naming."""

import base64
import re
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote

from nodesieve.parsers.hysteria2 import HYSTERIA2_SCHEMES, parse_hysteria2

SHARE_SCHEMES = frozenset(("vless", "trojan", "ss", *HYSTERIA2_SCHEMES))
_FLAG_TAIL = re.compile(r"\s*[\U0001F1E6-\U0001F1FF]{2}.*$")


def b64decode_str(text: str) -> str:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")


def parse_share_link(url: str) -> Optional[Tuple[str, str, str, int, Dict[str, str]]]:
    """Parse a non-Hysteria2 share link into (scheme, user, server, port, query), or None."""
    core, _, query_text = url.split("#", 1)[0].partition("?")
    scheme, sep, authority = core.partition("://")
    if not sep:
        return None
    scheme = scheme.lower()
    query = {k: v[0] for k, v in parse_qs(query_text, keep_blank_values=True).items()}
    authority = authority.rstrip("/")
    try:
        if scheme == "ss" and "@" not in authority:
            authority = b64decode_str(authority)
        user, at, host_port = authority.rpartition("@")
        if not at:
            return None
        host, colon, port_s = host_port.rpartition(":")
        if not colon or not host:
            return None
        server, port = host.strip("[]"), int(port_s)
    except (ValueError, UnicodeDecodeError):
        return None
    if not server or not 0 < port <= 65535:
        return None
    return scheme, unquote(user), server, port, query


def normalize_share_link(node: object) -> Optional[str]:
    """Validate a single-line supported share link and normalize its fragment encoding."""
    if not isinstance(node, str) or any(ord(c) < 32 or ord(c) == 127 for c in node):
        return None
    core, sep, fragment = node.strip().partition("#")
    if any(c.isspace() for c in core) or core.partition("://")[0].lower() not in SHARE_SCHEMES:
        return None
    return core + ("#" + quote(unquote(fragment), safe="") if sep else "")


def node_key(node: str) -> str:
    """Deduplication key ignoring display names and Hysteria 2 scheme aliases."""
    core = node.partition("#")[0]
    scheme, _, rest = core.partition("://")
    return "hysteria2://" + rest if scheme.lower() in HYSTERIA2_SCHEMES else core


def get_flag_emoji(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return ""
    cc = country_code.upper()
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


def get_node_name(node_uri: str) -> str:
    return unquote(node_uri.split("#", 1)[1]) if "#" in node_uri else "Unknown Node"


def extract_node_protocol(node_uri: str) -> str:
    if "://" not in node_uri:
        return "VPN"
    proto = node_uri.split("://", 1)[0].upper()
    return {"SHADOWSOCKS": "SS", "HY2": "HYSTERIA2"}.get(proto, proto)


def extract_host_port(node_uri: str) -> Tuple[Optional[str], Optional[int]]:
    """Extract (host, port) from any supported proxy URI."""
    if extract_node_protocol(node_uri) == "HYSTERIA2":
        link = parse_hysteria2(node_uri)
        return (link.server, link.port) if link else (None, None)
    parsed = parse_share_link(node_uri)
    return (parsed[2], parsed[3]) if parsed else (None, None)


def format_descriptive_node_name(
    node: str,
    country_code: Optional[str],
    country_name: Optional[str],
    ip_str: str,
    speed_mbps: Optional[float] = None,
) -> str:
    """Build a clean, idempotent descriptive display name for a validated node."""
    proto = extract_node_protocol(node)
    orig_tag = "Node"
    if "#" in node:
        raw = unquote(node.split("#", 1)[1])
        m = re.search(r"\[[A-Za-z0-9_-]+:\s*([^\[\]]+)\]", raw, flags=re.IGNORECASE)
        if m:
            cleaned = m.group(1).strip()
            while inner := re.match(r"^\[[A-Za-z0-9_-]+:\s*(.+)\]$", cleaned, flags=re.IGNORECASE):
                cleaned = inner.group(1).strip()
        else:
            cleaned = re.sub(r"^\s*\[(?:⚡|[\d\.]+\s*MB/s|[A-Za-z0-9_-]+).*?\]\s*", "", raw, flags=re.IGNORECASE)
            cleaned = re.sub(r"^[\U0001F1E6-\U0001F1FF]{2}[-\s]*", "", cleaned).split("|")[0].strip()
        orig_tag = _FLAG_TAIL.sub("", cleaned).strip() or "Node"

    flag = get_flag_emoji(country_code) if country_code else "🌐"
    c_name = (country_name or country_code or "Unknown").replace(" ", "-")
    parts = [f"[{proto}: {orig_tag}] {flag} {c_name}"]
    if speed_mbps is not None and speed_mbps > 0:
        parts.append(f"⚡ {speed_mbps:.1f} MB/s")
    if ip_str:
        parts.append(ip_str)
    return " | ".join(parts)
