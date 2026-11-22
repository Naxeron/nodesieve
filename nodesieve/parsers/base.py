"""Basic URI parsing, protocol detection, host/port extraction, and node naming."""

import base64
import re
import urllib.parse
from typing import Optional, Tuple

from nodesieve.parsers.hysteria2 import HYSTERIA2_SCHEMES, parse_hysteria2

SHARE_SCHEMES = frozenset(("vless", "trojan", "ss", *HYSTERIA2_SCHEMES))


def node_key(node: str) -> str:
    """Identify duplicate links across display names and Hysteria 2 scheme aliases."""
    core = node.partition("#")[0]
    scheme, _, rest = core.partition("://")
    return "hysteria2://" + rest if scheme.lower() in HYSTERIA2_SCHEMES else core


def get_flag_emoji(country_code: str) -> str:
    """Converts a 2-letter ISO country code into Unicode flag emoji."""
    if not country_code:
        return ""
    country_code = country_code.upper()
    if len(country_code) != 2:
        return ""
    return chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)


def get_node_name(node_uri: str) -> str:
    """Extracts decoded node tag/name from URI fragment."""
    if "#" in node_uri:
        return urllib.parse.unquote(node_uri.split("#", 1)[1])
    return "Unknown Node"


def extract_node_protocol(node_uri: str) -> str:
    """Identifies node protocol (VLESS, TROJAN, SS, etc.)."""
    if "://" in node_uri:
        proto = node_uri.split("://", 1)[0].upper()
        if proto == "SHADOWSOCKS":
            return "SS"
        if proto == "HY2":
            return "HYSTERIA2"
        return proto
    return "VPN"


def format_descriptive_node_name(
    node: str,
    country_code: str,
    country_name: str,
    ip_str: str,
    loc_score: float = 0.0,
    speed_mbps: Optional[float] = None,
) -> str:
    """Constructs a clean, standardized, descriptive name tag for a validated node."""
    proto = extract_node_protocol(node)

    orig_tag = ""
    if "#" in node:
        raw_tag = urllib.parse.unquote(node.split("#", 1)[1])
        proto_tag_match = re.search(r"\[[A-Za-z0-9_-]+:\s*([^\[\]]+)\]", raw_tag, flags=re.IGNORECASE)
        if proto_tag_match:
            orig_tag = proto_tag_match.group(1).strip()
            while re.match(r"^\[[A-Za-z0-9_-]+:\s*(.+)\]$", orig_tag, flags=re.IGNORECASE):
                orig_tag = re.match(r"^\[[A-Za-z0-9_-]+:\s*(.+)\]$", orig_tag, flags=re.IGNORECASE).group(1).strip()
            orig_tag = re.sub(r"\s*[\U0001F1E6-\U0001F1FF]{2}.*$", "", orig_tag).strip()
            orig_tag = orig_tag if orig_tag else "Node"
        else:
            cleaned = re.sub(
                r"^\s*\[(?:⚡|[\d\.]+\s*MB/s|[A-Za-z0-9_-]+).*?\]\s*",
                "",
                raw_tag,
                flags=re.IGNORECASE,
            )
            cleaned = re.sub(r"^[\U0001F1E6-\U0001F1FF]{2}[-\s]*", "", cleaned).strip()
            cleaned = cleaned.split("|")[0].strip()
            cleaned = re.sub(r"\s*[\U0001F1E6-\U0001F1FF]{2}.*$", "", cleaned).strip()
            orig_tag = cleaned if cleaned else "Node"
    else:
        orig_tag = "Node"

    flag = get_flag_emoji(country_code) if country_code else "🌐"
    c_name = (country_name or country_code or "Unknown").replace(" ", "-")

    parts = [f"[{proto}: {orig_tag}] {flag} {c_name}"]

    if speed_mbps is not None and speed_mbps > 0:
        parts.append(f"⚡ {speed_mbps:.1f} MB/s")

    if loc_score > 0:
        parts.append(f"LOC: {loc_score*100:.0f}%")

    if ip_str:
        parts.append(ip_str)

    return " | ".join(parts)


def extract_host_port(node_uri: str) -> Tuple[Optional[str], Optional[int]]:
    """Extracts server host/IP and integer port from any supported proxy URI scheme."""
    try:
        if extract_node_protocol(node_uri) == "HYSTERIA2":
            link = parse_hysteria2(node_uri)
            return (link.server, link.port) if link else (None, None)
        clean_uri = node_uri.split("#", 1)[0].split("?", 1)[0]
        if "://" not in clean_uri:
            return None, None

        _, netloc = clean_uri.split("://", 1)
        if not netloc:
            return None, None

        if "@" in netloc:
            host_port = netloc.rsplit("@", 1)[-1]
        else:
            try:
                b64_str = netloc + "=" * ((4 - len(netloc) % 4) % 4)
                decoded = base64.urlsafe_b64decode(b64_str).decode("utf-8")
                if "@" in decoded:
                    host_port = decoded.rsplit("@", 1)[-1]
                else:
                    return None, None
            except Exception:
                return None, None

        if "]" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_str)
        elif ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            return None, None

        if 0 < port <= 65535:
            return host, port
        return None, None
    except Exception:
        return None, None
