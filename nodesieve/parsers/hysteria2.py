"""Hysteria 2 share links, including UDP port lists and ranges."""

from dataclasses import dataclass
import re
from urllib.parse import parse_qs, unquote, urlsplit

HYSTERIA2_SCHEMES = ("hysteria2", "hy2")


@dataclass
class Hysteria2Link:
    server: str
    port: int
    ports: str
    password: str
    name: str
    query: dict[str, str]

    @property
    def sni(self) -> str:
        return self.query.get("sni") or self.query.get("peer", "")

    @property
    def alpn(self) -> list[str]:
        return [item.strip() for item in self.query.get("alpn", "").split(",") if item.strip()]


def _first_port(ports: str) -> int:
    for item in ports.split(","):
        m = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", item)
        if not m or not 1 <= int(m[1]) <= int(m[2] or m[1]) <= 65535:
            raise ValueError("Invalid Hysteria 2 port range")
    return int(re.split("[-,]", ports, maxsplit=1)[0])


def parse_hysteria2(url: str) -> Hysteria2Link | None:
    """Parse a direct Hysteria 2 URI, including mport query form."""
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url.partition("#")[0]):
        return None
    try:
        parts = urlsplit(url)
        if parts.scheme not in HYSTERIA2_SCHEMES or not parts.hostname or parts.path not in ("", "/"):
            return None
        auth, _, endpoint = parts.netloc.rpartition("@")
        addr = re.fullmatch(r"(?:\[[^\]]+\]|[^\s:\[\]@]+)(?::([^:]*))?", endpoint)
        if not addr:
            return None
        port_text = addr[1] if addr[1] is not None else "443"
        port = _first_port(port_text)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        ports = port_text if "-" in port_text or "," in port_text else ""
        if query.get("mport"):
            _first_port(query["mport"])
            ports = query["mport"]
        if query.get("obfs") and (query["obfs"] not in ("salamander", "gecko") or not query.get("obfs-password")):
            return None
        pin = query.get("pinSHA256") or query.get("pcs")
        if pin:
            pin = pin.replace(":", "").replace("-", "")
            if not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
                return None
            query["pinSHA256"] = pin.lower()
        return Hysteria2Link(parts.hostname, port, ports, unquote(auth), unquote(parts.fragment).strip(), query)
    except ValueError:
        return None
