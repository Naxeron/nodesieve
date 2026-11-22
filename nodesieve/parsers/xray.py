"""Converts share links to Xray outbound definitions.

Share links are written for Xray, so every option they carry goes over as it is: REALITY,
XTLS Vision, the transports with their settings (XHTTP's "extra" included), and the
FinalMask in "fm", which, among other things, fragments the TLS ClientHello.
"""

import base64
import json
import urllib.parse
from typing import Any, Dict, Optional, Tuple

from nodesieve.parsers.hysteria2 import HYSTERIA2_SCHEMES, Hysteria2Link, parse_hysteria2


def _b64decode(text: str) -> str:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")


def _host_port(text: str) -> Tuple[str, int]:
    """Server and port of "host:port" or "[v6]:port"; ValueError when there is no port."""
    host, _, port = text.rpartition(":")
    if not host:
        raise ValueError("no port")
    return host.strip("[]"), int(port)


def _parse(url: str) -> Optional[Tuple[str, str, str, int, Dict[str, str]]]:
    """(scheme, user part, server, port, query) of a link, or None when it has no server."""
    core = url.split("#", 1)[0]
    core, _, query_text = core.partition("?")
    scheme, sep, authority = core.partition("://")
    if not sep:
        return None
    scheme = scheme.lower()
    query = {key: values[0] for key, values in urllib.parse.parse_qs(query_text, keep_blank_values=True).items()}
    authority = authority.rstrip("/")
    try:
        if scheme == "ss" and "@" not in authority:
            # ss://base64(method:password@host:port)
            authority = _b64decode(authority)
        user, at, host_port = authority.rpartition("@")
        if not at:
            return None
        server, port = _host_port(host_port)
    except (ValueError, UnicodeDecodeError):
        return None
    if not server or not 0 < port <= 65535:
        return None
    return scheme, urllib.parse.unquote(user), server, port, query


def _finalmask(text: str) -> Optional[dict]:
    try:
        value = json.loads(text) if text else None
    except ValueError:
        return None
    return value if isinstance(value, dict) and value else None


def _stream_settings(scheme: str, q: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Transport and security of a VLESS or Trojan link; None for a transport Xray lacks."""
    network = (q.get("type") or "tcp").lower()
    host = q.get("host", "")
    path = q.get("path") or "/"
    sni = q.get("sni") or q.get("peer") or ""

    if network in ("tcp", "raw"):
        stream: Dict[str, Any] = {"network": "tcp"}
    elif network in ("ws", "websocket"):
        stream = {"network": "ws", "wsSettings": {"path": path}}
        if host or sni:
            stream["wsSettings"]["host"] = host or sni
    elif network == "httpupgrade":
        stream = {"network": "httpupgrade", "httpupgradeSettings": {"path": path}}
        if host or sni:
            stream["httpupgradeSettings"]["host"] = host or sni
    elif network == "grpc":
        grpc: Dict[str, Any] = {"serviceName": q.get("serviceName", ""), "multiMode": q.get("mode") == "multi"}
        if q.get("authority"):
            grpc["authority"] = q["authority"]
        stream = {"network": "grpc", "grpcSettings": grpc}
    elif network in ("xhttp", "splithttp"):
        xhttp: Dict[str, Any] = {"path": path, "mode": q.get("mode") or "auto"}
        if host:
            xhttp["host"] = host
        extra = _finalmask(q.get("extra", ""))
        if extra:
            xhttp["extra"] = extra
        stream = {"network": "xhttp", "xhttpSettings": xhttp}
    else:
        # kcp, quic, and HTTP/2, which Xray replaced with XHTTP.
        return None

    security = (q.get("security") or ("tls" if scheme == "trojan" else "none")).lower()
    if security == "reality":
        reality = {"serverName": sni, "fingerprint": q.get("fp") or "chrome",
                   "publicKey": q.get("pbk", ""), "shortId": q.get("sid", "")}
        if q.get("spx"):
            reality["spiderX"] = q["spx"]
        if q.get("pqv"):
            reality["mldsa65Verify"] = q["pqv"]
        stream.update(security="reality", realitySettings=reality)
    elif security == "tls":
        tls: Dict[str, Any] = {}
        if sni:
            tls["serverName"] = sni
        if q.get("fp"):
            tls["fingerprint"] = q["fp"]
        alpn = [name.strip() for name in q.get("alpn", "").split(",") if name.strip()]
        if alpn:
            tls["alpn"] = alpn
        # Xray 26 removed allowInsecure: a link's insecure=1 is left out and the certificate
        # is checked, as Xray clients do now; vcn and pcs are what replaced it.
        if q.get("vcn"):
            tls["verifyPeerCertByName"] = q["vcn"]
        if q.get("pcs"):
            tls["pinnedPeerCertSha256"] = q["pcs"]
        if q.get("ech"):
            tls["echConfigList"] = q["ech"]
        stream.update(security="tls", tlsSettings=tls)
    elif security != "none":
        return None

    finalmask = _finalmask(q.get("fm", ""))
    if finalmask:
        stream["finalmask"] = finalmask
    return stream


def _hysteria2_outbound(link: Hysteria2Link) -> Optional[dict]:
    q = link.query
    tls: Dict[str, Any] = {"alpn": link.alpn or ["h3"]}
    if link.sni:
        tls["serverName"] = link.sni
    if q.get("pinSHA256"):
        tls["pinnedPeerCertSha256"] = q["pinSHA256"]
    if q.get("vcn"):
        tls["verifyPeerCertByName"] = q["vcn"]
    if q.get("ech"):
        tls["echConfigList"] = q["ech"]
    stream = {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": link.password},
              "security": "tls", "tlsSettings": tls}
    mask = _finalmask(q.get("fm", "")) or {}
    for key, field in (("up", "brutalUp"), ("down", "brutalDown")):
        if q.get(key):
            params = mask.setdefault("quicParams", {})
            if not isinstance(params, dict):
                return None
            rate = q[key].strip()
            # A bare rate in a share link is Mbps. Xray reads bare rates as bps.
            params.setdefault(field, rate + " mbps" if rate.replace(".", "", 1).isdigit() else rate)
    if q.get("obfs") or link.ports:
        udp = mask.setdefault("udp", [])
        if not isinstance(udp, list):
            return None
        if q.get("obfs"):
            settings = {"password": q["obfs-password"]}
            if q["obfs"] == "gecko":
                settings["packetSize"] = "512-1200"
            udp.append({"type": "salamander", "settings": settings})
        if link.ports:
            udp.append({"type": "udphop", "settings": {"mode": "intervallocal,intervalremote",
                                                       "remotePorts": link.ports, "interval": 30}})
    if mask:
        stream["finalmask"] = mask
    return {"protocol": "hysteria", "settings": {"version": 2, "address": link.server, "port": link.port},
            "streamSettings": stream}


def node_url_to_xray_outbound(url: str) -> Optional[dict]:
    """The Xray outbound, without a tag, that a share link describes.

    None for a link Xray can't use: another scheme, no server, a transport Xray lacks, or a
    Shadowsocks plugin.
    """
    url = url.strip()
    if url.partition("://")[0].lower() in HYSTERIA2_SCHEMES:
        link = parse_hysteria2(url)
        return _hysteria2_outbound(link) if link else None
    parsed = _parse(url)
    if parsed is None:
        return None
    scheme, user, server, port, q = parsed

    if scheme == "vless":
        settings: Dict[str, Any] = {"address": server, "port": port, "id": user,
                                    "encryption": q.get("encryption") or "none"}
        if q.get("flow"):
            settings["flow"] = q["flow"]
        stream = _stream_settings(scheme, q)
        if stream is None:
            return None
        return {"protocol": "vless", "settings": settings, "streamSettings": stream}

    if scheme == "trojan":
        stream = _stream_settings(scheme, q)
        if stream is None:
            return None
        return {"protocol": "trojan", "settings": {"address": server, "port": port, "password": user},
                "streamSettings": stream}

    if scheme == "ss":
        if q.get("plugin"):
            return None
        if ":" not in user:
            # ss://base64(method:password)@host:port
            try:
                user = _b64decode(user)
            except (ValueError, UnicodeDecodeError):
                return None
        method, sep, password = user.partition(":")
        if not sep or not method:
            return None
        return {"protocol": "shadowsocks",
                "settings": {"address": server, "port": port, "method": method, "password": password}}

    return None
