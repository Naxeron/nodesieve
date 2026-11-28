"""Converts share links to Xray outbound definitions."""

import json
from typing import Any, Dict, Optional

from nodesieve.parsers.base import b64decode_str, parse_share_link
from nodesieve.parsers.hysteria2 import HYSTERIA2_SCHEMES, Hysteria2Link, parse_hysteria2


def _json_dict(text: str) -> Optional[dict]:
    try:
        value = json.loads(text) if text else None
    except ValueError:
        return None
    return value if isinstance(value, dict) and value else None


def _stream_settings(scheme: str, q: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Build Xray streamSettings for a VLESS or Trojan link, or None if unsupported."""
    network = (q.get("type") or "tcp").lower()
    host = q.get("host", "")
    path = q.get("path") or "/"
    sni = q.get("sni") or q.get("peer") or ""

    if network in ("tcp", "raw"):
        stream: Dict[str, Any] = {"network": "tcp"}
    elif network in ("ws", "websocket", "httpupgrade"):
        net = "httpupgrade" if network == "httpupgrade" else "ws"
        opts: Dict[str, Any] = {"path": path}
        if host or sni:
            opts["host"] = host or sni
        stream = {"network": net, f"{net}Settings": opts}
    elif network == "grpc":
        grpc: Dict[str, Any] = {"serviceName": q.get("serviceName", ""), "multiMode": q.get("mode") == "multi"}
        if q.get("authority"):
            grpc["authority"] = q["authority"]
        stream = {"network": "grpc", "grpcSettings": grpc}
    elif network in ("xhttp", "splithttp"):
        xhttp: Dict[str, Any] = {"path": path, "mode": q.get("mode") or "auto"}
        if host:
            xhttp["host"] = host
        if extra := _json_dict(q.get("extra", "")):
            xhttp["extra"] = extra
        stream = {"network": "xhttp", "xhttpSettings": xhttp}
    else:
        return None

    security = (q.get("security") or ("tls" if scheme == "trojan" else "none")).lower()
    if security == "reality":
        reality = {
            "serverName": sni,
            "fingerprint": q.get("fp") or "chrome",
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
        }
        if q.get("spx"):
            reality["spiderX"] = q["spx"]
        if q.get("pqv"):
            reality["mldsa65Verify"] = q["pqv"]
        stream.update(security="reality", realitySettings=reality)
    elif security == "tls":
        tls: Dict[str, Any] = {}
        for qk, tk in (("fp", "fingerprint"), ("vcn", "verifyPeerCertByName"),
                       ("pcs", "pinnedPeerCertSha256"), ("ech", "echConfigList")):
            if q.get(qk):
                tls[tk] = q[qk]
        if sni:
            tls["serverName"] = sni
        if alpn := [a.strip() for a in q.get("alpn", "").split(",") if a.strip()]:
            tls["alpn"] = alpn
        stream.update(security="tls", tlsSettings=tls)
    elif security != "none":
        return None

    if finalmask := _json_dict(q.get("fm", "")):
        stream["finalmask"] = finalmask
    return stream


def _hysteria2_outbound(link: Hysteria2Link) -> Optional[dict]:
    q = link.query
    tls: Dict[str, Any] = {"alpn": link.alpn or ["h3"]}
    if link.sni:
        tls["serverName"] = link.sni
    for qk, tk in (("pinSHA256", "pinnedPeerCertSha256"), ("vcn", "verifyPeerCertByName"), ("ech", "echConfigList")):
        if q.get(qk):
            tls[tk] = q[qk]
    stream: Dict[str, Any] = {
        "network": "hysteria",
        "hysteriaSettings": {"version": 2, "auth": link.password},
        "security": "tls",
        "tlsSettings": tls,
    }
    mask = _json_dict(q.get("fm", "")) or {}
    for key, field in (("up", "brutalUp"), ("down", "brutalDown")):
        if q.get(key):
            params = mask.setdefault("quicParams", {})
            if not isinstance(params, dict):
                return None
            rate = q[key].strip()
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
            udp.append({"type": "udphop", "settings": {
                "mode": "intervallocal,intervalremote", "remotePorts": link.ports, "interval": 30,
            }})
    if mask:
        stream["finalmask"] = mask
    return {
        "protocol": "hysteria",
        "settings": {"version": 2, "address": link.server, "port": link.port},
        "streamSettings": stream,
    }


def node_url_to_xray_outbound(url: str) -> Optional[dict]:
    """Build an untagged Xray outbound for a share link, or None if unsupported."""
    url = url.strip()
    if url.partition("://")[0].lower() in HYSTERIA2_SCHEMES:
        link = parse_hysteria2(url)
        return _hysteria2_outbound(link) if link else None
    parsed = parse_share_link(url)
    if parsed is None:
        return None
    scheme, user, server, port, q = parsed

    if scheme in ("vless", "trojan"):
        stream = _stream_settings(scheme, q)
        if stream is None:
            return None
        if scheme == "vless":
            settings: Dict[str, Any] = {"address": server, "port": port, "id": user,
                                        "encryption": q.get("encryption") or "none"}
            if q.get("flow"):
                settings["flow"] = q["flow"]
        else:
            settings = {"address": server, "port": port, "password": user}
        return {"protocol": scheme, "settings": settings, "streamSettings": stream}

    if scheme == "ss":
        if q.get("plugin"):
            return None
        if ":" not in user:
            try:
                user = b64decode_str(user)
            except (ValueError, UnicodeDecodeError):
                return None
        method, sep, password = user.partition(":")
        if not sep or not method:
            return None
        return {"protocol": "shadowsocks",
                "settings": {"address": server, "port": port, "method": method, "password": password}}

    return None
