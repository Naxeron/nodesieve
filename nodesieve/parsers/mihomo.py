"""Converts share links to Mihomo proxy definitions."""

import base64
import json
import re
import urllib.parse
from typing import Any, Optional

from nodesieve.parsers.hysteria2 import HYSTERIA2_SCHEMES, Hysteria2Link, parse_hysteria2

# Options in the "extra" JSON of an XHTTP link (Xray's names) and the Mihomo xhttp-opts
# key each one sets. Where two names set one key, the first one present wins: links
# carry both the current sessionID* names and the ones older Xray versions read.
_XHTTP_EXTRA_OPTIONS = (
    ("xPaddingBytes", "x-padding-bytes"),
    ("xPaddingKey", "x-padding-key"),
    ("xPaddingHeader", "x-padding-header"),
    ("xPaddingPlacement", "x-padding-placement"),
    ("xPaddingMethod", "x-padding-method"),
    ("uplinkHTTPMethod", "uplink-http-method"),
    ("sessionIDPlacement", "session-placement"),
    ("sessionPlacement", "session-placement"),
    ("sessionIDKey", "session-key"),
    ("sessionKey", "session-key"),
    ("sessionIDTable", "session-table"),
    ("sessionIDLength", "session-length"),
    ("seqPlacement", "seq-placement"),
    ("seqKey", "seq-key"),
    ("uplinkDataPlacement", "uplink-data-placement"),
    ("uplinkDataKey", "uplink-data-key"),
    ("uplinkChunkSize", "uplink-chunk-size"),
    ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
    ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
)

# The same for "xmux" inside it, which Mihomo calls reuse-settings.
_XHTTP_XMUX_OPTIONS = (
    ("maxConcurrency", "max-concurrency"),
    ("maxConnections", "max-connections"),
    ("cMaxReuseTimes", "c-max-reuse-times"),
    ("hMaxRequestTimes", "h-max-request-times"),
    ("hMaxReusableSecs", "h-max-reusable-secs"),
)


def without_mux(url: str) -> str:
    """The same link marked smux=0, which keeps multiplexing out of its Mihomo proxy."""
    core, hash_sign, tag = url.partition("#")
    if re.search(r"[?&]smux=", core):
        core = re.sub(r"([?&]smux=)[^&]*", r"\g<1>0", core)
    else:
        core += ("&" if "?" in core else "?") + "smux=0"
    return core + hash_sign + tag


def _option_text(value: Any) -> str:
    """An option from a link's JSON as the text Mihomo reads; "" when there is nothing to set.

    Xray reads 0 as "not set", while Mihomo would apply the zero or refuse it, so a
    zero is left out and Mihomo falls back to its default, as Xray does.
    """
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        value = str(int(value))
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return "" if value == "0" else value


def _xhttp_opts(path: str, host: str, mode: str, extra: str) -> dict:
    """Mihomo xhttp-opts of an XHTTP link.

    "extra" is Xray's JSON describing how requests are shaped: where the session id,
    sequence number and padding go and how connections are reused. The server expects
    exactly that shape, so every option Mihomo implements is carried over.
    """
    opts: dict = {"path": path}
    if host:
        opts["host"] = host
    if mode:
        opts["mode"] = mode

    try:
        settings = json.loads(extra) if extra else {}
    except ValueError:
        settings = {}
    if not isinstance(settings, dict):
        return opts

    headers = settings.get("headers")
    if isinstance(headers, dict) and headers:
        opts["headers"] = {str(name): str(value) for name, value in headers.items()}
    if settings.get("noGRPCHeader") is True:
        opts["no-grpc-header"] = True
    if isinstance(settings.get("xPaddingObfsMode"), bool):
        opts["x-padding-obfs-mode"] = settings["xPaddingObfsMode"]
    for name, key in _XHTTP_EXTRA_OPTIONS:
        text = _option_text(settings.get(name))
        if text:
            opts.setdefault(key, text)

    xmux = settings.get("xmux")
    if isinstance(xmux, dict):
        reuse: dict = {}
        for name, key in _XHTTP_XMUX_OPTIONS:
            text = _option_text(xmux.get(name))
            if text:
                reuse[key] = text
        keep_alive = xmux.get("hKeepAlivePeriod")
        if isinstance(keep_alive, (int, float)) and not isinstance(keep_alive, bool) and keep_alive:
            reuse["h-keep-alive-period"] = int(keep_alive)
        if reuse:
            opts["reuse-settings"] = reuse
    return opts


def _hysteria2_proxy(link: Hysteria2Link) -> dict:
    q = link.query
    proxy = {"name": link.name or f"hysteria2_{link.server}_{link.port}", "type": "hysteria2",
             "server": link.server, "port": link.port, "password": link.password, "udp": True}
    if link.ports:
        proxy["ports"] = link.ports
    if link.sni:
        proxy["sni"] = link.sni
    if link.alpn:
        proxy["alpn"] = link.alpn
    if q.get("insecure", "").lower() in ("1", "true") or q.get("allowInsecure", "").lower() in ("1", "true"):
        proxy["skip-cert-verify"] = True
    if q.get("pinSHA256"):
        proxy["fingerprint"] = q["pinSHA256"]
    if q.get("vcn"):
        proxy["name-cert-verify"] = q["vcn"].split(",")[0].strip()
    if q.get("ech"):
        proxy["ech-opts"] = {"enable": True, "config": q["ech"]}
    if q.get("obfs"):
        proxy.update({"obfs": q["obfs"], "obfs-password": q["obfs-password"]})
    for key in ("up", "down"):
        if q.get(key):
            proxy[key] = q[key]
    return proxy


def node_url_to_mihomo_dict(url: str, use_mux: bool = True) -> Optional[dict]:
    """Converts a raw share link into a Mihomo proxy config dict.

    use_mux adds sing-mux to nodes that can carry it, unless the link is marked smux=0.
    """
    try:
        url = url.strip()
        if not url:
            return None
        if url.partition("://")[0].lower() in HYSTERIA2_SCHEMES:
            link = parse_hysteria2(url)
            return _hysteria2_proxy(link) if link else None

        # Separate fragment / tag
        name = ""
        if "#" in url:
            url_no_frag, frag = url.split("#", 1)
            name = urllib.parse.unquote(frag).strip()
        else:
            url_no_frag = url

        # Separate query string
        if "?" in url_no_frag:
            main_part, query_str = url_no_frag.split("?", 1)
            query = urllib.parse.parse_qs(query_str)
        else:
            main_part = url_no_frag
            query = {}

        def q_get(k: str, default: str = "") -> str:
            v = query.get(k, [default])
            return v[0] if v else default

        if "://" not in main_part:
            return None

        proto, authority = main_part.split("://", 1)
        proto = proto.lower()
        if proto not in ("vless", "trojan", "ss"):
            return None

        server = None
        port = None
        user = ""
        cipher = ""
        password = ""

        if proto in ("vless", "trojan"):
            if "@" not in authority:
                return None
            user_part, host_port = authority.rsplit("@", 1)
            user = urllib.parse.unquote(user_part)
            if not host_port or ":" not in host_port:
                return None
            if "]" in host_port:
                h_str, p_str = host_port.rsplit(":", 1)
                server = h_str.strip("[]")
            else:
                server, p_str = host_port.rsplit(":", 1)
            port = int(p_str)

        elif proto == "ss":
            if "@" in authority:
                user_info, host_port = authority.rsplit("@", 1)
                if ":" in user_info:
                    cipher, password = user_info.split(":", 1)
                else:
                    try:
                        b64_str = user_info + "=" * (-len(user_info) % 4)
                        decoded = base64.urlsafe_b64decode(b64_str).decode("utf-8")
                        if ":" in decoded:
                            cipher, password = decoded.split(":", 1)
                        else:
                            return None
                    except Exception:
                        return None
                if not host_port or ":" not in host_port:
                    return None
                if "]" in host_port:
                    h_str, p_str = host_port.rsplit(":", 1)
                    server = h_str.strip("[]")
                else:
                    server, p_str = host_port.rsplit(":", 1)
                port = int(p_str)
            else:
                try:
                    b64_str = authority + "=" * (-len(authority) % 4)
                    decoded = base64.urlsafe_b64decode(b64_str).decode("utf-8")
                    if "@" in decoded:
                        user_info, host_port = decoded.rsplit("@", 1)
                        if ":" in user_info:
                            cipher, password = user_info.split(":", 1)
                        else:
                            return None
                        if not host_port or ":" not in host_port:
                            return None
                        if "]" in host_port:
                            h_str, p_str = host_port.rsplit(":", 1)
                            server = h_str.strip("[]")
                        else:
                            server, p_str = host_port.rsplit(":", 1)
                        port = int(p_str)
                    else:
                        return None
                except Exception:
                    return None

        if not server or not port or not (0 < port <= 65535):
            return None

        if not name:
            name = f"{proto}_{server}_{port}"

        proxy = {
            "name": name,
            "server": server,
            "port": int(port),
            "udp": True,
        }

        net_type = q_get("type", "tcp").lower()
        security = q_get("security", "").lower()
        sni = q_get("sni", "")
        host_hdr = q_get("host", "")
        path = urllib.parse.unquote(q_get("path", "/"))
        fp = q_get("fp", "")
        flow = q_get("flow", "")
        alpn_str = q_get("alpn", "")
        alpn = [a.strip() for a in alpn_str.split(",") if a.strip()] if alpn_str else []
        insecure = q_get("insecure", "0") in ("1", "true") or q_get("allowInsecure", "0") in ("1", "true")
        # vcn names what the server's certificate is issued to when that is not the SNI,
        # as with nodes addressed by IP. Xray accepts several names; Mihomo checks one.
        cert_name = next((name.strip() for name in q_get("vcn").split(",") if name.strip()), "")

        can_smux = use_mux and flow != "xtls-rprx-vision" and q_get("smux") not in ("0", "false")

        if proto == "vless":
            proxy["type"] = "vless"
            proxy["uuid"] = user
            if flow:
                proxy["flow"] = flow

            if security == "tls":
                proxy["tls"] = True
                if sni:
                    proxy["servername"] = sni
                if fp:
                    proxy["client-fingerprint"] = fp
                if alpn:
                    proxy["alpn"] = alpn
                if insecure:
                    proxy["skip-cert-verify"] = True
                if cert_name:
                    proxy["name-cert-verify"] = cert_name
            elif security == "reality":
                proxy["tls"] = True
                if sni:
                    proxy["servername"] = sni
                if fp:
                    proxy["client-fingerprint"] = fp
                proxy["reality-opts"] = {
                    "public-key": q_get("pbk", ""),
                    "short-id": q_get("sid", ""),
                }
                if q_get("spx"):
                    proxy["reality-opts"]["spider-x"] = urllib.parse.unquote(q_get("spx"))
            elif security == "none" or not security:
                proxy["tls"] = False

            if net_type in ("ws", "websocket"):
                proxy["network"] = "ws"
                ws_opts = {"path": path}
                if host_hdr or sni:
                    ws_opts["headers"] = {"Host": host_hdr or sni}
                proxy["ws-opts"] = ws_opts
            elif net_type == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {
                    "grpc-service-name": q_get("serviceName", "")
                }
            elif net_type == "xhttp":
                proxy["network"] = "xhttp"
                proxy["xhttp-opts"] = _xhttp_opts(path, host_hdr, q_get("mode"), q_get("extra"))
            elif net_type in ("http", "h2"):
                proxy["network"] = "http"
                http_opts = {"path": [path]}
                if host_hdr or sni:
                    http_opts["headers"] = {"Host": [host_hdr or sni]}
                proxy["http-opts"] = http_opts
            else:
                proxy["network"] = "tcp"

        elif proto == "trojan":
            proxy["type"] = "trojan"
            proxy["password"] = user
            if security == "tls" or not security:
                proxy["tls"] = True
                if sni:
                    proxy["sni"] = sni
                if fp:
                    proxy["client-fingerprint"] = fp
                if alpn:
                    proxy["alpn"] = alpn
                if insecure:
                    proxy["skip-cert-verify"] = True
                if cert_name:
                    proxy["name-cert-verify"] = cert_name
            elif security == "none":
                proxy["tls"] = False

            if net_type in ("ws", "websocket"):
                proxy["network"] = "ws"
                ws_opts = {"path": path}
                if host_hdr or sni:
                    ws_opts["headers"] = {"Host": host_hdr or sni}
                proxy["ws-opts"] = ws_opts
            elif net_type == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {
                    "grpc-service-name": q_get("serviceName", "")
                }
            else:
                proxy["network"] = "tcp"

        elif proto == "ss":
            proxy["type"] = "ss"
            proxy["cipher"] = cipher
            proxy["password"] = password

        if can_smux:
            proxy["smux"] = {
                "enabled": True,
                "protocol": "smux",
                "max-connections": 4,
                "min-streams": 4,
                "padding": False,
            }

        return proxy
    except Exception:
        return None
