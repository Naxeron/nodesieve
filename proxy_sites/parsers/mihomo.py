"""Converts proxy URI schemes (VLESS, Trojan, Shadowsocks) to Mihomo dictionary definitions."""

import base64
import urllib.parse
from typing import Optional


def node_url_to_mihomo_dict(url: str, use_mux: bool = True) -> Optional[dict]:
    """Converts a raw vless://, trojan://, or ss:// URL into a Mihomo proxy config dict."""
    try:
        url = url.strip()
        if not url:
            return None

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

        can_smux = use_mux and (flow != "xtls-rprx-vision")

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
            elif net_type in ("http", "h2", "xhttp"):
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
