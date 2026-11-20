#!/usr/bin/env python3
"""Compares proxy cores as the engine of nodesieve's IP check, on the configured subscriptions.

    python tools/core_bench.py [--rounds 3] [--speed 8] [--cores xray,mihomo] [--out DIR]

Every core serves every node of the subscriptions at once, each node through an HTTP proxy
listener of its own on 127.0.0.1, in one process per core, as nodesieve's MihomoBatch does
with Mihomo. A round asks Cloudflare's trace for each node's IPv4 and IPv6 exit through one
core, with the timeouts of nodesieve's IP check, then through the next core; the order of
the cores turns every round. Each core's memory and CPU come from /proc meanwhile. With
--speed N, the N nodes with the lowest latency are downloaded through as well, one node at a
time and its cores back to back.

Profiles (--cores):
  mihomo         the Mihomo nodesieve runs (./mihomo), links converted as nodesieve converts them
  mihomo-stable  another Mihomo binary (--mihomo-stable), such as a stable release
  xray           Xray with every option a link gives, FinalMask (fm) fragmenting included
  xray-nofrag    the same Xray without FinalMask's ClientHello fragmenting
  sing-box       sing-box; record_fragment where a link fragments a TLS (not REALITY) ClientHello

The results (results.json and report.md in --out) hold no credentials: no links, ids,
passwords or keys, and not this computer's own address.
"""

import argparse
import asyncio
import base64
import copy
import ipaddress
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import aiohttp  # noqa: E402
import yaml  # noqa: E402

from nodesieve.config import ConfigManager  # noqa: E402
from nodesieve.constants import MIHOMO_PATH  # noqa: E402
from nodesieve.core.fetcher import NodeFetcher  # noqa: E402
from nodesieve.core.batch import PortManager, _accepts, _relays, _serve_ready  # noqa: E402
from nodesieve.core.mihomo import _log_record, render_batch_config  # noqa: E402
from nodesieve.core.tester import NodeTester  # noqa: E402
from nodesieve.parsers.mihomo import _XHTTP_EXTRA_OPTIONS, _XHTTP_XMUX_OPTIONS, node_url_to_mihomo_dict  # noqa: E402
from nodesieve.core.xray import render_xray_config  # noqa: E402
from nodesieve.parsers.xray import node_url_to_xray_outbound  # noqa: E402

LISTEN = "127.0.0.1"
# nodesieve's IP check: IPv4 trace with a fallback, IPv6 trace, and their timeouts.
TRACE_V4 = ("https://1.1.1.1/cdn-cgi/trace", "https://cloudflare.com/cdn-cgi/trace")
TRACE_V6 = ("https://[2606:4700:4700::1111]/cdn-cgi/trace",)
SPEED_URL = "https://speed.cloudflare.com/__down?bytes={}"
# Entries nodesieve skips by name: a subscription's section headers.
HEADER_MARKS = ("Авто", "⬇")
START_TIMEOUT = 20.0
CLOCK_TICKS = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Core log messages that come with every connection that ends, failed or not.
_BENIGN = re.compile(r"context canceled|closed pipe|use of closed network connection|^connection ends$|close 1000 \(normal\)", re.I)


# --- Links -----------------------------------------------------------------------------


@dataclass
class Link:
    """A share link, parsed once for every core's converter."""

    idx: int
    raw: str
    scheme: str
    name: str
    host: str
    port: int
    user: str
    q: Dict[str, str]

    @property
    def finalmask(self) -> dict:
        try:
            value = json.loads(self.q.get("fm") or "{}")
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    @property
    def fragments(self) -> bool:
        """Whether the link's FinalMask fragments the ClientHello."""
        return any(isinstance(m, dict) and m.get("type") == "fragment" for m in self.finalmask.get("tcp") or [])

    @property
    def network(self) -> str:
        return (self.q.get("type") or "tcp").lower()

    @property
    def security(self) -> str:
        default = "tls" if self.scheme in ("trojan", "hysteria2") else "none"
        return (self.q.get("security") or default).lower()

    @property
    def kind(self) -> str:
        if self.scheme == "hysteria2":
            return "hysteria2"
        kind = f"{self.scheme} {self.network}/{self.security}"
        if "vision" in self.q.get("flow", ""):
            kind += "+vision"
        return kind + (" +frag" if self.fragments else "")

    @property
    def header(self) -> bool:
        return any(mark in self.name for mark in HEADER_MARKS)


def _b64(text: str) -> str:
    text = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")


def parse_link(idx: int, raw: str) -> Optional[Link]:
    """A share link's parts, or None for one that has no server."""
    scheme, sep, rest = raw.partition("://")
    if not sep:
        return None
    scheme = {"hy2": "hysteria2", "shadowsocks": "ss"}.get(scheme.lower(), scheme.lower())
    rest, _, fragment = rest.partition("#")
    rest, _, query = rest.partition("?")
    q = {key: values[0] for key, values in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
    rest = rest.rstrip("/")
    if scheme == "ss" and "@" not in rest:
        try:
            rest = _b64(rest)
        except Exception:
            return None
    userinfo, at, hostport = rest.rpartition("@")
    if not at:
        return None
    if hostport.startswith("["):
        host, _, port_text = hostport[1:].partition("]")
        port_text = port_text.lstrip(":")
    else:
        host, _, port_text = hostport.rpartition(":")
    match = re.match(r"^(\d+)", port_text)
    if not host or not match:
        return None
    if port_text != match.group(1) and scheme == "hysteria2":
        q.setdefault("mport", port_text)
    user = urllib.parse.unquote(userinfo)
    if scheme == "ss" and ":" not in user:
        try:
            user = _b64(user)
        except Exception:
            return None
    return Link(idx, raw, scheme, urllib.parse.unquote(fragment).strip(), host, int(match.group(1)), user, q)


def decode_subscription(text: str) -> List[str]:
    """The share links of a subscription payload, base64 or plain."""
    if "://" not in text:
        try:
            text = _b64(text)
        except Exception:
            return []
    return [line.strip() for line in text.splitlines() if "://" in line]


async def load_links(args: argparse.Namespace, config: dict) -> Tuple[List[str], str]:
    """Links of --links, or of the configured subscriptions, falling back to their cached copies."""
    if args.links:
        with open(args.links, encoding="utf-8") as f:
            return decode_subscription(f.read()), os.path.basename(args.links)
    subscriptions = [s.strip() for s in config.get("subscriptions", []) if isinstance(s, str) and s.strip()]
    fetcher = NodeFetcher(config)
    links: List[str] = []
    sources = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "v2rayN/6.31"}) as session:
        for number, url in enumerate(subscriptions, 1):
            found = [] if args.cached else decode_subscription(await fetcher._download(session, url) or "")
            source = "downloaded"
            if not found:
                try:
                    with open(fetcher._cache_path(url), encoding="utf-8") as f:
                        entry = json.load(f)
                    found = decode_subscription(entry.get("content") or "")
                    saved = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("fetched_at", 0)))
                    source = f"cached copy of {saved}"
                except (OSError, ValueError):
                    source = "unavailable"
            sources.append(f"subscription {number}: {len(found)} links, {source}")
            links.extend(found)
    return links, "; ".join(sources) or "no subscriptions configured"


# --- Converters ------------------------------------------------------------------------


class Unsupported(Exception):
    """A link the core cannot express."""


def _alpn(link: Link) -> List[str]:
    return [a.strip() for a in link.q.get("alpn", "").split(",") if a.strip()]


def _insecure(link: Link) -> bool:
    return link.q.get("insecure") in ("1", "true") or link.q.get("allowInsecure") in ("1", "true")


def _sni(link: Link) -> str:
    return link.q.get("sni") or link.q.get("peer") or ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def _congestion_note(link: Link) -> List[str]:
    congestion = (link.finalmask.get("quicParams") or {}).get("congestion")
    return [f"congestion {congestion} not set (BBR without up/down)"] if congestion and congestion != "bbr" else []


def _binary_version(binary: str, args: Sequence[str]) -> str:
    try:
        out = subprocess.run([binary, *args], capture_output=True, text=True, timeout=15).stdout
    except Exception as exc:
        return f"unknown ({exc})"
    return next((line.strip() for line in out.splitlines() if line.strip()), "unknown")[:120]


@dataclass
class Entry:
    """A node as one core serves it: its proxy or outbound, and what the conversion left out."""

    link: Link
    outbound: Any
    notes: List[str]
    port: int = 0


class Profile:
    """One core with one set of options: link conversion, configuration and its log."""

    family = ""
    version_args: Tuple[str, ...] = ()
    config_name = "config.json"

    def __init__(self, name: str, binary: str, **options: Any):
        self.name = name
        self.binary = binary
        self.options = options
        self.version = _binary_version(binary, self.version_args)

    def convert(self, link: Link, tag: str) -> Tuple[Any, List[str]]:
        raise NotImplementedError

    def render(self, entries: Sequence[Entry], ready_target: int, ready_port: int) -> str:
        raise NotImplementedError

    def run_args(self, path: str, work: str) -> List[str]:
        raise NotImplementedError

    def test_args(self, path: str, work: str) -> List[str]:
        raise NotImplementedError

    def node_errors(self, lines: Sequence[str]) -> Dict[int, List[str]]:
        """What the core logged about each node's failed connections."""
        return {}


class MihomoProfile(Profile):
    family = "mihomo"
    version_args = ("-v",)
    config_name = "config.yaml"

    def convert(self, link: Link, tag: str) -> Tuple[Any, List[str]]:
        notes: List[str] = []
        q = link.q
        if link.scheme == "hysteria2":
            proxy: Dict[str, Any] = {"name": tag, "type": "hysteria2", "server": link.host, "port": link.port,
                                     "password": link.user, "udp": True}
            if _sni(link):
                proxy["sni"] = _sni(link)
            if _insecure(link):
                proxy["skip-cert-verify"] = True
            if _alpn(link):
                proxy["alpn"] = _alpn(link)
            if q.get("obfs"):
                proxy["obfs"] = q["obfs"]
                proxy["obfs-password"] = q.get("obfs-password", "")
            if q.get("mport"):
                proxy["ports"] = q["mport"]
            return proxy, notes + _congestion_note(link) + ["nodesieve does not fetch Hysteria 2 links"]
        proxy = node_url_to_mihomo_dict(NodeTester._as_checked(link.raw), use_mux=False)
        if not proxy:
            raise Unsupported(f"nodesieve converts no Mihomo proxy from {link.scheme} links")
        proxy["name"] = tag
        if link.fragments:
            notes.append("ClientHello not fragmented (Mihomo cannot)")
        if link.network == "grpc" and q.get("authority") and q["authority"] != _sni(link):
            notes.append("gRPC authority left out")
        if link.network == "xhttp":
            try:
                extra = json.loads(q.get("extra") or "{}")
            except ValueError:
                extra = {}
            if isinstance(extra, dict):
                carried = {name for name, _ in _XHTTP_EXTRA_OPTIONS} | {"headers", "noGRPCHeader", "xPaddingObfsMode", "xmux"}
                left_out = sorted(set(extra) - carried)
                xmux = extra.get("xmux") if isinstance(extra.get("xmux"), dict) else {}
                left_out += [f"xmux.{key}" for key in sorted(set(xmux) - {n for n, _ in _XHTTP_XMUX_OPTIONS} - {"hKeepAlivePeriod"})]
                if left_out:
                    notes.append("XHTTP options left out: " + ", ".join(left_out))
        return proxy, notes

    def render(self, entries: Sequence[Entry], ready_target: int, ready_port: int) -> str:
        served = [(entry.outbound, entry.port) for entry in entries]
        served.append(({"name": "ready", "type": "http", "server": LISTEN, "port": ready_target}, ready_port))
        config = yaml.safe_load(render_batch_config(served))
        config["log-level"] = "warning"
        return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)

    def run_args(self, path: str, work: str) -> List[str]:
        return [self.binary, "-d", work, "-f", path]

    def test_args(self, path: str, work: str) -> List[str]:
        return [self.binary, "-t", "-d", work, "-f", path]

    def node_errors(self, lines: Sequence[str]) -> Dict[int, List[str]]:
        found: Dict[int, List[str]] = {}
        for line in lines:
            _, message = _log_record(line)
            match = re.search(r"\bnode-(\d+)\b", message)
            if match and "error" in message.lower():
                found.setdefault(int(match.group(1)), []).append(message.split("error: ", 1)[-1])
        return found


class XrayProfile(Profile):
    family = "xray"
    version_args = ("version",)

    def convert(self, link: Link, tag: str) -> Tuple[Any, List[str]]:
        notes: List[str] = []
        q = link.q
        finalmask = copy.deepcopy(link.finalmask)
        if not self.options.get("fragment", True) and link.fragments:
            finalmask["tcp"] = [m for m in finalmask["tcp"] if not (isinstance(m, dict) and m.get("type") == "fragment")]
            if not finalmask["tcp"]:
                del finalmask["tcp"]
            notes.append("ClientHello fragmenting left out")
        if link.scheme == "hysteria2":
            stream: Dict[str, Any] = {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": link.user},
                                      "security": "tls", "tlsSettings": self._tls(link, ["h3"])}
            if q.get("obfs") == "salamander":
                finalmask.setdefault("udp", []).append(
                    {"type": "salamander", "settings": {"password": q.get("obfs-password", "")}})
            elif q.get("obfs"):
                raise Unsupported(f"Hysteria 2 obfs {q['obfs']}")
            if q.get("mport"):
                finalmask.setdefault("quicParams", {}).setdefault("udpHop", {"ports": q["mport"]})
            if finalmask:
                stream["finalmask"] = finalmask
            return {"tag": tag, "protocol": "hysteria", "streamSettings": stream,
                    "settings": {"version": 2, "address": link.host, "port": link.port}}, notes
        if link.scheme in ("vless", "trojan", "ss"):
            # What nodesieve itself runs, as for Mihomo.
            outbound = node_url_to_xray_outbound(NodeTester._as_checked(link.raw))
            if outbound is None:
                raise Unsupported(f"nodesieve converts no Xray outbound from this {link.scheme} link")
            stream = outbound.get("streamSettings") or {}
            if not self.options.get("fragment", True) and "finalmask" in stream:
                if finalmask:
                    stream["finalmask"] = finalmask
                else:
                    del stream["finalmask"]
            return {**outbound, "tag": tag}, notes
        if link.scheme == "vless":
            protocol = "vless"
            settings: Dict[str, Any] = {"address": link.host, "port": link.port, "id": link.user,
                                        "encryption": q.get("encryption") or "none"}
            if q.get("flow"):
                settings["flow"] = q["flow"]
        elif link.scheme == "trojan":
            protocol = "trojan"
            settings = {"servers": [{"address": link.host, "port": link.port, "password": link.user}]}
        elif link.scheme == "ss":
            method, _, password = link.user.partition(":")
            protocol = "shadowsocks"
            settings = {"servers": [{"address": link.host, "port": link.port, "method": method, "password": password}]}
        else:
            raise Unsupported(f"{link.scheme} links")

        host, path = q.get("host") or "", q.get("path") or "/"
        net = link.network
        if net in ("tcp", "raw"):
            if q.get("headerType") == "http":
                raise Unsupported("TCP with an HTTP header")
            stream = {"network": "tcp"}
        elif net in ("ws", "websocket"):
            stream = {"network": "ws", "wsSettings": {"path": path, "host": host or _sni(link)}}
        elif net == "grpc":
            grpc = {"serviceName": q.get("serviceName", ""), "multiMode": q.get("mode") == "multi"}
            if q.get("authority"):
                grpc["authority"] = q["authority"]
            stream = {"network": "grpc", "grpcSettings": grpc}
        elif net in ("xhttp", "splithttp"):
            xhttp: Dict[str, Any] = {"path": path, "mode": q.get("mode") or "auto"}
            if host:
                xhttp["host"] = host
            if q.get("extra"):
                try:
                    xhttp["extra"] = json.loads(q["extra"])
                except ValueError:
                    notes.append("XHTTP extra unreadable")
            stream = {"network": "xhttp", "xhttpSettings": xhttp}
        elif net == "httpupgrade":
            stream = {"network": "httpupgrade", "httpupgradeSettings": {"path": path, "host": host or _sni(link)}}
        else:
            raise Unsupported(f"{net} transport")

        if link.security == "reality":
            reality = {"serverName": _sni(link), "fingerprint": q.get("fp") or "chrome",
                       "publicKey": q.get("pbk", ""), "shortId": q.get("sid", "")}
            if q.get("spx"):
                reality["spiderX"] = q["spx"]
            if q.get("pqv"):
                reality["mldsa65Verify"] = q["pqv"]
            stream.update(security="reality", realitySettings=reality)
        elif link.security == "tls":
            stream.update(security="tls", tlsSettings=self._tls(link, []))
        elif link.security != "none":
            raise Unsupported(f"security {link.security}")
        if finalmask:
            stream["finalmask"] = finalmask
        return {"tag": tag, "protocol": protocol, "settings": settings, "streamSettings": stream}, notes

    @staticmethod
    def _tls(link: Link, default_alpn: List[str]) -> dict:
        q = link.q
        tls: Dict[str, Any] = {}
        if _sni(link):
            tls["serverName"] = _sni(link)
        if q.get("fp"):
            tls["fingerprint"] = q["fp"]
        if _alpn(link) or default_alpn:
            tls["alpn"] = _alpn(link) or default_alpn
        if _insecure(link):
            tls["allowInsecure"] = True
        if q.get("vcn"):
            tls["verifyPeerCertByName"] = q["vcn"]
        if q.get("pcs"):
            tls["pinnedPeerCertSha256"] = q["pcs"]
        if q.get("ech"):
            tls["echConfigList"] = q["ech"]
        return tls

    def render(self, entries: Sequence[Entry], ready_target: int, ready_port: int) -> str:
        # nodesieve's own configuration, logging each connection for the per-node errors.
        ready = {"tag": "ready", "protocol": "http", "settings": {"servers": [{"address": LISTEN, "port": ready_target}]}}
        config = json.loads(render_xray_config([(entry.outbound, entry.port) for entry in entries] + [(ready, ready_port)]))
        config["log"]["loglevel"] = "info"
        return json.dumps(config, ensure_ascii=False, indent=1)

    def run_args(self, path: str, work: str) -> List[str]:
        return [self.binary, "run", "-c", path]

    def test_args(self, path: str, work: str) -> List[str]:
        return [self.binary, "run", "-test", "-c", path]

    def node_errors(self, lines: Sequence[str]) -> Dict[int, List[str]]:
        # A connection's lines carry its session id; the dispatcher's line names its outbound.
        session_node: Dict[str, int] = {}
        found: Dict[int, List[str]] = {}
        for line in lines:
            match = re.search(r"\[(\d+)\] app/dispatcher: taking detour \[node-(\d+)\]", line)
            if match:
                session_node[match.group(1)] = int(match.group(2))
                continue
            match = re.search(r"\[(?:Info|Warning|Error)\] \[(\d+)\] (.+)$", line)
            if match and match.group(1) in session_node:
                message = match.group(2)
                if re.search(r"fail|error|EOF|reset|refused|timeout|closed|invalid", message, re.I) and not _BENIGN.search(message):
                    found.setdefault(session_node[match.group(1)], []).append(message)
        return found


class SingBoxProfile(Profile):
    family = "sing-box"
    version_args = ("version",)

    def convert(self, link: Link, tag: str) -> Tuple[Any, List[str]]:
        notes: List[str] = []
        q = link.q
        if link.scheme == "hysteria2":
            out: Dict[str, Any] = {"type": "hysteria2", "tag": tag, "server": link.host, "server_port": link.port,
                                   "password": link.user, "tls": self._tls(link, ["h3"], utls=False)}
            if q.get("obfs") == "salamander":
                out["obfs"] = {"type": "salamander", "password": q.get("obfs-password", "")}
            elif q.get("obfs"):
                raise Unsupported(f"Hysteria 2 obfs {q['obfs']}")
            if q.get("mport"):
                out["server_ports"] = [ports.replace("-", ":") for ports in q["mport"].split(",")]
            return out, notes + _congestion_note(link)
        if link.scheme == "vless":
            if (q.get("encryption") or "none") != "none":
                raise Unsupported("VLESS Encryption")
            out = {"type": "vless", "tag": tag, "server": link.host, "server_port": link.port, "uuid": link.user}
            if q.get("flow"):
                out["flow"] = q["flow"]
        elif link.scheme == "trojan":
            out = {"type": "trojan", "tag": tag, "server": link.host, "server_port": link.port, "password": link.user}
        elif link.scheme == "ss":
            method, _, password = link.user.partition(":")
            out = {"type": "shadowsocks", "tag": tag, "server": link.host, "server_port": link.port,
                   "method": method, "password": password}
        else:
            raise Unsupported(f"{link.scheme} links")

        if link.security in ("tls", "reality"):
            tls = self._tls(link, [], utls=link.security == "reality" or bool(q.get("fp")))
            if link.security == "reality":
                tls["reality"] = {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}
            if link.fragments:
                if link.security == "tls" and self.options.get("fragment", True):
                    tls["record_fragment"] = True
                    notes.append("ClientHello split by sing-box's record_fragment, not as the link asks")
                else:
                    notes.append("ClientHello not fragmented (sing-box cannot with REALITY)")
            out["tls"] = tls
        elif link.security != "none":
            raise Unsupported(f"security {link.security}")

        host, path = q.get("host") or _sni(link), q.get("path") or "/"
        net = link.network
        if net in ("ws", "websocket"):
            transport: Dict[str, Any] = {"type": "ws", "path": path}
            early = re.search(r"[?&]ed=(\d+)", path)
            if early:
                transport["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
                transport["max_early_data"] = int(early.group(1))
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
            if host:
                transport["headers"] = {"Host": host}
            out["transport"] = transport
        elif net == "grpc":
            out["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
            if q.get("mode") == "multi":
                notes.append("gRPC multi mode left out")
            if q.get("authority") and q["authority"] != _sni(link):
                notes.append("gRPC authority left out")
        elif net == "httpupgrade":
            out["transport"] = {"type": "httpupgrade", "path": path, "host": host}
        elif net in ("xhttp", "splithttp"):
            raise Unsupported("sing-box has no XHTTP transport")
        elif net not in ("tcp", "raw"):
            raise Unsupported(f"{net} transport")
        if q.get("vcn") and "tls" in out:
            if _is_ip(_sni(link) or link.host):
                # No SNI goes out for an address, so checking the certificate against vcn
                # with SNI off is what the link asks for.
                out["tls"].update(server_name=q["vcn"].split(",")[0].strip(), disable_sni=True)
            else:
                notes.append("vcn left out: the certificate is checked against the SNI")
        return out, notes

    @staticmethod
    def _tls(link: Link, default_alpn: List[str], utls: bool) -> dict:
        tls: Dict[str, Any] = {"enabled": True}
        if _sni(link):
            tls["server_name"] = _sni(link)
        if _insecure(link):
            tls["insecure"] = True
        if _alpn(link) or default_alpn:
            tls["alpn"] = _alpn(link) or default_alpn
        if utls:
            tls["utls"] = {"enabled": True, "fingerprint": link.q.get("fp") or "chrome"}
        return tls

    def render(self, entries: Sequence[Entry], ready_target: int, ready_port: int) -> str:
        inbounds, rules = [], []
        for entry in entries:
            tag = entry.outbound["tag"]
            inbounds.append({"type": "mixed", "tag": f"in-{tag}", "listen": LISTEN, "listen_port": entry.port})
            rules.append({"inbound": [f"in-{tag}"], "outbound": tag})
        inbounds.append({"type": "mixed", "tag": "in-ready", "listen": LISTEN, "listen_port": ready_port})
        rules.append({"inbound": ["in-ready"], "outbound": "ready"})
        outbounds = [entry.outbound for entry in entries]
        outbounds.append({"type": "http", "tag": "ready", "server": LISTEN, "server_port": ready_target})
        return json.dumps({"log": {"level": "warn", "timestamp": False},
                           "dns": {"servers": [{"type": "local", "tag": "local"}]},
                           "inbounds": inbounds, "outbounds": outbounds,
                           "route": {"default_domain_resolver": "local", "rules": rules}}, ensure_ascii=False, indent=1)

    def run_args(self, path: str, work: str) -> List[str]:
        return [self.binary, "run", "-c", path, "-D", work]

    def test_args(self, path: str, work: str) -> List[str]:
        return [self.binary, "check", "-c", path, "-D", work]

    def node_errors(self, lines: Sequence[str]) -> Dict[int, List[str]]:
        found: Dict[int, List[str]] = {}
        for line in lines:
            match = re.search(r"\[(?:in-)?node-(\d+)\]: (.+)$", ANSI.sub("", line))
            if match and not _BENIGN.search(match.group(2)):
                found.setdefault(int(match.group(1)), []).append(match.group(2))
        return found


# --- Core processes --------------------------------------------------------------------


def proc_stats(pid: int) -> Optional[dict]:
    """Memory, threads and CPU time of a process, from /proc."""
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            status = f.read()
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            stat = f.read()
    except OSError:
        return None
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)

    def mb(key: str) -> float:
        return int(fields.get(key, "0 kB").split()[0]) / 1024

    after = stat.rsplit(")", 1)[1].split()  # after[0] is field 3, so utime (14) and stime (15)
    return {"rss_mb": mb("VmRSS"), "anon_mb": mb("RssAnon"), "hwm_mb": mb("VmHWM"),
            "threads": int(fields.get("Threads", "0").strip() or 0),
            "cpu_s": (int(after[11]) + int(after[12])) / CLOCK_TICKS}


class CoreProcess:
    """One core process serving every entry of a profile, sampled from /proc while it runs."""

    def __init__(self, profile: Profile, entries: Sequence[Entry]):
        self.profile = profile
        self.entries = list(entries)
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.work: Optional[str] = None
        self.log: List[str] = []
        self.ports: List[int] = []
        self.peak = {"anon_mb": 0.0, "rss_mb": 0.0, "threads": 0}
        self._sampler: Optional[asyncio.Task] = None
        self._ready_server: Optional[asyncio.AbstractServer] = None

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def stats(self) -> Optional[dict]:
        return proc_stats(self.proc.pid) if self.alive else None

    def reset_peak(self) -> None:
        self.peak = {"anon_mb": 0.0, "rss_mb": 0.0, "threads": 0}

    async def _sample(self) -> None:
        while self.alive:
            stats = self.stats()
            if stats:
                for key in self.peak:
                    self.peak[key] = max(self.peak[key], stats[key])
            await asyncio.sleep(0.1)

    async def start(self) -> Tuple[float, float]:
        """Starts the core: seconds until its listeners accept, and until it relays."""
        for entry in self.entries:
            entry.port = PortManager.get_free_port()
            self.ports.append(entry.port)
        ready_port = PortManager.get_free_port()
        self.ports.append(ready_port)
        # The ready listener leads to this server through an HTTP proxy outbound, as in nodesieve.
        self._ready_server = await asyncio.start_server(_serve_ready, LISTEN, 0)
        ready_target = self._ready_server.sockets[0].getsockname()[1]
        self.work = tempfile.mkdtemp(prefix=f"core-bench-{self.profile.name}-")
        path = os.path.join(self.work, self.profile.config_name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.profile.render(self.entries, ready_target, ready_port))
        log_path = os.path.join(self.work, "core.log")
        started = time.perf_counter()
        with open(log_path, "wb") as log_file:
            self.proc = await asyncio.create_subprocess_exec(
                *self.profile.run_args(path, self.work), cwd=self.work, stdin=asyncio.subprocess.DEVNULL,
                stdout=log_file, stderr=asyncio.subprocess.STDOUT)
        self._sampler = asyncio.create_task(self._sample())
        listening = None
        while True:
            if listening is None and await _accepts(ready_port, timeout=0.2):
                listening = time.perf_counter() - started
            if listening is not None and await _relays(ready_port):
                return listening, time.perf_counter() - started
            if not self.alive or time.perf_counter() - started > START_TIMEOUT:
                tail = self.read_log()[-4:]
                await self.stop()
                raise RuntimeError(f"{self.profile.name} did not start: " + " | ".join(ANSI.sub("", t) for t in tail))
            await asyncio.sleep(0.01)

    def read_log(self) -> List[str]:
        if self.work:
            try:
                with open(os.path.join(self.work, "core.log"), "rb") as f:
                    self.log = [line for line in f.read().decode("utf-8", "replace").splitlines() if line.strip()]
            except OSError:
                pass
        return self.log

    async def stop(self) -> None:
        if self._sampler is not None:
            self._sampler.cancel()
            await asyncio.gather(self._sampler, return_exceptions=True)
            self._sampler = None
        if self.alive:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self._ready_server is not None:
            self._ready_server.close()
            self._ready_server = None
        for port in self.ports:
            PortManager.release_port(port)
        self.ports = []
        self.read_log()
        if self.work:
            shutil.rmtree(self.work, ignore_errors=True)
            self.work = None


async def refused_nodes(profile: Profile, entries: Sequence[Entry]) -> Dict[int, str]:
    """Nodes the core's configuration check refuses, each with the core's reason."""

    async def check(subset: Sequence[Entry]) -> Tuple[bool, str]:
        work = tempfile.mkdtemp(prefix=f"core-bench-check-{profile.name}-")
        try:
            for number, entry in enumerate(subset):
                entry.port = 20000 + number  # never bound: the check only reads the configuration
            path = os.path.join(work, profile.config_name)
            with open(path, "w", encoding="utf-8") as f:
                f.write(profile.render(subset, 19998, 19999))
            proc = await asyncio.create_subprocess_exec(*profile.test_args(path, work), cwd=work,
                                                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            lines = [ANSI.sub("", line).strip() for line in out.decode("utf-8", "replace").splitlines() if line.strip()]
            errors = [line for line in lines if re.search(r"error|fail|fatal|invalid|unknown", line, re.I)]
            return proc.returncode == 0, (errors or lines or ["no output"])[-1][:240]
        finally:
            shutil.rmtree(work, ignore_errors=True)

    ok, _ = await check(entries)
    if ok:
        return {}
    refused = {}
    for entry in entries:
        ok, reason = await check([entry])
        if not ok:
            refused[entry.link.idx] = reason
    return refused


# --- Checks ----------------------------------------------------------------------------


def _describe(exc: BaseException) -> str:
    text = re.sub(r"\s+", " ", str(exc)).strip()
    return (f"{type(exc).__name__}: {text}" if text else type(exc).__name__)[:200]


async def _trace(session: aiohttp.ClientSession, urls: Sequence[str], proxy: Optional[str],
                 total: float, v6: bool) -> dict:
    """One family of nodesieve's IP check: the exit address and country Cloudflare's trace sees."""
    error = None
    for url in urls:
        started = time.perf_counter()
        try:
            async with session.get(url, proxy=proxy, timeout=aiohttp.ClientTimeout(total=total, connect=2.5)) as resp:
                if resp.status != 200:
                    error = f"HTTP {resp.status}"
                    continue
                text = await resp.text()
            latency = (time.perf_counter() - started) * 1000
        except Exception as exc:
            error = _describe(exc)
            continue
        ip = re.search(r"(?:^|\n)ip=([^\r\n]+)", text)
        loc = re.search(r"(?:^|\n)loc=([^\r\n]+)", text)
        if not (ip and loc):
            error = "trace without ip or loc"
        elif v6 != (":" in ip.group(1)):
            error = "trace answered over the other IP family"
        else:
            return {"ok": True, "ip": ip.group(1).strip(), "loc": loc.group(1).strip().upper(), "ms": round(latency, 1)}
    return {"ok": False, "error": error}


async def check_node(port: Optional[int]) -> dict:
    """nodesieve's IP check through a listener: both families at once, with its timeouts."""
    proxy = f"http://{LISTEN}:{port}" if port else None
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=6.0, connect=4.0)) as session:
        v4, v6 = await asyncio.gather(_trace(session, TRACE_V4, proxy, 4.0, False),
                                      _trace(session, TRACE_V6, proxy, 3.0, True))
    return {"v4": v4, "v6": v6}


async def run_round(process: CoreProcess, workers: int) -> dict:
    """Every node of a core checked once, `workers` at a time; the core's CPU and memory meanwhile."""
    process.reset_peak()
    before = process.stats() or {"cpu_s": 0.0}
    started = time.perf_counter()
    slots = asyncio.Semaphore(max(1, workers))

    async def one(entry: Entry) -> Tuple[int, dict]:
        async with slots:
            return entry.link.idx, await check_node(entry.port)

    results = dict(await asyncio.gather(*(one(entry) for entry in process.entries)))
    wall = time.perf_counter() - started
    after = process.stats()
    return {"wall_s": round(wall, 2), "cpu_s": round(after["cpu_s"] - before["cpu_s"], 3) if after else None,
            "peak_anon_mb": round(process.peak["anon_mb"], 1), "peak_rss_mb": round(process.peak["rss_mb"], 1),
            "peak_threads": process.peak["threads"], "alive": process.alive, "nodes": results}


async def speed_once(port: int, seconds: float, size: int) -> dict:
    """Downloads through a listener for up to `seconds`, as nodesieve's speedtest does."""
    started = time.perf_counter()
    first, total, error = None, 0, None
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(SPEED_URL.format(size), proxy=f"http://{LISTEN}:{port}",
                                   timeout=aiohttp.ClientTimeout(total=seconds + 6, connect=3.5)) as resp:
                if resp.status != 200:
                    return {"ok": False, "error": f"HTTP {resp.status}"}
                async for chunk in resp.content.iter_chunked(131072):
                    now = time.perf_counter()
                    first = first or now
                    total += len(chunk)
                    if now - first >= seconds:
                        break
                    if now - first > 2.0 and total / (now - first) / 1048576 < 0.05:
                        break
    except Exception as exc:
        error = _describe(exc)
    if first is None or total < 65536:
        return {"ok": False, "error": error or "too little data", "bytes": total}
    duration = max(time.perf_counter() - first, 0.05)
    return {"ok": True, "mb_s": round(total / duration / 1048576, 2), "bytes": total,
            "ttfb_ms": round((first - started) * 1000)}


async def tcp_reachable(links: Sequence[Link], timeout: float = 1.5) -> Dict[int, bool]:
    """nodesieve's Phase 0 for each node: a TCP connection to its server."""

    async def one(link: Link) -> Tuple[int, bool]:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(link.host, link.port), timeout)
        except Exception:
            return link.idx, False
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
        except Exception:
            pass
        return link.idx, True

    return dict(await asyncio.gather(*(one(link) for link in links)))


# --- The run ---------------------------------------------------------------------------


@dataclass
class Plan:
    """What one profile serves and everything measured of it."""

    profile: Profile
    entries: List[Entry]
    unsupported: Dict[int, str]
    refused: Dict[int, str] = field(default_factory=dict)
    starts: List[dict] = field(default_factory=list)
    start_error: Optional[str] = None
    process: Optional[CoreProcess] = None
    restarts: int = 0
    rounds: List[dict] = field(default_factory=list)
    errors: Dict[int, List[str]] = field(default_factory=dict)
    speed: Dict[int, dict] = field(default_factory=dict)

    def works(self, idx: int) -> Optional[int]:
        """Rounds in which a node answered over IPv4 or IPv6, or None for a node not served."""
        if not any(entry.link.idx == idx for entry in self.entries) or not self.rounds:
            return None
        return sum(1 for r in self.rounds if (n := r["nodes"].get(idx)) and (n["v4"]["ok"] or n["v6"]["ok"]))

    def latency(self, idx: int) -> Optional[float]:
        """Median over the rounds of nodesieve's latency: the faster family's trace."""
        values = []
        for r in self.rounds:
            n = r["nodes"].get(idx)
            if n:
                times = [n[f]["ms"] for f in ("v4", "v6") if n[f]["ok"]]
                if times:
                    values.append(min(times))
        return statistics.median(values) if values else None

    def last_error(self, idx: int) -> Optional[str]:
        for r in reversed(self.rounds):
            n = r["nodes"].get(idx)
            if n and not (n["v4"]["ok"] or n["v6"]["ok"]):
                return n["v4"].get("error") or n["v6"].get("error")
        return None


def find_binary(explicit: Optional[str], names: Sequence[str], places: Sequence[str]) -> Optional[str]:
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    home = os.path.expanduser("~")
    for place in places:
        path = place.replace("~", home)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def build_profiles(args: argparse.Namespace) -> List[Profile]:
    prefix = os.environ.get("PREFIX", "/usr")
    xray = find_binary(args.xray, ["xray"], ["/opt/v2rayn-bin/bin/xray/xray", "~/.local/share/v2rayN/bin/xray/xray",
                                             f"{prefix}/bin/xray", "/usr/bin/xray"])
    sing_box = find_binary(args.sing_box, ["sing-box"], ["/opt/v2rayn-bin/bin/sing_box/sing-box",
                                                         "~/.local/share/v2rayN/bin/sing_box/sing-box",
                                                         f"{prefix}/bin/sing-box", "/usr/bin/sing-box"])
    stable = find_binary(args.mihomo_stable, [], ["/opt/v2rayn-bin/bin/mihomo/mihomo",
                                                  "~/.local/share/v2rayN/bin/mihomo/mihomo"])
    if os.path.realpath(stable or "") == os.path.realpath(MIHOMO_PATH):
        stable = None
    available = {
        "mihomo": (lambda: MihomoProfile("mihomo", MIHOMO_PATH)) if os.path.isfile(MIHOMO_PATH) else None,
        "mihomo-stable": (lambda: MihomoProfile("mihomo-stable", stable)) if stable else None,
        "xray": (lambda: XrayProfile("xray", xray, fragment=True)) if xray else None,
        "xray-nofrag": (lambda: XrayProfile("xray-nofrag", xray, fragment=False)) if xray else None,
        "sing-box": (lambda: SingBoxProfile("sing-box", sing_box, fragment=True)) if sing_box else None,
    }
    wanted = [name.strip() for name in args.cores.split(",") if name.strip()] if args.cores else list(available)
    profiles = []
    for name in wanted:
        if name not in available:
            sys.exit(f"Unknown core profile {name}; known: {', '.join(available)}")
        if available[name] is None:
            print(f"[!] {name}: no binary found, left out (see --help for the path options)")
            continue
        profiles.append(available[name]())
    return profiles


async def direct_ip() -> Optional[str]:
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        result = await _trace(session, TRACE_V4[:1], None, 5.0, False)
    return result.get("ip")


async def run(args: argparse.Namespace) -> dict:
    config = ConfigManager.load(ConfigManager.default_path(ROOT))
    raw_links, source = await load_links(args, config)
    links: List[Link] = []
    seen = set()
    unparsed = 0
    for raw in raw_links:
        core = raw.split("#", 1)[0]
        if core in seen:
            continue
        seen.add(core)
        link = parse_link(0, raw)
        if link is None:
            unparsed += 1
        elif not link.header:
            link.idx = len(links) + 1
            links.append(link)
    headers = len(seen) - unparsed - len(links)
    print(f"[*] {source}; {len(links)} nodes, {headers} section headers left out"
          + (f", {unparsed} links without a server" if unparsed else ""))
    if args.limit:
        links = links[:args.limit]
    if not links:
        sys.exit("No nodes to check.")

    real_ip = await direct_ip()
    tcp = await tcp_reachable(links)
    print(f"[*] Direct trace {'answered' if real_ip else 'did not answer'}; "
          f"{sum(tcp.values())} of {len(links)} servers accept TCP (nodesieve's Phase 0)")

    plans: List[Plan] = []
    for profile in build_profiles(args):
        entries, unsupported = [], {}
        for link in links:
            try:
                outbound, notes = profile.convert(link, f"node-{link.idx}")
            except Unsupported as exc:
                unsupported[link.idx] = str(exc)
                continue
            entries.append(Entry(link, outbound, notes))
        plan = Plan(profile, entries, unsupported)
        plan.refused = await refused_nodes(profile, entries)
        plan.entries = [entry for entry in entries if entry.link.idx not in plan.refused]
        plans.append(plan)
        print(f"[*] {profile.name}: {profile.version}; serves {len(plan.entries)} nodes"
              + (f", cannot express {len(unsupported)}" if unsupported else "")
              + (f", refuses {len(plan.refused)}" if plan.refused else ""))

    try:
        for plan in plans:
            for number in range(args.starts):
                process = CoreProcess(plan.profile, plan.entries)
                try:
                    listening, relaying = await process.start()
                except Exception as exc:
                    plan.start_error = str(exc)
                    print(f"[-] {exc}")
                    break
                await asyncio.sleep(1.0)
                idle = process.stats() or {}
                plan.starts.append({"listening_ms": round(listening * 1000), "relaying_ms": round(relaying * 1000),
                                    "idle_anon_mb": round(idle.get("anon_mb", 0), 1),
                                    "idle_rss_mb": round(idle.get("rss_mb", 0), 1), "threads": idle.get("threads")})
                if number < args.starts - 1:
                    await process.stop()
                else:
                    plan.process = process
            if plan.starts:
                print(f"[*] {plan.profile.name}: relays {statistics.median(s['relaying_ms'] for s in plan.starts):.0f} ms "
                      f"after starting, {statistics.median(s['idle_anon_mb'] for s in plan.starts):.1f} MB of its own idle")

        live = [plan for plan in plans if plan.process is not None]
        for number in range(args.rounds):
            turn = number % max(1, len(live))
            for plan in live[turn:] + live[:turn]:
                if not plan.process.alive:
                    plan.restarts += 1
                    plan.process = CoreProcess(plan.profile, plan.entries)
                    await plan.process.start()
                result = await run_round(plan.process, args.workers or len(plan.entries))
                plan.rounds.append(result)
                working = sum(1 for n in result["nodes"].values() if n["v4"]["ok"] or n["v6"]["ok"])
                print(f"[*] Round {number + 1}/{args.rounds} {plan.profile.name:13} {working:3} of {len(plan.entries)} answer, "
                      f"{result['wall_s']:5.1f} s, CPU {result['cpu_s']} s, peak {result['peak_anon_mb']} MB"
                      + ("" if result["alive"] else ", EXITED"))

        if args.speed and live:
            await speed_phase(live, args)
    finally:
        for plan in plans:
            if plan.process is not None:
                await plan.process.stop()
                plan.errors = plan.profile.node_errors(plan.process.log)

    leaks = sorted({idx for plan in plans for r in plan.rounds for idx, n in r["nodes"].items()
                    if real_ip and real_ip in (n["v4"].get("ip"), n["v6"].get("ip"))})
    return {"links": links, "plans": plans, "tcp": tcp, "source": source, "leaks": leaks, "headers": headers}


async def speed_phase(plans: List[Plan], args: argparse.Namespace) -> None:
    """Downloads through the fastest nodes, one node at a time with its cores back to back."""
    reference = next((plan for plan in plans if plan.profile.name == "xray"), plans[0])
    ranked = sorted((idx for idx in (e.link.idx for e in reference.entries)
                     if reference.works(idx) == len(reference.rounds)), key=lambda idx: reference.latency(idx) or 1e9)
    chosen = ranked[:args.speed]
    print(f"[*] Speed: {len(chosen)} nodes, up to {args.speed_seconds:g} s or {args.speed_bytes / 1e6:g} MB each per core")
    for turn, idx in enumerate(chosen):
        order = plans[turn % len(plans):] + plans[:turn % len(plans)]
        line = []
        for plan in order:
            entry = next((e for e in plan.entries if e.link.idx == idx), None)
            if entry is None or not plan.works(idx) or not plan.process.alive:
                continue
            before = plan.process.stats()
            result = await speed_once(entry.port, args.speed_seconds, args.speed_bytes)
            after = plan.process.stats()
            if before and after and result.get("bytes"):
                result["cpu_ms_per_mb"] = round((after["cpu_s"] - before["cpu_s"]) * 1000 / (result["bytes"] / 1048576), 1)
            plan.speed[idx] = result
            line.append(f"{plan.profile.name} {result['mb_s'] if result['ok'] else 'failed'}")
        print(f"    #{idx}: " + ", ".join(line))


# --- Report ----------------------------------------------------------------------------


def _median(values: Sequence[Optional[float]]) -> Optional[float]:
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def _cell(name: str) -> str:
    """A node's name as a table cell: shortened, its own | escaped."""
    return name[:34].replace("|", "\\|")


def _fmt(value: Optional[float], digits: int = 0) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def report(result: dict, args: argparse.Namespace) -> Tuple[str, dict]:
    links: List[Link] = result["links"]
    plans: List[Plan] = result["plans"]
    by_idx = {link.idx: link for link in links}
    rounds = args.rounds
    out = [f"# Core comparison, {time.strftime('%Y-%m-%d %H:%M')}", "",
           f"{len(links)} nodes ({result['source']}); {rounds} rounds of nodesieve's IP check per core, "
           f"{args.workers or 'all'} nodes at once. Memory is the core's own (RssAnon), without its shared code.", ""]

    out += ["## Cores", "", "| core | version | binary | serves | can't express | refuses | relays after start | "
            "idle memory | peak memory | CPU per round | round |", "|" + "---|" * 11]
    for plan in plans:
        p = plan.profile
        size = os.path.getsize(p.binary) / 1048576
        out.append(f"| {p.name} | {p.version[:48]} | {size:.0f} MB | {len(plan.entries)} | {len(plan.unsupported)} | "
                   f"{len(plan.refused)} | {_fmt(_median([s['relaying_ms'] for s in plan.starts]))} ms | "
                   f"{_fmt(_median([s['idle_anon_mb'] for s in plan.starts]), 1)} MB | "
                   f"{_fmt(max((r['peak_anon_mb'] for r in plan.rounds), default=None), 1)} MB | "
                   f"{_fmt(_median([r['cpu_s'] for r in plan.rounds]), 2)} s | "
                   f"{_fmt(_median([r['wall_s'] for r in plan.rounds]), 1)} s |")
        if plan.start_error:
            out.append(f"| | did not start: {plan.start_error[:200]} |" + " |" * 9)

    served_by_all = [link.idx for link in links if all(plan.works(link.idx) is not None for plan in plans)]
    common = [idx for idx in served_by_all if all(plan.works(idx) == rounds for plan in plans)]
    out += ["", "## Results", "", f"Latency: median of nodesieve's latency over the {len(common)} nodes every core "
            "answers through in every round.", "",
            "| core | every round | some rounds | never | not served | latency |", "|---|---|---|---|---|---|"]
    for plan in plans:
        works = [plan.works(link.idx) for link in links]
        out.append(f"| {plan.profile.name} | {sum(1 for w in works if w == rounds)} | "
                   f"{sum(1 for w in works if w and w < rounds)} | {sum(1 for w in works if w == 0)} | "
                   f"{sum(1 for w in works if w is None)} | {_fmt(_median([plan.latency(i) for i in common]))} ms |")
    if result["leaks"]:
        out += ["", f"**Exit equal to this computer's address** (a leak) for nodes {result['leaks']}."]

    kinds = sorted({link.kind for link in links})
    out += ["", "## By node type", "", "Nodes that answered in at least one round, of the nodes of that type.", "",
            "| type | nodes | " + " | ".join(plan.profile.name for plan in plans) + " |", "|---|---|" + "---|" * len(plans)]
    for kind in kinds:
        members = [link.idx for link in links if link.kind == kind]
        cells = []
        for plan in plans:
            works = [plan.works(idx) for idx in members]
            served = [w for w in works if w is not None]
            cells.append(f"{sum(1 for w in served if w)}" + ("" if len(served) == len(members) else f" ({len(members) - len(served)} not served)"))
        out.append(f"| {kind} | {len(members)} | " + " | ".join(cells) + " |")

    disagree = [link.idx for link in links
                if len({plan.works(link.idx) for plan in plans if plan.works(link.idx) is not None}) > 1
                or any(plan.works(link.idx) is None for plan in plans)]
    out += ["", "## Where the cores differ", "",
            "Rounds a node answered in; — where the core does not serve it. TCP: nodesieve's Phase 0 reaches the server.", "",
            "| # | node | type | TCP | " + " | ".join(plan.profile.name for plan in plans) + " |",
            "|---|---|---|---|" + "---|" * len(plans)]
    for idx in disagree:
        link = by_idx[idx]
        cells = ["—" if plan.works(idx) is None else f"{plan.works(idx)}/{rounds}" for plan in plans]
        out.append(f"| {idx} | {_cell(link.name)} | {link.kind} | {'yes' if result['tcp'].get(idx) else 'no'} | " + " | ".join(cells) + " |")
    details = []
    for idx in disagree:
        lines = []
        for plan in plans:
            if idx in plan.unsupported:
                lines.append(f"  - {plan.profile.name}: cannot express it: {plan.unsupported[idx]}")
            elif idx in plan.refused:
                lines.append(f"  - {plan.profile.name}: refused: {plan.refused[idx]}")
            elif plan.works(idx) is not None and plan.works(idx) < rounds:
                core_said = [e for e in dict.fromkeys(plan.errors.get(idx, []))][:2]
                lines.append(f"  - {plan.profile.name}: {plan.last_error(idx) or 'answered in some rounds'}"
                             + ("".join(f"; core: {e[:220]}" for e in core_said)))
        if lines:
            details.append(f"- #{idx} {by_idx[idx].name[:40]}\n" + "\n".join(lines))
    if details:
        out += ["", "Why:", ""] + details

    notes: Dict[str, Dict[str, int]] = {}
    for plan in plans:
        for entry in plan.entries:
            for note in entry.notes:
                notes.setdefault(plan.profile.name, {}).setdefault(note, 0)
                notes[plan.profile.name][note] += 1
    if notes:
        out += ["", "## Conversion notes", ""]
        for name, counted in notes.items():
            for note, count in counted.items():
                out.append(f"- {name}: {note} ({count} nodes)")

    if any(plan.speed for plan in plans):
        speed_nodes = sorted({idx for plan in plans for idx in plan.speed})
        out += ["", "## Speed", "", f"MB/s, up to {args.speed_seconds:g} s or {args.speed_bytes / 1e6:g} MB per node and core, "
                "the cores of a node one after another.", "",
                "| # | node | type | " + " | ".join(plan.profile.name for plan in plans) + " |",
                "|---|---|---|" + "---|" * len(plans)]
        for idx in speed_nodes:
            cells = [(_fmt(plan.speed[idx]["mb_s"], 1) if plan.speed.get(idx, {}).get("ok") else
                      ("failed" if idx in plan.speed else "—")) for plan in plans]
            out.append(f"| {idx} | {_cell(by_idx[idx].name)} | {by_idx[idx].kind} | " + " | ".join(cells) + " |")
        medians = [_median([s.get("mb_s") for s in plan.speed.values() if s.get("ok")]) for plan in plans]
        cpu = [_median([s.get("cpu_ms_per_mb") for s in plan.speed.values() if s.get("ok")]) for plan in plans]
        out.append("| | median | | " + " | ".join(_fmt(value, 1) for value in medians) + " |")
        out.append("| | CPU ms per MB | | " + " | ".join(_fmt(value, 1) for value in cpu) + " |")

    data = {
        "when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "source": result["source"], "rounds": rounds,
        "nodes": [{"idx": link.idx, "name": link.name, "kind": link.kind, "scheme": link.scheme, "server": link.host,
                   "port": link.port, "tcp": result["tcp"].get(link.idx)} for link in links],
        "leaks": result["leaks"],
        "cores": [{"name": plan.profile.name, "version": plan.profile.version, "binary": plan.profile.binary,
                   "unsupported": plan.unsupported, "refused": plan.refused, "starts": plan.starts,
                   "start_error": plan.start_error, "restarts": plan.restarts,
                   "notes": {entry.link.idx: entry.notes for entry in plan.entries if entry.notes},
                   "rounds": plan.rounds, "core_errors": {idx: list(dict.fromkeys(e))[:5] for idx, e in plan.errors.items()},
                   "speed": plan.speed} for plan in plans],
    }
    return "\n".join(out) + "\n", data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n", 2)[2])
    parser.add_argument("--cores", help="comma-separated profiles (default: every one with a binary)")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--starts", type=int, default=3, help="starts measured per core (default 3)")
    parser.add_argument("--workers", type=int, default=0, help="nodes checked at once (default: all)")
    parser.add_argument("--speed", type=int, default=0, metavar="N", help="also download through the N fastest nodes")
    parser.add_argument("--speed-seconds", type=float, default=3.0)
    parser.add_argument("--speed-bytes", type=int, default=8_000_000)
    parser.add_argument("--links", help="a file of share links to check instead of the subscriptions")
    parser.add_argument("--cached", action="store_true", help="use the subscriptions' cached copies, download nothing")
    parser.add_argument("--limit", type=int, default=0, help="check only the first N nodes")
    parser.add_argument("--xray", help="Xray binary")
    parser.add_argument("--sing-box", dest="sing_box", help="sing-box binary")
    parser.add_argument("--mihomo-stable", dest="mihomo_stable", help="a second Mihomo binary to compare")
    parser.add_argument("--out", default=os.path.join("core-bench", time.strftime("%Y%m%d-%H%M%S")))
    parser.add_argument("--keep-logs", action="store_true",
                        help="also write each core's log to --out (server addresses, no credentials)")
    args = parser.parse_args()

    result = asyncio.run(run(args))
    text, data = report(result, args)
    os.makedirs(args.out, exist_ok=True)
    if args.keep_logs:
        for plan in result["plans"]:
            if plan.process is not None:
                with open(os.path.join(args.out, f"{plan.profile.name}.log"), "w", encoding="utf-8") as f:
                    f.write("\n".join(ANSI.sub("", line) for line in plan.process.log) + "\n")
    with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print("\n" + text)
    print(f"[+] Written to {os.path.join(args.out, 'report.md')} and results.json")


if __name__ == "__main__":
    main()
