"""AmneziaWG 3.0 configuration file parser and YAML generator for Mihomo."""

import os
from typing import Optional
from proxy_sites.logging import log


def parse_amnezia_conf(conf_path: str, proxy_name: str = "AmneziaWG") -> Optional[dict]:
    """Parses an AmneziaWG (.conf) file into a Mihomo wireguard proxy dictionary."""
    if not os.path.exists(conf_path):
        return None

    section = None
    iface_opts = {}
    peer_opts = {}

    try:
        with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip().lower()
                    continue

                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if section == "interface":
                        iface_opts[key] = val
                    elif section == "peer":
                        peer_opts[key] = val
    except Exception as e:
        log.error(f"Failed to parse AWG config {conf_path}: {e}")
        return None

    if not iface_opts or not peer_opts:
        return None

    ip = ""
    ipv6 = ""
    addr_val = iface_opts.get("address", "")
    if addr_val:
        addrs = [a.strip() for a in addr_val.replace(",", " ").split() if a.strip()]
        for a in addrs:
            if ":" in a:
                ipv6 = a.split("/")[0]
            else:
                ip = a.split("/")[0]

    endpoint = peer_opts.get("endpoint", "")
    server = ""
    port = None
    if endpoint:
        if ":" in endpoint:
            host_part, port_part = endpoint.rsplit(":", 1)
            server = host_part.strip("[]")
            if port_part.isdigit():
                port = int(port_part)
        else:
            server = endpoint

    keepalive = None
    ka_val = peer_opts.get("persistentkeepalive", "")
    if ka_val:
        ka_str = ka_val.split("-")[0].strip()
        if ka_str.isdigit():
            keepalive = int(ka_str)

    allowed_ips = ["0.0.0.0/0", "::/0"]
    allowed_val = peer_opts.get("allowedips", "")
    if allowed_val:
        a_list = [a.strip() for a in allowed_val.replace(" ", "").split(",") if a.strip()]
        if a_list:
            allowed_ips = a_list

    proxy = {
        "name": proxy_name,
        "type": "wireguard",
        "server": server,
        "port": port,
        "private-key": iface_opts.get("privatekey", ""),
        "public-key": peer_opts.get("publickey", ""),
        "udp": True,
        "allowed-ips": allowed_ips,
    }

    if peer_opts.get("presharedkey"):
        proxy["pre-shared-key"] = peer_opts.get("presharedkey")
    if ip:
        proxy["ip"] = ip
    if ipv6:
        proxy["ipv6"] = ipv6
    if keepalive is not None:
        proxy["persistent-keepalive"] = keepalive

    # Parse DNS
    dns_val = iface_opts.get("dns", "")
    if dns_val:
        dns_list = [d.strip() for d in dns_val.replace(",", " ").split() if d.strip()]
        public_dns = [
            d for d in dns_list
            if not d.startswith("100.64.") and not d.startswith("10.") and not d.startswith("172.16.")
        ]
        if public_dns:
            proxy["remote-dns-resolve"] = True
            proxy["dns"] = public_dns

    # Parse MTU
    if iface_opts.get("mtu") and iface_opts["mtu"].isdigit():
        proxy["mtu"] = int(iface_opts["mtu"])
    else:
        proxy["mtu"] = 1360

    awg_opts = {}
    int_keys = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime"]
    str_keys = ["h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"]
    v3_str_keys = {
        "headerprotectionkey": "header-protection-key",
        "contentpaddingaddition": "content-padding-addition",
        "rekeyaftertime": "rekey-after-time",
        "rekeytimeout": "rekey-timeout",
        "rejectaftertime": "reject-after-time",
        "keepalivetimeout": "keepalive-timeout",
        "maxhandshakeattempts": "max-handshake-attempts",
    }

    for k in int_keys:
        if k in iface_opts:
            val_str = iface_opts[k].split("-")[0].strip()
            if val_str.isdigit():
                awg_opts[k] = int(val_str)

    for k in str_keys:
        if k in iface_opts:
            val = iface_opts[k]
            # For i1-i5: preserve the full "<b 0x...>" tag as-is — mihomo's amneziawg-go UAPI
            # requires this exact format. Stripping to just "0x..." causes IPC error -22.
            # For h1-h4/j1-j3: pass as plain values (numeric strings or ints as needed).
            awg_opts[k] = val

    has_v3 = False
    for conf_k, yaml_k in v3_str_keys.items():
        if conf_k in iface_opts:
            val = iface_opts[conf_k]
            val_first = val.split("-")[0].strip()
            if val_first.isdigit():
                awg_opts[yaml_k] = int(val_first)
            else:
                awg_opts[yaml_k] = val
            has_v3 = True
    if has_v3:
        awg_opts["version"] = 3

    if awg_opts:
        proxy["amnezia-wg-option"] = awg_opts

    return proxy


def generate_awg_proxy_yaml(proxy: dict) -> str:
    """Generates formatted YAML snippet for AmneziaWG proxy."""
    lines = []
    escaped_name = proxy["name"].replace('"', '\\"')
    lines.append(f'  - name: "{escaped_name}"')
    lines.append(f"    type: {proxy['type']}")
    lines.append(f"    server: \"{proxy['server']}\"")
    if proxy.get("port") is not None:
        lines.append(f"    port: {proxy['port']}")
    lines.append(f"    private-key: \"{proxy['private-key']}\"")
    lines.append(f"    public-key: \"{proxy['public-key']}\"")
    if proxy.get("pre-shared-key"):
        lines.append(f"    pre-shared-key: \"{proxy['pre-shared-key']}\"")
    if proxy.get("ip"):
        lines.append(f"    ip: \"{proxy['ip']}\"")
    if proxy.get("ipv6"):
        lines.append(f"    ipv6: \"{proxy['ipv6']}\"")
    lines.append(f"    udp: {'true' if proxy.get('udp', True) else 'false'}")
    if proxy.get("persistent-keepalive") is not None:
        lines.append(f"    persistent-keepalive: {proxy['persistent-keepalive']}")
    if proxy.get("mtu") is not None:
        lines.append(f"    mtu: {proxy['mtu']}")
    if proxy.get("remote-dns-resolve"):
        lines.append("    remote-dns-resolve: true")
    if proxy.get("dns"):
        lines.append("    dns:")
        for d in proxy["dns"]:
            lines.append(f"      - \"{d}\"")
    if proxy.get("allowed-ips"):
        lines.append("    allowed-ips:")
        for ip_subnet in proxy["allowed-ips"]:
            lines.append(f"      - \"{ip_subnet}\"")

    if "amnezia-wg-option" in proxy and proxy["amnezia-wg-option"]:
        lines.append("    amnezia-wg-option:")
        for k, v in proxy["amnezia-wg-option"].items():
            if isinstance(v, str):
                escaped_v = v.replace('"', '\\"')
                lines.append(f"      {k}: \"{escaped_v}\"")
            elif isinstance(v, bool):
                lines.append(f"      {k}: {'true' if v else 'false'}")
            else:
                lines.append(f"      {k}: {v}")

    return "\n".join(lines)
