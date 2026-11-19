"""Generates shell script to deploy verified proxies and configurations.

Targets OpenWrt routers running Mihomo.
"""

import base64
import os
import re
from typing import List, Optional
import yaml
from proxy_sites.config import ConfigManager
from proxy_sites.constants import PROJECT_ROOT, ROUTER_SCRIPT_FILE
from proxy_sites.logging import log
from proxy_sites.parsers.awg import parse_amnezia_conf
from proxy_sites.parsers.base import extract_host_port, get_node_name
from proxy_sites.parsers.mihomo import node_url_to_mihomo_dict
from proxy_sites.router.config_builder import build_router_config_yaml
from proxy_sites.warp import WarpScanner


def generate_router_script(
    final_nodes: List[str],
    config: Optional[dict] = None,
    out_file: Optional[str] = None,
) -> str:
    """Creates apply_to_router.sh shell script for router deployment."""
    if config is None:
        config = ConfigManager.load()

    target_file = (
        os.path.join(PROJECT_ROOT, ROUTER_SCRIPT_FILE)
        if out_file in (None, ROUTER_SCRIPT_FILE)
        else out_file
    )

    awg_confs_in_final = []
    warp_proxies = []
    use_mux = config.get("use_mux", True)
    proxy_dicts = []
    raw_nodes = []

    for node in final_nodes:
        if node.startswith("warp://"):
            host_w, port_w = extract_host_port(node)
            name_w = get_node_name(node)
            if host_w and port_w:
                proxy_dict = WarpScanner.generate_warp_proxy_dict(
                    host_w, port_w, name_w, config=config
                )
                warp_proxies.append(proxy_dict)
        elif node.startswith("awg_conf:"):
            cfile = node.split("awg_conf:", 1)[1].split("#", 1)[0]
            if cfile not in awg_confs_in_final:
                awg_confs_in_final.append(cfile)
        else:
            p_dict = node_url_to_mihomo_dict(node, use_mux=use_mux)
            if p_dict:
                proxy_dicts.append(p_dict)
            else:
                if node.startswith("vless://"):
                    node = re.sub(
                        r"encryption=[^&#]+", "encryption=none", node
                    )
                raw_nodes.append(node)

    awg_proxy = None
    use_awg = config.get("use_amnezia_wg", False) or bool(awg_confs_in_final)
    default_conf = config.get("amnezia_wg_conf", "US.conf")
    awg_conf_name = (
        awg_confs_in_final[0] if awg_confs_in_final else default_conf
    )

    if use_awg:
        conf_path = os.path.join(PROJECT_ROOT, awg_conf_name)
        if not os.path.exists(conf_path) and os.path.exists(awg_conf_name):
            conf_path = awg_conf_name
        if os.path.exists(conf_path):
            proxy_name = os.path.splitext(os.path.basename(awg_conf_name))[0]
            awg_proxy = parse_amnezia_conf(
                conf_path, proxy_name=f"AWG_{proxy_name}"
            )
            if awg_proxy:
                log.info(
                    f"[*] AmneziaWG 3.0 config loaded: {awg_conf_name} "
                    f"as AWG_{proxy_name}"
                )
            else:
                log.info(
                    f"[-] Failed to parse AmneziaWG config: {awg_conf_name}"
                )
        else:
            log.info(f"[-] AmneziaWG conf file not found: {awg_conf_name}")

    sub_content_parts = []
    if proxy_dicts:
        dumped = yaml.dump(
            {"proxies": proxy_dicts}, allow_unicode=True, sort_keys=False
        ).strip()
        sub_content_parts.append(dumped)
    for node in raw_nodes:
        sub_content_parts.append(node.strip())
    sub_yaml_content = (
        "\n".join(sub_content_parts) + "\n" if sub_content_parts else ""
    )

    config_yaml = build_router_config_yaml(
        awg_proxy, warp_proxies, config=config
    )
    if not config_yaml.endswith("\n"):
        config_yaml += "\n"

    sub_b64 = base64.b64encode(sub_yaml_content.encode("utf-8")).decode("ascii")
    config_b64 = base64.b64encode(config_yaml.encode("utf-8")).decode("ascii")

    with open(target_file, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n")
        f.write("set -e\n")
        f.write("export PATH=\"/usr/sbin:/usr/bin:/sbin:/bin:$PATH\"\n\n")
        f.write("# Fallback base64 decoder for OpenWrt Busybox environments\n")
        f.write("if ! command -v base64 >/dev/null 2>&1; then\n")
        f.write("    base64() {\n")
        f.write("        if command -v busybox >/dev/null 2>&1 && busybox base64 </dev/null >/dev/null 2>&1; then\n")
        f.write('            busybox base64 "$@"\n')
        f.write("        elif command -v openssl >/dev/null 2>&1; then\n")
        f.write('            if [ "$1" = "-d" ] || [ "$1" = "--decode" ]; then\n')
        f.write("                openssl enc -d -base64\n")
        f.write("            else\n")
        f.write("                openssl enc -base64\n")
        f.write("            fi\n")
        f.write("        else\n")
        f.write('            if [ "$1" = "-d" ] || [ "$1" = "--decode" ]; then\n')
        f.write("                awk '\n")
        f.write("                BEGIN {\n")
        f.write('                    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"\n')
        f.write("                    for (i=0; i<64; i++) t[substr(b64,i+1,1)] = i\n")
        f.write("                }\n")
        f.write("                {\n")
        f.write('                    gsub(/[^A-Za-z0-9+\\/=]/, "")\n')
        f.write("                    for (i=1; i<=length($0); i+=4) {\n")
        f.write("                        c1 = t[substr($0,i,1)]\n")
        f.write("                        c2 = t[substr($0,i+1,1)]\n")
        f.write('                        c3 = substr($0,i+2,1) == "=" ? -1 : t[substr($0,i+2,1)]\n')
        f.write('                        c4 = substr($0,i+3,1) == "=" ? -1 : t[substr($0,i+3,1)]\n')
        f.write('                        printf "%c", (c1 * 4 + int(c2 / 16)) % 256\n')
        f.write('                        if (c3 != -1) printf "%c", ((c2 % 16) * 16 + int(c3 / 4)) % 256\n')
        f.write('                        if (c4 != -1) printf "%c", ((c3 % 4) * 64 + c4) % 256\n')
        f.write("                    }\n")
        f.write("                }'\n")
        f.write("            fi\n")
        f.write("        fi\n")
        f.write("    }\n")
        f.write("fi\n\n")
        f.write("# Deployed nodes:\n")
        for node in final_nodes:
            clean_node = re.sub(r"[\r\n]+", " ", str(node))
            clean_tag = re.sub(r"[\r\n]+", " ", get_node_name(node))
            f.write(f"#   - {clean_tag}: {clean_node}\n")
        f.write("\n")
        f.write("echo '[*] Preparing router configuration deployment...'\n")
        f.write("echo 'Applying nodes to mihomo proxy provider...'\n")
        f.write("mkdir -p /etc/mihomo/proxy-providers\n\n")

        f.write("# 1. Backup current files to .bak\n")
        f.write("[ -f /etc/mihomo/config.yaml ] && "
                "cp /etc/mihomo/config.yaml /etc/mihomo/config.yaml.bak\n")
        f.write("[ -f /etc/mihomo/proxy-providers/sub.yaml ] && "
                "cp /etc/mihomo/proxy-providers/sub.yaml "
                "/etc/mihomo/proxy-providers/sub.yaml.bak\n\n")

        f.write("rollback() {\n")
        f.write("    trap - EXIT\n")
        f.write("    echo '[-] Error detected during deployment! "
                "Rolling back...'\n")
        f.write("    if [ -f /etc/mihomo/config.yaml.bak ]; then "
                "mv -f /etc/mihomo/config.yaml.bak /etc/mihomo/config.yaml || true; "
                "else rm -f /etc/mihomo/config.yaml || true; fi\n")
        f.write("    if [ -f /etc/mihomo/proxy-providers/sub.yaml.bak ]; then "
                "mv -f /etc/mihomo/proxy-providers/sub.yaml.bak "
                "/etc/mihomo/proxy-providers/sub.yaml || true; "
                "else rm -f /etc/mihomo/proxy-providers/sub.yaml || true; fi\n")
        f.write("    rm -f /etc/mihomo/config.yaml.tmp "
                "/etc/mihomo/proxy-providers/sub.yaml.tmp || true\n")
        f.write("    /etc/init.d/mihomo restart || true\n")
        f.write("    /etc/init.d/magitrickle restart || true\n")
        f.write("    exit 1\n")
        f.write("}\n\n")
        f.write("success=0\n")
        f.write("trap 'if [ \"$success\" != \"1\" ]; then rollback; fi' EXIT\n\n")

        f.write("# 2. Stage new files to .tmp\n")
        f.write("echo '[*] Staging new configuration files...'\n")
        f.write(f"echo '{sub_b64}' | base64 -d > /etc/mihomo/proxy-providers/sub.yaml.tmp\n\n")

        f.write("cat << 'EOF' > /etc/mihomo/proxy-providers/direct.yaml\n")
        f.write("proxies:\n")
        f.write("  - name: \"Домашний интернет\"\n")
        f.write("    type: direct\n")
        f.write("EOF\n\n")

        f.write("echo 'Applying new mihomo config.yaml...'\n")
        f.write(f"echo '{config_b64}' | base64 -d > /etc/mihomo/config.yaml.tmp\n\n")

        f.write("# 3. Pre-flight syntax validation\n")
        f.write("echo '[*] Verifying configuration syntax via mihomo -t...'\n")
        f.write("/usr/bin/mihomo -t -d /etc/mihomo "
                "-f /etc/mihomo/config.yaml.tmp || rollback\n\n")

        f.write("# 4. Atomic move\n")
        f.write("echo '[*] Applying configuration files...'\n")
        f.write("mv -f /etc/mihomo/proxy-providers/sub.yaml.tmp "
                "/etc/mihomo/proxy-providers/sub.yaml\n")
        f.write("mv -f /etc/mihomo/config.yaml.tmp "
                "/etc/mihomo/config.yaml\n\n")

        f.write("# 5. Service restart\n")
        f.write("echo '[*] Restarting services...'\n")
        f.write("echo 'Restarting mihomo service...'\n")
        f.write("/etc/init.d/mihomo restart || rollback\n")
        f.write("sleep 1\n")
        f.write("echo 'Restarting magitrickle service...'\n")
        f.write("/etc/init.d/magitrickle restart || rollback\n")
        f.write("sleep 1\n\n")

        f.write("# 6. Post-restart verification\n")
        f.write("echo '[*] Verifying service status...'\n")
        f.write("/etc/init.d/mihomo status | "
                "grep -q running || rollback\n")
        f.write("/etc/init.d/magitrickle status | "
                "grep -q running || rollback\n\n")

        api_port = config.get("router_api_port", 9090) if config else 9090
        f.write(f"echo '[*] Verifying REST API connectivity on "
                f"127.0.0.1:{api_port}...'\n")
        f.write(f"(wget -qO- -T 3 http://127.0.0.1:{api_port}/version 2>/dev/null || "
                f"curl -s -m 3 http://127.0.0.1:{api_port}/version 2>/dev/null) | "
                "grep -q 'version' || rollback\n\n")

        f.write("# 7. Cleanup backups on success\n")
        f.write("rm -f /etc/mihomo/config.yaml.bak "
                "/etc/mihomo/proxy-providers/sub.yaml.bak\n")
        f.write("success=1\n")
        f.write("trap - EXIT\n")
        f.write("echo 'Done!'\n")

    return target_file
