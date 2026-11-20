"""Constants, default configuration, file paths, and YAML templates."""

import os
from pathlib import Path
from typing import Any, Dict, Set

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = "nodesieve_config.json"
# The settings file's name before the project was renamed from Proxy Site Checker;
# ConfigManager.default_path renames it to CONFIG_FILE.
LEGACY_CONFIG_FILE = "proxy_sites_config.json"
ROUTER_SCRIPT_FILE = "apply_to_router.sh"
CRASHED_LOG_FILE = "crashed_nodes.txt"
SUB_CACHE_DIR = "sub_cache"

MIHOMO_PATH = os.path.join(
    PROJECT_ROOT,
    "mihomo" + (".exe" if os.name == "nt" else "")
)
IPREGION_SCRIPT_PATH = os.path.join(PROJECT_ROOT, "ipregion.sh")
SSH_ROUTER_SCRIPT_PATH = os.path.join(PROJECT_ROOT, "ssh_router.py")

# Environment detection
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")

# Default Application Configuration
DEFAULT_CONFIG: Dict[str, Any] = {
    "subscriptions": [],
    "workers": "auto",
    "tcp_workers": 128,
    "allowed_countries": [],
    "use_warp_scanner": False,
    "warp_private_key": "",
    "warp_ipv6": "",
    "speedtest_timeout": 45,
    "ip_mode": "off",
    "use_mux": True,
    "mem_per_worker": 8,
    "use_amnezia_wg": False,
    "amnezia_wg_conf": "US.conf",
    "enable_loc_ranking": False,
    "use_warp_chaining": False,
    "enable_router_validation": True,
    "router_host": "192.168.1.1",
    "router_api_port": 9090,
    "router_proxy_port": 7890,
    "router_ssh_port": 22,
    "router_ssh_user": "root",
    "router_ssh_pass": "",
}

# Test Mihomo YAML template (used during individual node testing)
CONFIG_YAML_TEMPLATE = """mixed-port: {PORT}
allow-lan: false
mode: rule
log-level: warning
ipv6: true
proxy-providers:
  test_sub:
    type: file
    path: {NODE_FILE}
    health-check:
      enable: false
proxy-groups:
  - name: "TESTGROUP"
    type: select
    use:
      - test_sub
rules:
  - MATCH,TESTGROUP
"""

# Router connection constants
# Connectivity probe for router-side delay checks and Mihomo health checks.
GOOGLE_HEALTHCHECK_URL = "https://www.gstatic.com/generate_204"

# Exit countries the Mihomo-target IP check always rejects. Steer routing uses
# routing.main.excluded_countries instead.
GEOBLOCKED_REGIONS: Set[str] = {
    "RU",
    "BY",
    "CN",
    "IR",
    "KP",
    "SY",
    "CU",
}

# Router deployment Mihomo YAML template. The Gemini_* provider/group names are
# kept so routers deployed by earlier versions can be reloaded and probed.
ROUTER_CONFIG_TEMPLATE = (
    """mode: rule
ipv6: true
prefer-ipv6: false
mixed-port: 7890
log-level: error
allow-lan: true
unified-delay: true
tcp-concurrent: false
find-process-mode: off
external-controller: 0.0.0.0:9090
external-ui: ./ui
routing-mark: 2
profile:
  store-selected: true
  store-fake-ip: true
  tracing: true

dns:
  enable: true
  ipv6: true
  prefer-ipv6: false
  listen: 127.0.0.1:1053
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
  nameserver:
    - 8.8.8.8
    - 1.1.1.1

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  sniff:
    HTTP:
      ports: [80]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - Mijia Cloud
    - +.lan
    - +.local
    - +.msftconnecttest.com
    - +.msftncsi.com
    - +.3gppnetwork.org
    - +.openwrt.org
    - +.vsean.net
    - cudy.net

hosts:
  ntc.party: 130.255.77.28

{proxies_section}

proxy-providers:
  Gemini_Nodes:
    type: file
    path: ./proxy-providers/sub.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 30
      timeout: 3000
      max-failed-times: 2
      lazy: false
      expected-status: "204"

proxy-groups:
  - name: "Gemini_Auto"
    type: fallback
    icon: https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.3/"""
    """assets/svg/1f310.svg{awg_group_entry}
    use:
      - "Gemini_Nodes"
    url: https://www.gstatic.com/generate_204
    interval: 30
    timeout: 3000
    max-failed-times: 2
    lazy: false
    expected-status: "204"

rules:
  - MATCH,Gemini_Auto
"""
)
