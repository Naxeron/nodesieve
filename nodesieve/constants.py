"""Constants, default configuration and file paths."""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = "nodesieve_config.json"
CRASHED_LOG_FILE = "crashed_nodes.txt"
SUB_CACHE_DIR = "sub_cache"

# The cores nodes are checked through, each downloaded on first use.
XRAY_PATH = os.path.join(PROJECT_ROOT, "xray" + (".exe" if os.name == "nt" else ""))
MIHOMO_PATH = os.path.join(PROJECT_ROOT, "mihomo" + (".exe" if os.name == "nt" else ""))
CORES = ("xray", "mihomo")

# Environment detection
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")
# Python built for Android, such as Termux's: sys.platform is "android" from Python 3.13,
# and only Android builds have sys.getandroidapilevel. A Linux distribution running in
# proot on Android is not Android here: it has an /etc/resolv.conf of its own.
IS_ANDROID = sys.platform == "android" or hasattr(sys, "getandroidapilevel")

# Default Application Configuration
DEFAULT_CONFIG: Dict[str, Any] = {
    "subscriptions": [],
    # The core nodes are checked through: "xray", which the share links are written for, or
    # "mihomo", which the feed's Clash profile is for.
    "core": "xray",
    "workers": "auto",
    "tcp_workers": 128,
    "allowed_countries": [],
    "speedtest_timeout": 45,
    "ip_mode": "off",
    "use_mux": True,
    "mem_per_worker": 8,
    "enable_loc_ranking": False,
    # How install-router reaches the router over SSH.
    "router_host": "192.168.1.1",
    "router_ssh_port": 22,
    "router_ssh_user": "root",
    "router_ssh_pass": "",
    # Subscription feed (nodesieve/feed.py): its directory, empty for feed/ in the project
    # directory, and the server `serve` runs. feed_token, the secret part of the feed's
    # address, is created by the first `serve`.
    "feed_dir": "",
    "feed_host": "127.0.0.1",
    "feed_port": 9876,
    "feed_token": "",
    "feed_update_hours": 6,
    # A shell command run after each scan that updates the feed, except with --dry-run:
    # on a router, for example, one that asks the VPN app to fetch its subscription now.
    "feed_command": "",
}

# The local core instances that check nodes get their configuration from
# nodesieve.core.xray.render_xray_config or nodesieve.core.mihomo.render_batch_config.

# Connectivity probe of the feed's Clash profile.
GOOGLE_HEALTHCHECK_URL = "https://www.gstatic.com/generate_204"

# Exit countries a speed-ranked (mihomo target) scan always rejects. Steer routing uses
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
