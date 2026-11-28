"""Constants, default configuration, and file paths."""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = "nodesieve_config.json"
CRASHED_LOG_FILE = "crashed_nodes.txt"
SUB_CACHE_DIR = "sub_cache"
XRAY_PATH = os.path.join(PROJECT_ROOT, "xray" + (".exe" if os.name == "nt" else ""))

IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")
IS_ANDROID = sys.platform == "android" or hasattr(sys, "getandroidapilevel")

DEFAULT_CONFIG: Dict[str, Any] = {
    "subscriptions": [],
    "workers": "auto",
    "tcp_workers": 128,
    "allowed_countries": [],
    "speedtest_timeout": 45,
    "min_speed_percent": 50,
    "mem_per_worker": 8,
    "feed_dir": "",
    "feed_formats": ["links", "base64"],
    "feed_command": "",
}

GEOBLOCKED_REGIONS: Set[str] = {"RU", "BY", "CN", "IR", "KP", "SY", "CU"}
