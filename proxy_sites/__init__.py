"""Proxy Site Checker - High performance VPN subscription tester and router deployment toolkit."""

from proxy_sites.config import ConfigManager
from proxy_sites.constants import DEFAULT_CONFIG
from proxy_sites.core.fetcher import NodeFetcher
from proxy_sites.core.limits import ResourceLimits
from proxy_sites.core.mihomo import MihomoManager, MihomoRunner
from proxy_sites.core.tester import NodeTester
from proxy_sites.geo import GeolocationService
from proxy_sites.logging import (
    ErrorTracker,
    get_free_memory_mb,
    log,
    safe_close_writer,
    safe_print,
    update_progress,
)
from proxy_sites.parsers import (
    extract_host_port,
    extract_node_protocol,
    format_descriptive_node_name,
    generate_awg_proxy_yaml,
    get_flag_emoji,
    get_node_name,
    node_url_to_mihomo_dict,
    parse_amnezia_conf,
)
from proxy_sites.router import (
    build_router_config_yaml,
    generate_router_script,
    push_to_router,
)
from proxy_sites.ui import VPNDashboard, main, manage_subscriptions, settings_menu
from proxy_sites.warp import WarpScanner

__version__ = "2.0.0"

__all__ = [
    "DEFAULT_CONFIG",
    "ConfigManager",
    "ErrorTracker",
    "GeolocationService",
    "MihomoManager",
    "MihomoRunner",
    "NodeFetcher",
    "NodeTester",
    "ResourceLimits",
    "VPNDashboard",
    "WarpScanner",
    "build_router_config_yaml",
    "extract_host_port",
    "extract_node_protocol",
    "format_descriptive_node_name",
    "generate_awg_proxy_yaml",
    "generate_router_script",
    "get_flag_emoji",
    "get_free_memory_mb",
    "get_node_name",
    "log",
    "main",
    "manage_subscriptions",
    "node_url_to_mihomo_dict",
    "parse_amnezia_conf",
    "push_to_router",
    "safe_close_writer",
    "safe_print",
    "settings_menu",
    "update_progress",
]
