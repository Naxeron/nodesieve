#!/usr/bin/env python3
"""Proxy Site Checker - Main CLI Entrypoint."""

import asyncio
from functools import wraps
import sys

# Silence Windows asyncio proactor event loop closed noise
if sys.platform == "win32":
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport

        def silence_event_loop_closed(func):
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                try:
                    return func(self, *args, **kwargs)
                except RuntimeError as e:
                    if str(e) != "Event loop is closed":
                        raise
            return wrapper

        _ProactorBasePipeTransport.__del__ = silence_event_loop_closed(_ProactorBasePipeTransport.__del__)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# Import core application components from modular package
from proxy_sites import (
    DEFAULT_CONFIG,
    ConfigManager,
    ErrorTracker,
    GeolocationService,
    MihomoManager,
    MihomoRunner,
    NodeFetcher,
    NodeTester,
    ResourceLimits,
    VPNDashboard,
    WarpScanner,
    build_router_config_yaml,
    extract_host_port,
    extract_node_protocol,
    format_descriptive_node_name,
    generate_awg_proxy_yaml,
    generate_router_script,
    get_flag_emoji,
    get_node_name,
    main,
    manage_subscriptions,
    node_url_to_mihomo_dict,
    parse_amnezia_conf,
    push_to_router,
    safe_print,
    settings_menu,
    update_progress,
)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
