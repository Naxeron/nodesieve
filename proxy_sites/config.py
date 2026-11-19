"""Configuration management and persistence for Proxy Site Checker."""

import json
import copy
import os
import re
from typing import Any, Dict
from proxy_sites.constants import CONFIG_FILE, DEFAULT_CONFIG
from proxy_sites.logging import log


class ConfigManager:
    """Manages loading, validating, and persisting user settings."""

    @classmethod
    def load(cls, path: str = CONFIG_FILE) -> Dict[str, Any]:
        """Loads configuration from disk, applying defaults and normalizing legacy formats."""
        config = copy.deepcopy(DEFAULT_CONFIG)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                # Sanitize trailing commas before closing braces/brackets
                sanitized = re.sub(r",\s*([\]}])", r"\1", content)
                loaded = json.loads(sanitized)
                if isinstance(loaded, dict):
                    config.update(loaded)
            except Exception as e:
                log.warning(
                    f"[!] Warning: Failed to parse configuration file '{path}': {e}. "
                    "Using default values."
                )

        # Normalize legacy types/values
        cls._normalize_config(config)
        return config

    @classmethod
    def _normalize_config(cls, config: Dict[str, Any]) -> None:
        """Normalizes config entries for backwards-compatibility."""
        from proxy_sites.routing import normalize_routing
        config["routing"] = normalize_routing(config.get("routing"))
        # Convert legacy bool goida_mode to proper string
        goida_val = config.get("use_goida_proxies")
        if goida_val is True:
            config["use_goida_proxies"] = "all"
        elif goida_val is False:
            config["use_goida_proxies"] = "off"

        # Ensure subscriptions is a list
        if not isinstance(config.get("subscriptions"), list):
            config["subscriptions"] = DEFAULT_CONFIG["subscriptions"].copy()

        # Ensure allowed_countries is a list of uppercase strings
        allowed = config.get("allowed_countries", [])
        if isinstance(allowed, list):
            config["allowed_countries"] = [str(c).strip().upper() for c in allowed if str(c).strip()]
        else:
            config["allowed_countries"] = []

        # Ensure numeric fields have sane types
        try:
            config["speedtest_timeout"] = int(config.get("speedtest_timeout", 45))
        except (ValueError, TypeError):
            config["speedtest_timeout"] = 45

        try:
            config["tcp_workers"] = int(config.get("tcp_workers", 128))
        except (ValueError, TypeError):
            config["tcp_workers"] = 128

        try:
            config["mem_per_worker"] = float(config.get("mem_per_worker", 8))
        except (ValueError, TypeError):
            config["mem_per_worker"] = 8.0

        # Ensure router ports are valid integers in port range
        for port_field, default_port in [
            ("router_api_port", 9090),
            ("router_proxy_port", 7890),
            ("router_ssh_port", 22),
        ]:
            try:
                val = int(config.get(port_field, default_port))
                config[port_field] = val if 1 <= val <= 65535 else default_port
            except (ValueError, TypeError):
                config[port_field] = default_port

    @classmethod
    def save(cls, config: Dict[str, Any], path: str = CONFIG_FILE) -> None:
        """Saves current configuration to disk as formatted JSON."""
        cls._normalize_config(config)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
