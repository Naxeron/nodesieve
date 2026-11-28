"""Configuration management and persistence for nodesieve."""

import json
import copy
import os
import re
from typing import Any, Dict, Union
from nodesieve.constants import CONFIG_FILE, CORES, DEFAULT_CONFIG
from nodesieve.logging import log


class ConfigManager:
    """Manages loading, validating, and persisting user settings."""

    @classmethod
    def default_path(cls, project_root: Union[str, os.PathLike]) -> str:
        """The settings file in the project directory."""
        return os.path.join(project_root, CONFIG_FILE)

    @classmethod
    def load(cls, path: str = CONFIG_FILE, strict: bool = False) -> Dict[str, Any]:
        """Loads configuration from disk, filling in defaults and fixing malformed values.

        A file that can't be read is replaced by the defaults, with a warning. With
        strict, it raises ValueError instead: before saving, so that the defaults
        don't overwrite the file.
        """
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
                elif strict:
                    raise ValueError("it does not hold a JSON object")
            except Exception as e:
                if strict:
                    raise ValueError(f"cannot read '{path}': {e}") from e
                log.warning(
                    f"[!] Warning: Failed to parse configuration file '{path}': {e}. "
                    "Using default values."
                )

        cls._normalize_config(config)
        return config

    @classmethod
    def _normalize_config(cls, config: Dict[str, Any]) -> None:
        """Drop retired settings and replace malformed values with their defaults."""
        from nodesieve.routing import normalize_routing

        # Older settings files may hold credentials for a remote router or retired WARP/AWG options.
        for key in (
            "router_host", "router_ssh_port", "router_ssh_user", "router_ssh_pass", "router_ssh_key_path",
            "router_api_port", "router_proxy_port", "enable_router_validation",
            "use_warp_scanner", "warp_private_key", "warp_ipv6",
            "use_amnezia_wg", "amnezia_wg_conf", "use_warp_chaining",
        ):
            config.pop(key, None)
        config["routing"] = normalize_routing(config.get("routing"))

        core = config.get("core")
        core = core.strip().lower() if isinstance(core, str) else ""
        config["core"] = core if core in CORES else DEFAULT_CONFIG["core"]

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

        speed_percent = config.get("min_speed_percent")
        try:
            percent = float(speed_percent)
            if isinstance(speed_percent, bool) or not 0 <= percent <= 100:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            percent = DEFAULT_CONFIG["min_speed_percent"]
        config["min_speed_percent"] = percent

        try:
            config["tcp_workers"] = int(config.get("tcp_workers", 128))
        except (ValueError, TypeError):
            config["tcp_workers"] = 128

        try:
            config["mem_per_worker"] = float(config.get("mem_per_worker", 8))
        except (ValueError, TypeError):
            config["mem_per_worker"] = 8.0

        # Subscription feed
        try:
            port = int(config.get("feed_port", DEFAULT_CONFIG["feed_port"]))
            config["feed_port"] = port if 1 <= port <= 65535 else DEFAULT_CONFIG["feed_port"]
        except (ValueError, TypeError):
            config["feed_port"] = DEFAULT_CONFIG["feed_port"]
        for text_field in ("feed_dir", "feed_token", "feed_command"):
            value = config.get(text_field)
            config[text_field] = value.strip() if isinstance(value, str) else ""
        formats = config.get("feed_formats")
        if isinstance(formats, list):
            cleaned_formats = list(dict.fromkeys(
                str(fmt).strip().lower() for fmt in formats
                if isinstance(fmt, str) and fmt.strip().lower() in ("links", "base64", "clash")
            ))
            config["feed_formats"] = cleaned_formats or list(DEFAULT_CONFIG["feed_formats"])
        else:
            config["feed_formats"] = list(DEFAULT_CONFIG["feed_formats"])
        host = config.get("feed_host")
        config["feed_host"] = host.strip() if isinstance(host, str) and host.strip() else DEFAULT_CONFIG["feed_host"]
        try:
            hours = int(config.get("feed_update_hours", DEFAULT_CONFIG["feed_update_hours"]))
            config["feed_update_hours"] = hours if hours >= 1 else DEFAULT_CONFIG["feed_update_hours"]
        except (ValueError, TypeError):
            config["feed_update_hours"] = DEFAULT_CONFIG["feed_update_hours"]

    @classmethod
    def save(cls, config: Dict[str, Any], path: str = CONFIG_FILE) -> None:
        """Saves current configuration to disk as formatted JSON."""
        cls._normalize_config(config)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
