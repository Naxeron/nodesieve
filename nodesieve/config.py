"""Configuration loading, normalization, and persistence."""

import copy
import json
import math
import os
import re
from typing import Any, Dict, Union

from nodesieve.constants import CONFIG_FILE, DEFAULT_CONFIG
from nodesieve.logging import log

_FEED_FORMATS = ("links", "base64")


def _coerce_num(config: Dict[str, Any], key: str, cast, lo=None, hi=None) -> None:
    raw = config.get(key)
    try:
        if isinstance(raw, bool):
            raise ValueError
        val = cast(raw)
        if not math.isfinite(val) or (lo is not None and val < lo) or (hi is not None and val > hi):
            raise ValueError
        config[key] = val
    except (TypeError, ValueError, OverflowError):
        config[key] = cast(DEFAULT_CONFIG[key])


class ConfigManager:
    """Manages loading, validating, and persisting user settings."""

    @classmethod
    def default_path(cls, project_root: Union[str, os.PathLike]) -> str:
        return os.path.join(project_root, CONFIG_FILE)

    @classmethod
    def load(cls, path: str = CONFIG_FILE, strict: bool = False) -> Dict[str, Any]:
        """Load settings from disk, applying defaults. Raises ValueError on bad files when strict=True."""
        config = copy.deepcopy(DEFAULT_CONFIG)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.loads(re.sub(r",\s*([\]}])", r"\1", f.read()))
                if isinstance(loaded, dict):
                    config.update(loaded)
                elif strict:
                    raise ValueError("it does not hold a JSON object")
            except Exception as e:
                if strict:
                    raise ValueError(f"cannot read '{path}': {e}") from e
                log.warning(f"[!] Warning: Failed to parse configuration file '{path}': {e}. Using default values.")
        cls._normalize_config(config)
        return config

    @classmethod
    def _normalize_config(cls, config: Dict[str, Any]) -> None:
        from nodesieve.routing import normalize_routing

        config["routing"] = normalize_routing(config.get("routing"))
        if not isinstance(config.get("subscriptions"), list):
            config["subscriptions"] = []
        allowed = config.get("allowed_countries", [])
        config["allowed_countries"] = (
            [str(c).strip().upper() for c in allowed if str(c).strip()] if isinstance(allowed, list) else []
        )
        _coerce_num(config, "speedtest_timeout", int)
        _coerce_num(config, "min_speed_percent", float, 0, 100)
        _coerce_num(config, "tcp_workers", int)
        _coerce_num(config, "mem_per_worker", float)
        for field in ("feed_dir", "feed_command"):
            val = config.get(field)
            config[field] = val.strip() if isinstance(val, str) else ""
        fmts = config.get("feed_formats")
        cleaned = (
            list(dict.fromkeys(f.strip().lower() for f in fmts if isinstance(f, str) and f.strip().lower() in _FEED_FORMATS))
            if isinstance(fmts, list)
            else []
        )
        config["feed_formats"] = cleaned or list(_FEED_FORMATS)

    @classmethod
    def save(cls, config: Dict[str, Any], path: str = CONFIG_FILE) -> None:
        cls._normalize_config(config)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
