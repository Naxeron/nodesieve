"""Unit tests for configuration manager and serialization."""

import os
from pathlib import Path
import pytest

from nodesieve.config import ConfigManager
from nodesieve.constants import CONFIG_FILE, DEFAULT_CONFIG


def test_load_default_and_round_trip(tmp_path):
    cfg = ConfigManager.load(str(tmp_path / "missing.json"))
    assert cfg["tcp_workers"] == DEFAULT_CONFIG["tcp_workers"]
    assert cfg["speedtest_timeout"] == DEFAULT_CONFIG["speedtest_timeout"]

    cfg_file = str(tmp_path / "config.json")
    ConfigManager.save({"subscriptions": ["https://example.com/sub.txt"], "tcp_workers": 256,
                        "allowed_countries": ["us", "de"]}, cfg_file)
    loaded = ConfigManager.load(cfg_file)
    assert loaded["subscriptions"] == ["https://example.com/sub.txt"]
    assert loaded["tcp_workers"] == 256
    assert loaded["allowed_countries"] == ["US", "DE"]


@pytest.mark.parametrize("raw,expected", [
    (["links"], ["links"]),
    (["LINKS", "base64", "links", "unknown"], ["links", "base64"]),
    ([], ["links", "base64"]),
    (["clash"], ["links", "base64"]),
    ("links", ["links", "base64"]),
])
def test_feed_formats_normalization(tmp_path, raw, expected):
    cfg_file = str(tmp_path / "config.json")
    ConfigManager.save({"feed_formats": raw}, cfg_file)
    assert ConfigManager.load(cfg_file)["feed_formats"] == expected


@pytest.mark.parametrize("value,expected", [
    ("62.5", 62.5), (0, 0), (100, 100), (-1, 50), (101, 50), ("nan", 50), ("invalid", 50), (True, 50), (None, 50),
])
def test_min_speed_percent_normalization(tmp_path, value, expected):
    cfg_file = str(tmp_path / "config.json")
    ConfigManager.save({"min_speed_percent": value}, cfg_file)
    assert ConfigManager.load(cfg_file)["min_speed_percent"] == expected


def test_trailing_commas_corrupted_json_and_strict_mode(tmp_path):
    trailing = tmp_path / "trailing.json"
    trailing.write_text('{\n  "subscriptions": [\n    "https://example.com/sub.txt",\n  ],\n  "workers": 64,\n}\n')
    loaded = ConfigManager.load(str(trailing))
    assert (loaded["subscriptions"], loaded["workers"]) == (["https://example.com/sub.txt"], 64)

    for text in ('NOT_VALID_JSON{{{', "[1, 2]"):
        bad = tmp_path / "bad.json"
        bad.write_text(text)
        with pytest.raises(ValueError):
            ConfigManager.load(str(bad), strict=True)
        assert ConfigManager.load(str(bad))["tcp_workers"] == DEFAULT_CONFIG["tcp_workers"]


def test_default_settings_path(tmp_path):
    assert ConfigManager.default_path(tmp_path) == os.path.join(tmp_path, CONFIG_FILE)
    assert list(Path(tmp_path).iterdir()) == []
