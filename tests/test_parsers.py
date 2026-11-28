"""Unit tests for shared URI parsing, protocol detection, and descriptive node naming."""

import pytest

from nodesieve.parsers.base import (
    extract_host_port,
    extract_node_protocol,
    format_descriptive_node_name,
    get_flag_emoji,
)


def test_flag_emoji_and_protocol_detection():
    assert (get_flag_emoji("US"), get_flag_emoji("de"), get_flag_emoji(""), get_flag_emoji("USA")) == ("🇺🇸", "🇩🇪", "", "")
    assert extract_node_protocol("vless://user@host:443#tag") == "VLESS"
    assert extract_node_protocol("trojan://pass@host:443#tag") == "TROJAN"
    assert extract_node_protocol("ss://pass@host:443#tag") == "SS"
    assert extract_node_protocol("shadowsocks://pass@host:443#tag") == "SS"
    assert extract_node_protocol("hy2://pass@host:443#tag") == "HYSTERIA2"


@pytest.mark.parametrize("uri,expected", [
    ("vless://11111111-1111-4111-8111-111111111111@198.51.100.95:443?security=none#tag", ("198.51.100.95", 443)),
    ("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#tag", ("1.2.3.4", 8388)),
    ("ss://YWVzLTEyOC1nY206cHdAcy5leGFtcGxlOjgzODg#S", ("s.example", 8388)),
    ("vless://uuid@[2606:4700:4700::1111]:443?security=tls#Tag", ("2606:4700:4700::1111", 443)),
])
def test_extract_host_port(uri, expected):
    assert extract_host_port(uri) == expected


def test_format_descriptive_node_name_and_idempotency():
    name = format_descriptive_node_name("vless://test@1.2.3.4:443#OriginalTag", "US", "United States", "1.2.3.4", 15.5)
    assert name == "[VLESS: OriginalTag] 🇺🇸 United-States | ⚡ 15.5 MB/s | 1.2.3.4"

    unknown = format_descriptive_node_name("trojan://pass@192.0.2.9:443#Tag", None, None, "")
    assert unknown == "[TROJAN: Tag] 🌐 Unknown"

    # Re-formatting preserves inner tag without nesting protocol brackets.
    renamed = f"vless://test@1.2.3.4:443#{name}"
    name2 = format_descriptive_node_name(renamed, "US", "United States", "1.2.3.4", 20.0)
    assert name2.startswith("[VLESS: OriginalTag]") and "⚡ 20.0 MB/s" in name2 and "[VLESS: [VLESS:" not in name2

    # Extracts inner protocol tag behind speed prefix and strips trailing duplicate country/flags.
    for raw in (
        "vless://u@127.0.0.1:443#[⚡ 15.2 MB/s] [VLESS: MyServer] 🇺🇸 United-States | 1.2.3.4",
        "vless://u@127.0.0.1:443#MyServer 🇺🇸 United-States | 1.2.3.4",
    ):
        res = format_descriptive_node_name(raw, "US", "United States", "1.2.3.4")
        assert res.startswith("[VLESS: MyServer]") and "United-States] 🇺🇸 United-States" not in res
