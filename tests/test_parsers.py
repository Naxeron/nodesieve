"""Unit tests for URL parsers, protocol detectors, and naming formatters."""

import unittest
from proxy_sites.parsers.base import (
    extract_host_port,
    extract_node_protocol,
    format_descriptive_node_name,
    get_flag_emoji,
)
from proxy_sites.parsers.mihomo import node_url_to_mihomo_dict


class TestParsers(unittest.TestCase):
    def test_get_flag_emoji(self):
        self.assertEqual(get_flag_emoji("US"), "🇺🇸")
        self.assertEqual(get_flag_emoji("de"), "🇩🇪")
        self.assertEqual(get_flag_emoji(""), "")
        self.assertEqual(get_flag_emoji("USA"), "")

    def test_extract_node_protocol(self):
        self.assertEqual(extract_node_protocol("vless://user@host:443#tag"), "VLESS")
        self.assertEqual(extract_node_protocol("trojan://pass@host:443#tag"), "TROJAN")
        self.assertEqual(extract_node_protocol("ss://pass@host:443#tag"), "SS")
        self.assertEqual(extract_node_protocol("shadowsocks://pass@host:443#tag"), "SS")
        self.assertEqual(extract_node_protocol("warp://1.1.1.1:2408#tag"), "WARP")
        self.assertEqual(extract_node_protocol("awg_conf:US.conf#tag"), "AWG")

    def test_extract_host_port_vless(self):
        node = "vless://11111111-1111-4111-8111-111111111111@198.51.100.95:443?path=%2F&security=none#tag"
        host, port = extract_host_port(node)
        self.assertEqual(host, "198.51.100.95")
        self.assertEqual(port, 443)

    def test_extract_host_port_warp(self):
        node = "warp://162.159.192.1:2408#WARP"
        host, port = extract_host_port(node)
        self.assertEqual(host, "162.159.192.1")
        self.assertEqual(port, 2408)

    def test_extract_host_port_ss_b64(self):
        # ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#tag
        node = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#tag"
        host, port = extract_host_port(node)
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8388)

    def test_node_url_to_mihomo_dict_vless_reality(self):
        url = "vless://22222222-2222-4222-8222-222222222222@203.0.113.43:52463?security=reality&encryption=none&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&headerType=none&fp=random&spx=%2F&type=tcp&sni=example.com&sid=0123456789ab#Latvia_Server"
        d = node_url_to_mihomo_dict(url, use_mux=True)
        self.assertIsNotNone(d)
        self.assertEqual(d["type"], "vless")
        self.assertEqual(d["server"], "203.0.113.43")
        self.assertEqual(d["port"], 52463)
        self.assertEqual(d["uuid"], "22222222-2222-4222-8222-222222222222")
        self.assertTrue(d["tls"])
        self.assertEqual(d["servername"], "example.com")
        self.assertEqual(d["client-fingerprint"], "random")
        self.assertEqual(d["reality-opts"]["public-key"], "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        self.assertEqual(d["reality-opts"]["short-id"], "0123456789ab")
        self.assertEqual(d["reality-opts"]["spider-x"], "/")
        self.assertTrue(d["smux"]["enabled"])

    def test_node_url_to_mihomo_dict_trojan_ws(self):
        url = "trojan://test-password@198.51.100.83:443?path=/ws-path&security=tls&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=www.example.com#Trojan_France"
        d = node_url_to_mihomo_dict(url, use_mux=False)
        self.assertIsNotNone(d)
        self.assertEqual(d["type"], "trojan")
        self.assertEqual(d["server"], "198.51.100.83")
        self.assertEqual(d["port"], 443)
        self.assertEqual(d["password"], "test-password")
        self.assertTrue(d["tls"])
        self.assertEqual(d["sni"], "www.example.com")
        self.assertEqual(d["network"], "ws")
        self.assertEqual(d["ws-opts"]["path"], "/ws-path")
        self.assertNotIn("smux", d)

    def test_format_descriptive_node_name(self):
        name = format_descriptive_node_name(
            node="vless://test@1.2.3.4:443#OriginalTag",
            country_code="US",
            country_name="United States",
            ip_str="1.2.3.4",
            speed_mbps=15.5,
        )
        self.assertEqual(name, "[VLESS: OriginalTag] \U0001F1FA\U0001F1F8 United-States | ⚡ 15.5 MB/s | 1.2.3.4")

    def test_format_descriptive_node_name_location_score_and_unknown_country(self):
        name = format_descriptive_node_name(
            node="trojan://secret@example.org:443#Tag",
            country_code="DE",
            country_name="Germany",
            ip_str="192.0.2.1 | 2001:db8::1",
            loc_score=0.846,
        )
        self.assertEqual(name, "[TROJAN: Tag] \U0001F1E9\U0001F1EA Germany | LOC: 85% | 192.0.2.1 | 2001:db8::1")
        unknown = format_descriptive_node_name(
            node="awg_conf:US.conf#AWG_US", country_code=None, country_name=None, ip_str="",
        )
        self.assertEqual(unknown, "[AWG: US.conf] \U0001F310 Unknown")

    def test_extract_host_port_warp_ipv6(self):
        node = "warp://[2606:4700:4700::1111]:2408#WARP"
        host, port = extract_host_port(node)
        self.assertEqual(host, "2606:4700:4700::1111")
        self.assertEqual(port, 2408)

    def test_format_descriptive_node_name_preserves_inner_tag(self):
        # First round
        name1 = format_descriptive_node_name(
            node="vless://test@1.2.3.4:443#Latvia_Server",
            country_code="LV",
            country_name="Latvia",
            ip_str="203.0.113.43",
        )
        self.assertIn("[VLESS: Latvia_Server]", name1)

        # Re-formatting in second round / speedtest
        reformatted_node = f"vless://test@1.2.3.4:443#{name1}"
        name2 = format_descriptive_node_name(
            node=reformatted_node,
            country_code="LV",
            country_name="Latvia",
            ip_str="203.0.113.43",
            speed_mbps=20.0,
        )
        self.assertIn("[VLESS: Latvia_Server]", name2)
        self.assertIn("⚡ 20.0 MB/s", name2)

    def test_format_descriptive_node_name_warp_and_protocols_idempotency(self):
        """format_descriptive_node_name prevents nested protocol tags for WARP and other schemes."""
        warp_node = "warp://127.0.0.1:443#[WARP: Warp-US] \U0001F1FA\U0001F1F8 United-States | 1.1.1.1"
        formatted = format_descriptive_node_name(
            node=warp_node,
            country_code="US",
            country_name="United States",
            ip_str="1.1.1.1",
        )
        self.assertNotIn("[WARP: [WARP:", formatted)
        self.assertTrue(formatted.startswith("[WARP: Warp-US]"))

    def test_format_descriptive_node_name_speed_prefix_and_duplicate_country_cleaning(self):
        """Extracts the innermost protocol tag behind a speed tag and strips duplicate country names."""
        # Case 1: Node preceded by speed tag
        node1 = "vless://uuid@127.0.0.1:443#[⚡ 15.2 MB/s] [VLESS: MyServer] \U0001F1FA\U0001F1F8 United-States | 1.2.3.4"
        res1 = format_descriptive_node_name(
            node=node1,
            country_code="US",
            country_name="United States",
            ip_str="1.2.3.4",
            speed_mbps=15.2,
        )
        self.assertNotIn("[VLESS: [VLESS:", res1)
        self.assertTrue(res1.startswith("[VLESS: MyServer]"))

        # Case 2: Node with trailing flag and country name in original tag
        node2 = "vless://uuid@127.0.0.1:443#MyServer \U0001F1FA\U0001F1F8 United-States | 1.2.3.4"
        res2 = format_descriptive_node_name(
            node=node2,
            country_code="US",
            country_name="United States",
            ip_str="1.2.3.4",
        )
        self.assertNotIn("United-States] \U0001F1FA\U0001F1F8 United-States", res2)
        self.assertTrue(res2.startswith("[VLESS: MyServer]"))

    def test_extract_host_port_ipv6_vless(self):
        node = "vless://uuid@[2606:4700:4700::1111]:443?security=tls#Tag"
        host, port = extract_host_port(node)
        self.assertEqual(host, "2606:4700:4700::1111")
        self.assertEqual(port, 443)


if __name__ == "__main__":
    unittest.main()
