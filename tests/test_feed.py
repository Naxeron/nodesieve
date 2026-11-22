"""Subscription feed: what a scan publishes for VPN apps, and the server that hands it out."""

import asyncio
import base64
import errno
import json
import os
from pathlib import Path
import re
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import TestClient, TestServer
import pytest
import yaml

from nodesieve.config import ConfigManager
from nodesieve.constants import MIHOMO_PATH
import nodesieve.feed as feed_module
from nodesieve.feed import (
    BASE64_NAME,
    CLASH_NAME,
    LINKS_NAME,
    build_app,
    clash_profile,
    feed_directory,
    feed_status,
    run_feed_command,
    write_feed,
)
from nodesieve.routing import normalize_routing
import nodesieve.ui.cli as cli_module
from nodesieve.ui.dashboard import VPNDashboard

# A node as a Mihomo-target scan leaves it: renamed after what was measured, and marked
# smux=0 because its server did not answer through multiplexing.
VLESS = ("vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&sni=example.org&type=ws"
         "&path=%2Fws&smux=0#%5BVLESS%3A%20First%5D%20%F0%9F%87%A9%F0%9F%87%AA%20Germany%20%7C%20203.0.113.1")
VLESS_SHARED = VLESS.replace("&smux=0", "")
VLESS_NAME = "[VLESS: First] 🇩🇪 Germany | 203.0.113.1"
# One whose server answered through multiplexing, so it keeps it.
TROJAN = "trojan://private-password@192.0.2.2:443?security=tls&sni=example.org#Second"
SS = "ss://YWVzLTI1Ni1nY206c2VjcmV0@192.0.2.3:8388#Third"
# VMess stays out of the feed.
VMESS = "vmess://eyJhZGQiOiIxOTIuMC4yLjUifQ==#vmess"
HYSTERIA = "hysteria2://secret@192.0.2.8:443#hysteria"
TOKEN = "t" * 24
FILES = (LINKS_NAME, BASE64_NAME, CLASH_NAME)


def feed_config(tmp_path, **settings):
    return {"feed_dir": str(tmp_path / "feed"), **settings}


def read(tmp_path, name):
    return (tmp_path / "feed" / name).read_text(encoding="utf-8")


# The files a scan writes

def test_scan_results_become_share_links_base64_and_a_clash_profile(tmp_path):
    result = write_feed([VLESS, VMESS, TROJAN, HYSTERIA, HYSTERIA.replace("hysteria2://", "hy2://")], feed_config(tmp_path))
    directory = tmp_path / "feed"
    assert result == {"written": True, "count": 3, "left_out": 1, "directory": str(directory)}
    links = read(tmp_path, LINKS_NAME)
    # In the scan's order, one per line. smux is nodesieve's own marker: no other app reads it.
    assert links == VLESS_SHARED + "\n" + TROJAN + "\n" + HYSTERIA + "\n"
    assert base64.b64decode(read(tmp_path, BASE64_NAME)).decode() == links
    profile = yaml.safe_load(read(tmp_path, CLASH_NAME))
    names = [VLESS_NAME, "Second", "hysteria"]
    assert [proxy["name"] for proxy in profile["proxies"]] == names
    assert profile["proxy-groups"] == [
        {"name": "nodesieve", "type": "select", "proxies": ["Auto", *names]},
        {"name": "Auto", "type": "fallback", "proxies": names, "url": "https://www.gstatic.com/generate_204",
         "expected-status": "204", "interval": 300},
    ]
    assert profile["rules"] == ["MATCH,nodesieve"]
    # Multiplexing stays as the scan found it: off where the server did not answer through it.
    assert "smux" not in profile["proxies"][0]
    assert profile["proxies"][1]["smux"]["enabled"] is True
    assert profile["proxies"][2] == {"type": "hysteria2", "name": "hysteria", "server": "192.0.2.8",
                                     "port": 443, "password": "secret", "udp": True}
    # The files hold proxy credentials.
    assert directory.stat().st_mode & 0o777 == 0o700
    for name in FILES:
        assert (directory / name).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("settings", [{"routing": normalize_routing({"enabled": True})}, {"use_mux": False}])
def test_profile_turns_multiplexing_on_only_where_the_scan_checked_it(tmp_path, settings):
    # Steer scans don't check multiplexing, so their links carry no smux marker either way.
    write_feed([TROJAN, SS], feed_config(tmp_path, **settings))
    proxies = yaml.safe_load(read(tmp_path, CLASH_NAME))["proxies"]
    assert [proxy["type"] for proxy in proxies] == ["trojan", "ss"]
    assert not any("smux" in proxy for proxy in proxies)


@pytest.mark.parametrize("nodes", [[], [VMESS, "hy2://user@:443"], ["vless://unreadable"]])
def test_scan_without_share_links_leaves_the_feed_as_it_was(tmp_path, nodes):
    config = feed_config(tmp_path)
    write_feed([VLESS, TROJAN], config)
    before = {name: (tmp_path / "feed" / name).read_bytes() for name in FILES}
    result = write_feed(nodes, config)
    assert not result["written"] and result["count"] == 0
    assert {name: (tmp_path / "feed" / name).read_bytes() for name in FILES} == before
    assert feed_status(config)["count"] == 2


def test_feed_in_a_directory_others_may_enter_is_readable_for_a_web_server(tmp_path):
    # uhttpd serves only files anyone may read; the router's installer opens the feed's
    # directory for that (711: enter, not list).
    (tmp_path / "feed").mkdir(mode=0o711)
    (tmp_path / "feed").chmod(0o711)
    write_feed([TROJAN], feed_config(tmp_path))
    assert {(tmp_path / "feed" / name).stat().st_mode & 0o777 for name in FILES} == {0o644}


def test_first_scan_without_share_links_writes_nothing(tmp_path):
    config = feed_config(tmp_path)
    assert not write_feed([VMESS], config)["written"]
    assert not (tmp_path / "feed").exists()
    assert feed_status(config) is None


def test_links_that_could_break_the_feed_are_left_out(tmp_path):
    nodes = [
        TROJAN.replace("#Second", "#Second\nvless://injected@192.0.2.9:443#line"),
        "trojan://two words@192.0.2.4:443#Space",
        "vmess://eyJhZGQiOiIxOTIuMC4yLjUifQ==",
        "vless://unreadable",
        42,
        None,
        TROJAN,
        TROJAN.replace("#Second", "#The same server again"),
    ]
    result = write_feed(nodes, feed_config(tmp_path))
    assert (result["count"], result["left_out"]) == (1, 6)
    assert read(tmp_path, LINKS_NAME) == TROJAN + "\n"


def test_profile_names_are_unique_and_never_a_reserved_name():
    proxies = [{"name": name, "type": "trojan", "server": f"192.0.2.{number}", "port": 443, "password": "x"}
               for number, name in enumerate(["Node", "Node", "Auto", "DIRECT", "Node (2)", ""], 1)]
    profile = yaml.safe_load(clash_profile(proxies))
    assert [proxy["name"] for proxy in profile["proxies"]] == [
        "Node", "Node (2)", "Auto (2)", "DIRECT (2)", "Node (2) (2)", "trojan_192.0.2.6_443"]
    assert proxies[1]["name"] == "Node"


def test_profile_passes_mihomo_check(tmp_path):
    if not (os.path.isfile(MIHOMO_PATH) and os.access(MIHOMO_PATH, os.X_OK)):
        pytest.skip(f"Mihomo binary not executable at {MIHOMO_PATH}")
    write_feed([VLESS, TROJAN, SS, HYSTERIA], feed_config(tmp_path))
    check = subprocess.run([MIHOMO_PATH, "-t", "-d", str(tmp_path), "-f", str(tmp_path / "feed" / CLASH_NAME)],
                           capture_output=True, text=True, timeout=60)
    assert check.returncode == 0, check.stdout + check.stderr


def test_feed_is_in_the_project_directory_unless_set_elsewhere(tmp_path):
    project = Path(feed_module.PROJECT_ROOT)  # an empty temporary directory, see conftest.py
    assert feed_directory({}) == (project / "feed").resolve()
    assert feed_directory({"feed_dir": "elsewhere/feed"}) == (project / "elsewhere" / "feed").resolve()
    assert feed_directory({"feed_dir": str(tmp_path)}) == tmp_path.resolve()


def test_feed_settings_fall_back_to_their_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"feed_port": 70000, "feed_update_hours": 0, "feed_host": "  ",
                                "feed_token": " abc ", "feed_dir": 5}))
    config = ConfigManager.load(str(path))
    assert [config[key] for key in ("feed_port", "feed_update_hours", "feed_host", "feed_token", "feed_dir")] == [
        9876, 6, "127.0.0.1", "abc", ""]


def test_strict_load_refuses_settings_it_cannot_read(tmp_path):
    path = tmp_path / "settings.json"
    for text in ('{"subscriptions": ["https://example.org/sub"]', "[1, 2]"):
        path.write_text(text)
        with pytest.raises(ValueError):
            ConfigManager.load(str(path), strict=True)
        assert ConfigManager.load(str(path))["subscriptions"] == []


# The server

def request(config, path, method="GET"):
    async def send():
        async with TestClient(TestServer(build_app(config, TOKEN))) as client:
            response = await client.request(method, path)
            headers = {name.lower(): value for name, value in response.headers.items()}
            return response.status, await response.read(), headers
    return asyncio.run(send())


@pytest.mark.parametrize("name", FILES)
def test_server_serves_each_feed_file_with_subscription_headers(tmp_path, name):
    config = feed_config(tmp_path, feed_update_hours=3)
    write_feed([VLESS, TROJAN], config)
    status, body, headers = request(config, f"/{TOKEN}/{name}")
    assert status == 200
    assert body == (tmp_path / "feed" / name).read_bytes()
    assert headers["content-type"] == "text/plain; charset=utf-8"
    assert headers["cache-control"] == "no-store"
    assert headers["profile-update-interval"] == "3"
    assert headers["profile-title"] == "nodesieve"
    assert request(config, f"/{TOKEN}/{name}", "HEAD")[0] == 200


@pytest.mark.parametrize("path", [
    f"/{'x' * 24}/{LINKS_NAME}",
    f"/{TOKEN}/nodesieve_config.json",
    f"/{TOKEN}/..%2Fnodesieve_config.json",
    f"/{TOKEN}/",
    f"/{TOKEN}",
    "/",
])
def test_server_hides_everything_but_the_feed(tmp_path, path):
    config = feed_config(tmp_path)
    write_feed([TROJAN], config)
    (tmp_path / "feed" / "nodesieve_config.json").write_text("{}")
    (tmp_path / "nodesieve_config.json").write_text("{}")
    assert request(config, path)[0] == 404


def test_server_answers_503_until_a_scan_writes_the_feed(tmp_path):
    status, body, _ = request(feed_config(tmp_path), f"/{TOKEN}/{LINKS_NAME}")
    assert status == 503
    assert b"python -m nodesieve check" in body


def test_server_hands_out_each_new_scan_without_a_restart(tmp_path):
    config = feed_config(tmp_path)
    write_feed([VLESS], config)

    async def fetch_twice():
        async with TestClient(TestServer(build_app(config, TOKEN))) as client:
            first = await (await client.get(f"/{TOKEN}/{LINKS_NAME}")).text()
            write_feed([TROJAN], config)
            second = await (await client.get(f"/{TOKEN}/{LINKS_NAME}")).text()
            return first, second

    assert asyncio.run(fetch_twice()) == (VLESS_SHARED + "\n", TROJAN + "\n")


# Scans

@pytest.mark.parametrize("settings,expected", [
    ({}, [VLESS_SHARED, HYSTERIA, TROJAN]),
    ({"min_speed_percent": 0}, [VLESS_SHARED, HYSTERIA, TROJAN, SS]),
    ({"min_speed_percent": 100}, [VLESS_SHARED, HYSTERIA]),
])
def test_mihomo_check_publishes_nodes_meeting_the_speed_cutoff_fastest_first(tmp_path, settings, expected):
    dashboard = VPNDashboard(feed_config(tmp_path, **settings))
    verified = [(node, 5.0, node) for node in (SS, TROJAN, VLESS, HYSTERIA)]
    measured = [(VLESS, 2e6, 0.0), (HYSTERIA, 2e6, 0.0), (TROJAN, 1e6, 0.0), (SS, 999_999, 0.0)]
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(verified, None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=measured)):
        assert asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME).splitlines() == expected


def test_speed_cutoff_uses_the_fastest_measurement_before_limiting_the_location_ranked_feed(tmp_path):
    slow = [f"trojan://pass@slow{i}.example:443" for i in range(30)]
    fast = [f"trojan://pass@fast{i}.example:443" for i in range(30)]
    # The highest location score comes first. The fastest nodes are all below the first 30.
    measured = [(SS, 1_510_000, 1.0)] + [(node, 1_250_000, 1.0) for node in slow]
    measured.extend((node, 2_000_000, 0.9) for node in fast)
    verified = [(node, 5.0, node) for node, _, _ in measured]
    path = settings_file(tmp_path, **feed_config(tmp_path), allowed_countries=["DE"], min_speed_percent=0)
    with patch.object(VPNDashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(verified, None))), \
            patch.object(VPNDashboard, "run_speedtest_nodes_async", AsyncMock(return_value=measured)):
        cli_module.main(["check", "--config-file", str(path), "--min-speed-percent", "75.5"])
    assert read(tmp_path, LINKS_NAME).splitlines() == [SS, *fast[:29]]
    assert json.loads(path.read_text())["min_speed_percent"] == 0


def test_mihomo_check_uses_verified_nodes_when_every_speedtest_fails(tmp_path):
    dashboard = VPNDashboard(feed_config(tmp_path))
    verified = [(SS, 5.0, SS), (TROJAN, 9.0, TROJAN)]
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(verified, None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=[])):
        assert asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME).splitlines() == [SS, TROJAN]


def test_scan_without_survivors_keeps_the_feed_and_says_so(tmp_path, caplog):
    config = feed_config(tmp_path)
    write_feed([VLESS, TROJAN], config)
    before = read(tmp_path, LINKS_NAME)
    dashboard = VPNDashboard(config)
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([], None))):
        assert not asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME) == before
    assert "keeps the 2 nodes of the scan from" in caplog.text


def location():
    summary = {"country": "DE", "score": 1.0, "votes": 3, "total": 3, "counts": {"DE": 3}}
    return {**summary, "source": "geoip", "status": "ok", "tested_families": ["ipv4"],
            "families": {"ipv4": {**summary, "counts": {"DE": 3}}}}


def test_steer_check_publishes_the_ranked_main_pool(tmp_path):
    slow = "vless://12345678-1234-1234-1234-123456789012@slow.example:443?security=tls#slow"
    fast = "trojan://password@fast.example:443?security=tls#fast"
    metadata = {slow: {"location": location(), "latency_ms": 7}, fast: {"location": location(), "latency_ms": 5}}
    config = {**feed_config(tmp_path), "routing": normalize_routing({"enabled": True}),
              "routing_output_dir": str(tmp_path / "steer"), "router_host": "192.0.2.1"}
    dashboard = VPNDashboard(config)
    scan = AsyncMock(return_value=([(slow, 7, slow), (fast, 5, fast)], MagicMock(node_metadata=metadata)))
    with patch.object(dashboard, "fetch_and_verify_candidates_async", scan):
        assert asyncio.run(dashboard.run_pipeline_async())
    assert read(tmp_path, LINKS_NAME) == fast + "\n" + slow + "\n"
    assert json.loads((tmp_path / "steer" / "routing-report.json").read_text())["ready"]


def test_feed_command_reports_how_it_went(caplog):
    assert run_feed_command({}) is None
    assert run_feed_command({"feed_command": "true"}) is True
    assert run_feed_command({"feed_command": "echo first >&2; echo boom >&2; exit 3"}) is False
    assert "feed_command failed with exit code 3: boom" in caplog.text
    assert run_feed_command({"feed_command": "sleep 5"}, timeout=0.2) is False
    assert "did not finish within 0 seconds" in caplog.text


@pytest.mark.parametrize("dry_run,survivors,runs", [(False, True, 1), (True, True, 0), (False, False, 0)])
def test_feed_command_follows_each_scan_that_updates_the_feed(tmp_path, dry_run, survivors, runs):
    marker = tmp_path / "ran"
    config = {**feed_config(tmp_path), "feed_command": f"echo ran >> '{marker}'"}
    write_feed([VLESS], config)
    marker.unlink(missing_ok=True)
    dashboard = VPNDashboard(config)
    verified = [(TROJAN, 9.0, TROJAN)] if survivors else []
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=(verified, None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=[(TROJAN, 1e6, 0.0)])):
        asyncio.run(dashboard.run_pipeline_async(dry_run=dry_run))
    assert (marker.read_text().count("ran") if marker.exists() else 0) == runs


def test_check_fails_when_the_feed_cannot_be_written(tmp_path, caplog):
    dashboard = VPNDashboard({**feed_config(tmp_path)})
    with patch.object(dashboard, "fetch_and_verify_candidates_async", AsyncMock(return_value=([(TROJAN, 9.0, TROJAN)], None))), \
            patch.object(dashboard, "run_speedtest_nodes_async", AsyncMock(return_value=[(TROJAN, 1e6, 0.0)])), \
            patch("nodesieve.ui.dashboard.write_feed", side_effect=PermissionError("read-only")):
        assert not asyncio.run(dashboard.run_pipeline_async())
    assert "Cannot write the subscription feed: read-only" in caplog.text


# python -m nodesieve serve

def run_cli(*argv):
    with pytest.raises(SystemExit) as exit_info:
        cli_module.main(list(argv))
    return exit_info.value.code


def settings_file(tmp_path, **settings):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"subscriptions": ["https://example.org/sub"], **settings}))
    return path


def test_serve_creates_the_token_once_and_saves_nothing_else(tmp_path):
    path = settings_file(tmp_path)
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock) as served:
        assert run_cli("serve", "--config-file", str(path), "--feed-host", "0.0.0.0", "--feed-port", "8001",
                       "--target", "steer") == 0
    saved = json.loads(path.read_text())
    token = saved["feed_token"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{24}", token)
    assert served.await_args.args[1:] == (token, "0.0.0.0", 8001)
    # Overrides given for that run are not saved with the token.
    assert saved["subscriptions"] == ["https://example.org/sub"]
    assert (saved["feed_host"], saved["feed_port"], saved["routing"]["enabled"]) == ("127.0.0.1", 9876, False)
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock) as served:
        assert run_cli("serve", "--config-file", str(path)) == 0
    assert served.await_args.args[1:] == (token, "127.0.0.1", 9876)
    assert json.loads(path.read_text())["feed_token"] == token


@pytest.mark.parametrize("settings,options", [
    ({"feed_token": "short"}, []),
    ({"feed_token": "not/a/path/segment/at/all"}, []),
    ({}, ["--feed-port", "0"]),
    ({}, ["--feed-port", "70000"]),
    ({}, ["--feed-host", " "]),
])
def test_serve_refuses_unusable_settings(tmp_path, settings, options):
    path = settings_file(tmp_path, **settings)
    before = path.read_text()
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock) as served:
        assert run_cli("serve", "--config-file", str(path), *options) == 1
    served.assert_not_called()
    assert path.read_text() == before


@pytest.mark.parametrize("options", [
    ["--dry-run"], ["--add-sub", "https://example.org/new"], ["--routing-show"], ["--show-config"],
])
def test_serve_runs_on_its_own(tmp_path, options):
    path = settings_file(tmp_path)
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock) as served:
        assert run_cli("serve", "--config-file", str(path), *options) == 1
    served.assert_not_called()
    assert "feed_token" not in json.loads(path.read_text())


def test_serve_does_not_save_over_settings_it_cannot_read(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"subscriptions": ["https://example.org/sub"]')
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock) as served:
        assert run_cli("serve", "--config-file", str(path)) == 1
    served.assert_not_called()
    assert path.read_text() == '{"subscriptions": ["https://example.org/sub"]'


def test_serve_keeps_the_crash_log_of_the_last_scan(tmp_path):
    crash_log = Path(cli_module.PROJECT_ROOT) / "crashed_nodes.txt"
    crash_log.write_text("from the last scan\n")
    path = settings_file(tmp_path, feed_token="k" * 24)
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock):
        assert run_cli("serve", "--config-file", str(path)) == 0
    assert crash_log.read_text() == "from the last scan\n"


def test_serve_explains_a_port_in_use(tmp_path, caplog):
    path = settings_file(tmp_path, feed_token="k" * 24)
    busy = OSError(errno.EADDRINUSE, "Address already in use")
    with patch("nodesieve.ui.cli.serve_feed", new_callable=AsyncMock, side_effect=busy):
        assert run_cli("serve", "--config-file", str(path)) == 1
    assert "port 9876 is in use" in caplog.text
