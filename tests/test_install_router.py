"""install-router: what is sent to an OpenWrt router, and what its answers lead to."""

import io
import json
from pathlib import Path
import subprocess
import tarfile
from unittest.mock import patch

import pytest

import nodesieve.router.install as install
from nodesieve.router.install import (
    ARCHIVE_PATH,
    CODE_ROOT,
    INSTALLER,
    STEER_REFRESH,
    code_archive,
    install_router,
    installer_script,
    router_settings,
)
import nodesieve.ui.cli as cli_module

FACTS = {"release": "24.10.5", "arch": "aarch64", "free_kb": "7331404", "packager": "/bin/opkg",
         "installed": "no", "settings": "no", "feed_dir": "", "steer": "yes", "web_home": "/www",
         "lan": "192.168.1.1"}
INSTALLED = ("NS_INFO: settings=new\nNS_INFO: feed_dir=/www/nodesieve/abc\nNS_INFO: python=Python 3.11.18\n"
             "NS_OK: nodesieve is installed in /opt/nodesieve.\n")
CONFIG = {"subscriptions": ["https://example.org/sub"], "router_host": "192.168.1.1",
          "router_ssh_pass": "ssh-secret", "routing": {"enabled": False}}


class FakeRouter:
    """The SSH side of RouterClient: answers the look at the router, records what is sent."""

    def __init__(self, reply=(0, INSTALLED, ""), upload_ok=True, **facts):
        self.facts = "".join(f"{key}={value}\n" for key, value in {**FACTS, **facts}.items())
        self.reply = reply
        self.upload_ok = upload_ok
        self.commands = []
        self.uploads = []

    def exec_command(self, cmd, timeout=15.0, stdin_data=None):
        self.commands.append((cmd, stdin_data))
        return self.reply if cmd == "sh -s" else (0, self.facts, "")

    def stream_file_to_router(self, content, remote_path, mode="0644"):
        self.uploads.append((remote_path, mode, content))
        return self.upload_ok

    @property
    def installer_runs(self):
        return [stdin for cmd, stdin in self.commands if cmd == "sh -s"]


def run(router, config=CONFIG, **options):
    with patch.object(install, "RouterClient", return_value=router):
        return install_router(dict(config), **options)


def values(script):
    """The NS_ values a generated installer sets, as the shell reads them."""
    assignments = script.split("\n#!/bin/sh", 1)[0]
    shown = subprocess.run(["sh", "-c", assignments + '\nprintf "%s\\0" "$NS_MODE" "$NS_EVERY" "$NS_WEB" '
                            '"$NS_ARCHIVE" "$NS_PACKAGES" "$NS_SETTINGS"'],
                           capture_output=True, text=True, check=True).stdout
    return dict(zip(("mode", "every", "web", "archive", "packages", "settings"), shown.split("\0")))


# What is sent

def test_archive_holds_the_code_and_nothing_else():
    with tarfile.open(fileobj=io.BytesIO(code_archive())) as archive:
        members = archive.getmembers()
    names = {member.name for member in members}
    package = {path.relative_to(CODE_ROOT).as_posix() for path in (CODE_ROOT / "nodesieve").rglob("*.py")
               if "__pycache__" not in path.parts}
    assert package <= names
    assert {"nodesieve/router/openwrt_install.sh", "THIRD_PARTY_NOTICES.md"} <= names
    assert "ipregion.sh" not in names
    assert not any("__pycache__" in name or name.startswith("tests") or name.endswith(".json") for name in names)
    assert all(member.uid == 0 and member.uname == "root" for member in members)
    assert {member.mode for member in members if member.isfile()} == {0o644}


def test_router_settings_keep_the_scan_preferences_and_drop_this_computer():
    config = {**CONFIG, "allowed_countries": ["DE"], "workers": 200, "router_ssh_user": "admin",
              "router_ssh_key_path": "/home/me/.ssh/id", "routing_output_dir": "/home/me/out",
              "feed_dir": "/home/me/feed", "feed_host": "0.0.0.0", "feed_port": 1234, "feed_token": "local",
              "feed_command": "notify-send done"}
    settings = router_settings(config, "/www/nodesieve", steer=True, token="T" * 24)
    assert settings["subscriptions"] == CONFIG["subscriptions"]
    assert settings["allowed_countries"] == ["DE"] and settings["routing"] == {"enabled": False}
    assert settings["workers"] == "auto"
    assert (settings["feed_dir"], settings["feed_token"]) == ("/www/nodesieve/" + "T" * 24, "T" * 24)
    assert settings["feed_command"] == STEER_REFRESH
    for key in ("router_host", "router_ssh_pass", "router_ssh_user", "router_ssh_key_path", "routing_output_dir",
                "feed_host", "feed_port"):
        assert key not in settings
    assert router_settings(CONFIG, "/www/nodesieve", steer=False)["feed_command"] == ""


def test_installer_gets_its_values_exactly_as_given():
    settings = {"subscriptions": ["https://example.org/it's?a=1&b=$(touch /tmp/pwned)`id`"], "note": "\"quoted\""}
    script = installer_script("install", 12, "/www/nodesieve", settings)
    assert values(script) == {"mode": "install", "every": "12", "web": "/www/nodesieve", "archive": ARCHIVE_PATH,
                              "packages": install.PACKAGES,
                              "settings": json.dumps(settings, ensure_ascii=False, separators=(",", ":"))}
    assert script.endswith(INSTALLER.read_text())
    subprocess.run(["sh", "-n", "-c", script], check=True)


# The installation

def test_install_sends_the_code_then_runs_the_installer(caplog):
    router = FakeRouter()
    assert run(router)
    [(path, mode, archive)] = router.uploads
    assert (path, mode) == (ARCHIVE_PATH, "0600")
    assert tarfile.open(fileobj=io.BytesIO(archive)).getmember("nodesieve/__main__.py")
    assert router.commands[0][0] != "sh -s", "the router is looked at before anything is sent"
    [script] = router.installer_runs
    sent = values(script)
    assert (sent["mode"], sent["every"], sent["web"]) == ("install", "6", "/www/nodesieve")
    settings = json.loads(sent["settings"])
    assert settings["subscriptions"] == CONFIG["subscriptions"] and settings["feed_command"] == STEER_REFRESH
    assert "ssh-secret" not in script
    assert "http://192.168.1.1/nodesieve/abc/links.txt" in caplog.text
    assert "http://127.0.0.1/nodesieve/abc/links.txt" in caplog.text


def test_dry_run_only_looks_at_the_router(caplog):
    router = FakeRouter()
    assert run(router, dry_run=True)
    assert router.uploads == [] and router.installer_runs == []
    assert "Nothing was changed" in caplog.text


def test_a_router_with_settings_keeps_them(caplog):
    router = FakeRouter(installed="yes", settings="yes", free_kb="1000",
                        reply=(0, INSTALLED.replace("settings=new", "settings=kept"), ""))
    assert run(router)
    assert "keeps its settings" in caplog.text
    assert len(router.uploads) == 1


def test_web_server_directory_and_scan_schedule_come_through():
    router = FakeRouter(web_home="/srv/www/", steer="no")
    assert run(router, every=24)
    sent = values(router.installer_runs[0])
    assert (sent["web"], sent["every"]) == ("/srv/www/nodesieve", "24")
    settings = json.loads(sent["settings"])
    assert settings["feed_dir"].startswith("/srv/www/nodesieve/") and settings["feed_command"] == ""


@pytest.mark.parametrize("facts,message", [
    ({"release": ""}, "not running OpenWrt"),
    ({"packager": ""}, "neither opkg nor apk"),
    ({"free_kb": "100000"}, "storage free"),
])
def test_install_refuses_a_router_it_cannot_install_on(caplog, facts, message):
    router = FakeRouter(**facts)
    assert not run(router)
    assert router.uploads == [] and router.installer_runs == []
    assert message in caplog.text


def test_install_reports_an_unreachable_router(caplog):
    router = FakeRouter()
    router.facts = None
    with patch.object(router, "exec_command", return_value=(-1, "", "Authentication failed.")):
        assert not run(router)
    assert "Cannot reach the router at 192.168.1.1 over SSH: Authentication failed." in caplog.text


@pytest.mark.parametrize("reply,message", [
    ((1, "Installing python3\n", "NS_ERROR: Installing python3 failed: see /tmp/nodesieve-packages.log on the router.\n"),
     "Installing python3 failed"),
    ((0, "NS_INFO: settings=new\n", ""), "the router did not confirm it"),
])
def test_install_reports_what_went_wrong_on_the_router(caplog, reply, message):
    assert not run(FakeRouter(reply=reply))
    assert message in caplog.text


def test_install_stops_when_the_code_cannot_be_sent(caplog):
    router = FakeRouter(upload_ok=False)
    assert not run(router)
    assert router.installer_runs == []
    assert "Could not send the code" in caplog.text


def test_remove_sends_no_code(caplog):
    router = FakeRouter(installed="yes", reply=(0, "NS_OK: nodesieve was removed from the router.\n", ""))
    assert run(router, remove=True)
    assert router.uploads == []
    assert values(router.installer_runs[0])["mode"] == "remove"
    dry = FakeRouter(installed="yes")
    assert run(dry, remove=True, dry_run=True)
    assert dry.installer_runs == []


# python -m nodesieve install-router

def run_cli(tmp_path, *argv):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"subscriptions": ["https://example.org/sub"]}))
    with patch("nodesieve.ui.cli.install_router", return_value=True) as installer, \
            pytest.raises(SystemExit) as exit_info:
        cli_module.main(["--config-file", str(settings), *argv])
    return exit_info.value.code, installer


def test_cli_installs_with_the_router_options_of_this_run(tmp_path):
    code, installer = run_cli(tmp_path, "install-router", "--router-host", "10.0.0.1", "--scan-every", "12",
                              "--dry-run")
    assert code == 0
    config = installer.call_args.args[0]
    assert config["router_host"] == "10.0.0.1"
    assert installer.call_args.kwargs == {"every": 12, "dry_run": True, "remove": False}
    code, installer = run_cli(tmp_path, "install-router", "--remove")
    assert code == 0 and installer.call_args.kwargs == {"every": 6, "dry_run": False, "remove": True}


@pytest.mark.parametrize("argv", [
    ["install-router", "--scan-every", "5"],
    ["install-router", "--routing-show"],
    ["install-router", "--add-sub", "https://example.org/new"],
    ["check", "--remove"],
    ["--scan-every", "6"],
])
def test_cli_refuses_options_that_do_not_fit(tmp_path, argv):
    code, installer = run_cli(tmp_path, *argv)
    assert code == 1
    installer.assert_not_called()


def test_cli_keeps_the_crash_log_of_the_last_scan(tmp_path):
    crash_log = Path(cli_module.PROJECT_ROOT) / "crashed_nodes.txt"
    crash_log.write_text("from the last scan\n")
    assert run_cli(tmp_path, "install-router")[0] == 0
    assert crash_log.read_text() == "from the last scan\n"
