"""Install nodesieve on an OpenWrt router, so that the router scans for itself.

`python -m nodesieve install-router` runs on a computer or phone that reaches the router
over SSH. The repository is private, so the router can't download nodesieve itself: this
sends the code of this checkout, and then `openwrt_install.sh`, which on the router

- installs Python and its modules with the package manager,
- puts the code in /opt/nodesieve, keeping the router's settings and caches there,
- creates the router's settings on the first install, from this computer's: the same
  subscriptions and scan preferences, with the feed in the directory the router's web
  server (uhttpd) serves, so that the local network can subscribe to it,
- schedules `check` with cron.

With Zapret Manager on the router, the router's settings also get a feed_command that
asks Steer to fetch its subscription after each scan that updated the feed. Steer itself
is not changed: its main section is subscribed to the feed once, in the panel.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import shlex
import tarfile
from typing import Optional

from nodesieve.constants import DEFAULT_CONFIG
from nodesieve.feed import BASE64_NAME, CLASH_NAME, LINKS_NAME, new_token
from nodesieve.logging import log
from nodesieve.router.client import RouterClient

# The checkout this module belongs to: the code that is installed.
CODE_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = Path(__file__).with_name("openwrt_install.sh")
ROUTER_DIR = "/opt/nodesieve"
ARCHIVE_PATH = "/tmp/nodesieve-code.tgz"
PACKAGES = "python3 python3-aiohttp python3-yaml"
STEER_REFRESH = "/opt/zapret-manager-luci/backend.sh steer_action sub_refresh x"
# Hours between scheduled scans: divisors of a day, so the scans stay evenly spaced. 0: none.
SCAN_HOURS = (0, 1, 2, 3, 4, 6, 8, 12, 24)
# Python with the modules it pulls in, the Mihomo binary the first scan downloads, caches.
MIN_FREE_MB = 150
# Settings that describe this computer or how it reaches the router, not the router.
_NOT_FOR_THE_ROUTER = (
    "router_host", "router_ssh_port", "router_ssh_user",
    "router_ssh_pass", "router_ssh_key_path", "routing_output_dir",
    "feed_dir", "feed_host", "feed_port", "feed_token", "feed_command",
)

# Read-only look at the router, one key=value per line.
_PRECHECK = r"""
. /etc/openwrt_release 2>/dev/null || :
echo "release=${DISTRIB_RELEASE:-}"
echo "arch=$(uname -m)"
echo "free_kb=$(df -k / 2>/dev/null | awk 'NR==2 {print $4}')"
echo "packager=$(command -v opkg || command -v apk || :)"
echo "installed=$([ -f /opt/nodesieve/nodesieve/__main__.py ] && echo yes || echo no)"
echo "settings=$([ -f /opt/nodesieve/nodesieve_config.json ] && echo yes || echo no)"
echo "feed_dir=$(jsonfilter -i /opt/nodesieve/nodesieve_config.json -e @.feed_dir 2>/dev/null || :)"
echo "steer=$([ -x /opt/zapret-manager-luci/backend.sh ] && echo yes || echo no)"
echo "web_home=$(uci -q get uhttpd.main.home || :)"
echo "lan=$(ubus call network.interface.lan status 2>/dev/null | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null || :)"
"""


def _owned_by_root(member: tarfile.TarInfo) -> tarfile.TarInfo:
    member.uid = member.gid = 0
    member.uname = member.gname = "root"
    member.mode = 0o755 if member.isdir() else 0o644
    return member


def code_archive(root: Path = CODE_ROOT) -> bytes:
    """The code the router runs, as a .tar.gz: the nodesieve package and the third-party notices."""
    package = root / "nodesieve"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path in [package, *sorted(package.rglob("*"))]:
            if "__pycache__" in path.parts or not (path.is_dir() or path.suffix in (".py", ".sh")):
                continue
            archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False, filter=_owned_by_root)
        archive.add(root / "THIRD_PARTY_NOTICES.md", arcname="THIRD_PARTY_NOTICES.md", recursive=False,
                    filter=_owned_by_root)
    return buffer.getvalue()


def router_settings(config: dict, web_dir: str, steer: bool, token: Optional[str] = None) -> dict:
    """The router's settings: this computer's subscriptions and scan preferences, set up for the router.

    Its worker count is sized for its own memory, and its feed goes where its web server
    serves it.
    """
    token = token or new_token()
    settings = {key: value for key, value in config.items() if key not in _NOT_FOR_THE_ROUTER}
    settings.update({
        "workers": "auto",
        "feed_dir": f"{web_dir}/{token}",
        "feed_token": token,
        "feed_command": STEER_REFRESH if steer else "",
    })
    return settings


def _facts(output: str) -> dict:
    facts = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            facts[key.strip()] = value.strip()
    return facts


def installer_script(mode: str, every: int, web_dir: str, settings: dict) -> str:
    """The installer with its values set, for `sh -s` on the router."""
    values = {
        "NS_MODE": mode,
        "NS_EVERY": str(every),
        "NS_WEB": web_dir,
        "NS_ARCHIVE": ARCHIVE_PATH,
        "NS_PACKAGES": PACKAGES,
        "NS_SETTINGS": json.dumps(settings, ensure_ascii=False, separators=(",", ":")),
    }
    assignments = "".join(f"{name}={shlex.quote(value)}\n" for name, value in values.items())
    return assignments + INSTALLER.read_text(encoding="utf-8")


def _report(code: int, out: str, err: str) -> tuple[bool, dict]:
    """Show what the installer said; whether it finished, and its NS_INFO values."""
    lines = (out + "\n" + err).splitlines()
    info = _facts("\n".join(line.removeprefix("NS_INFO: ") for line in lines if line.startswith("NS_INFO: ")))
    for line in lines:
        if line.startswith("NS_NOTE: "):
            log.warning("[!] " + line.removeprefix("NS_NOTE: ")[:300])
    done = [line.removeprefix("NS_OK: ") for line in lines if line.startswith("NS_OK: ")]
    if code != 0 or not done:
        errors = [line.removeprefix("NS_ERROR: ") for line in lines if line.startswith("NS_ERROR: ")]
        for message in errors or [err.strip().splitlines()[-1] if err.strip() else "the router did not confirm it"]:
            log.error("[-] " + message[:300])
        return False, info
    log.info("[+] " + done[-1][:300])
    return True, info


def install_router(config: dict, every: int = 6, dry_run: bool = False, remove: bool = False) -> bool:
    """Install nodesieve on the router at router_host, or remove it; True when the router confirmed it."""
    host = config.get("router_host", DEFAULT_CONFIG["router_host"])
    user = config.get("router_ssh_user", DEFAULT_CONFIG["router_ssh_user"])
    client = RouterClient(
        host=host,
        ssh_port=config.get("router_ssh_port", DEFAULT_CONFIG["router_ssh_port"]),
        ssh_user=user,
        ssh_pass=config.get("router_ssh_pass", ""),
        ssh_key_path=config.get("router_ssh_key_path"),
    )
    code, out, err = client.exec_command(_PRECHECK, timeout=30)
    if code != 0:
        log.error(f"[-] Cannot reach the router at {host} over SSH: {(err.strip() or 'no answer')[:300]}")
        return False
    facts = _facts(out)
    if not facts.get("release"):
        log.error(f"[-] {host} is not running OpenWrt, so nodesieve can't be installed there.")
        return False
    web_home = facts.get("web_home", "").rstrip("/") or "/www"
    web_dir = f"{web_home}/nodesieve"
    log.info(f"[*] Router {host}: OpenWrt {facts['release']}, {facts.get('arch', '?')}"
             + (", nodesieve installed" if facts.get("installed") == "yes" else ""))

    if remove:
        if dry_run:
            log.info(f"[+] [DRY RUN] Would remove {ROUTER_DIR}, {web_dir} and the scheduled scan. Nothing was changed.")
            return True
        code, out, err = client.exec_command("sh -s", timeout=120,
                                             stdin_data=installer_script("remove", 0, web_dir, {}))
        return _report(code, out, err)[0]

    if not facts.get("packager"):
        log.error("[-] The router has neither opkg nor apk, so its packages can't be installed.")
        return False
    try:
        free_mb = int(facts.get("free_kb", "")) / 1024
    except ValueError:
        free_mb = None
    if facts.get("installed") != "yes" and free_mb is not None and free_mb < MIN_FREE_MB:
        log.error(f"[-] The router has {free_mb:.0f} MB of storage free; nodesieve needs about {MIN_FREE_MB} MB "
                  "(Python, and the Mihomo binary the first scan downloads).")
        return False
    if not facts.get("web_home"):
        log.warning("[!] The router has no web server (uhttpd), so nothing will serve its feed to the network.")
    steer = facts.get("steer") == "yes"
    settings = router_settings(config, web_dir, steer)
    keep_settings = facts.get("settings") == "yes"
    if keep_settings:
        log.info(f"[*] The router keeps its settings in {ROUTER_DIR}/nodesieve_config.json; only the code is replaced.")
    elif not settings.get("subscriptions"):
        log.warning("[!] There are no subscriptions in the settings here to give the router. Add them there with "
                    f"`cd {ROUTER_DIR} && python3 -m nodesieve --add-sub <url>`.")
    schedule = f"every {every} hours" if every else "no schedule"
    log.info(f"[*] Plan: install {PACKAGES} if missing, the code in {ROUTER_DIR}, the feed under {web_dir}, "
             f"scans with `check` {schedule}" + ("; after each, Steer fetches the feed." if steer else "."))
    if dry_run:
        log.info("[+] [DRY RUN] Nothing was changed on the router.")
        return True

    if not client.stream_file_to_router(code_archive(), ARCHIVE_PATH, mode="0600"):
        log.error("[-] Could not send the code to the router.")
        return False
    log.info("[*] Installing on the router. Installing packages can take a few minutes...")
    code, out, err = client.exec_command("sh -s", timeout=900,
                                         stdin_data=installer_script("install", every, web_dir, settings))
    done, info = _report(code, out, err)
    if not done:
        return False

    feed_dir = info.get("feed_dir", "")
    if info.get("python"):
        log.info(f"[*] On the router: {info['python']}. Scans log to /tmp/nodesieve.log there.")
    log.info(f"[*] To scan now: ssh {user}@{host} 'cd {ROUTER_DIR} && python3 -m nodesieve check'")
    if feed_dir.startswith(web_home + "/"):
        path = feed_dir[len(web_home):]
        lan = facts.get("lan") or host
        log.info("[*] Once a scan has written it, the router serves the feed to the local network:")
        log.info(f"    Share links: http://{lan}{path}/{LINKS_NAME}")
        log.info(f"    Share links in base64: http://{lan}{path}/{BASE64_NAME}")
        log.info(f"    Clash/Mihomo profile: http://{lan}{path}/{CLASH_NAME}")
        if steer:
            log.info(f"[*] For Steer, subscribe its main section to http://127.0.0.1{path}/{LINKS_NAME} in the "
                     "Zapret Manager panel (Steer, Connection tab). Each scan that updates the feed then has "
                     "Steer fetch it.")
    return True
