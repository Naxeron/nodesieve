"""Command-line entry point for scans and settings management."""

import argparse
import asyncio
import json
import os
import sys
from typing import List, NoReturn, Optional

from nodesieve.config import ConfigManager
from nodesieve.constants import CRASHED_LOG_FILE, DEFAULT_CONFIG, PROJECT_ROOT
from nodesieve.logging import log
from nodesieve.routing import normalize_routing
from nodesieve.ui.dashboard import VPNDashboard


def _die(msg: str) -> NoReturn:
    log.error(f"[-] {msg}")
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m nodesieve",
        allow_abbrev=False,
        description="nodesieve - Check VPN proxy exit IPs and locations, and publish working ones as a subscription feed",
    )
    add = parser.add_argument
    add("action", nargs="?", default="check", choices=["check", "config"],
        help="'check' (default: scan subscriptions and update feed) or 'config' (print settings).")
    add("--dry-run", action="store_true", help="Scan and write the feed, skipping feed_command for this run.")
    add("-s", "--sub", "--subscription", dest="subscriptions", action="append",
        help="Additional subscription URL for this run.")
    add("-w", "--workers", dest="workers", help="Concurrent HTTP workers (positive integer or 'auto').")
    add("--tcp-workers", dest="tcp_workers", type=int, help="Concurrent TCP ping workers.")
    add("-c", "--countries", "--allowed-countries", dest="allowed_countries",
        help="Comma-separated exit country codes to allow (e.g. 'US,DE'). Blank for all.")
    add("--speedtest-timeout", dest="speedtest_timeout", type=int, help="Per-node speedtest timeout in seconds.")
    add("--min-speed-percent", type=float, metavar="PERCENT",
        help=f"Minimum speed as percentage of fastest node (0-100, default {DEFAULT_CONFIG['min_speed_percent']}).")
    add("--config-file", dest="config_file", help="Path to custom configuration file.")
    add("--rank-by", dest="rank_by", choices=["speed", "location"],
        help="Ranking mode for this run: 'speed' (default) or 'location' (14-provider GeoIP consensus).")
    add("--output-dir", dest="routing_output_dir", help="Directory for the Steer routing report (default: steer-output).")
    add("--show-config", action="store_true", help="Print active configuration and exit.")
    add("--add-sub", dest="add_sub", help="Add a subscription URL to persistent configuration and exit.")
    add("--remove-sub", dest="remove_sub", help="Remove a subscription URL or 1-based index from configuration and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    cfg_path = args.config_file or ConfigManager.default_path(PROJECT_ROOT)
    try:
        config = ConfigManager.load(cfg_path)
    except ValueError as exc:
        _die(f"Invalid configuration: {exc}")

    if args.add_sub is not None and args.remove_sub is not None:
        _die("Conflicting options: Cannot specify both --add-sub and --remove-sub simultaneously.")
    managing = args.action == "config" or args.show_config or args.add_sub is not None or args.remove_sub is not None
    if args.dry_run and managing:
        _die("--dry-run is an option of 'check'.")

    if args.rank_by is not None:
        config["routing"]["enabled"] = args.rank_by == "location"
        config["routing"]["target"] = "steer"
        try:
            config["routing"] = normalize_routing(config["routing"])
        except ValueError as exc:
            _die(f"Invalid routing configuration: {exc}")
    if args.routing_output_dir is not None:
        if not args.routing_output_dir.strip():
            _die("--output-dir cannot be empty.")
        config["routing_output_dir"] = os.path.abspath(os.path.expanduser(args.routing_output_dir.strip()))

    if args.add_sub is not None:
        new_sub = args.add_sub.strip()
        if not new_sub:
            _die("Subscription URL cannot be empty.")
        subs = config.setdefault("subscriptions", [])
        if new_sub in subs:
            log.warning(f"[*] Subscription already exists: {new_sub}")
            sys.exit(0)
        subs.append(new_sub)
        ConfigManager.save(config, cfg_path)
        log.info(f"[+] Added subscription: {new_sub}")
        sys.exit(0)

    if args.remove_sub is not None:
        target = args.remove_sub.strip()
        if not target:
            _die("Subscription index or URL cannot be empty.")
        subs = config.get("subscriptions", [])
        if target.isdigit() and 1 <= int(target) <= len(subs):
            removed = subs.pop(int(target) - 1)
        elif target in subs:
            subs.remove(target)
            removed = target
        else:
            _die(f"Subscription not found: {target}")
        ConfigManager.save(config, cfg_path)
        log.info(f"[+] Removed subscription: {removed}")
        sys.exit(0)

    if args.show_config or args.action == "config":
        print(json.dumps(config, indent=4, ensure_ascii=False))
        sys.exit(0)

    if args.subscriptions:
        clean = [s.strip() for s in args.subscriptions]
        if any(not s for s in clean):
            _die("Subscription URL cannot be empty.")
        config.setdefault("subscriptions", []).extend(clean)

    if args.workers is not None:
        val = str(args.workers).strip().lower()
        if val == "auto":
            config["workers"] = "auto"
        else:
            try:
                w = int(val)
                if w <= 0:
                    raise ValueError
                config["workers"] = w
            except ValueError:
                _die("Workers must be a positive integer or 'auto'.")

    if args.tcp_workers is not None:
        if args.tcp_workers <= 0:
            _die("TCP workers must be a positive integer.")
        config["tcp_workers"] = args.tcp_workers

    if args.allowed_countries is not None:
        config["allowed_countries"] = [c.strip().upper() for c in args.allowed_countries.split(",") if c.strip()]

    if args.speedtest_timeout is not None:
        if args.speedtest_timeout <= 0:
            _die("Speedtest timeout must be a positive integer.")
        config["speedtest_timeout"] = args.speedtest_timeout

    if args.min_speed_percent is not None:
        if not 0 <= args.min_speed_percent <= 100:
            _die("--min-speed-percent must be between 0 and 100.")
        config["min_speed_percent"] = args.min_speed_percent

    try:
        os.unlink(os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE))
    except OSError:
        pass
    log.info("[*] Starting nodesieve pipeline...")
    if not asyncio.run(VPNDashboard(config=config).run_pipeline_async(dry_run=args.dry_run)):
        sys.exit(1)
