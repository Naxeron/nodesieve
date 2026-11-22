"""Command-line entry point for scans, the feed server and settings."""

import argparse
import asyncio
import errno
import json
import os
import shlex
import sys
from typing import List, Optional

from nodesieve.config import ConfigManager
from nodesieve.constants import CORES, CRASHED_LOG_FILE, DEFAULT_CONFIG, PROJECT_ROOT
from nodesieve.feed import new_token, serve_feed, valid_token
from nodesieve.logging import log
from nodesieve.routing import normalize_routing
from nodesieve.ui.dashboard import VPNDashboard
from nodesieve.ui.routing import format_routing, routing_menu


class _ActionCapture(argparse.Action):
    """Tracks whether a positional action was explicitly passed or defaulted."""

    def __call__(self, parser, namespace, values, option_string=None):
        if values is not None:
            setattr(namespace, self.dest, values)
            setattr(namespace, "action_explicit", True)
        else:
            setattr(namespace, self.dest, "check")
            setattr(namespace, "action_explicit", False)


def build_parser() -> argparse.ArgumentParser:
    """The command line: one action, and options that adjust it."""
    parser = argparse.ArgumentParser(
        prog="python -m nodesieve",
        allow_abbrev=False,  # Keep --remove from resolving to --remove-sub.
        description="nodesieve - Check VPN proxy exit IPs and locations, and publish the working ones "
                    "as a subscription feed",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default=None,
        choices=["check", "config", "routing", "serve"],
        action=_ActionCapture,
        help="'check' (default: scan the subscriptions and update the feed), "
             "'config' (print the settings), "
             "'routing' (edit Steer main-pool routing in a terminal, or display it when piped), "
             "'serve' (serve the subscription feed that scans write, for VPN apps to subscribe to).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and write the feed, skipping feed_command for this run.",
    )

    # Sourcing & concurrency overrides
    parser.add_argument(
        "-s", "--sub", "--subscription",
        dest="subscriptions",
        action="append",
        help="Additional subscription URL to fetch fresh nodes from.",
    )
    parser.add_argument(
        "-w", "--workers",
        dest="workers",
        help="Number of concurrent HTTP workers (or 'auto').",
    )
    parser.add_argument(
        "--tcp-workers",
        dest="tcp_workers",
        type=int,
        help="Number of concurrent TCP ping workers.",
    )
    parser.add_argument(
        "-c", "--countries", "--allowed-countries",
        dest="allowed_countries",
        help="Comma-separated exit country codes to allow (e.g. 'US,DE'). Blank for all.",
    )
    parser.add_argument(
        "--speedtest-timeout",
        dest="speedtest_timeout",
        type=int,
        help="Timeout in seconds for speedtesting each candidate node.",
    )
    parser.add_argument(
        "--min-speed-percent",
        type=float,
        metavar="PERCENT",
        help="Minimum download speed as a percentage of the fastest node in this Mihomo-target scan "
             f"(0 to 100, default {DEFAULT_CONFIG['min_speed_percent']}). Use 0 to disable the cutoff.",
    )
    parser.add_argument(
        "--core",
        choices=list(CORES),
        help="The core to check nodes through, for this run: 'xray' (the default), which share links "
             "are written for, or 'mihomo'.",
    )
    parser.add_argument(
        "--config-file",
        dest="config_file",
        help="Path to custom configuration file.",
    )

    # Steer main-pool routing
    parser.add_argument(
        "--target",
        choices=["mihomo", "steer"],
        help="What a scan ranks by, for this run: 'steer' qualifies nodes by location consensus against "
             "the routing.main policy, 'mihomo' by exit country and speed.",
    )
    parser.add_argument(
        "--output-dir",
        dest="routing_output_dir",
        help="Directory for the Steer routing report (default: steer-output).",
    )
    routing_actions = parser.add_mutually_exclusive_group()
    routing_actions.add_argument(
        "--routing-setup",
        action="store_true",
        help="Open the interactive Steer routing editor and exit (requires a terminal).",
    )
    routing_actions.add_argument(
        "--routing-show",
        action="store_true",
        help="Print Steer routing preferences without credentials or interaction and exit.",
    )

    # Subscription feed server
    parser.add_argument(
        "--feed-host",
        dest="feed_host",
        help="Address 'serve' listens on (default 127.0.0.1). Use the LAN address to serve local network clients.",
    )
    parser.add_argument(
        "--feed-port",
        dest="feed_port",
        type=int,
        help="Port 'serve' listens on (default: 9876).",
    )

    # Non-interactive config management flags
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Print current active configuration and exit.",
    )
    parser.add_argument(
        "--add-sub",
        dest="add_sub",
        help="Add a new subscription URL to persistent configuration and exit.",
    )
    parser.add_argument(
        "--remove-sub",
        dest="remove_sub",
        help="Remove a subscription URL from persistent configuration and exit.",
    )

    return parser


def serve(config: dict, cfg_path: str, args: argparse.Namespace) -> None:
    """Serve the subscription feed until Ctrl+C, then exit.

    The first run creates the feed's token and saves only that to the settings file, so
    no override given for this run is saved with it.
    """
    host = (args.feed_host if args.feed_host is not None else config["feed_host"]).strip()
    port = args.feed_port if args.feed_port is not None else config["feed_port"]
    if not host:
        log.error("[-] --feed-host cannot be empty.")
        sys.exit(1)
    if not 1 <= port <= 65535:
        log.error(f"[-] Invalid port {port} for --feed-port. Port must be between 1 and 65535.")
        sys.exit(1)
    token = config["feed_token"]
    if not token:
        token = new_token()
        try:
            saved = ConfigManager.load(cfg_path, strict=True)
            saved["feed_token"] = token
            ConfigManager.save(saved, cfg_path)
        except (OSError, ValueError) as exc:
            log.error(f"[-] Could not save the feed's token to {cfg_path}: {exc}")
            sys.exit(1)
        config["feed_token"] = token
        log.info(f"[*] Created the feed's token, the secret part of its address, and saved it to {cfg_path}.")
    elif not valid_token(token):
        log.error("[-] feed_token must be 16 to 128 letters, digits, '-' or '_'. Clear it to have a new one created.")
        sys.exit(1)
    try:
        asyncio.run(serve_feed(config, token, host, port))
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            log.error(f"[-] Cannot serve the feed: port {port} is in use. Is serve already running? "
                      "Choose another port with --feed-port.")
        else:
            log.error(f"[-] Cannot serve the feed on {host}:{port}: {exc}")
        sys.exit(1)
    sys.exit(0)


def main(argv: Optional[List[str]] = None) -> None:
    """Run one action: a scan by default."""
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg_path = args.config_file or ConfigManager.default_path(PROJECT_ROOT)
    try:
        config = ConfigManager.load(cfg_path)
    except ValueError as exc:
        log.error(f"[-] Invalid configuration: {exc}")
        sys.exit(1)

    if args.add_sub is not None and args.remove_sub is not None:
        log.error("[-] Conflicting options: Cannot specify both --add-sub and --remove-sub simultaneously.")
        sys.exit(1)
    managing = args.action == "config" or args.show_config or args.add_sub is not None or args.remove_sub is not None
    routing_management = args.action == "routing" or args.routing_setup or args.routing_show
    scanning = args.action == "check" and not (managing or routing_management)
    if args.dry_run and not scanning:
        log.error("[-] --dry-run is an option of 'check'.")
        sys.exit(1)
    if routing_management and (getattr(args, "action_explicit", False) and args.action == "check"):
        log.error("[-] Conflicting options: Routing setup/display cannot be combined with a scan.")
        sys.exit(1)
    if routing_management and managing:
        log.error("[-] Conflicting options: Choose routing setup/display or other configuration management.")
        sys.exit(1)
    if args.action == "serve" and (routing_management or managing):
        log.error("[-] Conflicting options: 'serve' runs on its own, without routing or configuration options.")
        sys.exit(1)

    # Routing overrides also apply to display and setup, before their early exits.
    try:
        config["routing"] = normalize_routing(config.get("routing"))
    except ValueError as exc:
        log.error(f"[-] Invalid routing configuration: {exc}")
        sys.exit(1)
    if args.target is not None:
        config["routing"]["enabled"] = args.target == "steer"
        config["routing"]["target"] = "steer"
        try:
            config["routing"] = normalize_routing(config["routing"])
        except ValueError as exc:
            log.error(f"[-] Invalid routing configuration: {exc}")
            sys.exit(1)
    if args.routing_output_dir is not None:
        if not args.routing_output_dir.strip():
            log.error("[-] --output-dir cannot be empty.")
            sys.exit(1)
        config["routing_output_dir"] = os.path.abspath(os.path.expanduser(args.routing_output_dir.strip()))

    if routing_management:
        if args.routing_show or (args.action == "routing" and not args.routing_setup and not sys.stdin.isatty()):
            print(format_routing(config))
            sys.exit(0)
        if not sys.stdin.isatty():
            log.error("[-] --routing-setup requires an interactive terminal. Use --routing-show to view preferences.")
            sys.exit(1)
        draft = routing_menu(config)
        if draft is not None:
            try:
                ConfigManager.save(draft, cfg_path)
            except (OSError, ValueError) as exc:
                log.error(f"[-] Could not save routing preferences: {exc}")
                sys.exit(1)
            print(f"Saved routing preferences to {cfg_path}.")
            if draft["routing"]["enabled"]:
                command = "python -m nodesieve check"
                if args.config_file:
                    command += " --config-file " + shlex.quote(cfg_path)
                print(f"Run `{command}` to test proxies and rank the main pool.")
            else:
                print("Steer routing is disabled. Enable it in the routing editor when ready.")
        sys.exit(0)

    # Handle config subcommands / flags
    if args.add_sub is not None:
        new_sub = args.add_sub.strip()
        if not new_sub:
            log.error("[-] Subscription URL cannot be empty.")
            sys.exit(1)
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
            log.error("[-] Subscription index or URL cannot be empty.")
            sys.exit(1)
        subs = config.get("subscriptions", [])
        removed = None
        if target.isdigit() and 1 <= int(target) <= len(subs):
            removed = subs.pop(int(target) - 1)
        elif target in subs:
            subs.remove(target)
            removed = target
        if removed:
            ConfigManager.save(config, cfg_path)
            log.info(f"[+] Removed subscription: {removed}")
            sys.exit(0)
        else:
            log.error(f"[-] Subscription not found: {target}")
            sys.exit(1)

    if args.show_config or args.action == "config":
        print(json.dumps(config, indent=4, ensure_ascii=False))
        sys.exit(0)

    if args.action == "serve":
        serve(config, cfg_path, args)

    # Apply runtime CLI overrides to active config with strict validation
    if args.subscriptions:
        clean_subs = []
        for s in args.subscriptions:
            cleaned = s.strip()
            if not cleaned:
                log.error("[-] Subscription URL cannot be empty.")
                sys.exit(1)
            clean_subs.append(cleaned)
        config.setdefault("subscriptions", []).extend(clean_subs)

    if args.workers is not None:
        val_str = str(args.workers).strip().lower()
        if val_str == "auto":
            config["workers"] = "auto"
        else:
            try:
                w_val = int(val_str)
                if w_val <= 0:
                    log.error("[-] Workers must be a positive integer or 'auto'.")
                    sys.exit(1)
                config["workers"] = w_val
            except ValueError:
                log.error("[-] Workers must be a positive integer or 'auto'.")
                sys.exit(1)

    if args.tcp_workers is not None:
        if args.tcp_workers <= 0:
            log.error("[-] TCP workers must be a positive integer.")
            sys.exit(1)
        config["tcp_workers"] = args.tcp_workers

    if args.allowed_countries is not None:
        config["allowed_countries"] = [
            c.strip().upper() for c in args.allowed_countries.split(",") if c.strip()
        ]

    if args.core is not None:
        config["core"] = args.core

    if args.speedtest_timeout is not None:
        if args.speedtest_timeout <= 0:
            log.error("[-] Speedtest timeout must be a positive integer.")
            sys.exit(1)
        config["speedtest_timeout"] = args.speedtest_timeout

    if args.min_speed_percent is not None:
        if not 0 <= args.min_speed_percent <= 100:
            log.error("[-] --min-speed-percent must be between 0 and 100.")
            sys.exit(1)
        config["min_speed_percent"] = args.min_speed_percent

    # A scan starts a new crash log.
    try:
        with open(os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE), "w", encoding="utf-8") as f:
            f.write("--- CRASHED NODES LOG ---\n\n")
    except OSError:
        pass
    log.info("[*] Starting nodesieve pipeline...")
    if not asyncio.run(VPNDashboard(config=config).run_pipeline_async(dry_run=args.dry_run)):
        sys.exit(1)
