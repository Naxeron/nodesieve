"""Streamlined single-command CLI entrypoint and non-interactive configuration management."""

import argparse
import asyncio
import errno
import json
import os
import shlex
import sys
from typing import List, Optional

from nodesieve.config import ConfigManager
from nodesieve.constants import CRASHED_LOG_FILE, PROJECT_ROOT
from nodesieve.feed import new_token, serve_feed, valid_token
from nodesieve.logging import log
from nodesieve.routing import normalize_routing
from nodesieve.ui.dashboard import VPNDashboard
from nodesieve.ui.routing import format_routing, routing_menu


def clear_screen() -> None:
    """Clears the console window across POSIX and Windows terminals."""
    os.system("clear" if os.name == "posix" else "cls")


class _ActionCapture(argparse.Action):
    """Tracks whether a positional action was explicitly passed or defaulted."""

    def __call__(self, parser, namespace, values, option_string=None):
        if values is not None:
            setattr(namespace, self.dest, values)
            setattr(namespace, "action_explicit", True)
        else:
            setattr(namespace, self.dest, "run")
            setattr(namespace, "action_explicit", False)


def build_parser() -> argparse.ArgumentParser:
    """Constructs the modern single-command argument parser for nodesieve."""
    parser = argparse.ArgumentParser(
        prog="python -m nodesieve",
        description="nodesieve - Check VPN proxy exit IPs and locations and configure Mihomo or Steer routing",
    )

    # Positional action (defaults to "run")
    parser.add_argument(
        "action",
        nargs="?",
        default=None,
        choices=["run", "check", "deploy", "config", "routing", "serve"],
        action=_ActionCapture,
        help="Pipeline phase to execute: 'run' (default: full test, verify & deploy), "
             "'check' (test & verify without deploying), "
             "'deploy' (deploy existing configuration to router), "
             "'config' (manage configuration), "
             "'routing' (edit Steer main-pool routing in a terminal, or display it when piped), "
             "'serve' (serve the subscription feed that scans write, for VPN apps to subscribe to).",
    )

    # Phase flags
    parser.add_argument(
        "--run",
        dest="flag_run",
        action="store_true",
        help="Execute the full end-to-end check, verification, and deployment workflow.",
    )
    parser.add_argument(
        "--check",
        "--check-only",
        dest="flag_check_only",
        action="store_true",
        help="Run node fetch, testing, and router-side verification only (do not deploy to router).",
    )
    parser.add_argument(
        "--deploy",
        "--deploy-only",
        dest="flag_deploy_only",
        action="store_true",
        help="Deploy the latest verified configuration to the router without re-running node tests.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute the full pipeline and generate router configuration without modifying or restarting the router.",
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
        "--no-router-validation",
        "--skip-router-validation",
        dest="disable_router_validation",
        action="store_true",
        help="Skip Stage 2 router-side verification.",
    )
    parser.add_argument(
        "--speedtest-timeout",
        dest="speedtest_timeout",
        type=int,
        help="Timeout in seconds for speedtesting each candidate node.",
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
        help="Router configuration target. Steer manages the servers of its main section; Mihomo disables that for this run.",
    )
    parser.add_argument(
        "--output-dir",
        dest="routing_output_dir",
        help="Directory for Steer routing artifacts (default: steer-output).",
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

    # Router connection overrides
    parser.add_argument(
        "--router-host",
        dest="router_host",
        help="Router IP address or hostname (default: 192.168.1.1).",
    )
    parser.add_argument(
        "--router-api-port",
        dest="router_api_port",
        type=int,
        help="Router Mihomo REST API port (default: 9090).",
    )
    parser.add_argument(
        "--router-proxy-port",
        dest="router_proxy_port",
        type=int,
        help="Router main proxy listener port (default: 7890).",
    )
    parser.add_argument(
        "--router-ssh-port",
        dest="router_ssh_port",
        type=int,
        help="Router SSH port (default: 22).",
    )
    parser.add_argument(
        "--router-ssh-user",
        dest="router_ssh_user",
        help="Router SSH username (default: root).",
    )
    parser.add_argument(
        "--router-ssh-pass",
        dest="router_ssh_pass",
        help="Router SSH password.",
    )

    # Subscription feed server
    parser.add_argument(
        "--feed-host",
        dest="feed_host",
        help="Address 'serve' listens on (default: 127.0.0.1, this device only; 0.0.0.0 for the local network).",
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


def manage_subscriptions(config: dict, dash: Optional[VPNDashboard] = None) -> None:
    """Non-interactive and interactive helper for managing subscription URLs."""
    subs = config.get("subscriptions", [])
    print("=== Configured Subscriptions ===")
    if not subs:
        print("No subscriptions configured.")
    else:
        for i, sub in enumerate(subs, 1):
            print(f"{i}. {sub}")


def settings_menu(config: dict) -> None:
    """Displays active configuration settings."""
    print("=== nodesieve Settings ===")
    print(f"TCP Workers: {config.get('tcp_workers', 128)}")
    print(f"HTTP Workers: {config.get('workers', 'auto')}")
    print(f"Allowed Countries: {', '.join(config.get('allowed_countries', [])) or 'ALL'}")
    print(f"Speedtest Timeout: {config.get('speedtest_timeout', 45)}s")
    print(f"Router Validation: {'ON' if config.get('enable_router_validation', True) else 'OFF'}")
    print(f"Router Host: {config.get('router_host', '192.168.1.1')}")


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
    """Primary CLI application entry point with streamlined single-command execution."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Initialize crashed nodes log. The feed server runs beside scans and keeps the last scan's log.
    if args.action != "serve":
        crashed_log_path = os.path.join(PROJECT_ROOT, CRASHED_LOG_FILE)
        try:
            with open(crashed_log_path, "w", encoding="utf-8") as f:
                f.write("--- CRASHED NODES LOG ---\n\n")
        except Exception:
            pass

    # Load configuration
    cfg_path = args.config_file or ConfigManager.default_path(PROJECT_ROOT)
    try:
        config = ConfigManager.load(cfg_path)
    except ValueError as exc:
        log.error(f"[-] Invalid configuration: {exc}")
        sys.exit(1)

    # Validate subscription management mutual exclusivity
    if args.add_sub is not None and args.remove_sub is not None:
        log.error("[-] Conflicting options: Cannot specify both --add-sub and --remove-sub simultaneously.")
        sys.exit(1)

    # Validate config/sub management vs pipeline phase execution flags
    pipeline_flags_present = bool(args.flag_run or args.flag_check_only or args.flag_deploy_only or args.dry_run)
    if (args.add_sub is not None or args.remove_sub is not None) and pipeline_flags_present:
        log.error("[-] Conflicting options: Cannot specify pipeline execution flags with subscription management flags.")
        sys.exit(1)

    if args.action == "config" and pipeline_flags_present:
        log.error("[-] Conflicting options: Cannot specify pipeline phase flags with 'config' action.")
        sys.exit(1)

    if args.show_config and pipeline_flags_present:
        log.error("[-] Conflicting options: Cannot specify pipeline phase flags with --show-config.")
        sys.exit(1)

    routing_management = args.action == "routing" or args.routing_setup or args.routing_show
    explicit_pipeline_action = (
        getattr(args, "action_explicit", False) and args.action in {"run", "check", "deploy"}
    )
    if routing_management and (pipeline_flags_present or explicit_pipeline_action):
        log.error("[-] Conflicting options: Routing setup/display cannot be combined with pipeline execution.")
        sys.exit(1)
    if routing_management and (
        args.action == "config" or args.show_config or args.add_sub is not None or args.remove_sub is not None
    ):
        log.error("[-] Conflicting options: Choose routing setup/display or other configuration management.")
        sys.exit(1)
    if args.action == "serve" and (
        pipeline_flags_present or routing_management or args.show_config
        or args.add_sub is not None or args.remove_sub is not None
    ):
        log.error("[-] Conflicting options: 'serve' runs on its own, without pipeline, routing or configuration options.")
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
                print(f"Run `{command}` to test proxies and generate routing artifacts.")
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

    if args.disable_router_validation:
        config["enable_router_validation"] = False

    if args.speedtest_timeout is not None:
        if args.speedtest_timeout <= 0:
            log.error("[-] Speedtest timeout must be a positive integer.")
            sys.exit(1)
        config["speedtest_timeout"] = args.speedtest_timeout

    if args.router_host is not None:
        host_val = args.router_host.strip()
        if not host_val:
            log.error("[-] Router host cannot be empty.")
            sys.exit(1)
        config["router_host"] = host_val

    port_options = [
        ("router-api-port", args.router_api_port, "router_api_port"),
        ("router-proxy-port", args.router_proxy_port, "router_proxy_port"),
        ("router-ssh-port", args.router_ssh_port, "router_ssh_port"),
    ]
    for flag_name, port_val, cfg_key in port_options:
        if port_val is not None:
            if not (1 <= port_val <= 65535):
                log.error(f"[-] Invalid port {port_val} for --{flag_name}. Port must be between 1 and 65535.")
                sys.exit(1)
            config[cfg_key] = port_val

    if args.router_ssh_user is not None:
        user_val = args.router_ssh_user.strip()
        if not user_val:
            log.error("[-] Router SSH user cannot be empty.")
            sys.exit(1)
        config["router_ssh_user"] = user_val
    if args.router_ssh_pass:
        config["router_ssh_pass"] = args.router_ssh_pass

    # Determine execution phase
    action_explicit = getattr(args, "action_explicit", False)
    explicit_run = bool(args.flag_run or (args.action == "run" and action_explicit))
    deploy_only = bool(args.flag_deploy_only or (args.action == "deploy" and action_explicit))
    check_only = bool(args.flag_check_only or (args.action == "check" and action_explicit))
    dry_run = args.dry_run

    if explicit_run and (check_only or deploy_only):
        log.error("[-] Conflicting phase options: Cannot specify full run ('--run') together with check-only or deploy-only.")
        sys.exit(1)

    if check_only and deploy_only:
        log.error("[-] Conflicting phase options: Cannot specify both check and deploy phases simultaneously.")
        sys.exit(1)

    dash = VPNDashboard(config=config)

    log.info("[*] Starting nodesieve pipeline...")
    success = asyncio.run(
        dash.run_pipeline_async(
            check_only=check_only,
            deploy_only=deploy_only,
            dry_run=dry_run,
        )
    )

    if not success:
        sys.exit(1)
