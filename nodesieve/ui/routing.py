"""Dependency-free terminal editor for Steer main-pool routing preferences."""

from copy import deepcopy
import os
import re
from typing import Callable, Optional

from nodesieve.router.steer import OUTPUT_DIR
from nodesieve.routing import normalize_routing


def _main_lines(policy: dict) -> list[str]:
    return [
        "Main proxy pool: automatic location ranking",
        f"  Excluded countries: {', '.join(policy['excluded_countries']) or '(none)'}",
        f"  Allowed countries: {', '.join(policy['allowed_countries']) or 'any country outside the exclusions'}",
        f"  Evidence required: {policy['min_agreement'] * 100:g}% agreement, at least {policy['min_votes']} valid reports per IP family.",
        "  All qualifying nodes; ranked by agreement, reports, then latency.",
        "  Steer then picks a working server by its own selection setting.",
    ]


def format_routing(config: dict) -> str:
    """Show preferences without exposing subscriptions, credentials, or node URLs."""
    routing = normalize_routing(config.get("routing"))
    lines = [
        "Steer routing",
        f"Enabled: {'ON' if routing['enabled'] else 'OFF'}",
        "",
        *_main_lines(routing["main"]),
        "",
        "Steer's own services and devices still decide which traffic uses its main section.",
        "A main pool without a qualifying proxy is reported as unresolved.",
        f"Output directory: {config.get('routing_output_dir') or OUTPUT_DIR}",
    ]
    return "\n".join(lines)


def _edit_main(
    routing: dict,
    choice: str,
    read: Callable[[str], str],
    write: Callable[[str], None],
) -> None:
    candidate = deepcopy(routing)
    policy = candidate["main"]
    if choice in {"2", "3"}:
        key = "excluded_countries" if choice == "2" else "allowed_countries"
        label = "Excluded" if choice == "2" else "Allowed"
        current = ", ".join(policy[key]) or "none"
        value = read(f"{label} country codes [{current}] (blank keeps current, '-' clears): ").strip()
        if not value:
            return
        policy[key] = [] if value == "-" else [code.upper() for code in re.split(r"[\s,]+", value) if code]
    else:
        threshold = read(f"Minimum agreement, percent [{policy['min_agreement'] * 100:g}]: ").strip()
        votes = read(f"Minimum valid country reports per IP family [{policy['min_votes']}]: ").strip()
        try:
            if threshold:
                policy["min_agreement"] = float(threshold.removesuffix("%")) / 100
            if votes:
                policy["min_votes"] = int(votes)
        except ValueError:
            write("Use a percentage such as 60 and a whole number of reports such as 3. Main settings were not changed.")
            return
    try:
        checked = normalize_routing(candidate)
    except ValueError as exc:
        write(f"Invalid main preference: {exc}. Main settings were not changed.")
        return
    routing["main"] = checked["main"]
    write("Main preferences updated. Choose Save settings to keep them.")


def routing_menu(
    config: dict,
    input_fn: Optional[Callable[[str], str]] = None,
    output_fn: Optional[Callable[[str], None]] = None,
) -> Optional[dict]:
    """Return a saved draft or None on cancel; caller handles TTY checks and saving."""
    read = input_fn or input
    write = output_fn or print
    draft = deepcopy(config)
    draft["routing"] = normalize_routing(draft.get("routing"))
    write("Set your preferences, enable Steer routing, then save. Saving does not deploy.")
    write("Main supplies the servers for the traffic already assigned to the main section of Steer.")
    write("Location agreement = reports for the leading country / all valid country reports.")
    write("For example, 3 of 5 reports agreeing means 60%. ipregion is the primary source.")
    write("IPv4 and IPv6 are checked separately. Ties, unknown country, and insufficient evidence do not qualify.")
    try:
        while True:
            write("\n" + format_routing(draft))
            write("\n1. Enable / disable Steer routing\n2. Excluded countries\n3. Allowed countries (optional)")
            write("4. Agreement threshold and minimum reports\n5. Output directory\n6. Save settings\n0. Cancel")
            choice = read("Choice: ").strip().lower()
            if choice in {"0", "q", "quit", "cancel"}:
                write("Cancelled. Settings were not saved.")
                return None
            if choice in {"6", "s", "save"}:
                draft["routing"] = normalize_routing(draft["routing"])
                return draft
            if choice == "1":
                draft["routing"]["enabled"] = not draft["routing"]["enabled"]
            elif choice in {"2", "3", "4"}:
                _edit_main(draft["routing"], choice, read, write)
            elif choice == "5":
                value = read(f"Output directory [{OUTPUT_DIR}]: ").strip() or OUTPUT_DIR
                draft["routing_output_dir"] = os.path.abspath(os.path.expanduser(value))
            else:
                write("Choose a number from 0 to 6.")
    except (EOFError, KeyboardInterrupt):
        write("\nCancelled. Settings were not saved.")
        return None
