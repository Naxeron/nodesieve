#!/usr/bin/env python3
"""Replace the bundled ipregion.sh with the latest version from its repository.

    python update_ipregion.py

A newer version is installed only if it still prints the JSON report this project
reads; otherwise ipregion.sh is left as it is. THIRD_PARTY_NOTICES.md records the
commit the script was taken from. Review an update with `git diff`, then commit it.
"""

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional, Tuple
import urllib.request

from proxy_sites.location import GEOIP_GROUP, REPORT_VERSION

REPOSITORY = "vernette/ipregion"
SCRIPT_NAME = "ipregion.sh"
NOTICES_NAME = "THIRD_PARTY_NOTICES.md"
PROJECT_ROOT = Path(__file__).resolve().parent

# The commit link and date in THIRD_PARTY_NOTICES.md, e.g.
# [`d431acf`](https://github.com/vernette/ipregion/commit/<40 hex digits>) (2026-11-16)
RECORDED_SOURCE = re.compile(
    r"\[`[0-9a-f]{7,40}`\]\(https://github\.com/" + re.escape(REPOSITORY)
    + r"/commit/([0-9a-f]{40})\)(\s*)\(\d{4}-\d{2}-\d{2}\)"
)


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "update-ipregion"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def latest_upstream() -> Tuple[str, str]:
    """The upstream commit that last changed the script, and its date as YYYY-MM-DD."""
    commits = json.loads(_get(
        f"https://api.github.com/repos/{REPOSITORY}/commits?path={SCRIPT_NAME}&per_page=1"
    ))
    sha = commits[0]["sha"]
    date = commits[0]["commit"]["committer"]["date"][:10]
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError("unexpected answer from the GitHub API")
    return sha, date


def download(sha: str) -> bytes:
    """The script exactly as it is in the given upstream commit."""
    return _get(f"https://raw.githubusercontent.com/{REPOSITORY}/{sha}/{SCRIPT_NAME}")


def incompatibilities(script: bytes) -> List[str]:
    """Why this version of the script cannot replace the bundled one. Empty if it can."""
    text = script.decode("utf-8", errors="replace")
    first_line = text.split("\n", 1)[0]
    if not first_line.startswith("#!") or "bash" not in first_line:
        return ["it is not a bash script"]
    reasons = []
    version = re.search(r"^(?:readonly\s+)?JSON_VERSION=[\"']?(\d+)", text, re.MULTILINE)
    if version is None:
        reasons.append("it does not state its JSON report version")
    elif int(version.group(1)) != REPORT_VERSION:
        reasons.append(
            f"it prints JSON report version {version.group(1)}, and this project reads version {REPORT_VERSION}"
        )
    groups = re.search(r"^(?:readonly\s+)?SERVICE_GROUPS=\(([^)]*)\)", text, re.MULTILINE)
    if groups is None or GEOIP_GROUP not in groups.group(1).split():
        reasons.append(f'it has no "{GEOIP_GROUP}" group')
    bash = shutil.which("bash")
    if bash:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / SCRIPT_NAME
            candidate.write_bytes(script)
            # -n only parses the script, it does not run it.
            check = subprocess.run([bash, "-n", str(candidate)], capture_output=True, text=True)
        if check.returncode != 0:
            detail = (check.stderr.strip().splitlines() or ["no details"])[-1]
            reasons.append(f"bash finds a syntax error in it: {detail}")
    return reasons


def recorded_commit(root: Path) -> Optional[str]:
    """The upstream commit that THIRD_PARTY_NOTICES.md names as the bundled script's source."""
    try:
        match = RECORDED_SOURCE.search((root / NOTICES_NAME).read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return None
    return match.group(1) if match else None


def record_commit(root: Path, sha: str, date: str) -> bool:
    """Point THIRD_PARTY_NOTICES.md at a new source commit. False if it has no such reference."""
    path = root / NOTICES_NAME
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    updated, count = RECORDED_SOURCE.subn(
        lambda match: f"[`{sha[:7]}`](https://github.com/{REPOSITORY}/commit/{sha}){match.group(2)}({date})",
        text, count=1,
    )
    if count:
        path.write_bytes(updated.encode("utf-8"))
    return bool(count)


def install(root: Path, script: bytes) -> None:
    """Replace the bundled script in one step, keeping it executable."""
    descriptor, temporary = tempfile.mkstemp(prefix=".ipregion-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(script)
        os.chmod(temporary, 0o755)
        os.replace(temporary, root / SCRIPT_NAME)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def update(root: Path = PROJECT_ROOT) -> int:
    """Bring the bundled script up to date. Returns the process exit code."""
    try:
        sha, date = latest_upstream()
        script = download(sha)
    except (OSError, ValueError, LookupError, TypeError, http.client.HTTPException) as error:
        print(f"Could not get {SCRIPT_NAME} from GitHub: {error}", file=sys.stderr)
        return 1

    target = root / SCRIPT_NAME
    previous = recorded_commit(root)
    if target.is_file() and target.read_bytes() == script:
        print(f"{SCRIPT_NAME} is up to date (upstream commit {sha[:7]}, {date}).")
        if previous != sha and record_commit(root, sha, date):
            print(f"Corrected the commit recorded in {NOTICES_NAME}.")
        return 0

    reasons = incompatibilities(script)
    if reasons:
        print(f"Upstream commit {sha[:7]} ({date}) was not installed:", file=sys.stderr)
        for reason in reasons:
            print(f"  - {reason}", file=sys.stderr)
        print(f"{SCRIPT_NAME} was left unchanged.", file=sys.stderr)
        return 1

    install(root, script)
    print(f"Updated {SCRIPT_NAME} to upstream commit {sha[:7]} ({date}).")
    if previous and previous != sha:
        print(f"Changes: https://github.com/{REPOSITORY}/compare/{previous}...{sha}")
    if not record_commit(root, sha, date):
        print(f"{NOTICES_NAME} has no commit reference to update. Record {sha[:7]} there by hand.")
    print("Review it with `git diff`, then commit.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    return update()


if __name__ == "__main__":
    sys.exit(main())
