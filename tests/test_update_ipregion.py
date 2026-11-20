"""The ipregion.sh updater, with GitHub replaced by canned answers."""

import json
import os
import shutil

import pytest

from nodesieve.constants import IPREGION_SCRIPT_PATH
from nodesieve.location import GEOIP_GROUP, REPORT_VERSION
import update_ipregion

OLD = "1" * 40
NEW = "2" * 40
NOTICE = (
    "`ipregion.sh` is an unmodified copy of ipregion, taken from commit\n"
    f"[`{OLD[:7]}`](https://github.com/vernette/ipregion/commit/{OLD})\n"
    "(2026-01-01). It is distributed under the MIT License.\n"
)


def script(version=REPORT_VERSION, groups=f"platforms {GEOIP_GROUP}", body="echo new"):
    lines = ["#!/usr/bin/env bash", f"readonly SERVICE_GROUPS=({groups})"]
    if version is not None:
        lines.append(f"readonly JSON_VERSION={version}")
    return ("\n".join(lines + [body]) + "\n").encode()


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A project directory with an outdated script; `upstream` is what GitHub would serve."""
    (tmp_path / "ipregion.sh").write_bytes(script(body="echo old"))
    (tmp_path / "THIRD_PARTY_NOTICES.md").write_text(NOTICE)
    upstream = {"script": script()}
    monkeypatch.setattr(update_ipregion, "latest_upstream", lambda: (NEW, "2026-02-03"))
    monkeypatch.setattr(update_ipregion, "download", lambda sha: upstream["script"])
    return tmp_path, upstream


def test_new_upstream_version_replaces_the_script_and_its_recorded_commit(project, capsys):
    root, upstream = project
    assert update_ipregion.update(root) == 0
    assert (root / "ipregion.sh").read_bytes() == upstream["script"]
    assert os.access(root / "ipregion.sh", os.X_OK)
    notice = (root / "THIRD_PARTY_NOTICES.md").read_text()
    assert f"[`{NEW[:7]}`](https://github.com/vernette/ipregion/commit/{NEW})\n(2026-02-03). It is" in notice
    assert OLD not in notice
    assert f"compare/{OLD}...{NEW}" in capsys.readouterr().out
    assert sorted(path.name for path in root.iterdir()) == ["THIRD_PARTY_NOTICES.md", "ipregion.sh"]


def test_script_that_is_already_current_only_gets_its_recorded_commit_corrected(project, capsys):
    root, upstream = project
    (root / "ipregion.sh").write_bytes(upstream["script"])
    os.chmod(root / "ipregion.sh", 0o644)
    assert update_ipregion.update(root) == 0
    assert "up to date" in capsys.readouterr().out
    assert not os.access(root / "ipregion.sh", os.X_OK)  # the file itself was not rewritten
    assert update_ipregion.recorded_commit(root) == NEW

    assert update_ipregion.update(root) == 0
    assert "Corrected" not in capsys.readouterr().out


@pytest.mark.parametrize("candidate,reason", [
    (script(version=REPORT_VERSION + 1), f"JSON report version {REPORT_VERSION + 1}"),
    (script(version=None), "does not state its JSON report version"),
    (script(groups="platforms cdn"), f'no "{GEOIP_GROUP}" group'),
    (b"<!DOCTYPE html><html>Not Found</html>", "not a bash script"),
    (b"", "not a bash script"),
])
def test_incompatible_upstream_version_is_refused(project, capsys, candidate, reason):
    root, upstream = project
    upstream["script"] = candidate
    assert update_ipregion.update(root) == 1
    assert reason in capsys.readouterr().err
    assert (root / "ipregion.sh").read_bytes() == script(body="echo old")
    assert (root / "THIRD_PARTY_NOTICES.md").read_text() == NOTICE


@pytest.mark.skipif(not shutil.which("bash"), reason="Requires bash")
def test_upstream_version_with_a_syntax_error_is_refused(project, capsys):
    root, upstream = project
    upstream["script"] = script(body="if true; then")
    assert update_ipregion.update(root) == 1
    assert "syntax error" in capsys.readouterr().err
    assert (root / "ipregion.sh").read_bytes() == script(body="echo old")


def test_unreachable_github_changes_nothing(project, monkeypatch, capsys):
    root, _ = project

    def offline():
        raise OSError("network is unreachable")

    monkeypatch.setattr(update_ipregion, "latest_upstream", offline)
    assert update_ipregion.update(root) == 1
    assert "network is unreachable" in capsys.readouterr().err
    assert (root / "ipregion.sh").read_bytes() == script(body="echo old")
    assert (root / "THIRD_PARTY_NOTICES.md").read_text() == NOTICE


def test_notices_without_a_commit_reference_are_reported_not_rewritten(project, capsys):
    root, upstream = project
    (root / "THIRD_PARTY_NOTICES.md").write_text("ipregion.sh comes from vernette/ipregion.\n")
    assert update_ipregion.update(root) == 0
    assert (root / "ipregion.sh").read_bytes() == upstream["script"]
    assert f"Record {NEW[:7]} there by hand" in capsys.readouterr().out
    assert (root / "THIRD_PARTY_NOTICES.md").read_text() == "ipregion.sh comes from vernette/ipregion.\n"


def test_latest_upstream_reads_the_commit_and_its_date(monkeypatch):
    answer = [{"sha": NEW, "commit": {"committer": {"date": "2026-02-03T04:05:06Z"}}}]
    monkeypatch.setattr(update_ipregion, "_get", lambda url: json.dumps(answer).encode())
    assert update_ipregion.latest_upstream() == (NEW, "2026-02-03")


@pytest.mark.parametrize("answer", [
    [],
    {"message": "API rate limit exceeded"},
    [{"sha": "../../evil", "commit": {"committer": {"date": "2026-02-03T04:05:06Z"}}}],
    [{"sha": NEW, "commit": {"committer": {"date": "yesterday"}}}],
])
def test_unexpected_github_answer_is_an_error_not_an_update(project, monkeypatch, capsys, answer):
    root, _ = project
    monkeypatch.undo()
    monkeypatch.setattr(update_ipregion, "_get", lambda url: json.dumps(answer).encode())
    assert update_ipregion.update(root) == 1
    assert "Could not get ipregion.sh from GitHub" in capsys.readouterr().err
    assert (root / "ipregion.sh").read_bytes() == script(body="echo old")


def test_bundled_script_is_one_the_updater_would_accept():
    with open(IPREGION_SCRIPT_PATH, "rb") as bundled:
        assert update_ipregion.incompatibilities(bundled.read()) == []
