"""Shared test setup: isolate PROJECT_ROOT to a temp dir and forbid core downloads."""

import os
from pathlib import Path

import pytest

from nodesieve.core.fetcher import NodeFetcher

PROJECT_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT_USERS = (
    "nodesieve.core.batch",
    "nodesieve.core.fetcher",
    "nodesieve.feed",
    "nodesieve.ui.cli",
)


@pytest.fixture(autouse=True)
def _temporary_project_dir(tmp_path_factory, monkeypatch):
    project = tmp_path_factory.mktemp("project")
    for module in _PROJECT_ROOT_USERS:
        monkeypatch.setattr(f"{module}.PROJECT_ROOT", project)
    monkeypatch.setattr(NodeFetcher, "cache_dir", str(project / "sub_cache"))


@pytest.fixture(autouse=True)
def _no_core_downloads(monkeypatch):
    def refuse(url, *args, **kwargs):
        raise AssertionError(f"a test tried to download {url}")

    monkeypatch.setattr("nodesieve.core.xray.download", refuse)
    monkeypatch.setattr("nodesieve.core.xray.release_assets", refuse)


def _project_files():
    files = {}
    for directory, subdirs, names in os.walk(PROJECT_DIR):
        subdirs[:] = [d for d in subdirs if not d.startswith(".") and d not in ("__pycache__", "venv")]
        for name in names:
            path = os.path.join(directory, name)
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            files[os.path.relpath(path, PROJECT_DIR)] = (st.st_size, st.st_mtime_ns)
    return files


_FILES_AT_START = pytest.StashKey[dict]()
_CHANGED_FILES = pytest.StashKey[list]()


def pytest_sessionstart(session):
    session.config.stash[_FILES_AT_START] = _project_files()


def pytest_sessionfinish(session, exitstatus):
    before = session.config.stash.get(_FILES_AT_START, None)
    if before is None:
        return
    after = _project_files()
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    session.config.stash[_CHANGED_FILES] = changed
    if changed and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    changed = config.stash.get(_CHANGED_FILES, None)
    if changed:
        terminalreporter.write_sep("=", "files in the project directory changed during the test run", red=True)
        for path in changed:
            terminalreporter.write_line(f"  {path}")
