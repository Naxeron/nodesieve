"""Shared test setup: tests run against a temporary project directory, never the real one.

The checker keeps its output in the project directory: apply_to_router.sh (which
`deploy` pushes to the router as it is), crashed_nodes.txt, sub_cache/ and the
default settings file. A test that wrote there would replace or truncate the
user's real files, so every test gets an empty project directory of its own, and
the run fails if any file in the real project directory changed anyway.
"""

import os
from pathlib import Path

import pytest

from nodesieve.core.fetcher import NodeFetcher

PROJECT_DIR = Path(__file__).resolve().parent.parent

# Modules that build paths inside the project directory when they run.
_PROJECT_ROOT_USERS = (
    "nodesieve.core.fetcher",
    "nodesieve.core.mihomo",
    "nodesieve.core.router_validator",
    "nodesieve.parsers.base",
    "nodesieve.router.pusher",
    "nodesieve.router.script_generator",
    "nodesieve.ui.cli",
    "nodesieve.ui.dashboard",
)


@pytest.fixture(autouse=True)
def _temporary_project_dir(tmp_path_factory, monkeypatch):
    """Point the checker's project directory, and so its output files, at an empty temporary one."""
    project = tmp_path_factory.mktemp("project")
    for module in _PROJECT_ROOT_USERS:
        monkeypatch.setattr(f"{module}.PROJECT_ROOT", project)
    monkeypatch.setattr(NodeFetcher, "cache_dir", str(project / "sub_cache"))


def _project_files():
    """Size and modification time of each file in the project, skipping caches and dot-directories."""
    files = {}
    for directory, subdirs, names in os.walk(PROJECT_DIR):
        subdirs[:] = [d for d in subdirs if not d.startswith(".") and d not in ("__pycache__", "venv")]
        for name in names:
            path = os.path.join(directory, name)
            try:
                stat = os.lstat(path)
            except FileNotFoundError:
                continue
            files[os.path.relpath(path, PROJECT_DIR)] = (stat.st_size, stat.st_mtime_ns)
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
    changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
    session.config.stash[_CHANGED_FILES] = changed
    if changed and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    changed = config.stash.get(_CHANGED_FILES, None)
    if changed:
        terminalreporter.write_sep("=", "files in the project directory changed during the test run", red=True)
        for path in changed:
            terminalreporter.write_line(f"  {path}")
        terminalreporter.write_line(
            "A test must write to a temporary directory. Files edited during the run show up here too."
        )
