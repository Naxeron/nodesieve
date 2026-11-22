"""Memory detection and startup with the packages available on OpenWrt and Termux."""

from pathlib import Path
import subprocess
import sys
import types

import pytest

import nodesieve.logging as logging_module
from nodesieve.logging import UNKNOWN_MEMORY_MB, get_free_memory_mb

PROJECT = Path(__file__).resolve().parent.parent


def meminfo(tmp_path, monkeypatch, text):
    path = tmp_path / "meminfo"
    path.write_text(text)
    monkeypatch.setattr(logging_module, "MEMINFO_PATH", str(path))


def test_free_memory_is_memavailable_from_proc_meminfo(tmp_path, monkeypatch):
    meminfo(tmp_path, monkeypatch, "MemTotal:       16000000 kB\nMemFree:          500000 kB\n"
                                   "MemAvailable:    2048000 kB\nBuffers:          100000 kB\n")
    assert get_free_memory_mb() == 2000


def test_kernels_without_memavailable_count_free_memory_buffers_and_cache(tmp_path, monkeypatch):
    meminfo(tmp_path, monkeypatch, "MemTotal: 1000000 kB\nMemFree: 102400 kB\nBuffers: 51200 kB\nCached: 51200 kB\n")
    assert get_free_memory_mb() == 200


def test_without_proc_meminfo_psutil_answers(tmp_path, monkeypatch):
    monkeypatch.setattr(logging_module, "MEMINFO_PATH", str(tmp_path / "missing"))
    fake = types.SimpleNamespace(virtual_memory=lambda: types.SimpleNamespace(available=3 * 1024 * 1024 * 1024))
    monkeypatch.setitem(sys.modules, "psutil", fake)
    assert get_free_memory_mb() == 3072
    monkeypatch.setitem(sys.modules, "psutil", None)  # not installed
    assert get_free_memory_mb() == UNKNOWN_MEMORY_MB


# Exercise every module in a fresh interpreter with psutil unavailable.
WITHOUT_PSUTIL = """
import sys
sys.modules["psutil"] = None
import importlib, pkgutil
import nodesieve
for module in pkgutil.walk_packages(nodesieve.__path__, "nodesieve."):
    importlib.import_module(module.name)
from nodesieve.core.limits import ResourceLimits
from nodesieve.logging import get_free_memory_mb
workers, free = ResourceLimits.get_max_safe_workers({})
assert workers >= 1 and free > 0 and get_free_memory_mb() > 0
from nodesieve.ui.cli import main
main(["--help"])
"""


def test_nodesieve_runs_without_psutil():
    finished = subprocess.run([sys.executable, "-c", WITHOUT_PSUTIL], cwd=PROJECT, capture_output=True,
                              text=True, timeout=60)
    assert finished.returncode == 0, finished.stderr
    assert "--feed-host" in finished.stdout


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-termux.txt"])
def test_requirements_ask_psutil_only_where_proc_meminfo_is_missing(name):
    lines = [line.strip() for line in (PROJECT / name).read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    psutil = [line for line in lines if line.startswith("psutil")]
    assert all('platform_system != "Linux" and platform_system != "Android"' in line for line in psutil)
    assert {"aiohttp", "PyYAML"} <= set(lines)
