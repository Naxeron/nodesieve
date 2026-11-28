"""Memory detection and startup with the minimal packages on OpenWrt and Termux."""

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


def test_free_memory_from_proc_meminfo_and_psutil_fallback(tmp_path, monkeypatch):
    meminfo(tmp_path, monkeypatch, "MemTotal: 16000000 kB\nMemFree: 500000 kB\nMemAvailable: 2048000 kB\n")
    assert get_free_memory_mb() == 2000

    meminfo(tmp_path, monkeypatch, "MemTotal: 1000000 kB\nMemFree: 102400 kB\nBuffers: 51200 kB\nCached: 51200 kB\n")
    assert get_free_memory_mb() == 200

    monkeypatch.setattr(logging_module, "MEMINFO_PATH", str(tmp_path / "missing"))
    fake = types.SimpleNamespace(virtual_memory=lambda: types.SimpleNamespace(available=3 * 1024 * 1024 * 1024))
    monkeypatch.setitem(sys.modules, "psutil", fake)
    assert get_free_memory_mb() == 3072
    monkeypatch.setitem(sys.modules, "psutil", None)
    assert get_free_memory_mb() == UNKNOWN_MEMORY_MB


WITHOUT_OPTIONAL_DEPS = """
import sys, tempfile, importlib, pkgutil
from pathlib import Path
sys.modules["psutil"] = None
sys.modules["yaml"] = None
import nodesieve
for module in pkgutil.walk_packages(nodesieve.__path__, "nodesieve."):
    importlib.import_module(module.name)
from nodesieve.core.limits import ResourceLimits
from nodesieve.logging import get_free_memory_mb
from nodesieve.feed import LINKS_NAME, BASE64_NAME, write_feed
workers, free = ResourceLimits.get_max_safe_workers({})
assert workers >= 1 and free > 0 and get_free_memory_mb() > 0
with tempfile.TemporaryDirectory() as directory:
    node = "vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&type=tcp#One"
    result = write_feed([node], {"feed_dir": directory})
    assert result["written"] and result["count"] == 1
    assert (Path(directory) / LINKS_NAME).exists()
    assert (Path(directory) / BASE64_NAME).exists()
from nodesieve.ui.cli import main
main(["--help"])
"""


def test_nodesieve_runs_without_psutil_or_pyyaml():
    finished = subprocess.run([sys.executable, "-c", WITHOUT_OPTIONAL_DEPS], cwd=PROJECT,
                              capture_output=True, text=True, timeout=60)
    assert finished.returncode == 0, finished.stderr
    assert "--rank-by" in finished.stdout


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-termux.txt"])
def test_requirements_only_ask_aiohttp_and_non_linux_psutil(name):
    lines = [line.strip() for line in (PROJECT / name).read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    psutil = [line for line in lines if line.startswith("psutil")]
    assert all('platform_system != "Linux" and platform_system != "Android"' in line for line in psutil)
    assert "aiohttp" in lines and not any("yaml" in line.lower() for line in lines)
