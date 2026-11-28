"""Logging, progress display, thread-safe printing, memory queries, and error tracking."""

import asyncio
import datetime
import logging
import sys
import threading
import time
from typing import Dict, Optional

_print_lock = threading.Lock()
MEMINFO_PATH = "/proc/meminfo"
UNKNOWN_MEMORY_MB = 1024.0


def get_free_memory_mb() -> float:
    """Available system memory in MB from /proc/meminfo (Linux/Android) or psutil elsewhere."""
    fields: Dict[str, int] = {}
    try:
        with open(MEMINFO_PATH, encoding="ascii") as meminfo:
            for line in meminfo:
                name, _, rest = line.partition(":")
                parts = rest.split()
                if parts and parts[0].isdigit():
                    fields[name.strip()] = int(parts[0])
                if name == "MemAvailable":
                    break
    except (OSError, UnicodeDecodeError):
        pass
    if "MemAvailable" in fields:
        return fields["MemAvailable"] / 1024
    if "MemFree" in fields:
        return (fields["MemFree"] + fields.get("Buffers", 0) + fields.get("Cached", 0)) / 1024
    try:
        import psutil
    except ImportError:
        return UNKNOWN_MEMORY_MB
    return psutil.virtual_memory().available / (1024 * 1024)


def _prefix() -> str:
    return f"[{datetime.datetime.now():%H:%M:%S} | {get_free_memory_mb():.0f}MB Free] "


class MemPrefixFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        return _prefix() + msg if record.levelno == logging.INFO and msg.startswith(("[*", "[-", "[>")) else msg


def setup_logger(name: str = "nodesieve") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(MemPrefixFormatter())
        logger.addHandler(ch)
    return logger


log = setup_logger()


class ErrorTracker:
    """Thread-safe collector and summarizer for runtime errors."""

    _errors: Dict[str, int] = {}
    _lock = threading.Lock()

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._errors.clear()

    @classmethod
    def record_error(cls, context: str, e: Exception) -> None:
        msg = str(e).strip()
        if len(msg) >= 150:
            msg = msg[:147] + "..."
        key = f"[{context}] {type(e).__name__}: {msg}" if msg else f"[{context}] {type(e).__name__}"
        with cls._lock:
            cls._errors[key] = cls._errors.get(key, 0) + 1

    @classmethod
    def print_summary(cls) -> None:
        with cls._lock:
            if not cls._errors:
                return
            log.info("\n=== Error Summary ===")
            for err, count in sorted(cls._errors.items(), key=lambda x: x[1], reverse=True)[:20]:
                log.info(f"{err} x{count}")
            log.info("=====================\n")


def safe_print(msg: str) -> None:
    line = "\033[2K\r" + _prefix() + msg + "\n"
    with _print_lock:
        sys.stdout.write(line)
        sys.stdout.flush()


def update_progress(completed: int, total: int, start_time: float) -> None:
    elapsed = time.time() - start_time
    perc = int(100 * completed / total) if total > 0 else 100
    filled = int(30 * completed / total) if total > 0 else 30
    bar = "=" * filled + "-" * (30 - filled)
    if completed > 0 and elapsed > 2:
        eta_m, eta_s = divmod(int((total - completed) / (completed / elapsed)), 60)
        eta_str = f"{eta_m}m {eta_s}s"
    else:
        eta_str = "--m --s"
    with _print_lock:
        sys.stdout.write(f"\033[2K\r[{bar}] {perc}% | {completed}/{total} | ETA: {eta_str}")
        sys.stdout.flush()


async def safe_close_writer(writer: Optional[asyncio.StreamWriter], timeout: float = 0.2) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except Exception:
        pass
