"""Logging, progress display, thread-safe printing, and error tracking utilities."""

import asyncio
import datetime
import logging
import sys
import threading
import time
from typing import Dict, Optional
import psutil

# Safe Print / Progress lock
_print_lock = threading.Lock()


def get_free_memory_mb() -> float:
    """Returns available system memory in megabytes."""
    return psutil.virtual_memory().available / (1024 * 1024)


class MemPrefixFormatter(logging.Formatter):
    """Logging formatter that prefixes info lines with current timestamp and free memory."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        free_mem = get_free_memory_mb()
        prefix = f"[{timestamp} | {free_mem:.0f}MB Free] "

        # Only prefix if it's an info level starting with specific indicator tags
        if record.levelno == logging.INFO and record.getMessage().startswith(("[*", "[-", "[>")):
            return prefix + record.getMessage()
        return record.getMessage()


def setup_logger(name: str = "nodesieve") -> logging.Logger:
    """Creates or configures standard logger for the application."""
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
        """Clears all accumulated errors."""
        with cls._lock:
            cls._errors.clear()

    @classmethod
    def record_error(cls, context: str, e: Exception) -> None:
        """Records an error occurrence with formatted message and context."""
        err_msg = str(e).strip()
        if not err_msg:
            err_str = f"[{context}] {type(e).__name__}"
        else:
            err_msg = err_msg if len(err_msg) < 150 else err_msg[:147] + "..."
            err_str = f"[{context}] {type(e).__name__}: {err_msg}"

        with cls._lock:
            cls._errors[err_str] = cls._errors.get(err_str, 0) + 1

    @classmethod
    def print_summary(cls) -> None:
        """Logs a formatted summary of the top recorded errors."""
        with cls._lock:
            if not cls._errors:
                return
            log.info("\n=== Error Summary ===")
            sorted_errs = sorted(cls._errors.items(), key=lambda x: x[1], reverse=True)
            for err, count in sorted_errs[:20]:
                log.info(f"{err} x{count}")
            log.info("=====================\n")


def safe_print(msg: str) -> None:
    """Thread-safe line print with memory timestamp prefix, clearing current terminal line."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    free_mem = get_free_memory_mb()
    prefix = f"[{timestamp} | {free_mem:.0f}MB Free] "

    with _print_lock:
        sys.stdout.write("\033[2K\r")
        sys.stdout.write(prefix + msg + "\n")
        sys.stdout.flush()


def update_progress(completed: int, total: int, start_time: float) -> None:
    """Renders a single-line progress bar with percentage, counts, and estimated time remaining."""
    elapsed = time.time() - start_time
    perc = int(100 * completed / total) if total > 0 else 100
    bar_len = 30
    filled = int(bar_len * completed / total) if total > 0 else bar_len
    bar = "=" * filled + "-" * (bar_len - filled)

    if completed > 0 and elapsed > 2:
        rate = completed / elapsed
        eta = (total - completed) / rate
        eta_m, eta_s = divmod(int(eta), 60)
        eta_str = f"{eta_m}m {eta_s}s"
    else:
        eta_str = "--m --s"

    line = f"\r[{bar}] {perc}% | {completed}/{total} | ETA: {eta_str}"
    with _print_lock:
        sys.stdout.write("\033[2K\r" + line)
        sys.stdout.flush()


async def safe_close_writer(writer: Optional[asyncio.StreamWriter], timeout: float = 0.2) -> None:
    """Safely closes an asyncio StreamWriter adhering to concurrency teardown guidelines.

    Wraps writer.wait_closed() in a short timeout to prevent hangs if the remote peer
    does not immediately acknowledge TCP FIN.
    """
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except Exception:
        pass
