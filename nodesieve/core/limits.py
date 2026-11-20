"""System resource discovery, file descriptor scaling, and concurrency limit calculations."""

from typing import Optional, Tuple
from nodesieve.constants import IS_TERMUX
from nodesieve.logging import get_free_memory_mb


class ResourceLimits:
    """Calculates safe concurrent worker bounds based on system memory and OS file descriptor limits."""

    @staticmethod
    def get_max_safe_workers(config: Optional[dict] = None) -> Tuple[int, float]:
        """Determines maximum safe concurrent HTTP/Mihomo workers given memory and open file limits."""
        free_mem_mb = get_free_memory_mb()
        safe_mem_mb = max(0, free_mem_mb - 500)

        mem_per_worker = 8.0
        if config and "mem_per_worker" in config:
            try:
                mem_per_worker = float(config["mem_per_worker"])
            except (ValueError, TypeError):
                pass

        max_safe_workers = int(safe_mem_mb / mem_per_worker)

        # Scale RLIMIT_NOFILE if on Unix-like platform
        try:
            import resource

            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_soft = 65535 if hard == resource.RLIM_INFINITY else hard
            if soft < target_soft:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (target_soft, hard))
                    soft = target_soft
                except Exception:
                    pass

            if soft == resource.RLIM_INFINITY or soft > 65535:
                soft = 65535

            fd_limit_workers = max(1, int(soft / 15))
            max_safe_workers = min(max_safe_workers, fd_limit_workers)
        except Exception:
            pass

        # Subprocess workers cap: limit process spawning concurrency to avoid OS thrashing
        max_subprocess_limit = 24 if IS_TERMUX else 256
        max_safe_workers = min(max_safe_workers, max_subprocess_limit)

        if max_safe_workers < 1:
            max_safe_workers = 1

        return max_safe_workers, free_mem_mb
