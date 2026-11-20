"""System resource discovery, file descriptor scaling, and concurrency limit calculations."""

import math
from typing import Optional, Tuple
from nodesieve.constants import IS_ANDROID, IS_TERMUX
from nodesieve.logging import get_free_memory_mb

# Memory left to the system, Python itself and the core's code, which every instance shares.
RESERVED_MB = 500
# One core instance holds memory of its own (heap and stacks) whether it serves 1 node or 128:
# about 20 MB for Mihomo (alpha-100ff73), 12 MB for Xray (26.10). Each node adds about 0.5 MB
# while its IP check runs, 1.1 MB under the location probe's 16 parallel requests (2026-11-20).
# The budget per node checked at once, mem_per_worker, covers that share and the check's Python side.
CORE_INSTANCE_MB = 24.0
DEFAULT_MEM_PER_WORKER_MB = 8.0
# Nodes one core instance serves. When an instance exits in the middle of a check, its
# unfinished nodes are checked again, each with an instance of its own.
NODES_PER_INSTANCE = 32
# Nodes checked at once. On Android this keeps the core processes of a scan to three:
# Android 12 and newer kill child processes beyond 32 across all apps.
MAX_WORKERS = 256
MAX_WORKERS_ANDROID = 64


class ResourceLimits:
    """Calculates safe concurrent worker bounds based on system memory and OS file descriptor limits."""

    @staticmethod
    def core_instances(workers: int) -> Tuple[int, int]:
        """Nodes per core instance, and instances at once, for checking `workers` nodes at once.

        One instance more than the nodes fill lets a new batch start while the last nodes of
        another are still being checked.
        """
        workers = max(1, int(workers))
        per_instance = min(NODES_PER_INSTANCE, workers)
        return per_instance, math.ceil(workers / per_instance) + 1

    @staticmethod
    def memory_needed_mb(workers: int, mem_per_worker: float = DEFAULT_MEM_PER_WORKER_MB) -> float:
        """Memory a scan checking `workers` nodes at once needs: its nodes and its core instances."""
        _, instances = ResourceLimits.core_instances(workers)
        return workers * mem_per_worker + instances * CORE_INSTANCE_MB

    @staticmethod
    def get_max_safe_workers(config: Optional[dict] = None) -> Tuple[int, float]:
        """The most nodes to check at once given free memory and open file limits, and the free memory in MB."""
        free_mem_mb = get_free_memory_mb()
        safe_mem_mb = max(0, free_mem_mb - RESERVED_MB)

        mem_per_worker = DEFAULT_MEM_PER_WORKER_MB
        if config and "mem_per_worker" in config:
            try:
                mem_per_worker = float(config["mem_per_worker"])
            except (ValueError, TypeError):
                pass
        if not mem_per_worker > 0:
            mem_per_worker = DEFAULT_MEM_PER_WORKER_MB

        max_safe_workers = int(safe_mem_mb / (mem_per_worker + CORE_INSTANCE_MB / NODES_PER_INSTANCE))
        while max_safe_workers > 1 and ResourceLimits.memory_needed_mb(max_safe_workers, mem_per_worker) > safe_mem_mb:
            max_safe_workers -= 1

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

        # The nodes checked at once also set a scan's CPU load, its connections and its core
        # processes, one per NODES_PER_INSTANCE nodes.
        max_workers = MAX_WORKERS_ANDROID if (IS_TERMUX or IS_ANDROID) else MAX_WORKERS
        max_safe_workers = min(max_safe_workers, max_workers)

        if max_safe_workers < 1:
            max_safe_workers = 1

        return max_safe_workers, free_mem_mb
