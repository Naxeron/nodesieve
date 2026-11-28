"""System resource discovery, file descriptor scaling, and worker limits."""

import math
from typing import Optional, Tuple

from nodesieve.constants import IS_ANDROID, IS_TERMUX
from nodesieve.logging import get_free_memory_mb

RESERVED_MB = 500
CORE_INSTANCE_MB = 24.0
DEFAULT_MEM_PER_WORKER_MB = 8.0
NODES_PER_INSTANCE = 32
MAX_WORKERS = 256
MAX_WORKERS_ANDROID = 64


class ResourceLimits:
    """Calculates safe concurrent worker bounds from free memory and RLIMIT_NOFILE."""

    @staticmethod
    def core_instances(workers: int) -> Tuple[int, int]:
        workers = max(1, int(workers))
        per_instance = min(NODES_PER_INSTANCE, workers)
        return per_instance, math.ceil(workers / per_instance) + 1

    @staticmethod
    def memory_needed_mb(workers: int, mem_per_worker: float = DEFAULT_MEM_PER_WORKER_MB) -> float:
        _, instances = ResourceLimits.core_instances(workers)
        return workers * mem_per_worker + instances * CORE_INSTANCE_MB

    @staticmethod
    def get_max_safe_workers(config: Optional[dict] = None) -> Tuple[int, float]:
        free_mem_mb = get_free_memory_mb()
        safe_mem_mb = max(0.0, free_mem_mb - RESERVED_MB)

        mem_per_worker = DEFAULT_MEM_PER_WORKER_MB
        if config and "mem_per_worker" in config:
            try:
                val = float(config["mem_per_worker"])
                if val > 0:
                    mem_per_worker = val
            except (ValueError, TypeError):
                pass

        workers = int(safe_mem_mb / (mem_per_worker + CORE_INSTANCE_MB / NODES_PER_INSTANCE))
        while workers > 1 and ResourceLimits.memory_needed_mb(workers, mem_per_worker) > safe_mem_mb:
            workers -= 1

        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = 65535 if hard == resource.RLIM_INFINITY else hard
            if soft < target:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
                    soft = target
                except Exception:
                    pass
            soft = 65535 if (soft == resource.RLIM_INFINITY or soft > 65535) else soft
            workers = min(workers, max(1, int(soft / 15)))
        except Exception:
            pass

        cap = MAX_WORKERS_ANDROID if (IS_TERMUX or IS_ANDROID) else MAX_WORKERS
        return max(1, min(workers, cap)), free_mem_mb
