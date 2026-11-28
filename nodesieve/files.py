"""Atomic file writes with explicit permissions."""

import os
import tempfile
from pathlib import Path
from typing import Union


def write_atomic(path: Union[Path, str], data: Union[str, bytes], mode: int = 0o600) -> None:
    """Replace path atomically with text or bytes and Unix permissions mode."""
    target = Path(path)
    binary = isinstance(data, bytes)
    fd, tmp = tempfile.mkstemp(prefix=".ns-", dir=target.parent)
    try:
        kwargs = {} if binary else {"encoding": "utf-8", "newline": "\n"}
        with os.fdopen(fd, "wb" if binary else "w", **kwargs) as out:
            out.write(data)
            out.flush()
            if hasattr(os, "fchmod"):
                os.fchmod(out.fileno(), mode)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
