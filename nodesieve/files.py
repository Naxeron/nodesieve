"""Writing the files that hold proxy credentials."""

import os
import tempfile
from pathlib import Path


def write_private(path: Path, text: str, mode: int = 0o600) -> None:
    """Replace path with text in one step, with permissions mode (owner only by default).

    The text goes to a temporary file next to path first, so a reader sees the old
    file or the new one, never part of either.
    """
    fd, temporary = tempfile.mkstemp(prefix=".psc-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(text)
            output.flush()
            # Windows has no fchmod before Python 3.13; its files carry no Unix modes anyway.
            if hasattr(os, "fchmod"):
                os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
