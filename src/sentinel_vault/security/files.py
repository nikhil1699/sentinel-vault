"""Private-file helpers for keys and databases. Used by every trust domain."""

from __future__ import annotations

import os
import stat
from pathlib import Path

_GROUP_OTHER_BITS = stat.S_IRWXG | stat.S_IRWXO


class InsecurePermissionsError(RuntimeError):
    """A secret file or directory is accessible by group or others."""


def check_private(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & _GROUP_OTHER_BITS:
        raise InsecurePermissionsError(
            f"{path} is accessible by group/others (mode {stat.S_IMODE(mode):o}); "
            f"fix with: chmod {'700' if path.is_dir() else '600'} {path}"
        )


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` with mode 0700, or verify an existing one is private."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(path)
    return path


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write via a temp file created with O_EXCL, then atomically rename into place."""
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def ensure_private_file(path: Path) -> None:
    """Create an empty 0600 file if missing (so SQLite inherits safe permissions)."""
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    check_private(path)
