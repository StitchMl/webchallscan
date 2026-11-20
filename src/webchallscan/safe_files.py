"""Path containment helpers for operator-supplied local files.

Every input and output file must resolve inside the current working tree.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


def resolve_input_file(path: str, what: str) -> Path:
    """Return a resolved existing regular file inside the working directory."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError(f"invalid {what} path")
    try:
        file = Path(path).resolve(strict=True)
        file.relative_to(Path.cwd().resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{what} must be inside the working directory") from exc
    if not file.is_file():
        raise ValueError(f"{what} must be a regular file")
    return file


def read_input_file(path: str, what: str, limit: int, too_large: str) -> bytes:
    """Read at most ``limit`` bytes from a contained regular file."""
    file = resolve_input_file(path, what)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(file, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError(f"{what} must be a regular file")
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"cannot read {what}") from exc
    if len(raw) > limit:
        raise ValueError(too_large)
    return raw


def resolve_output_file(path: str, what: str) -> Path:
    """Return a path for a new file whose parent directory is inside the working tree."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError(f"invalid {what} path")
    target = Path(path)
    if target.name in {"", ".", ".."}:
        raise ValueError(f"invalid {what} path")
    try:
        parent = target.parent.resolve(strict=True)
        parent.relative_to(Path.cwd().resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{what} must be inside the working directory") from exc
    return parent / target.name
