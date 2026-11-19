"""Bounded, strictly offline JavaScript source-map v3 metadata audit.

Source names, content, URLs and arbitrary fields may contain credentials and
are deliberately never returned to the caller.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 2_000_000
MAX_SOURCES = 500
_HINDS = ("TODO", "FIXME", "FLAG", "SECRET", "PASSWORD", "DEBUG")
_EXTENSION = re.compile(r"\.([A-Za-z0-9]{1,8})(?:[?#].*)?$")
_KNOWN = {"js", "jsx", "ts", "tsx", "vue", "mjs", "cjs", "css", "scss", "html"}
_MAX_CONTENT = 100_000


def audit_source_map(data: object) -> dict:
    """Report aggregate source-map structure without returning source names/content."""
    if not isinstance(data, dict) or data.get("version") != 3:
        raise ValueError("expected a JavaScript source-map v3 object")
    sources = data.get("sources")
    if (not isinstance(sources, list) or len(sources) > MAX_SOURCES
            or any(not isinstance(x, str) or len(x) > 2048 for x in sources)):
        raise ValueError("invalid or oversized source-map sources")
    mappings = data.get("mappings", "")
    if not isinstance(mappings, str) or len(mappings) > MAX_BYTES:
        raise ValueError("invalid source-map mappings")
    contents = data.get("sourcesContent", None)
    if contents is not None and (
            not isinstance(contents, list) or len(contents) != len(sources)
            or any(x is not None and not isinstance(x, str) for x in contents)):
        raise ValueError("source-map sourcesContent must align with sources")
    if contents and sum(len(x) for x in contents if x is not None) > MAX_BYTES:
        raise ValueError("source-map embedded content is too large")
    extensions: Counter[str] = Counter()
    for name in sources:
        # File-extension-only classification: never reveal arbitrary names.
        match = _EXTENSION.search(name)
        suffix = match.group(1).lower() if match else ""
        extensions[suffix if suffix in _KNOWN else "other"] += 1

    hints: set[str] = set()
    for body in (contents or [])[:MAX_SOURCES]:
        if body is None:
            continue
        # Only inspect limited text; no source lines, values or content in output.
        for hint in _HINDS:
            if re.search(r"(?<![A-Za-z0-9_])" + hint + r"(?![A-Za-z0-9_])",
                         body[:_MAX_CONTENT], re.I):
                hints.add(hint)
    return {
        "schema": "webchallscan/source-map-audit-v1",
        "source_count": len(sources),
        "embedded_source_count": sum(x is not None for x in (contents or [])),
        "extension_categories": dict(sorted(extensions.items())),
        "comment_hint_categories": sorted(hints),
        "active_tests_executed": 0,
        "limitations": [
            "Offline source-map v3 metadata review only: no files or URLs were requested.",
            "Source paths, file names, source content and arbitrary field values are omitted.",
            "Keyword categories are review hints, not confirmed secrets or vulnerabilities.",
            "Source-map accessibility and disclosure must be confirmed manually.",
        ],
    }


def audit_source_map_file(path: str) -> dict:
    """Read a regular local map inside the working tree, never arbitrary paths.

    Source maps are untrusted input. Limit path scope and actual bytes read,
    rather than trusting stat() followed by an unbounded read_text().
    """
    if not isinstance(path, str) or not path or "\\x00" in path:
        raise ValueError("invalid source-map file path")
    trusted_root = Path.cwd().resolve()
    try:
        candidate = Path(path).resolve(strict=True)
        candidate.relative_to(trusted_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("source-map file must be inside the working directory") from exc
    if candidate.suffix.lower() != ".map":
        raise ValueError("source-map file must have a .map extension")
    if not candidate.is_file():
        raise ValueError("source-map input must be a regular file")
    # The post-open fstat remains essential against file replacement races.
    # Never follow a final symlink during open, even if swapped after resolve.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("source-map input must be a regular file")
            raw = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise ValueError("cannot read source-map file") from exc
    if len(raw) > MAX_BYTES:
        raise ValueError("source-map file exceeds 2 MB")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid source-map JSON file") from exc
    return audit_source_map(data)
