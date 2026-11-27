"""Build a redacted route inventory from a local static web build."""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit

from .planner import plan_inventory
from .safe_files import read_input_file
from .scanner import PageParser, Scanner

MAX_SOURCE_FILES = 2000
MAX_SOURCE_FILE_SIZE = 1_000_000
MAX_SOURCE_TOTAL_SIZE = 20_000_000
SOURCE_SUFFIXES = {".html", ".htm", ".js"}


def _source_root(path: str) -> tuple[Path, bool]:
    if not path or "\x00" in path:
        raise ValueError("invalid source path")
    try:
        source = Path(path).resolve(strict=True)
        source.relative_to(Path.cwd().resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("source must be inside the working directory") from exc
    if source.is_symlink() or not (source.is_dir() or source.is_file()):
        raise ValueError("source must be a regular file or directory")
    return source, source.is_file()


def _source_files(root: Path, is_file: bool) -> list[Path]:
    if is_file:
        candidates = [root]
    else:
        candidates = []
        for current, dirs, files in os.walk(root, followlinks=False):
            base = Path(current)
            dirs[:] = sorted(name for name in dirs
                             if not (base / name).is_symlink())
            candidates.extend(base / name for name in sorted(files)
                              if not (base / name).is_symlink())
    selected = sorted(path for path in candidates
                      if path.suffix.casefold() in SOURCE_SUFFIXES)
    if len(selected) > MAX_SOURCE_FILES:
        raise ValueError("source contains too many web files")
    return selected


def _source_route(path: Path, root: Path, is_file: bool) -> str:
    relative = path.name if is_file else path.relative_to(root).as_posix()
    if relative.casefold() in {"index.html", "index.htm"}:
        return "/"
    if relative.casefold().endswith(("/index.html", "/index.htm")):
        return "/" + relative.rsplit("/", 1)[0] + "/"
    return "/" + relative


def _safe_endpoint(origin: str, base: str, candidate: str) -> tuple[str, list[str]] | None:
    try:
        absolute = urljoin(base, candidate)
        parsed = urlsplit(absolute)
        expected = urlsplit(origin)
        if ((parsed.scheme.lower(), parsed.netloc.lower()) !=
                (expected.scheme.lower(), expected.netloc.lower())
                or parsed.username or parsed.password or not parsed.path.startswith("/")):
            return None
        path = parsed.path
        if (path.startswith("//") or "\\" in path or "%" in path or ".." in path
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)):
            return None
        parameters = sorted({name for name, _ in parse_qsl(parsed.query, max_num_fields=100)
                             if name and len(name) <= 64})
    except (ValueError, UnicodeError):
        return None
    return path, parameters


def _add_endpoint(endpoints: dict, method: str,
                  result: tuple[str, list[str]] | None, source_type: str) -> None:
    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    if result is None or method not in allowed:
        return
    path, params = result
    key = method, path
    entry = endpoints.setdefault(key, {
        "method": method, "path": path, "parameters": [], "type": source_type,
    })
    entry["parameters"] = sorted(set(entry["parameters"]) | set(params))


def _html_endpoints(text: str, source_route: str, origin: str, endpoints: dict) -> None:
    base = urljoin(origin, source_route)
    page = _safe_endpoint(origin, base, source_route)
    _add_endpoint(endpoints, "GET", page, "LocalHTML")
    parser = PageParser()
    parser.feed(text)
    for href in parser.links:
        _add_endpoint(endpoints, "GET", _safe_endpoint(origin, base, href), "LocalLink")
    for form in parser.forms:
        action = form.action or source_route
        names = sorted({name for name, _, _ in form.inputs if name and len(name) <= 64})
        result = _safe_endpoint(origin, base, action)
        _add_endpoint(endpoints, form.method, result, "LocalForm")
        if result is not None and names:
            entry = endpoints[(form.method, result[0])]
            entry["parameters"] = sorted(set(entry["parameters"]) | set(names))


def _javascript_endpoints(text: str, origin: str, base: str, endpoints: dict) -> None:
    for route in Scanner._static_get_routes(text):
        _add_endpoint(endpoints, "GET", _safe_endpoint(origin, base, route), "LocalJavaScript")
    for method, route in Scanner._static_api_hints(text):
        _add_endpoint(endpoints, method, _safe_endpoint(origin, base, route), "LocalJavaScript")


def source_inventory(path: str, origin: str) -> dict:
    """Inspect bounded HTML/JS files and return the existing redacted inventory schema."""
    parsed_origin = urlsplit(origin)
    if (parsed_origin.scheme not in {"http", "https"} or not parsed_origin.netloc
            or parsed_origin.username or parsed_origin.password or parsed_origin.path not in {"", "/"}
            or parsed_origin.query or parsed_origin.fragment):
        raise ValueError("source origin must be an HTTP(S) origin")
    normalized_origin = f"{parsed_origin.scheme.lower()}://{parsed_origin.netloc.lower()}"
    root, is_file = _source_root(path)
    files = _source_files(root, is_file)
    if not files:
        raise ValueError("source contains no HTML or JavaScript files")
    endpoints: dict[tuple[str, str], dict] = {}
    total_size = 0
    for file in files:
        try:
            raw = read_input_file(str(file), "source file", MAX_SOURCE_FILE_SIZE,
                                  "source file exceeds the size limit")
            total_size += len(raw)
            if total_size > MAX_SOURCE_TOTAL_SIZE:
                raise ValueError("source files exceed the size limit")
        except OSError as exc:
            raise ValueError("cannot read source file") from exc
        text = raw.decode("utf-8", errors="replace")
        route = _source_route(file, root, is_file)
        base = urljoin(normalized_origin, route)
        if file.suffix.casefold() in {".html", ".htm"}:
            _html_endpoints(text[:MAX_SOURCE_FILE_SIZE], route, normalized_origin, endpoints)
            _javascript_endpoints(text, normalized_origin, base, endpoints)
        else:
            _javascript_endpoints(text[:MAX_SOURCE_FILE_SIZE], normalized_origin, base, endpoints)
    result = {
        "schema": "webchallscan/network-inventory-v1",
        "origin": normalized_origin,
        "observed_requests": 0,
        "endpoints": sorted(endpoints.values(), key=lambda item: (
            item["path"], item["method"], item["parameters"], item["type"],
        )),
        "passive_findings": [],
        "active_tests_executed": 0,
        "skipped_items": 0,
        "limitations": [
            "Offline source inventory: no HTTP requests or active tests were sent.",
            "Only literal routes in bounded HTML and JavaScript files are included.",
            "Dynamic routes, authenticated pages and runtime-generated endpoints may be absent.",
            "POST and other write routes are recorded for review but are never replayed by inventory seeding.",
        ],
        "source_files": len(files),
        "source_bytes": total_size,
    }
    plan_inventory(result, normalized_origin)
    return result
