"""Bounded offline import of Burp Suite XML HTTP history exports.

Reads local XML only: no HTTP requests, raw bodies, cookie values or request
headers are retained. The output uses the existing redacted inventory schema.
"""
from __future__ import annotations

import base64
import os
import re
import stat
from urllib.parse import parse_qsl
from pathlib import Path
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from .network import _safe_request
from .burp_json_hints import json_string_field_hints
from .posture import inspect_response

MAX_XML = 5_000_000
MAX_ITEMS = 500
MAX_RESPONSE_TEXT = 1_000_000


_RESPONSE_HEADER_NAMES = frozenset({
    "content-type", "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options",
    "access-control-allow-origin", "access-control-allow-credentials",
})


def _decode_payload(node: ET.Element, raw_text: str) -> bytes:
    if node.get("base64", "").lower() == "true":
        return base64.b64decode(raw_text, validate=True)
    return raw_text.encode("utf-8", "replace")


def _parse_response_head(head: bytes) -> tuple[dict[str, str], tuple[str, ...]]:
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in head.splitlines()[1:100]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.decode("ascii", "ignore").strip().lower()
        if key == "set-cookie":
            if len(cookies) < 50:
                cookies.append(value.decode("utf-8", "replace").strip()[:8192])
        elif key in _RESPONSE_HEADER_NAMES:
            headers[key] = value.decode("utf-8", "replace").strip()[:4096]
    return headers, tuple(cookies)


def _response_headers(item: ET.Element) -> tuple[dict[str, str], tuple[str, ...]]:
    node = item.find("response")
    if node is None or not node.text:
        return {}, ()
    raw_text = node.text.strip()
    if len(raw_text) > MAX_RESPONSE_TEXT:
        return {}, ()
    try:
        raw = _decode_payload(node, raw_text)
    except ValueError:
        return {}, ()
    if len(raw) > MAX_RESPONSE_TEXT:
        return {}, ()
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    return _parse_response_head(head)


_CSRF_NAMES = frozenset({
    "csrf", "_csrf", "csrf_token", "csrftoken", "xsrf_token",
    "_xsrf", "authenticity_token", "__requestverificationtoken",
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
})


def _split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
        return head, body
    if b"\n\n" in raw:
        head, body = raw.split(b"\n\n", 1)
        return head, body
    return raw, b""


def _scan_request_head(head: bytes) -> tuple[bool, str]:
    content_type = ""
    header_marker = False
    for line in head.splitlines()[1:100]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        name = name.decode("ascii", "ignore").strip().lower()
        if name in _CSRF_NAMES:
            header_marker = True
        if name == "content-type":
            content_type = value.decode("ascii", "ignore").strip().lower()[:128]
    return header_marker, content_type


def _body_csrf_source(content_type: str, body: bytes) -> str | None:
    if len(body) > 100_000:
        return None
    if "application/x-www-form-urlencoded" in content_type:
        try:
            names = (name.lower() for name, _ in parse_qsl(
                body.decode("utf-8", "replace"), keep_blank_values=True,
                max_num_fields=100,
            ))
            if any(name in _CSRF_NAMES for name in names):
                return "form-field"
        except ValueError:
            pass
    elif "application/json" in content_type:
        # Parse JSON *keys* only, never retain values or reflect arbitrary keys.
        # Regex is conservative: no claims about nested/dynamic CSRF protection.
        if any(re.search(rb'"' + name.encode("ascii") +
                         rb'"\s*:', body, re.I)
               for name in _CSRF_NAMES):
            return "json-field"
    return None


def _csrf_request_sources(item: ET.Element, method: str) -> tuple[str, ...]:
    """Identify CSRF marker *presence* in already captured writes, never values."""
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return ()
    node = item.find("request")
    if node is None or not node.text:
        return ()
    raw_text = node.text.strip()
    if not raw_text or len(raw_text) > 350_000:
        return ()
    try:
        raw = _decode_payload(node, raw_text)
    except ValueError:
        return ()
    if len(raw) > 200_000:
        return ()
    head, body = _split_head_body(raw)
    header_marker, content_type = _scan_request_head(head)
    found: set[str] = {"header"} if header_marker else set()
    body_source = _body_csrf_source(content_type, body)
    if body_source:
        found.add(body_source)
    return tuple(sorted(found))


def read_bounded_burp_xml(path: str) -> bytes:
    """Read only a bounded regular XML file inside the current work tree."""
    # The export path is operator-controlled, not a URL or a remote fetch.
    # Restrict agent-supplied paths to the working tree and read a regular
    # file with a hard cap (not stat() followed by an unbounded read).
    try:
        file = Path(path).resolve(strict=True)
        file.relative_to(Path.cwd().resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("Burp XML must be inside the working directory") from exc
    if file.suffix.lower() != ".xml" or not file.is_file():
        raise ValueError("Burp input must be a regular .xml file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(file, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Burp input must be a regular .xml file")
            raw = stream.read(MAX_XML + 1)
    except OSError as exc:
        raise ValueError("cannot read Burp XML export") from exc
    if len(raw) > MAX_XML:
        raise ValueError("Burp XML export exceeds the 5 MB limit")
    return raw


def _parse_xml_items(raw: bytes) -> list[ET.Element]:
    # Refuse DTDs/entities instead of processing potentially hostile exports.
    if b"<!doctype" in raw.lower() or b"<!entity" in raw.lower():
        raise ValueError("DTD and XML entities are not supported")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("invalid Burp XML export") from exc
    if root.tag != "items":
        raise ValueError("expected a Burp XML <items> export")
    items = root.findall("item")
    if not 1 <= len(items) <= MAX_ITEMS:
        raise ValueError("Burp export requires 1-500 items")
    return items


def _parse_expected_origin(expected_origin: str | None) -> tuple[str, str] | None:
    if expected_origin is None:
        return None
    parsed = urlsplit(expected_origin)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise ValueError("expected origin must be an HTTP(S) origin")
    return (parsed.scheme.lower(), parsed.netloc.lower())


def _item_origin(url: str) -> tuple[str, str] | None:
    try:
        parts = urlsplit(url)
        current = (parts.scheme.lower(), parts.netloc.lower())
    except ValueError:
        return None
    if current[0] not in {"http", "https"} or not current[1] or parts.username or parts.password:
        return None
    return current


def _entry_is_valid(entry: dict | None) -> bool:
    if entry is None or entry["method"] not in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return False
    path = str(entry["path"])
    return (path.startswith("/") and not path.startswith("//")
            and not any(c in path for c in ("\\", "#", "?")))


def _record_json_hints(record: dict, item: ET.Element, method: str) -> None:
    # Metadata only: never store the captured body or any value.
    hints = json_string_field_hints(item, method)
    if hints:
        known = record.setdefault("json_fields", [])
        for field in hints:
            if field not in known and len(known) < 12:
                known.append(field)


def _parse_status(item: ET.Element) -> int:
    try:
        return int(item.findtext("status", ""))
    except (ValueError, TypeError):
        return 0


def _csrf_signal(item: ET.Element, entry: dict, status: int) -> dict | None:
    sources = _csrf_request_sources(item, str(entry["method"]))
    if not sources:
        return None
    return {
        "rule": "BURP-CSRF-MARKER-001",
        "title": "CSRF-named request metadata observed",
        "severity": "info",
        "confidence": "low",
        "method": str(entry["method"]),
        "path": str(entry["path"]),
        "status": str(status),
        "evidence": "Captured request contains CSRF marker categories: " +
                    ", ".join(sources) +
                    "; names and token values omitted. Protection effectiveness unverified.",
    }


def _record_posture(posture: dict, item: ET.Element, entry: dict, status: int, origin: tuple[str, str]) -> None:
    signal = _csrf_signal(item, entry, status)
    if signal:
        posture[(signal["rule"], signal["method"], signal["path"])] = signal
    headers, cookies = _response_headers(item)
    is_document = (entry["method"] == "GET" and
                   "text/html" in headers.get("content-type", "").lower())
    signals = inspect_response(
        str(entry["method"]), str(entry["path"]),
        "Document" if is_document else "Other",
        status, headers, origin[0] == "https",
        cookie_headers=cookies,
    )
    for found in signals:
        posture[(found["rule"], found["method"], found["path"])] = found


def _import_item(item: ET.Element, origin: tuple[str, str] | None,
                 observations: dict, posture: dict) -> tuple[bool, tuple[str, str] | None]:
    """Return (accepted, origin). origin is fixed by the first valid item."""
    url = item.findtext("url")
    method = item.findtext("method")
    if not url or not method:
        return False, origin
    current = _item_origin(url)
    if current is None:
        return False, origin
    if origin is None:
        origin = current
    entry = _safe_request(method, url, origin)
    if not _entry_is_valid(entry):
        return False, origin
    identity = (str(entry["method"]), str(entry["path"]), tuple(entry["parameters"]))
    record = observations.setdefault(identity, {
        **entry, "type": "BurpHistory", "statuses": [], "count": 0,
    })
    record["count"] += 1
    _record_json_hints(record, item, str(entry["method"]))
    status = _parse_status(item)
    if 100 <= status <= 599:
        if status not in record["statuses"]:
            record["statuses"].append(status)
        _record_posture(posture, item, entry, status, origin)
    return True, origin


def import_burp_xml(path: str, expected_origin: str | None = None) -> dict:
    raw = read_bounded_burp_xml(path)
    items = _parse_xml_items(raw)
    origin = _parse_expected_origin(expected_origin)
    observations: dict[tuple[str, str, tuple[str, ...]], dict] = {}
    posture: dict[tuple[str, str, str], dict] = {}
    skipped = 0
    for item in items:
        accepted, origin = _import_item(item, origin, observations, posture)
        if not accepted:
            skipped += 1
    if origin is None:
        raise ValueError("no valid HTTP(S) origin found in Burp XML")
    if expected_origin is not None and not observations:
        raise ValueError("no matching items for the expected origin")
    endpoints = sorted(observations.values(), key=lambda x: (
        x["path"], x["method"], x["parameters"],
    ))
    for endpoint in endpoints:
        endpoint["statuses"].sort()
        if "json_fields" in endpoint:
            endpoint["json_fields"].sort()
    return {
        "schema": "webchallscan/network-inventory-v1",
        "origin": origin[0] + "://" + origin[1],
        "observed_requests": sum(e["count"] for e in endpoints),
        "endpoints": endpoints,
        "passive_findings": [posture[k] for k in sorted(posture)],
        "active_tests_executed": 0,
        "skipped_items": skipped,
        "limitations": [
            "Offline Burp XML import: no HTTP requests or active tests were sent.",
            "Only one exact origin is included; other origins are ignored.",
            "Request bodies, raw responses, credentials and parameter values are discarded.",
            "JSON POST field paths are passive hints only; no request is replayed.",
            "Header configuration signals are not confirmed exploitability.",
        ],
    }
