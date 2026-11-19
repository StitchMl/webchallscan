"""Bounded offline import of Burp Suite XML HTTP history exports.

Reads local XML only: no HTTP requests, raw bodies, cookie values or request
headers are retained. The output uses the existing redacted inventory schema.
"""
from __future__ import annotations

import base64
import binascii
import re
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


def _response_headers(item: ET.Element) -> tuple[dict[str, str], tuple[str, ...]]:
    node = item.find("response")
    if node is None or not node.text:
        return {}, ()
    raw_text = node.text.strip()
    if len(raw_text) > MAX_RESPONSE_TEXT:
        return {}, ()
    try:
        if node.get("base64", "").lower() == "true":
            raw = base64.b64decode(raw_text, validate=True)
        else:
            raw = raw_text.encode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return {}, ()
    if len(raw) > MAX_RESPONSE_TEXT:
        return {}, ()
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
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
        elif key in {
            "content-type", "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options",
            "access-control-allow-origin", "access-control-allow-credentials",
        }:
            headers[key] = value.decode("utf-8", "replace").strip()[:4096]
    return headers, tuple(cookies)


_CSRF_NAMES = frozenset({
    "csrf", "_csrf", "csrf_token", "csrftoken", "xsrf_token",
    "_xsrf", "authenticity_token", "__requestverificationtoken",
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
})


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
        raw = (base64.b64decode(raw_text, validate=True)
               if node.get("base64", "").lower() == "true"
               else raw_text.encode("utf-8", "replace"))
    except (ValueError, binascii.Error):
        return ()
    if len(raw) > 200_000:
        return ()
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw:
        head, body = raw.split(b"\n\n", 1)
    else:
        head, body = raw, b""
    content_type = ""
    found: set[str] = set()
    for line in head.splitlines()[1:100]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        name = name.decode("ascii", "ignore").strip().lower()
        if name in _CSRF_NAMES:
            found.add("header")
        if name == "content-type":
            content_type = value.decode("ascii", "ignore").strip().lower()[:128]
    if "application/x-www-form-urlencoded" in content_type and len(body) <= 100_000:
        try:
            names = (name.lower() for name, _ in parse_qsl(
                body.decode("utf-8", "replace"), keep_blank_values=True,
                max_num_fields=100,
            ))
            if any(name in _CSRF_NAMES for name in names):
                found.add("form-field")
        except ValueError:
            pass
    elif "application/json" in content_type and len(body) <= 100_000:
        # Parse JSON *keys* only, never retain values or reflect arbitrary keys.
        # Regex is conservative: no claims about nested/dynamic CSRF protection.
        if any(re.search(rb'"' + name.encode("ascii") +
                         rb'"\s*:', body, re.I)
               for name in _CSRF_NAMES):
            found.add("json-field")
    return tuple(sorted(found))


def import_burp_xml(path: str, expected_origin: str | None = None) -> dict:
    file = Path(path)
    if file.stat().st_size > MAX_XML:
        raise ValueError("Burp XML export exceeds the 5 MB limit")
    raw = file.read_bytes()
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
    origin = None
    if expected_origin is not None:
        parsed = urlsplit(expected_origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc
                or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment):
            raise ValueError("expected origin must be an HTTP(S) origin")
        origin = (parsed.scheme.lower(), parsed.netloc.lower())
    observations: dict[tuple[str, str, tuple[str, ...]], dict] = {}
    posture: dict[tuple[str, str, str], dict] = {}
    skipped = 0
    for item in items:
        url = item.findtext("url")
        method = item.findtext("method")
        if not url or not method:
            skipped += 1
            continue
        try:
            parts = urlsplit(url)
            current = (parts.scheme.lower(), parts.netloc.lower())
        except ValueError:
            skipped += 1
            continue
        if current[0] not in {"http", "https"} or not current[1] or parts.username or parts.password:
            skipped += 1
            continue
        if origin is None:
            origin = current
        entry = _safe_request(method, url, origin)
        if (entry is None or entry["method"] not in
                {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or
                not str(entry["path"]).startswith("/") or str(entry["path"]).startswith("//")
                or any(c in str(entry["path"]) for c in ("\\", "#", "?"))):
            skipped += 1
            continue
        identity = (str(entry["method"]), str(entry["path"]), tuple(entry["parameters"]))
        record = observations.setdefault(identity, {
            **entry, "type": "BurpHistory", "statuses": [], "count": 0,
        })
        record["count"] += 1
        # Metadata only: never store the captured body or any value.
        hints = json_string_field_hints(item, str(entry["method"]))
        if hints:
            known = record.setdefault("json_fields", [])
            for field in hints:
                if field not in known and len(known) < 12:
                    known.append(field)
        raw_status = item.findtext("status", "")
        try:
            status = int(raw_status)
        except (ValueError, TypeError):
            status = 0
        if 100 <= status <= 599:
            if status not in record["statuses"]:
                record["statuses"].append(status)
            sources = _csrf_request_sources(item, str(entry["method"]))
            if sources:
                signal = {
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
                key = (signal["rule"], signal["method"], signal["path"])
                posture[key] = signal
            headers, cookies = _response_headers(item)
            is_document = (entry["method"] == "GET" and
                           "text/html" in headers.get("content-type", "").lower())
            signals = inspect_response(
                str(entry["method"]), str(entry["path"]),
                "Document" if is_document else "Other",
                status, headers, origin[0] == "https",
                cookie_headers=cookies,
            )
            for signal in signals:
                key = (signal["rule"], signal["method"], signal["path"])
                posture[key] = signal
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
