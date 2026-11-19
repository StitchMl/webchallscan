"""Offline, redacted JSON-field discovery from previously captured Burp requests.

Never return raw requests, body values, authentication field names or tokens.
This module does not perform HTTP requests or prepare active probes.
"""
from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET

_MAX_REQUEST = 120_000
_MAX_BODY = 65_536
_MAX_FIELDS = 12
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}\Z")
_PRIVATE = re.compile(
    r"(?:password|passwd|secret|token|csrf|xsrf|auth|cookie|session|"
    r"key|bearer|credential|otp|nonce|signature|private)",
    re.I,
)


def _decode_request(node: ET.Element, encoded: str) -> bytes | None:
    try:
        raw = (base64.b64decode(encoded, validate=True)
               if node.get("base64", "").lower() == "true"
               else encoded.encode("utf-8", "replace"))
    except ValueError:
        return None
    return raw if len(raw) <= _MAX_REQUEST else None


def _json_body(raw: bytes) -> dict | None:
    if b"\r\n\r\n" in raw:
        header, body = raw.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw:
        header, body = raw.split(b"\n\n", 1)
    else:
        return None
    if not body or len(body) > _MAX_BODY:
        return None
    if not any(
        line.partition(b":")[0].strip().lower() == b"content-type"
        and b"application/json" in line.lower()
        for line in header.splitlines()[1:80]
    ):
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _collect_fields(value: dict, parents: tuple[str, ...], found: list[list[str]]) -> None:
    if len(parents) >= 5 or len(found) >= _MAX_FIELDS:
        return
    for key, child in value.items():
        if len(found) >= _MAX_FIELDS:
            break
        if not isinstance(key, str) or not _FIELD.fullmatch(key) or _PRIVATE.search(key):
            continue
        path = (*parents, key)
        if isinstance(child, str):
            found.append(list(path))
        elif isinstance(child, dict):
            _collect_fields(child, path, found)


def json_string_field_hints(item: ET.Element, method: str) -> list[list[str]]:
    """Find bounded nested string-field *names* from existing JSON POST bodies."""
    if method != "POST":
        return []
    node = item.find("request")
    if node is None or not node.text:
        return []
    encoded = node.text.strip()
    if not encoded or len(encoded) > _MAX_REQUEST:
        return []
    raw = _decode_request(node, encoded)
    if raw is None:
        return []
    data = _json_body(raw)
    if data is None:
        return []
    found: list[list[str]] = []
    _collect_fields(data, (), found)
    return found
