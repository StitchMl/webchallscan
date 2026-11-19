"""Explicit secret-bearing Burp Cookie -> existing session-file bridge.

This is intentionally separate from redacted --import-burp. It makes no HTTP
requests and writes an exclusive owner-only file (0600 on POSIX).
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit

from .burp_import import MAX_ITEMS, read_bounded_burp_xml
from .session import load_session_file

_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_MAX_REQUEST = 1_000_000


def _cookie_header(item: ET.Element) -> str:
    node = item.find("request")
    if node is None or not node.text:
        return ""
    raw_text = node.text.strip()
    if len(raw_text) > _MAX_REQUEST:
        return ""
    try:
        raw = (base64.b64decode(raw_text, validate=True)
               if node.get("base64", "").lower() == "true"
               else raw_text.encode("latin-1", "replace"))
    except (ValueError, binascii.Error):
        return ""
    if len(raw) > _MAX_REQUEST:
        return ""
    headers = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0].splitlines()
    if not headers or not headers[0].startswith(b"GET "):
        return ""
    for line in headers[1:100]:
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"cookie":
            return value.strip().decode("ascii", "replace")
    return ""


def _safe_cookies(value: str, domain: str, path: str, secure: bool) -> list[dict]:
    entries = []
    names = set()
    for part in value.split(";")[:51]:
        name, sep, content = part.strip().partition("=")
        if not sep or not _COOKIE_NAME.fullmatch(name) or name in names:
            raise ValueError("Burp request contains invalid or duplicate cookies")
        if (not content or len(content) > 4096
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in content)):
            raise ValueError("Burp request contains an unsupported cookie value")
        names.add(name)
        entries.append({
            "name": name, "value": content, "domain": domain,
            # Scope is unknown from Cookie: constrain to the selected path.
            "path": path, "secure": secure, "httpOnly": False,
            "sameSite": "",
        })
    if not 1 <= len(entries) <= 50:
        raise ValueError("Burp request must have 1-50 valid cookies")
    return entries


def export_burp_session(xml_path: str, output_path: str,
                        expected_origin: str, *, request_path: str | None = None,
                        request_index: int = 1) -> dict:
    """Select a matching GET from Burp and save a private scanner session.

    request_index is 1-based among valid, same-origin GET+Cookie candidates,
    after the optional exact path filter. Only private output stores cookies.
    """
    if type(request_index) is not int or not 1 <= request_index <= MAX_ITEMS:
        raise ValueError("Burp session request index must be 1-500")
    if request_path is not None and (
            not isinstance(request_path, str) or not request_path.startswith("/")
            or request_path.startswith("//") or "?" in request_path
            or "#" in request_path or "%" in request_path
            or "\\" in request_path or ".." in request_path
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in request_path)
            or len(request_path) > 2048):
        raise ValueError("Burp session request path must be an exact, safe path")
    parsed_origin = urlsplit(expected_origin)
    if (parsed_origin.scheme not in {"http", "https"} or not parsed_origin.hostname
            or parsed_origin.username or parsed_origin.password
            or parsed_origin.path not in {"", "/"}
            or parsed_origin.query or parsed_origin.fragment):
        raise ValueError("exact HTTP(S) --expect-origin is required")
    expected = (parsed_origin.scheme.lower(), parsed_origin.netloc.lower())
    raw = read_bounded_burp_xml(xml_path)
    if b"<!doctype" in raw.lower() or b"<!entity" in raw.lower():
        raise ValueError("DTD and XML entities are prohibited")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("invalid Burp XML export") from exc
    items = root.findall("item")
    if root.tag != "items" or not 1 <= len(items) <= MAX_ITEMS:
        raise ValueError("expected Burp XML with 1-500 items")
    session = None
    candidates = 0
    for item in items:
        url = item.findtext("url")
        if not url or item.findtext("method", "").upper() != "GET":
            continue
        parsed = urlsplit(url)
        if ((parsed.scheme.lower(), parsed.netloc.lower()) != expected
                or parsed.username or parsed.password):
            continue
        path = parsed.path or "/"
        if request_path is not None and path != request_path:
            continue
        cookie_header = _cookie_header(item)
        if not cookie_header:
            continue
        if (not path.startswith("/") or path.startswith("//")
                or "%" in path or "\\" in path or ".." in path):
            continue
        candidates += 1
        if candidates != request_index:
            continue
        session = {
            "url": urlunsplit((parsed.scheme, parsed.netloc, path, "", "")),
            "profile": "desktop", "headers": {},
            "cookies": _safe_cookies(cookie_header, parsed.hostname or "",
                                     path, parsed.scheme == "https"),
        }
        break
    if session is None:
        raise ValueError("no matching GET with a valid Cookie header")
    # Validate against the existing scanner session contract before writing.
    output = Path(output_path)
    blob = json.dumps(session, indent=2).encode("utf-8")
    if len(blob) > 2_000_000:
        raise ValueError("session exceeds the file size cap")
    fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(blob)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    try:
        parsed_session = load_session_file(str(output))
    except (OSError, ValueError):
        output.unlink(missing_ok=True)
        raise
    return {
        "schema": "webchallscan/burp-session-export-v1",
        "cookies_exported": len(parsed_session.cookies),
        "selected_request_index": request_index,
        "origin": expected_origin,
        "session_file_created": True,
        "notes": [
            "The private session file contains live cookies; do not share it.",
            "Cookie Path is constrained to the selected request path; original cookie attributes cannot be recovered from Cookie headers.",
            "Only GET requests with an explicit Cookie header are eligible; request bodies and CSRF tokens are never exported.",
            "Delete the file after authorized validation.",
        ],
    }
