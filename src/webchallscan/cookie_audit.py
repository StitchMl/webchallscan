"""Offline, value-redacted format review for existing scanner session cookies."""
from __future__ import annotations

import base64
import binascii
import json
import re

from .jwt_audit import audit_jwt
from .session import load_session_file


_HEX = re.compile(r"^[0-9a-fA-F]{16,4096}$")
_BASE64 = re.compile(r"^[A-Za-z0-9_+/=-]{16,4096}$")


def _structure(value: str) -> tuple[str, list[str]]:
    if not value or len(value) > 4096:
        return "unknown", []
    if value.count(".") == 2:
        try:
            info = audit_jwt(value)
        except ValueError:
            return "signed-session-like", []
        signals = [item["rule"] for item in info["signals"]]
        return "jwt-like", signals
    if value.count(".") >= 1:
        return "signed-session-like", []
    if len(value) % 2 == 0 and _HEX.fullmatch(value):
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            return "unknown", []
        return _encoded_category("hex", decoded), []
    if _BASE64.fullmatch(value):
        try:
            decoded = base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_", validate=True,
            )
        except (ValueError, binascii.Error):
            return "unknown", []
        return _encoded_category("base64", decoded), []
    return "unknown", []


def _encoded_category(prefix: str, raw: bytes) -> str:
    if len(raw) > 4096:
        return prefix + "-shaped"
    try:
        content = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return prefix + "-shaped"
    return prefix + "-json-like" if isinstance(content, (dict, list)) else prefix + "-shaped"


def audit_session_file(path: str) -> dict:
    """Report aggregate format categories; never expose cookie/claim values."""
    session = load_session_file(path)
    categories: dict[str, int] = {}
    signal_counts: dict[str, int] = {}
    for cookie in session.cookies[:500]:
        category, signals = _structure(cookie.value)
        categories[category] = categories.get(category, 0) + 1
        for name in set(signals):
            signal_counts[name] = signal_counts.get(name, 0) + 1
    return {
        "schema": "webchallscan/session-format-audit-v1",
        "cookie_count": len(session.cookies),
        "format_categories": dict(sorted(categories.items())),
        "jwt_review_signals": dict(sorted(signal_counts.items())),
        "active_tests_executed": 0,
        "limitations": [
            "This is an offline shape/format review, not signature validation or decryption.",
            "Cookie names, values, raw JWT payloads and claim values are omitted.",
            "An encoded or signed-looking value does not establish a framework or vulnerability.",
        ],
    }
