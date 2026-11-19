"""Offline metadata-only JWT inspection (no signature verification)."""
from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path

_ALLOWED_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_TOKEN_BYTES = 16_384
MAX_SECTION_BYTES = 8_192


def _decode_json_part(value: str) -> dict:
    if not value or len(value) > MAX_SECTION_BYTES or not _ALLOWED_B64URL.fullmatch(value):
        raise ValueError("invalid JWT base64url section")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        decoded = json.loads(raw)
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("invalid JWT JSON section") from exc
    if not isinstance(decoded, dict):
        raise ValueError("JWT header and payload must be objects")
    return decoded


def audit_jwt(token: str) -> dict:
    """Report only names/categories of JWT metadata; never return claim values."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
        raise ValueError("invalid JWT size")
    components = token.strip().split(".")
    if len(components) != 3:
        raise ValueError("expected a compact JWT with three sections")
    header, claims = (_decode_json_part(component) for component in components[:2])
    if len(components[2]) > MAX_SECTION_BYTES or (
            components[2] and not _ALLOWED_B64URL.fullmatch(components[2])):
        raise ValueError("invalid JWT signature section")
    alg = header.get("alg")
    if not isinstance(alg, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", alg):
        raise ValueError("JWT header has an invalid alg")
    signals = []
    if alg.lower() == "none":
        signals.append({
            "rule": "JWT-ALG-NONE", "severity": "medium",
            "evidence": "Unsecured JWT algorithm declared; acceptance by the server is not established.",
        })
    if any(k in header for k in ("kid", "jku", "x5u", "x5c")):
        signals.append({
            "rule": "JWT-KEY-REFERENCE", "severity": "info",
            "evidence": "JWT contains a key-selection or key-retrieval header; values are omitted.",
        })
    if alg.upper().startswith("HS"):
        signals.append({
            "rule": "JWT-HMAC-REVIEW", "severity": "info",
            "evidence": "HMAC-signed JWT: review key strength and algorithm allowlist; no key test was run.",
        })
    sensitive_claims = sorted(k for k in claims if k.lower() in {
        "role", "roles", "admin", "is_admin", "isadmin", "permissions", "scope",
        "user_id", "uid", "sub", "file", "path",
    })
    if sensitive_claims:
        signals.append({
            "rule": "JWT-AUTHORIZATION-CLAIMS", "severity": "info",
            "evidence": "JWT contains authorization/identity-related claim names; values are omitted.",
        })
    return {
        "schema": "webchallscan/jwt-audit-v1",
        "algorithm": alg,
        "header_names": sorted(str(k)[:64] for k in header)[:100],
        "claim_names": sorted(str(k)[:64] for k in claims)[:100],
        "authorization_claim_names": sensitive_claims,
        "signals": signals,
        "active_tests_executed": 0,
        "limitations": [
            "Offline structure inspection only; no signature or issuer verification.",
            "No token values, signing keys or claim values are included in the result.",
            "Algorithm metadata alone does not establish authentication bypass.",
        ],
    }


def audit_jwt_file(path: str) -> dict:
    file = Path(path)
    if file.stat().st_size > MAX_TOKEN_BYTES:
        raise ValueError("JWT input file is too large")
    # Never echo input text or an exception containing token material.
    token = file.read_text(encoding="utf-8").strip()
    return audit_jwt(token)
