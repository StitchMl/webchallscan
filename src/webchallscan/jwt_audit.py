"""Offline JWT metadata audit with bounded checks for a few known weak HMAC keys."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

_ALLOWED_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_TOKEN_BYTES = 16_384
MAX_SECTION_BYTES = 8_192

# A fixed, intentionally tiny offline diagnostic set; not a password dictionary.
_COMMON_HMAC_KEYS = (b"secret", b"123456")
_HMAC_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512}


def _known_weak_hmac_key(token: str, algorithm: str) -> bool:
    digest = _HMAC_ALGORITHMS.get(algorithm)
    if digest is None:
        return False
    encoded_signature = token.rsplit(".", 1)[1]
    try:
        signature = base64.b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4),
            altchars=b"-_", validate=True,
        )
    except ValueError:
        return False
    if len(signature) != digest().digest_size:
        return False
    signed_data = token.rsplit(".", 1)[0].encode("ascii")
    return any(hmac.compare_digest(
        hmac.new(key, signed_data, digest).digest(), signature,
    ) for key in _COMMON_HMAC_KEYS)


def _decode_json_part(value: str) -> dict:
    if not value or len(value) > MAX_SECTION_BYTES or not _ALLOWED_B64URL.fullmatch(value):
        raise ValueError("invalid JWT base64url section")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        decoded = json.loads(raw)
    except ValueError as exc:
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
            "evidence": "HMAC-signed JWT: review key strength and algorithm allowlist.",
        })
        if _known_weak_hmac_key(token, alg):
            signals.append({
                "rule": "JWT-HMAC-KNOWN-WEAK-KEY", "severity": "medium",
                "evidence": ("JWT signature matches a fixed, commonly used weak HMAC key offline; "
                             "server acceptance and token validity are not established."),
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
            "Only a tiny fixed set of weak HMAC keys is checked; no general signature, issuer or audience verification.",
            "No token values, signing keys or claim values are included in the result.",
            "Algorithm metadata alone does not establish authentication bypass.",
        ],
    }


def audit_jwt_file(path: str) -> dict:
    """Inspect only an explicit, bounded local token file in the work area."""
    workspace = Path.cwd().resolve()
    supplied = Path(path)
    try:
        relative = supplied.relative_to(workspace) if supplied.is_absolute() else supplied
    except ValueError as exc:
        raise ValueError("JWT file must be inside the working directory") from exc
    filename = relative.name
    if (len(relative.parts) != 1
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(?:jwt|txt)", filename)
            or ".." in filename):
        raise ValueError("JWT file must be a simple .jwt or .txt filename")
    file = workspace / filename
    if file.is_symlink() or not file.is_file():
        raise ValueError("JWT input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(file, flags)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("JWT input must be a regular file")
            raw = stream.read(MAX_TOKEN_BYTES + 1)
    except OSError as exc:
        raise ValueError("cannot read JWT input file") from exc
    if len(raw) > MAX_TOKEN_BYTES:
        raise ValueError("JWT input file is too large")
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("invalid JWT input encoding") from exc
    return audit_jwt(token)
