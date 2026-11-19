"""Non-invasive HTTP response posture checks for observed browser traffic.

Only response metadata is inspected. No response content, cookies or auth values
are retained; all signals are configuration observations, not exploit proofs.
"""
from __future__ import annotations

from .jwt_audit import audit_jwt


Signal = tuple[str, str, str, str]

_JWT_COOKIE_SIGNALS = (
    ("JWT-ALG-NONE", "COOKIE-JWT-ALG-NONE", "JWT cookie declares unsecured algorithm", "low",
     "Observed a compact JWT cookie declaring alg=none; "
     "server acceptance and authentication bypass are unverified."),
    ("JWT-KEY-REFERENCE", "COOKIE-JWT-KEY-REFERENCE", "JWT cookie includes key-reference metadata", "info",
     "Observed a JWT key-selection/retrieval header; "
     "header values and cookie contents are omitted."),
    ("JWT-HMAC-REVIEW", "COOKIE-JWT-HMAC-REVIEW", "JWT cookie uses HMAC algorithm", "info",
     "Observed HMAC algorithm metadata in a JWT cookie; "
     "key strength and signature validity were not tested."),
    ("JWT-AUTHORIZATION-CLAIMS", "COOKIE-JWT-AUTHZ-CLAIMS", "JWT cookie includes authorization-related claims", "info",
     "Observed authorization or identity claim categories "
     "in a JWT cookie; claim names and values are omitted."),
)


def _document_signals(h: dict[str, str], secure_origin: bool) -> list[Signal]:
    signals: list[Signal] = []
    if secure_origin and "strict-transport-security" not in h:
        signals.append(("HEADER-HSTS", "HSTS absent", "info",
                        "HTTPS document response omits Strict-Transport-Security"))
    if "content-security-policy" not in h:
        signals.append(("HEADER-CSP", "CSP absent", "info",
                        "Document response omits Content-Security-Policy"))
    if "x-content-type-options" not in h:
        signals.append(("HEADER-NOSNIFF", "X-Content-Type-Options absent", "info",
                        "Document response omits X-Content-Type-Options"))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", "").lower():
        signals.append(("HEADER-FRAMING", "No framing restriction observed", "low",
                        "Neither X-Frame-Options nor CSP frame-ancestors is present"))
    return signals


def _cookie_attribute_signals(attributes: list[str], secure_origin: bool) -> list[Signal]:
    attr_names = {part.strip().split("=", 1)[0].lower() for part in attributes}
    signals: list[Signal] = []
    if secure_origin and "secure" not in attr_names:
        signals.append(("COOKIE-SECURE", "Cookie lacks Secure attribute", "low",
                        "A cookie on an HTTPS response omits Secure; the cookie name and value are hidden"))
    if "httponly" not in attr_names:
        signals.append(("COOKIE-HTTPONLY", "Cookie lacks HttpOnly attribute", "info",
                        "A cookie omits HttpOnly; applicability depends on the cookie's purpose"))
    if "samesite" not in attr_names:
        signals.append(("COOKIE-SAMESITE", "Cookie lacks SameSite attribute", "info",
                        "A cookie omits an explicit SameSite attribute; browser defaults may apply"))
    if "samesite" in attr_names and any(
            part.strip().lower().startswith("samesite=none") for part in attributes
    ) and "secure" not in attr_names:
        signals.append(("COOKIE-SAMESITE-NONE", "SameSite=None cookie lacks Secure", "low",
                        "SameSite=None appears without Secure; modern browsers may reject the cookie"))
    return signals


def _cookie_jwt_signals(value: str) -> list[Signal]:
    # JWT signals are based solely on structure observed in existing
    # Set-Cookie headers. Never include cookie names, token values,
    # signatures, custom claim names, or arbitrary header values.
    if not 0 < len(value) <= 4096 or value.count(".") != 2:
        return []
    try:
        audit = audit_jwt(value)
    except ValueError:
        return []
    known = {signal["rule"] for signal in audit["signals"]}
    return [(rule, title, severity, evidence)
            for source, rule, title, severity, evidence in _JWT_COOKIE_SIGNALS
            if source in known]


def _cookie_signals(cookie: object, secure_origin: bool) -> list[Signal]:
    if not isinstance(cookie, str) or not cookie or len(cookie) > 8192:
        return []
    first, *attributes = cookie.split(";")
    if "=" not in first or not first.split("=", 1)[0].strip():
        return []
    value = first.split("=", 1)[1].strip().strip('"')
    return _cookie_attribute_signals(attributes, secure_origin) + _cookie_jwt_signals(value)


def inspect_response(method: str, path: str, resource_type: str,
                     status: int, headers: dict[str, str],
                     secure_origin: bool, *,
                     cookie_headers: tuple[str, ...] | None = None) -> list[dict[str, str]]:
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    out: list[dict[str, str]] = []

    def add(rule: str, title: str, severity: str, evidence: str) -> None:
        out.append({"rule": rule, "title": title, "severity": severity,
                    "confidence": "medium", "method": method, "path": path,
                    "evidence": evidence, "status": str(status)})
    # Report document-level policies only for successful HTML documents.
    if resource_type == "Document" and 200 <= status < 300:
        for signal in _document_signals(h, secure_origin):
            add(*signal)
    # Only flag the potentially dangerous combination; a permissive CORS origin
    # by itself is not proof of unauthorized access.
    if h.get("access-control-allow-origin", "").strip() == "*" and h.get(
            "access-control-allow-credentials", "").strip().lower() == "true":
        add("HEADER-CORS-CONFLICT", "Conflicting CORS credential policy", "low",
            "Wildcard ACAO appears together with Access-Control-Allow-Credentials: true")
    # Inspect only Set-Cookie attributes. Never store cookie values or names.
    # This is intentionally conservative: a cookie's purpose is unknown.
    # Multiple Set-Cookie headers are independent, not comma-joinable.
    # Keep their names and values only in memory; deduplicate findings by rule.
    cookies = (cookie_headers if cookie_headers is not None
               else (h.get("set-cookie", ""),))
    emitted: set[str] = set()
    for cookie in cookies[:50]:
        for signal in _cookie_signals(cookie, secure_origin):
            if signal[0] not in emitted:
                emitted.add(signal[0])
                add(*signal)
    return out
