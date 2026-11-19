"""Non-invasive HTTP response posture checks for observed browser traffic.

Only response metadata is inspected. No response content, cookies or auth values
are retained; all signals are configuration observations, not exploit proofs.
"""
from __future__ import annotations


def inspect_response(method: str, path: str, resource_type: str,
                     status: int, headers: dict[str, str],
                     secure_origin: bool) -> list[dict[str, str]]:
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    out: list[dict[str, str]] = []
    def add(rule: str, title: str, severity: str, evidence: str) -> None:
        out.append({"rule": rule, "title": title, "severity": severity,
                    "confidence": "medium", "method": method, "path": path,
                    "evidence": evidence, "status": str(status)})
    # Report document-level policies only for successful HTML documents.
    if resource_type == "Document" and 200 <= status < 300:
        if secure_origin and "strict-transport-security" not in h:
            add("HEADER-HSTS", "HSTS absent", "info",
                "HTTPS document response omits Strict-Transport-Security")
        if "content-security-policy" not in h:
            add("HEADER-CSP", "CSP absent", "info",
                "Document response omits Content-Security-Policy")
        if "x-content-type-options" not in h:
            add("HEADER-NOSNIFF", "X-Content-Type-Options absent", "info",
                "Document response omits X-Content-Type-Options")
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", "").lower():
            add("HEADER-FRAMING", "No framing restriction observed", "low",
                "Neither X-Frame-Options nor CSP frame-ancestors is present")
    # Only flag the potentially dangerous combination; a permissive CORS origin
    # by itself is not proof of unauthorized access.
    if h.get("access-control-allow-origin", "").strip() == "*" and h.get(
            "access-control-allow-credentials", "").strip().lower() == "true":
        add("HEADER-CORS-CONFLICT", "Conflicting CORS credential policy", "low",
            "Wildcard ACAO appears together with Access-Control-Allow-Credentials: true")
    # Inspect only Set-Cookie attributes. Never store cookie values or names.
    # This is intentionally conservative: a cookie's purpose is unknown.
    cookie = h.get("set-cookie", "")
    if cookie and len(cookie) <= 8192:
        first, *attributes = cookie.split(";")
        if "=" in first and first.split("=", 1)[0].strip():
            attr_names = {part.strip().split("=", 1)[0].lower()
                          for part in attributes}
            if secure_origin and "secure" not in attr_names:
                add("COOKIE-SECURE", "Cookie lacks Secure attribute", "low",
                    "A cookie on an HTTPS response omits Secure; the cookie name and value are hidden")
            if "httponly" not in attr_names:
                add("COOKIE-HTTPONLY", "Cookie lacks HttpOnly attribute", "info",
                    "A cookie omits HttpOnly; applicability depends on the cookie's purpose")
            if "samesite" not in attr_names:
                add("COOKIE-SAMESITE", "Cookie lacks SameSite attribute", "info",
                    "A cookie omits an explicit SameSite attribute; browser defaults may apply")
            if "samesite" in attr_names and any(
                    part.strip().lower().startswith("samesite=none") for part in attributes
            ) and "secure" not in attr_names:
                add("COOKIE-SAMESITE-NONE", "SameSite=None cookie lacks Secure", "low",
                    "SameSite=None appears without Secure; modern browsers may reject the cookie")
    return out
