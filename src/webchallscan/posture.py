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
    return out
