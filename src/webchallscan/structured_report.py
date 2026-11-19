"""Compact, privacy-preserving views for non-scanner structured results.

Only allowlisted metadata is displayed. The original JSON output remains the
default for existing scripts and pipelines.
"""
from __future__ import annotations

from collections import Counter
from textwrap import shorten
from urllib.parse import urlsplit

from .report import ANSI, _use_color

MAX_ROWS = 12


def render_structured_text(result: dict, color: str = "auto",
                           verbose: bool = False) -> str:
    """Render known result schemas without dumping credentials or payload values."""
    if not isinstance(result, dict):
        raise ValueError("structured result must be an object")
    schema = result.get("schema", "")
    if not isinstance(schema, str) or not schema.startswith("webchallscan/"):
        raise ValueError("unsupported structured output schema")
    use_color = _use_color(color)

    def paint(value: object, style: str) -> str:
        text = str(value)
        return ANSI[style] + text + ANSI["reset"] if use_color else text

    def safe(value: object, limit: int = 96) -> str:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        if not isinstance(value, str):
            return "-"
        # Avoid printing controls, ANSI escapes, and overly long imported metadata.
        plain = "".join(c if " " <= c <= "~" else " " for c in value)
        return shorten(plain, width=limit, placeholder="...") if len(plain) > limit else plain

    def limited(items: object) -> list:
        return items if isinstance(items, list) else []

    def lines_for(title: str, entries: list, formatter, *, style: str = "label") -> None:
        output.append("")
        output.append(paint(f"{title}  ({len(entries)})", style))
        amount = len(entries) if verbose else min(len(entries), MAX_ROWS)
        for item in entries[:amount]:
            value = formatter(item)
            if value:
                output.append("  " + safe(value, 150))
        if amount < len(entries):
            output.append(paint(f"  ... {len(entries)-amount} more; use --verbose for all rows", "muted"))

    names = {
        "network-inventory-v1": "NETWORK INVENTORY",
        "audit-plan-v1": "OFFLINE REVIEW PLAN",
        "quick-v1": "QUICK TRIAGE",
        "api-contract-results-v1": "API CONTRACT VALIDATION",
        "read-only-results-v1": "CROSS-ROLE REVIEW",
        "json-results-v1": "JSON API VALIDATION",
        "jwt-audit-v1": "OFFLINE JWT AUDIT",
        "session-format-audit-v1": "SESSION FORMAT AUDIT",
        "burp-session-export-v1": "BURP SESSION EXPORT",
        "source-map-audit-v1": "OFFLINE SOURCE MAP AUDIT",
    }
    label = schema.split("/", 1)[1]
    if label not in names:
        raise ValueError("no human-readable renderer for this schema")
    output = [
        paint("WEBCHALLSCAN", "heading") + "  /  " + paint(names[label], "white"),
        "-" * 70,
    ]
    origin = result.get("origin")
    if isinstance(origin, str):
        parsed = urlsplit(origin)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            output.append("Origin: " + safe(parsed.scheme + "://" + parsed.netloc))
    for key, description in (
        ("observed_requests", "Observed requests"),
        ("endpoint_count", "Endpoints"),
        ("requests_sent", "Requests sent"),
        ("active_tests_executed", "Active tests"),
        ("cookies_exported", "Cookies exported"),
        ("cookie_count", "Cookies audited"),
    ):
        value = result.get(key)
        if type(value) is int:
            output.append(f"{description}: {value}")

    endpoints = limited(result.get("endpoints"))
    if endpoints:
        lines_for("ENDPOINTS", endpoints,
                  lambda e: f"{safe(e.get('method')):7} {safe(e.get('path'))}  "
                            f"params={len(limited(e.get('parameters')))}"
                            if isinstance(e, dict) else "")
    checks = limited(result.get("checks"))
    if checks:
        lines_for("REVIEW TASKS", checks,
                  lambda e: f"{safe(e.get('method')):7} {safe(e.get('path'))}  "
                            f"checks={len(limited(e.get('checks')))}"
                            if isinstance(e, dict) else "")
    triage = limited(result.get("triage"))
    if triage:
        lines_for("TRIAGE", triage,
                  lambda e: f"{safe(e.get('method')):7} {safe(e.get('path'))}"
                            if isinstance(e, dict) else "")
    for name in ("findings", "passive_findings"):
        findings = limited(result.get(name))
        if findings:
            severity = Counter(safe(f.get("severity", "info")).lower()
                               for f in findings if isinstance(f, dict))
            output.append("")
            output.append(paint(
                "FINDINGS  " + "  ".join(f"{key.upper()} {value}"
                                         for key, value in sorted(severity.items())),
                "white",
            ))
            lines_for("DETAILS", findings,
                      lambda f: f"[{safe(f.get('severity', 'info')).upper()}] "
                                f"{safe(f.get('rule'))}  {safe(f.get('title') or f.get('evidence'))}"
                                if isinstance(f, dict) else "")
    cases = limited(result.get("cases"))
    if cases:
        def case_item(entry):
            if not isinstance(entry, dict):
                return ""
            checks = limited(entry.get("checks"))
            if checks:
                outcomes = ", ".join(safe(check.get("outcome"))
                                     for check in checks if isinstance(check, dict))
            else:
                outcomes = safe(entry.get("outcome", entry.get("authorization_review", "-")))
            return (f"#{safe(entry.get('case', entry.get('id', '?')))} "
                    f"{safe(entry.get('path', '-'))}  {outcomes}")
        lines_for("CASES", cases, case_item)
    if label == "jwt-audit-v1":
        output.append("Algorithm: " + safe(result.get("algorithm", "unknown"), 48))
        output.append("Header names: " + str(len(limited(result.get("header_names")))))
        output.append("Claim names: " + str(len(limited(result.get("claim_names")))))
        signals = limited(result.get("signals"))
        lines_for("REVIEW SIGNALS", signals,
                  lambda e: safe(e.get("rule")) if isinstance(e, dict) else "")
    if label == "session-format-audit-v1":
        categories = result.get("format_categories", {})
        if isinstance(categories, dict):
            output.append("Cookie formats:")
            for key, count in sorted(categories.items()):
                if type(count) is int:
                    output.append(f"  {safe(key, 48)}: {count}")
    if label == "source-map-audit-v1":
        for key, name in (("source_count", "Sources"),
                          ("embedded_source_count", "Embedded source contents")):
            if type(result.get(key)) is int:
                output.append(f"{name}: {result[key]}")
        extensions = result.get("extension_categories", {})
        if isinstance(extensions, dict):
            output.append(paint("SOURCE TYPES", "label"))
            for key, count in sorted(extensions.items()):
                if key in {"js", "jsx", "ts", "tsx", "vue", "mjs",
                           "cjs", "css", "scss", "html", "other"} and type(count) is int:
                    output.append(f"  {key}: {count}")
        categories = limited(result.get("comment_hint_categories"))
        if categories:
            output.append(paint("COMMENT HINT CATEGORIES", "medium"))
            for category in categories:
                if category in {"TODO", "FIXME", "FLAG", "SECRET", "PASSWORD", "DEBUG"}:
                    output.append("  " + category)
    if label == "burp-session-export-v1":
        output.append(paint("Sensitive session file created; keep it private.", "medium"))

    limitations = limited(result.get("limitations"))
    if limitations:
        output.append("")
        output.append(paint("LIMITATIONS", "medium"))
        for note in limitations[:(len(limitations) if verbose else 3)]:
            if isinstance(note, str):
                output.append("  - " + safe(note, 140))
    output.append("")
    output.append(paint("JSON remains the default; omit --human for machine-readable output.", "muted"))
    return "\n".join(output)
