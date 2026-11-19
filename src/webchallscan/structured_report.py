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


_NAMES = {
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
_COUNTERS = (
    ("observed_requests", "Observed requests"),
    ("endpoint_count", "Endpoints"),
    ("requests_sent", "Requests sent"),
    ("active_tests_executed", "Active tests"),
    ("cookies_exported", "Cookies exported"),
    ("cookie_count", "Cookies audited"),
)
_SOURCE_EXTENSIONS = {"js", "jsx", "ts", "tsx", "vue", "mjs",
                      "cjs", "css", "scss", "html", "other"}
_COMMENT_HINTS = {"TODO", "FIXME", "FLAG", "SECRET", "PASSWORD", "DEBUG"}


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


def _method_path(e: object) -> str:
    return f"{safe(e.get('method')):7} {safe(e.get('path'))}" if isinstance(e, dict) else ""


def _endpoint_row(e: object) -> str:
    if not isinstance(e, dict):
        return ""
    return (f"{_method_path(e)}  params={len(limited(e.get('parameters')))}  "
            f"json-fields={len(limited(e.get('json_fields')))}")


def _check_row(e: object) -> str:
    if not isinstance(e, dict):
        return ""
    return (f"{_method_path(e)}  checks={len(limited(e.get('checks')))}  "
            f"json-fields={len(limited(e.get('json_field_paths')))}")


def _finding_row(f: object) -> str:
    if not isinstance(f, dict):
        return ""
    return (f"[{safe(f.get('severity', 'info')).upper()}] "
            f"{safe(f.get('rule'))}  {safe(f.get('title') or f.get('evidence'))}")


def _case_row(entry: object) -> str:
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


class _Renderer:
    """Accumulates the human-readable view of one structured result."""

    def __init__(self, result: dict, use_color: bool, verbose: bool) -> None:
        self.result = result
        self.use_color = use_color
        self.verbose = verbose
        self.output: list[str] = []

    def paint(self, value: object, style: str) -> str:
        text = str(value)
        return ANSI[style] + text + ANSI["reset"] if self.use_color else text

    def lines_for(self, title: str, entries: list, formatter, *, style: str = "label") -> None:
        self.output.extend(["", self.paint(f"{title}  ({len(entries)})", style)])
        amount = len(entries) if self.verbose else min(len(entries), MAX_ROWS)
        for item in entries[:amount]:
            value = formatter(item)
            if value:
                self.output.append("  " + safe(value, 150))
        if amount < len(entries):
            self.output.append(self.paint(
                f"  ... {len(entries)-amount} more; use --verbose for all rows", "muted"))

    def header(self, label: str) -> None:
        self.output.extend([
            self.paint("WEBCHALLSCAN", "heading") + "  /  " + self.paint(_NAMES[label], "white"),
            "-" * 70,
        ])
        origin = self.result.get("origin")
        if isinstance(origin, str):
            parsed = urlsplit(origin)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                self.output.append("Origin: " + safe(parsed.scheme + "://" + parsed.netloc))
        for key, description in _COUNTERS:
            value = self.result.get(key)
            if type(value) is int:
                self.output.append(f"{description}: {value}")

    def listings(self) -> None:
        result = self.result
        for key, title, row in (("endpoints", "ENDPOINTS", _endpoint_row),
                                ("checks", "REVIEW TASKS", _check_row),
                                ("triage", "TRIAGE", _method_path)):
            entries = limited(result.get(key))
            if entries:
                self.lines_for(title, entries, row)
        for name in ("findings", "passive_findings"):
            findings = limited(result.get(name))
            if findings:
                self.finding_summary(findings)
        cases = limited(result.get("cases"))
        if cases:
            self.lines_for("CASES", cases, _case_row)

    def finding_summary(self, findings: list) -> None:
        severity = Counter(safe(f.get("severity", "info")).lower()
                           for f in findings if isinstance(f, dict))
        self.output.extend(["", self.paint(
            "FINDINGS  " + "  ".join(f"{key.upper()} {value}"
                                     for key, value in sorted(severity.items())),
            "white",
        )])
        self.lines_for("DETAILS", findings, _finding_row)

    def jwt_section(self) -> None:
        result = self.result
        self.output.extend([
            "Algorithm: " + safe(result.get("algorithm", "unknown"), 48),
            "Header names: " + str(len(limited(result.get("header_names")))),
            "Claim names: " + str(len(limited(result.get("claim_names")))),
        ])
        signals = limited(result.get("signals"))
        self.lines_for("REVIEW SIGNALS", signals,
                       lambda e: safe(e.get("rule")) if isinstance(e, dict) else "")

    def session_section(self) -> None:
        categories = self.result.get("format_categories", {})
        if isinstance(categories, dict):
            self.output.append("Cookie formats:")
            for key, count in sorted(categories.items()):
                if type(count) is int:
                    self.output.append(f"  {safe(key, 48)}: {count}")

    def source_types(self, extensions: object) -> None:
        if isinstance(extensions, dict):
            self.output.append(self.paint("SOURCE TYPES", "label"))
            for key, count in sorted(extensions.items()):
                if key in _SOURCE_EXTENSIONS and type(count) is int:
                    self.output.append(f"  {key}: {count}")

    def source_map_section(self) -> None:
        result = self.result
        for key, name in (("source_count", "Sources"),
                          ("embedded_source_count", "Embedded source contents")):
            if type(result.get(key)) is int:
                self.output.append(f"{name}: {result[key]}")
        self.source_types(result.get("extension_categories", {}))
        categories = limited(result.get("comment_hint_categories"))
        if categories:
            self.output.append(self.paint("COMMENT HINT CATEGORIES", "medium"))
            for category in categories:
                if category in _COMMENT_HINTS:
                    self.output.append("  " + category)

    def schema_section(self, label: str) -> None:
        if label == "jwt-audit-v1":
            self.jwt_section()
        if label == "session-format-audit-v1":
            self.session_section()
        if label == "source-map-audit-v1":
            self.source_map_section()
        if label == "burp-session-export-v1":
            self.output.append(self.paint("Sensitive session file created; keep it private.", "medium"))

    def footer(self) -> None:
        limitations = limited(self.result.get("limitations"))
        if limitations:
            self.output.extend(["", self.paint("LIMITATIONS", "medium")])
            for note in limitations[:(len(limitations) if self.verbose else 3)]:
                if isinstance(note, str):
                    self.output.append("  - " + safe(note, 140))
        self.output.extend(["", self.paint(
            "JSON remains the default; omit --human for machine-readable output.", "muted")])


def render_structured_text(result: dict, color: str = "auto",
                           verbose: bool = False) -> str:
    """Render known result schemas without dumping credentials or payload values."""
    if not isinstance(result, dict):
        raise ValueError("structured result must be an object")
    schema = result.get("schema", "")
    if not isinstance(schema, str) or not schema.startswith("webchallscan/"):
        raise ValueError("unsupported structured output schema")
    use_color = _use_color(color)
    label = schema.split("/", 1)[1]
    if label not in _NAMES:
        raise ValueError("no human-readable renderer for this schema")
    renderer = _Renderer(result, use_color, verbose)
    renderer.header(label)
    renderer.listings()
    renderer.schema_section(label)
    renderer.footer()
    return "\n".join(renderer.output)
