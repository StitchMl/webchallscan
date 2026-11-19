"""Readable, zero-dependency terminal reporting.

Default to a compact triage view; --verbose preserves full replay guidance.
The machine-readable JSON schema is intentionally independent of this module.
"""
from __future__ import annotations

from collections import Counter
import json
import os
import shutil
import sys
from textwrap import wrap

from .model import ScanReport, redact_url

ANSI = {
    "reset": "\x1b[0m",
    "critical": "\x1b[1;91m",
    "high": "\x1b[1;31m",
    "medium": "\x1b[1;33m",
    "low": "\x1b[1;36m",
    "info": "\x1b[94m",
    "label": "\x1b[1;96m",
    "ready": "\x1b[1;92m",
    "muted": "\x1b[2m",
    "heading": "\x1b[1;95m",
    "white": "\x1b[1;97m",
}
ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}


def _use_color(mode: str) -> bool:
    if mode not in {"auto", "always", "never"}:
        raise ValueError("color must be auto, always or never")
    return mode == "always" or (
        mode == "auto" and sys.stdout.isatty()
        and "NO_COLOR" not in os.environ and os.getenv("TERM", "") != "dumb"
    )


class _Painter:
    """Colour and wrap helper bound to one terminal width."""

    def __init__(self, paint: bool, width: int) -> None:
        self.paint = paint
        self.width = width

    def c(self, value: str, style: str) -> str:
        return f"{ANSI.get(style, '')}{value}{ANSI['reset']}" if self.paint else value

    def field(self, label: str, value: str, *, style: str = "label",
              indent: str = "    ") -> list[str]:
        prefix = f"{indent}{label:<12} "
        lines = wrap(str(value), width=max(24, self.width - len(prefix)),
                     break_long_words=False, break_on_hyphens=False,
                     replace_whitespace=True, drop_whitespace=True) or ["-"]
        output = [self.c(prefix, style) + lines[0]]
        output.extend(" " * len(prefix) + line for line in lines[1:])
        return output


def _display_limit(top: int | None, verbose: bool) -> int | None:
    if top is not None:
        return top
    return None if verbose else 20


def _severity_rank(severity: str) -> int:
    lowered = severity.lower()
    return ORDER.index(lowered) if lowered in ORDER else len(ORDER)


def _is_eligible(severity: str, min_severity: str) -> bool:
    lowered = severity.lower()
    if lowered not in ORDER:
        return min_severity == "info"
    return ORDER.index(lowered) <= ORDER.index(min_severity)


def _verbose_item_lines(p: _Painter, item, replay: dict) -> list[str]:
    ready = item.exploit_status == "payload-ready"
    lines = p.field("Exploit", item.exploit_status, style="ready" if ready else "label")
    lines.extend(p.field("Flag path", item.flag_path))
    lines.extend(p.field("Vector", item.vector))
    lines.extend(p.field("Replay",
                         f"{replay['method']} {replay['path']}  "
                         f"cookies={','.join(replay['cookie_names']) or 'none'}  "
                         f"fields={','.join(f['name'] for f in replay['body']) or 'none'}"))
    lines.extend(p.field("Proof", replay["proof_payload"] or "none"))
    lines.extend(p.field("Expected", replay["expected_evidence"] or "manual comparison"))
    recovery = item.recovery_payload if ready and item.recovery_payload else "not proven"
    lines.extend(p.field("Recovery", recovery))
    return lines


def _item_lines(p: _Painter, item, severity: str, title: str, verbose: bool) -> list[str]:
    replay = item.to_dict()["replay"]
    style = severity if severity in ORDER else "label"
    badge = p.c(f"[{title}]", style)
    lines = [
        "",
        f"{badge}  {p.c(item.title, 'white')}",
        p.c(f"  {item.rule}  |  {item.id}  |  {item.profile}  |  confidence: {item.confidence}", "muted"),
    ]
    lines.extend(p.field("Target", redact_url(item.url)))
    if item.parameter:
        lines.extend(p.field("Parameter", item.parameter))
    lines.extend(p.field("Evidence", item.evidence))
    if item.exploit_status in {"payload-ready", "flag-recovered"}:
        lines.extend(p.field("Status", item.exploit_status, style="ready"))
    if item.patch:
        lines.extend(p.field("Fix", item.patch))
    if verbose:
        lines.extend(_verbose_item_lines(p, item, replay))
    elif item.proof_payload:
        lines.extend(p.field("Proof", replay["proof_payload"]))
    return lines


def _group_lines(p: _Painter, visible: list, separator: str, verbose: bool) -> list[str]:
    groups: dict[str, list] = {severity: [] for severity in ORDER}
    other: list = []
    for item in visible:
        groups.get(item.severity.lower(), other).append(item)
    lines: list[str] = []
    for severity in ORDER + ("other",):
        items = groups[severity] if severity in groups else other
        if not items:
            continue
        lines.extend(["", separator])
        title = SEVERITY_LABEL.get(severity, "OTHER")
        lines.append(p.c(f"{title}  ({len(items)})", severity if severity in ORDER else "label"))
        lines.append(separator)
        for item in items:
            lines.extend(_item_lines(p, item, severity, title, verbose))
    return lines


def _findings_lines(p: _Painter, report: ScanReport, visible: list, hidden: int,
                    separator: str, verbose: bool) -> list[str]:
    if not report.findings:
        return [
            "",
            p.c("No evidence-backed findings.", "ready"),
            "This does not prove the target is safe.",
        ]
    lines: list[str] = []
    if not visible:
        lines.extend(["", p.c("No findings match the selected severity filter.", "muted")])
    lines.extend(_group_lines(p, visible, separator, verbose))
    if hidden:
        lines.extend(["", p.c(
            f"{hidden} finding detail(s) omitted by the display limit or severity filter. "
            "Use --verbose, --top or --min-severity to adjust the view.",
            "medium",
        )])
    if not verbose:
        lines.extend(["", p.c("Tip: use --verbose for replay, vectors and full verification details.", "muted")])
    return lines


def _notes_lines(p: _Painter, report: ScanReport, separator: str) -> list[str]:
    lines: list[str] = []
    if report.coverage:
        lines.extend(["", separator, p.c(f"COVERAGE NOTES  ({len(report.coverage)})", "medium")])
        for note in report.coverage:
            lines.extend(p.field("-", note, style="muted", indent="  "))
    if report.errors:
        lines.extend(["", separator, p.c(f"REQUEST ERRORS  ({len(report.errors)})", "high")])
        for message in report.errors:
            safe = redact_url(message) if "://" in message else message
            lines.extend(p.field("-", safe, style="muted", indent="  "))
    return lines


def render_text(report: ScanReport, color: str = "auto",
                verbose: bool = False, *,
                top: int | None = None, min_severity: str = "info") -> str:
    """Display actionable scan triage with detailed evidence on demand."""
    paint = _use_color(color)
    if min_severity not in ORDER:
        raise ValueError("invalid minimum severity")
    if top is not None and not 1 <= top <= 1000:
        raise ValueError("--top must be 1-1000")
    limit = _display_limit(top, verbose)
    eligible = [item for item in report.findings
                if _is_eligible(item.severity, min_severity)]
    filtered = sorted(eligible, key=lambda item: _severity_rank(item.severity))
    visible = filtered[:limit] if limit is not None else filtered
    hidden = len(report.findings) - len(visible)
    width = max(62, min(108, shutil.get_terminal_size(fallback=(88, 24)).columns))
    separator = "-" * min(width, 88)
    p = _Painter(paint, width)

    counts = Counter(item.severity.lower() for item in report.findings)
    summary = "   ".join(
        p.c(f"{SEVERITY_LABEL[severity]} {counts[severity]}", severity)
        for severity in ORDER if counts[severity]
    ) or p.c("No findings", "ready")

    lines = [
        p.c("WEBCHALLSCAN", "heading") + p.c("  /  SECURITY TRIAGE", "muted"),
        separator,
        p.c("Target", "label") + "   " + redact_url(report.target),
        f"Mode: {'ACTIVE LOW-IMPACT' if report.active else 'PASSIVE'}  "
        f"Profiles: {','.join(report.profiles)}  Session: {report.session_source}",
        f"Pages: {report.pages_scanned}  Requests: {report.requests_sent}  "
        f"Findings: {len(report.findings)}",
        "",
        p.c("FINDINGS OVERVIEW", "white"),
        summary,
    ]
    lines.extend(_findings_lines(p, report, visible, hidden, separator, verbose))
    lines.extend(_notes_lines(p, report, separator))
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
