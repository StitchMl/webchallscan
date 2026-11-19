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


def render_text(report: ScanReport, color: str = "auto",
                verbose: bool = False, *,
                top: int | None = None, min_severity: str = "info") -> str:
    """Display actionable scan triage with detailed evidence on demand."""
    paint = _use_color(color)
    if min_severity not in ORDER:
        raise ValueError("invalid minimum severity")
    if top is not None and not 1 <= top <= 1000:
        raise ValueError("--top must be 1-1000")
    limit = top if top is not None else (None if verbose else 20)
    cutoff = ORDER.index(min_severity)
    eligible = [item for item in report.findings
                if ((item.severity.lower() not in ORDER and min_severity == "info")
                    or (item.severity.lower() in ORDER
                        and ORDER.index(item.severity.lower()) <= cutoff))]
    filtered = sorted(eligible, key=lambda item: (
        ORDER.index(item.severity.lower()) if item.severity.lower() in ORDER else len(ORDER)
    ))
    visible = filtered[:limit] if limit is not None else filtered
    hidden = len(report.findings) - len(visible)
    width = max(62, min(108, shutil.get_terminal_size(fallback=(88, 24)).columns))
    separator = "-" * min(width, 88)

    def c(value: str, style: str) -> str:
        return f"{ANSI.get(style, '')}{value}{ANSI['reset']}" if paint else value

    def field(label: str, value: str, *, style: str = "label",
              indent: str = "    ") -> list[str]:
        prefix = f"{indent}{label:<12} "
        lines = wrap(str(value), width=max(24, width - len(prefix)),
                     break_long_words=False, break_on_hyphens=False,
                     replace_whitespace=True, drop_whitespace=True) or ["-"]
        output = [c(prefix, style) + lines[0]]
        output.extend(" " * len(prefix) + line for line in lines[1:])
        return output

    counts = Counter(item.severity.lower() for item in report.findings)
    summary = "   ".join(
        c(f"{SEVERITY_LABEL[severity]} {counts[severity]}", severity)
        for severity in ORDER if counts[severity]
    ) or c("No findings", "ready")

    lines = [
        c("WEBCHALLSCAN", "heading") + c("  /  SECURITY TRIAGE", "muted"),
        separator,
        c("Target", "label") + "   " + redact_url(report.target),
        f"Mode: {'ACTIVE LOW-IMPACT' if report.active else 'PASSIVE'}  "
        f"Profiles: {','.join(report.profiles)}  Session: {report.session_source}",
        f"Pages: {report.pages_scanned}  Requests: {report.requests_sent}  "
        f"Findings: {len(report.findings)}",
        "",
        c("FINDINGS OVERVIEW", "white"),
        summary,
    ]
    if not report.findings:
        lines.extend([
            "",
            c("No evidence-backed findings.", "ready"),
            "This does not prove the target is safe.",
        ])
    else:
        if not visible:
            lines.extend(["", c("No findings match the selected severity filter.", "muted")])
        groups = {severity: [] for severity in ORDER}
        other = []
        for item in visible:
            groups.get(item.severity.lower(), other).append(item)
        for severity in ORDER + ("other",):
            items = groups[severity] if severity in groups else other
            if not items:
                continue
            lines.extend(["", separator])
            title = SEVERITY_LABEL.get(severity, "OTHER")
            lines.append(c(f"{title}  ({len(items)})", severity if severity in ORDER else "label"))
            lines.append(separator)
            for index, item in enumerate(items, 1):
                replay = item.to_dict()["replay"]
                badge = c(f"[{title}]", severity if severity in ORDER else "label")
                lines.extend([
                    "",
                    f"{badge}  {c(item.title, 'white')}",
                    c(f"  {item.rule}  |  {item.id}  |  {item.profile}  |  confidence: {item.confidence}", "muted"),
                ])
                lines.extend(field("Target", redact_url(item.url)))
                if item.parameter:
                    lines.extend(field("Parameter", item.parameter))
                lines.extend(field("Evidence", item.evidence))
                if item.exploit_status in {"payload-ready", "flag-recovered"}:
                    lines.extend(field("Status", item.exploit_status, style="ready"))
                if item.patch:
                    lines.extend(field("Fix", item.patch))
                if verbose:
                    lines.extend(field("Exploit", item.exploit_status,
                                       style="ready" if item.exploit_status == "payload-ready" else "label"))
                    lines.extend(field("Flag path", item.flag_path))
                    lines.extend(field("Vector", item.vector))
                    lines.extend(field("Replay",
                                       f"{replay['method']} {replay['path']}  "
                                       f"cookies={','.join(replay['cookie_names']) or 'none'}  "
                                       f"fields={','.join(f['name'] for f in replay['body']) or 'none'}"))
                    lines.extend(field("Proof", replay["proof_payload"] or "none"))
                    lines.extend(field("Expected", replay["expected_evidence"] or "manual comparison"))
                    lines.extend(field("Recovery",
                                       item.recovery_payload if item.exploit_status == "payload-ready"
                                       and item.recovery_payload else "not proven"))
                elif item.proof_payload:
                    lines.extend(field("Proof", replay["proof_payload"]))
        if hidden:
            lines.extend(["", c(
                f"{hidden} finding detail(s) omitted by the display limit or severity filter. "
                "Use --verbose, --top or --min-severity to adjust the view.",
                "medium",
            )])
        if not verbose:
            lines.extend(["", c("Tip: use --verbose for replay, vectors and full verification details.", "muted")])

    if report.coverage:
        lines.extend(["", separator, c(f"COVERAGE NOTES  ({len(report.coverage)})", "medium")])
        for note in report.coverage:
            lines.extend(field("-", note, style="muted", indent="  "))
    if report.errors:
        lines.extend(["", separator, c(f"REQUEST ERRORS  ({len(report.errors)})", "high")])
        for message in report.errors:
            safe = redact_url(message) if "://" in message else message
            lines.extend(field("-", safe, style="muted", indent="  "))
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
