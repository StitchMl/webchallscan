"""Shareable Markdown summaries from the existing redacted finding model."""
from __future__ import annotations

from collections import Counter
import re

from .model import ScanReport, redact_url
from .report import ORDER


def _inline(value: object) -> str:
    """Escape Markdown syntax and avoid HTML/control interpretation."""
    text = str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    for char in ("\\", "*", "_", "`", "[", "]", "<", ">", "|"):
        text = text.replace(char, "\\" + char)
    return text


def _display_limit(top: int | None, verbose: bool) -> int | None:
    if top is not None:
        return top
    return None if verbose else 20


def _header_lines(report: ScanReport, counts: Counter) -> list[str]:
    lines = [
        "# webchallscan — scan report",
        "",
        f"**Target:** {_inline(redact_url(report.target))}",
        f"**Mode:** {'Active low-impact' if report.active else 'Passive'}",
        f"**Profiles:** {_inline(', '.join(report.profiles))}",
        f"**Pages:** {report.pages_scanned} · **Requests:** {report.requests_sent} · "
        f"**Findings:** {len(report.findings)}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|:--|--:|",
    ]
    for severity in ORDER:
        lines.append(f"| {severity.upper()} | {counts[severity]} |")
    return lines


def _verbose_lines(f, replay: dict) -> list[str]:
    lines = [
        f"- **Vector:** {_inline(f.vector)}",
        f"- **Exploit status:** {_inline(f.exploit_status)}",
        f"- **Flag path:** {_inline(f.flag_path)}",
        f"- **Replay:** {_inline(replay['method'])} {_inline(replay['path'])}",
        f"- **Expected:** {_inline(replay['expected_evidence'] or 'manual comparison')}",
    ]
    if f.proof_payload:
        lines.append(f"- **Proof payload:** {_inline(f.proof_payload)}")
    if f.exploit_status == "payload-ready" and f.recovery_payload:
        lines.append(f"- **Recovery payload:** {_inline(f.recovery_payload)}")
    return lines


def _finding_lines(f, verbose: bool) -> list[str]:
    replay = f.to_dict()["replay"]
    lines = [
        "",
        f"### {_inline(f.severity.upper())}: {_inline(f.title)}",
        "",
        f"**Rule:** {_inline(f.rule)} · **ID:** {_inline(f.id)} · "
        f"**Confidence:** {_inline(f.confidence)} · **Profile:** {_inline(f.profile)}",
        "",
        f"- **Target:** {_inline(redact_url(f.url))}",
    ]
    if f.parameter:
        lines.append(f"- **Parameter:** {_inline(f.parameter)}")
    lines.append(f"- **Evidence:** {_inline(f.evidence)}")
    if f.patch:
        lines.append(f"- **Fix:** {_inline(f.patch)}")
    if f.exploit_status in ("payload-ready", "flag-recovered"):
        lines.append(f"- **Status:** {_inline(f.exploit_status)}")
    if verbose:
        lines.extend(_verbose_lines(f, replay))
    elif f.proof_payload:
        lines.append(f"- **Proof payload:** {_inline(f.proof_payload)}")
    return lines


def _footer_lines(report: ScanReport, hidden: int) -> list[str]:
    lines: list[str] = []
    if hidden:
        lines.extend([
            "",
            f"*{hidden} finding detail(s) omitted by the display limit or severity filter. "
            "Use --verbose, --top or --min-severity to change this view.*",
        ])
    if report.coverage:
        lines.extend(["", "## Coverage limitations"])
        lines.extend(f"- {_inline(note)}" for note in report.coverage)
    if report.errors:
        lines.extend(["", "## Request errors"])
        lines.extend(f"- {_inline(redact_url(error) if '://' in error else error)}"
                     for error in report.errors)
    lines.extend(["", "---", "Generated for manual review; no finding is a guarantee of exploitability."])
    return lines


def render_markdown(report: ScanReport, *, verbose: bool = False,
                    top: int | None = None, min_severity: str = "info") -> str:
    if min_severity not in ORDER:
        raise ValueError("invalid minimum severity")
    if top is not None and not 1 <= top <= 1000:
        raise ValueError("--top must be 1-1000")
    severity_index = ORDER.index(min_severity)
    eligible = [f for f in report.findings if f.severity.lower() in ORDER
                and ORDER.index(f.severity.lower()) <= severity_index]
    eligible.sort(key=lambda f: ORDER.index(f.severity.lower()))
    limit = _display_limit(top, verbose)
    visible = eligible[:limit] if limit is not None else eligible
    hidden = len(report.findings) - len(visible)
    counts = Counter(f.severity.lower() for f in report.findings)
    lines = _header_lines(report, counts)
    lines.extend(["", "## Finding details"])
    if not report.findings:
        lines.extend(["", "No evidence-backed findings; this does not prove the target is safe."])
    elif not visible:
        lines.extend(["", "No finding details match the selected severity filter."])
    for f in visible:
        lines.extend(_finding_lines(f, verbose))
    lines.extend(_footer_lines(report, hidden))
    return "\n".join(lines)
