from __future__ import annotations

import json
import os
import sys

from .model import ScanReport, redact_url

ANSI = {
    "reset": "\x1b[0m", "critical": "\x1b[1;31m", "high": "\x1b[31m",
    "medium": "\x1b[33m", "low": "\x1b[36m", "info": "\x1b[2m",
    "label": "\x1b[1;34m", "ready": "\x1b[1;32m",
}


def _use_color(mode: str) -> bool:
    return mode == "always" or (mode == "auto" and sys.stdout.isatty() and not os.getenv("NO_COLOR"))


def render_text(report: ScanReport, color: str = "auto") -> str:
    paint = _use_color(color)
    def c(value: str, style: str) -> str:
        return f"{ANSI[style]}{value}{ANSI['reset']}" if paint else value
    lines = [c("WEBCHALLSCAN", "label") + f"  {redact_url(report.target)}",
             f"Mode: {'ACTIVE LOW-IMPACT' if report.active else 'PASSIVE'}  Profiles: {','.join(report.profiles)}  Session: {report.session_source}  Pages: {report.pages_scanned}  Requests: {report.requests_sent}  Findings: {len(report.findings)}"]
    if not report.findings:
        lines.append("\nNo evidence-backed findings. This does not prove the target is safe.")
    for item in report.findings:
        status_style = "ready" if item.exploit_status in {"payload-ready", "flag-recovered"} else "info"
        replay = item.to_dict()["replay"]
        lines.extend(["", f"{item.id}  {c('[' + item.severity.upper() + ']', item.severity)} {item.title}",
            f"  {c('Target:', 'label')} {redact_url(item.url)}" + (f"  parameter={item.parameter}" if item.parameter else ""),
            f"  {c('Profile:', 'label')} {item.profile}",
            f"  {c('Confidence:', 'label')} {item.confidence}",
            f"  {c('Evidence:', 'label')} {item.evidence}",
            f"  {c('Exploit:', 'label')} {c(item.exploit_status, status_style)}",
            f"  {c('Flag path:', 'label')} {item.flag_path}",
            f"  {c('Vector:', 'label')} {item.vector}",
            f"  {c('Replay:', 'label')} {replay['method']} {replay['path']}  cookies={','.join(replay['cookie_names']) or 'none'}  fields={','.join(field['name'] for field in replay['body']) or 'none'}",
            f"  {c('Proof:', 'label')} {replay['proof_payload'] or 'none'}  expect={replay['expected_evidence'] or 'manual comparison'}",
            f"  {c('Recovery:', 'label')} {item.recovery_payload if item.exploit_status == 'payload-ready' and item.recovery_payload else 'not proven'}",
            f"  {c('Patch:', 'label')} {item.patch}"])
    if report.errors:
        lines.extend(["", c("Errors:", "medium"), *[
            f"  - {redact_url(e) if '://' in e else e}" for e in report.errors
        ]])
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)

