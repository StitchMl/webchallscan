from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from .model import Finding, REDACTED, ScanReport, redact_url


def _parameter_location(finding: Finding) -> str:
    if finding.method == "GET":
        return "query string"
    body_names = {name for name, _ in finding.request_fields}
    if finding.parameter in body_names:
        return "request body"
    query_names = {name for name, _ in parse_qsl(urlsplit(finding.url).query, keep_blank_values=True)}
    if finding.parameter in query_names:
        return "query string"
    return "request body"


def _request_line(finding: Finding, include_secrets: bool) -> str:
    parsed = urlsplit(finding.url)
    path = parsed.path or "/"
    if parsed.query:
        query = parsed.query if include_secrets else "&".join(
            f"{name}={REDACTED}" for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        )
        path = f"{path}?{query}"
    return f"{finding.method} {path} HTTP/1.1"


def _finding_steps(finding: Finding, include_secrets: bool) -> list[str]:
    location = _parameter_location(finding)
    lines = [
        f"[{finding.id}] {finding.title} ({finding.severity}, {finding.rule})",
        f"    Request line : {_request_line(finding, include_secrets)}",
        f"    Host         : {urlsplit(finding.url).netloc}",
        f"    Parameter    : {finding.parameter or '(none)'}  [{location}]",
        "    Steps:",
        "      1. In Burp Proxy > HTTP history, find this request, right-click > Send to Repeater.",
        f"      2. In the Repeater tab, locate the \"{finding.parameter}\" parameter in the {location}.",
    ]
    step = 3
    if finding.proof_payload:
        lines.append(f"      {step}. Set that parameter's value to the proof payload:")
        lines.append(f"             {finding.proof_payload}")
        step += 1
        evidence = finding.expected_evidence or "the target-specific marker recorded in evidence"
        lines.append(f"      {step}. Click Send. Confirm the response contains: {evidence}")
        step += 1
    if finding.exploit_status == "payload-ready" and finding.recovery_payload:
        lines.append(f"      {step}. To reach the flag, set the same parameter to:")
        lines.append(f"             {finding.recovery_payload}")
        step += 1
        lines.append(f"      {step}. Click Send and read the response for the flag.")
        step += 1
    if finding.session_cookies:
        names = ", ".join(sorted({name for name, _ in finding.session_cookies}))
        if include_secrets:
            cookie = "; ".join(f"{name}={value}" for name, value in finding.session_cookies)
            lines.append(f"      {step}. Keep the Cookie header set to: {cookie}")
        else:
            lines.append(
                f"      {step}. Keep the authenticated Cookie header (names: {names}); "
                "re-run with --include-session-secrets to print the values."
            )
    return lines


def render_burp_procedure(report: ScanReport, include_secrets: bool = False) -> str:
    """Return a manual, copy-free Burp Repeater procedure (Community-friendly).

    No files are written and nothing is auto-imported. Each reproducible finding
    becomes numbered steps: which request to send to Repeater, which parameter to
    edit, the exact payload, and the response evidence that confirms it.
    """
    findings = [f for f in report.findings if f.proof_payload or f.recovery_payload]
    header = [
        "Burp Repeater procedure (Community edition)",
        f"Target                 : {report.target if include_secrets else redact_url(report.target)}",
        f"Reproducible findings  : {len(findings)}",
        "",
    ]
    if not findings:
        header.append("No finding produced a proof or recovery payload, so there is nothing to replay.")
        return "\n".join(header)
    blocks = []
    for finding in findings:
        blocks.append("\n".join(_finding_steps(finding, include_secrets)))
    return "\n".join(header) + "\n\n".join(blocks) + "\n"
