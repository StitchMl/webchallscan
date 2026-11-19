from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit

from .model import REDACTED, Finding, ScanReport, redact_url


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


def _raw_http_template(finding: Finding, include_secrets: bool) -> str:
    """Build a redacted HTTP/1.1 Repeater template for an existing proof.

    This is a template, not a replayable capture: hidden fields and query
    values remain placeholders unless a proof parameter replaces them.
    """
    if finding.method not in {"GET", "POST"}:
        return "Raw HTTP template not available for this method."
    if finding.method == "POST" and finding.content_type != "application/x-www-form-urlencoded":
        return "Raw HTTP template not available for this content type."
    parsed = urlsplit(finding.url)
    location = _parameter_location(finding)
    proof = finding.proof_payload or finding.recovery_payload
    query = [
        (name, value if include_secrets else REDACTED)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    if location == "query string" and finding.parameter:
        replaced = False
        for i, (name, _) in enumerate(query):
            if name == finding.parameter:
                query[i] = (name, proof)
                replaced = True
        if not replaced:
            query.append((finding.parameter, proof))
    target = parsed.path or "/"
    if query:
        target += "?" + urlencode(query)
    host = parsed.netloc
    headers = [
        f"{finding.method} {target} HTTP/1.1",
        f"Host: {host}",
    ]
    for name, value in finding.client_headers:
        if name.lower() in {"user-agent", "accept-language",
                            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}:
            if not any(c in name + value for c in "\r\n"):
                headers.append(f"{name}: {value}")
    if finding.session_cookies:
        cookies = "; ".join(
            f"{name}={value if include_secrets else REDACTED}"
            for name, value in finding.session_cookies
            if not any(c in name + value for c in "\r\n")
        )
        if cookies:
            headers.append(f"Cookie: {cookies}")
    body = ""
    if finding.method == "POST":
        fields = [
            (name, proof if name == finding.parameter and location == "request body"
             else REDACTED)
            for name, _ in finding.request_fields
        ]
        if finding.parameter and location == "request body" and not any(
            name == finding.parameter for name, _ in fields
        ):
            fields.append((finding.parameter, proof))
        body = urlencode(fields)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {len(body.encode('utf-8'))}")
    return "\r\n".join(headers) + "\r\n\r\n" + body


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


def render_burp_procedure(report: ScanReport, include_secrets: bool = False,
                          raw_http: bool = False) -> str:
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
        steps = _finding_steps(finding, include_secrets)
        if raw_http:
            steps.extend([
                "    Raw HTTP request template (replace [REDACTED] values before sending):",
                _raw_http_template(finding, include_secrets),
            ])
        blocks.append("\n".join(steps))
    return "\n".join(header) + "\n\n".join(blocks) + "\n"
