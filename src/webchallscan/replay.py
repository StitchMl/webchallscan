from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .model import Finding, REDACTED, ScanReport


def _request(finding: Finding, payload: str, include_secrets: bool) -> str:
    parsed = urlsplit(finding.url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    fields = list(finding.request_fields)
    if finding.method == "GET":
        values = []
        found = False
        for name, value in pairs:
            if name == finding.parameter:
                values.append((name, payload)); found = True
            else:
                values.append((name, value if include_secrets else REDACTED))
        if finding.parameter and not found:
            values.append((finding.parameter, payload))
        path = urlunsplit(("", "", parsed.path or "/", urlencode(values), ""))
        body = ""
    else:
        values = []
        found = False
        for name, value in fields:
            if name == finding.parameter:
                values.append((name, payload)); found = True
            else:
                values.append((name, value if include_secrets else REDACTED))
        if finding.parameter and not found:
            values.append((finding.parameter, payload))
        path = urlunsplit(("", "", parsed.path or "/", parsed.query if include_secrets else urlencode([(n, REDACTED) for n, _ in pairs]), ""))
        body = urlencode(values)
    headers = [("Host", parsed.netloc), *finding.client_headers]
    if finding.session_cookies:
        cookies = "; ".join(f"{name}={value if include_secrets else REDACTED}" for name, value in finding.session_cookies)
        headers.append(("Cookie", cookies))
    if body:
        headers.extend((("Content-Type", finding.content_type), ("Content-Length", str(len(body.encode())))))
    return "\r\n".join([f"{finding.method} {path} HTTP/1.1", *(f"{k}: {v}" for k, v in headers), "", body])


def render_finding_requests(finding: Finding, include_secrets: bool = False) -> tuple[tuple[str, str], ...]:
    """Return semantic raw HTTP requests suitable for Burp Repeater."""
    blocks = []
    if finding.proof_payload:
        blocks.append(("proof", _request(finding, finding.proof_payload, include_secrets) + "\r\n"))
    if finding.exploit_status == "payload-ready" and finding.recovery_payload:
        blocks.append(("recovery", _request(finding, finding.recovery_payload, include_secrets) + "\r\n"))
    return tuple(blocks)


def write_burp_output(report: ScanReport, destination: str, include_secrets: bool = False) -> tuple[Path, ...]:
    target = Path(destination)
    findings = [finding for finding in report.findings if finding.proof_payload or finding.recovery_payload]
    if not findings:
        raise ValueError("no replayable proof or recovery requests were produced")
    target.mkdir(parents=True, exist_ok=False)
    written = []
    index = 0
    for finding in findings:
        for kind, request in render_finding_requests(finding, include_secrets):
            index += 1
            path = target / f"{index:03d}-{finding.id}-{kind}.http"
            with path.open("x", encoding="utf-8", newline="") as stream:
                stream.write(request)
            written.append(path)
    return tuple(written)


def select_burp_request(report: ScanReport, selector: str, include_secrets: bool = False) -> str:
    identity, separator, kind = selector.partition(":")
    if not identity or (separator and kind not in {"proof", "recovery"}):
        raise ValueError("--burp-request must select a finding and optional proof/recovery kind")
    if identity == "first-ready":
        finding = next((item for item in report.findings if item.exploit_status == "payload-ready" and item.recovery_payload), None)
        kind = kind or "recovery"
    elif identity == "first-proof":
        finding = next((item for item in report.findings if item.proof_payload), None)
        kind = kind or "proof"
    else:
        finding = next((item for item in report.findings if item.id == identity), None)
    if finding is None:
        raise ValueError("--burp-request selector matched no request in this scan")
    requests = dict(render_finding_requests(finding, include_secrets))
    selected_kind = kind or ("recovery" if "recovery" in requests else "proof")
    if selected_kind not in requests:
        raise ValueError(f"finding {identity} has no {selected_kind} request")
    return requests[selected_kind]
