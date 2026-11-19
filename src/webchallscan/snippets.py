"""Redacted reproduction snippets for high-confidence, manually verified findings.

Snippets are text only: this module never performs network requests.
"""
from __future__ import annotations

import shlex
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .model import REDACTED, Finding, ScanReport


def _replay_parts(finding: Finding) -> tuple[str, str | None] | None:
    if finding.method not in {"GET", "POST"} or not finding.proof_payload:
        return None
    if finding.method == "POST" and finding.content_type != "application/x-www-form-urlencoded":
        return None
    url = urlsplit(finding.url)
    query = [(name, REDACTED) for name, _ in parse_qsl(url.query, keep_blank_values=True)]
    body = [(name, REDACTED) for name, _ in finding.request_fields]
    in_body = finding.method == "POST" and finding.parameter in {name for name, _ in body}
    if finding.method == "POST" and in_body:
        body = [(name, finding.proof_payload if name == finding.parameter else value)
                for name, value in body]
    else:
        query = [(name, finding.proof_payload if name == finding.parameter else value)
                 for name, value in query]
        if finding.parameter and finding.parameter not in {name for name, _ in query}:
            query.append((finding.parameter, finding.proof_payload))
    safe_url = urlunsplit((url.scheme, url.netloc, url.path or "/", urlencode(query), ""))
    return safe_url, urlencode(body) if finding.method == "POST" else None


def render_snippets(report: ScanReport, kind: str) -> str:
    if kind not in {"curl", "python"}:
        raise ValueError("snippet format must be curl or python")
    eligible = [item for item in report.findings
                if item.confidence == "high" and item.proof_payload]
    lines = [f"Redacted {kind} reproductions (high confidence only)",
             "Replace [REDACTED] placeholders with authorized lab values before use.",
             "No requests are executed by this export.", ""]
    total = 0
    for finding in eligible:
        parts = _replay_parts(finding)
        if parts is None:
            continue
        url, body = parts
        lines.append(f"# [{finding.id}] {finding.rule}: {finding.title}")
        if kind == "curl":
            pieces = ["curl", "-i", "-sS", "-X", finding.method,
                      shlex.quote(url)]
            if body is not None:
                pieces.extend(["-H", shlex.quote("Content-Type: application/x-www-form-urlencoded"),
                               "--data-raw", shlex.quote(body)])
            if finding.session_cookies:
                names = sorted({name for name, _ in finding.session_cookies})
                cookies = "; ".join(name + "=" + REDACTED for name in names)
                pieces.extend(["-H", shlex.quote("Cookie: " + cookies)])
            lines.append(" ".join(pieces))
        else:
            lines.extend([
                "from urllib.request import Request, urlopen",
                f"url = {url!r}",
                f"data = {body!r}.encode('utf-8')" if body is not None else "data = None",
                f"headers = {{'Content-Type': 'application/x-www-form-urlencoded'}}" if body is not None
                else "headers = {}",
            ])
            if finding.session_cookies:
                names = sorted({name for name, _ in finding.session_cookies})
                cookies = "; ".join(name + "=" + REDACTED for name in names)
                lines.append(f"headers['Cookie'] = {cookies!r}")
            lines.extend([
                f"request = Request(url, data=data, headers=headers, method={finding.method!r})",
                "with urlopen(request, timeout=5) as response:",
                "    print(response.status, response.read(65536)[:1024])",
            ])
        lines.append("")
        total += 1
    if not total:
        lines.append("No high-confidence finding supports a GET/form POST snippet.")
    return "\n".join(lines)
