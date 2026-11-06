from __future__ import annotations

import json

from webchallscan.model import Finding, ScanReport
from webchallscan.replay import render_burp_procedure
from webchallscan.report import render_json, render_text


def ready_finding():
    return Finding(
        rule="WEB-CMDI-001",
        title="Verified command injection",
        severity="critical",
        confidence="high",
        url="https://challenge.example/run?token=secret-query",
        parameter="cmd",
        method="POST",
        request_fields=(("csrf", "secret-csrf"), ("cmd", "default")),
        client_headers=(("User-Agent", "Browser/1.0"),),
        session_cookies=(("session", "secret-cookie"),),
        proof_payload=";printf PROOF",
        expected_evidence="PROOF",
        recovery_payload=";cat /flag",
        exploit_status="payload-ready",
    )


def test_reports_redact_query_hidden_fields_and_cookie_values():
    report = ScanReport(
        "https://challenge.example/run?token=secret-query", True,
        findings=[ready_finding()], profiles=("desktop",), session_source="browser-extension",
    )
    for output in (render_json(report), render_text(report, "never")):
        assert "secret-query" not in output
        assert "secret-csrf" not in output
        assert "secret-cookie" not in output
    decoded = json.loads(render_json(report))
    assert decoded["findings"][0]["replay"]["cookie_names"] == ["session"]
    assert decoded["findings"][0]["replay"]["body"][0]["value"] == "[REDACTED]"


def test_burp_procedure_hides_secrets_but_shows_payloads_by_default():
    report = ScanReport("https://challenge.example/run?token=secret-query", True, findings=[ready_finding()])
    text = render_burp_procedure(report, include_secrets=False)
    # The procedure is human steps, not an importable request file.
    assert "Burp Repeater procedure" in text
    assert "Send to Repeater" in text
    # Payloads are the attack input, so they are always shown.
    assert ";printf PROOF" in text
    assert ";cat /flag" in text
    assert "PROOF" in text  # expected evidence
    assert 'the "cmd" parameter' in text
    assert "request body" in text
    # Secrets stay hidden unless explicitly requested.
    assert "secret-query" not in text
    assert "secret-csrf" not in text
    assert "secret-cookie" not in text
    assert "--include-session-secrets" in text


def test_burp_procedure_reveals_cookie_values_when_opted_in():
    report = ScanReport("https://challenge.example/run?token=secret-query", True, findings=[ready_finding()])
    text = render_burp_procedure(report, include_secrets=True)
    assert "session=secret-cookie" in text
    assert "token=secret-query" in text


def test_burp_procedure_reports_when_nothing_is_reproducible():
    finding = Finding(
        rule="WEB-INFO-001", title="Passive match", severity="low", confidence="low",
        url="https://challenge.example/", parameter="q",
    )
    report = ScanReport("https://challenge.example/", True, findings=[finding])
    text = render_burp_procedure(report)
    assert "nothing to replay" in text
