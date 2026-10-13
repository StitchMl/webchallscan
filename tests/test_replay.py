from __future__ import annotations

import json

import pytest

from webchallscan.model import Finding, ScanReport
from webchallscan.replay import select_burp_request, write_burp_output
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


def test_burp_export_is_raw_exclusive_and_secret_opt_in(tmp_path):
    report = ScanReport("https://challenge.example/run", True, findings=[ready_finding()])
    redacted_dir = tmp_path / "redacted"
    files = write_burp_output(report, str(redacted_dir), include_secrets=False)
    assert [path.name.rsplit("-", 1)[-1] for path in files] == ["proof.http", "recovery.http"]
    redacted = "\n".join(path.read_text(encoding="utf-8") for path in files)
    assert redacted.startswith("POST /run?token=%5BREDACTED%5D HTTP/1.1")
    assert "secret-cookie" not in redacted and "secret-csrf" not in redacted
    assert "###" not in redacted

    secret_dir = tmp_path / "with-secrets"
    secret = "\n".join(path.read_text(encoding="utf-8") for path in write_burp_output(
        report, str(secret_dir), include_secrets=True,
    ))
    assert "session=secret-cookie" in secret
    assert "csrf=secret-csrf" in secret
    assert "token=secret-query" in secret

    with pytest.raises(FileExistsError):
        write_burp_output(report, str(secret_dir), include_secrets=True)


def test_single_burp_community_request_is_clean_stdout_payload():
    finding = ready_finding()
    report = ScanReport("https://challenge.example/run", True, findings=[finding])
    raw = select_burp_request(report, finding.id + ":recovery", include_secrets=True)
    assert raw.startswith("POST /run?token=secret-query HTTP/1.1\r\n")
    assert "cmd=%3Bcat+%2Fflag" in raw
    assert "###" not in raw
    with pytest.raises(ValueError):
        select_burp_request(report, finding.id + ":missing")
    assert select_burp_request(report, "first-ready", include_secrets=True) == raw
    assert "cmd=%3Bprintf+PROOF" in select_burp_request(report, "first-proof")

