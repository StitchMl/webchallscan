from webchallscan.model import Finding, ScanReport
from webchallscan.snippets import render_snippets
from webchallscan.cli import main


def report():
    return ScanReport("https://lab.example/", True, findings=[
        Finding(
            rule="WEB-CMDI-001", title="Confirmed input execution",
            severity="high", confidence="high",
            url="https://lab.example/run?token=PRIVATE",
            parameter="cmd", method="POST",
            request_fields=(("csrf", "PRIVATECSRF"), ("cmd", "old")),
            session_cookies=(("session", "PRIVATECOOKIE"),),
            proof_payload=";printf PROOF",
        ),
        Finding(
            rule="WEB-SSTI-001", title="Template evaluation",
            severity="high", confidence="high",
            url="https://lab.example/search?token=PRIVATE&q=old",
            parameter="q", method="GET", proof_payload="{{7340*3}}",
        ),
        Finding(
            rule="WEB-SQLI-001", title="Unverified hypothesis",
            severity="info", confidence="low", url="https://lab.example/search?q=old",
            parameter="q", method="GET", proof_payload="'",
        ),
    ])


def test_curl_snippets_redact_and_include_only_verified_payloads():
    text = render_snippets(report(), "curl")
    assert text.count("curl -i -sS -X") == 2
    assert "cmd=%3Bprintf+PROOF" in text
    assert "q=%7B%7B7340%2A3%7D%7D" in text
    assert "csrf=%5BREDACTED%5D" in text
    assert "session=[REDACTED]" in text
    for secret in ("PRIVATECSRF", "PRIVATECOOKIE", "token=PRIVATE"):
        assert secret not in text


def test_python_snippet_is_redacted_and_contains_stdlib_replay():
    text = render_snippets(report(), "python")
    assert text.count("from urllib.request import Request, urlopen") == 2
    assert "timeout=5" in text
    assert "PRIVATECSRF" not in text
    assert "PRIVATECOOKIE" not in text


def test_cli_rejects_multiple_renderers(capsys):
    assert main(["http://127.0.0.1/", "--authorized",
                 "--export-curl", "--export-python"]) == 2
    assert "choose only one" in capsys.readouterr().err
    assert main(["http://127.0.0.1/", "--authorized",
                 "--burp-procedure", "--export-curl"]) == 2


def test_no_verified_findings_emits_safe_message():
    output = render_snippets(ScanReport("https://lab.example/", False), "curl")
    assert "No high-confidence finding" in output
