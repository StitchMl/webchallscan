import json

from webchallscan.markdown_report import render_markdown
from webchallscan.model import Finding, ScanReport
from webchallscan.report import render_json


def fixture_report():
    return ScanReport("https://lab.example/?token=PRIVATE", True,
                      pages_scanned=2, requests_sent=8,
                      findings=[
                          Finding(rule="WEB-NOTE", title="Passive <review> | note",
                                  severity="info", confidence="medium",
                                  url="https://lab.example/?secret=PRIVATE",
                                  evidence="Header note *needs* review",
                                  patch="Configure policy before deployment."),
                          Finding(rule="WEB-SQLI", title="SQL error",
                                  severity="high", confidence="high",
                                  url="https://lab.example/api?q=PRIVATE",
                                  evidence="Deterministic SQL parser signal",
                                  parameter="q", proof_payload="'",
                                  expected_evidence="database error",
                                  vector="Check input manually"),
                      ], coverage=["One origin only."],
                      errors=["https://lab.example/failed?token=PRIVATE"])


def test_markdown_export_is_readable_redacted_and_severity_sorted():
    report = fixture_report()
    result = render_markdown(report)
    assert "# webchallscan" in result
    assert "| HIGH | 1 |" in result
    assert "## Finding details" in result
    assert result.index("SQL error") < result.index("Passive")
    assert r"Passive \\<review\\> \\| note" in result
    assert r"note \\*needs\\* review" in result
    assert "PRIVATE" not in result
    assert "\x1b[" not in result
    assert "## Coverage limitations" in result
    assert "## Request errors" in result
    assert "Replay" not in result


def test_markdown_verbose_and_top_are_presentation_only():
    report = fixture_report()
    before = render_json(report)
    short = render_markdown(report, top=1, min_severity="high")
    assert short.count("### HIGH:") == 1
    assert "1 finding detail(s) omitted" in short
    assert "Passive \\<review" not in short
    verbose = render_markdown(report, verbose=True)
    assert "Replay:" in verbose and "Vector:" in verbose
    assert before == render_json(report)
    assert len(json.loads(before)["findings"]) == 2


def test_cli_markdown_scan_and_reject_non_scan(monkeypatch, capsys):
    from webchallscan import cli
    monkeypatch.setattr(cli, "scan_profiles", lambda *args, **kwargs: fixture_report())
    command = ["https://lab.example/", "--authorized", "--format", "markdown"]
    assert cli.main(command) == 1
    out = capsys.readouterr().out
    assert out.startswith("# webchallscan")
    assert "PRIVATE" not in out
    assert cli.main(["--authorized", "--plan-inventory", "anything.json",
                     "--format", "markdown"]) == 2
    assert "only to scanner" in capsys.readouterr().err
