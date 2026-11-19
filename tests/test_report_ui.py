import json
import re

from webchallscan.model import Finding, ScanReport
from webchallscan.report import render_json, render_text


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def sample():
    return ScanReport(
        "https://lab.example/search?token=PRIVATE", True, pages_scanned=3,
        requests_sent=11, profiles=("desktop", "mobile"),
        findings=[
            Finding(
                rule="WEB-CSP-001", title="Content Security Policy absent",
                severity="medium", confidence="medium", profile="mobile",
                url="https://lab.example/account?auth=SECRET",
                evidence="A response does not include an appropriate CSP.",
                patch="Set a Content-Security-Policy for the document.",
                vector="Check the response headers for missing CSP.",
            ),
            Finding(
                rule="WEB-SQLI-001", title="SQL injection error",
                severity="high", confidence="high", profile="desktop",
                url="https://lab.example/search?q=PRIVATE",
                parameter="q", evidence="SQL error appeared only after a quote.",
                patch="Bind every query parameter.",
                proof_payload="'", expected_evidence="database error",
                vector="Run a targeted parameter check in an authorized lab.",
                recovery_payload="never run automatically",
            ),
            Finding(
                rule="WEB-NOTE-001", title="Informational review",
                severity="info", confidence="low", url="https://lab.example/",
                evidence="A non-exploitable configuration note.",
            ),
        ],
        coverage=["Only linked routes and validated inventory endpoints were checked."],
        errors=["https://lab.example/error?secret=PRIVATE: request failed"],
    )


def test_compact_report_has_summary_groups_and_focuses_on_actionable_fields():
    report = sample()
    value = render_text(report, "never")
    assert "FINDINGS OVERVIEW" in value
    assert "HIGH 1" in value and "MEDIUM 1" in value and "INFO 1" in value
    assert value.index("SQL injection error") < value.index("Content Security Policy absent")
    assert "Target" in value and "Evidence" in value and "Fix" in value
    assert "Proof" in value
    assert "Replay" not in value
    assert "Flag path" not in value
    assert "Tip: use --verbose" in value
    assert "COVERAGE NOTES" in value and "REQUEST ERRORS" in value
    assert "PRIVATE" not in value and "SECRET" not in value
    assert not ANSI_PATTERN.search(value)


def test_verbose_mode_includes_existing_replay_details():
    value = render_text(sample(), "never", verbose=True)
    for label in ("Replay", "Flag path", "Exploit", "Vector", "Recovery", "Expected"):
        assert label in value
    assert "Tip: use --verbose" not in value
    assert "PRIVATE" not in value


def test_colors_are_controllable_and_do_not_change_plain_text(monkeypatch):
    report = sample()
    color = render_text(report, "always")
    plain = render_text(report, "never")
    assert "\x1b[1;31m" in color
    assert "\x1b[1;33m" in color
    assert "\x1b[94m" in color
    assert ANSI_PATTERN.sub("", color) == plain
    monkeypatch.setenv("NO_COLOR", "1")
    assert not ANSI_PATTERN.search(render_text(report, "auto"))
    assert ANSI_PATTERN.search(render_text(report, "always"))


def test_empty_report_and_json_schema_are_unchanged():
    report = ScanReport("http://lab.example/", False, pages_scanned=1)
    value = render_text(report, "never")
    assert "No evidence-backed findings" in value
    assert "This does not prove the target is safe" in value
    decoded = json.loads(render_json(sample()))
    assert decoded["schema"] == "webchallscan/v3"
    assert len(decoded["findings"]) == 3
    assert "replay" in decoded["findings"][0]
    assert "PRIVATE" not in render_json(sample())


def test_cli_verbose_reaches_text_renderer_without_touching_json(monkeypatch, capsys):
    from webchallscan import cli
    report = sample()
    monkeypatch.setattr(cli, "scan_profiles", lambda *args, **kwargs: report)
    assert cli.main(["https://lab.example/", "--authorized", "--verbose",
                     "--color", "never"]) == 1
    assert "Replay" in capsys.readouterr().out
    assert cli.main(["https://lab.example/", "--authorized", "--format", "json",
                     "--verbose"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "webchallscan/v3"
