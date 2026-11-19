import json

import pytest

from webchallscan.model import Finding, ScanReport
from webchallscan.report import render_json, render_text


def report():
    severities = ["info"] * 24 + ["high"] * 4 + ["medium"] * 3
    return ScanReport("https://lab.example/", False, pages_scanned=1,
                      findings=[
                          Finding(rule=f"RULE-{index}", title=f"Finding number {index}",
                                  severity=severity, confidence="medium",
                                  url=f"https://lab.example/{index}",
                                  evidence="deterministic observation")
                          for index, severity in enumerate(severities)
                      ])


def test_default_scanner_text_caps_to_twenty_while_preserving_full_summary():
    output = render_text(report(), "never")
    assert "Findings: 31" in output
    assert "HIGH 4" in output and "MEDIUM 3" in output and "INFO 24" in output
    assert output.count("    Target") == 20
    assert "11 finding detail(s) omitted" in output
    assert "Finding number 24" in output
    assert "Finding number 30" in output
    assert "Finding number 19" not in output


def test_severity_and_top_are_presentation_only():
    source = report()
    before = render_json(source)
    output = render_text(source, "never", top=2, min_severity="high")
    assert output.count("    Target") == 2
    assert "HIGH 4" in output
    assert "MEDIUM 3" in output
    assert "29 finding detail(s) omitted" in output
    assert "Finding number 24" in output
    assert "Finding number 25" in output
    assert "Finding number 27" not in output
    assert before == render_json(source)
    assert len(json.loads(before)["findings"]) == 31


def test_verbose_displays_all_by_default():
    output = render_text(report(), "never", verbose=True)
    assert output.count("    Target") == 31
    assert "omitted by the display" not in output


def test_invalid_limits_are_rejected():
    for invalid in (0, -1, 1001):
        with pytest.raises(ValueError):
            render_text(report(), "never", top=invalid)
    with pytest.raises(ValueError):
        render_text(report(), "never", min_severity="unknown")


def test_cli_filters_do_not_change_scan_exit_codes(monkeypatch, capsys):
    from webchallscan import cli
    monkeypatch.setattr(cli, "scan_profiles", lambda *a, **kw: report())
    flags = ["https://lab.example/", "--authorized"]
    assert cli.main(flags + ["--top", "1", "--min-severity", "high",
                             "--color", "never"]) == 1
    output = capsys.readouterr().out
    assert output.count("    Target") == 1
    assert "Findings: 31" in output
    assert cli.main(flags + ["--top", "1", "--format", "json"]) == 2
    assert "only to scanner text" in capsys.readouterr().err
    assert cli.main(flags + ["--top", "0"]) == 2
    assert "--top must be" in capsys.readouterr().err
