from webchallscan.cli import main
from webchallscan.model import ScanReport


def test_authorization_required(capsys):
    assert main(["http://127.0.0.1/"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_total_scan_failure_has_distinct_exit(monkeypatch, capsys):
    report = ScanReport("http://127.0.0.1:1/", False, pages_scanned=0, errors=["unreachable"])
    monkeypatch.setattr("webchallscan.cli.Scanner.scan", lambda self: report)
    assert main(["http://127.0.0.1:1/", "--authorized", "--color", "never"]) == 3
    assert "unreachable" in capsys.readouterr().out

