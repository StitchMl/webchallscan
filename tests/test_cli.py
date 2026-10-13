from webchallscan.cli import main
from webchallscan.model import ScanReport


def test_authorization_required(capsys):
    assert main(["http://127.0.0.1/"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_total_scan_failure_has_distinct_exit(monkeypatch, capsys):
    report = ScanReport("http://127.0.0.1:1/", False, pages_scanned=0, errors=["unreachable"])
    monkeypatch.setattr("webchallscan.cli.scan_profiles", lambda *args, **kwargs: report)
    assert main(["http://127.0.0.1:1/", "--authorized", "--color", "never"]) == 3
    assert "unreachable" in capsys.readouterr().out


def test_cli_defaults_to_both_profiles(monkeypatch, capsys):
    report = ScanReport("http://127.0.0.1/", False, pages_scanned=2,
                        profiles=("desktop", "mobile"))
    captured = {}
    def fake_scan(*args, **kwargs):
        captured.update(kwargs)
        return report
    monkeypatch.setattr("webchallscan.cli.scan_profiles", fake_scan)
    assert main(["http://127.0.0.1/", "--authorized", "--color", "never"]) == 0
    assert captured["profiles"] == ("desktop", "mobile")
    assert "Profiles: desktop,mobile" in capsys.readouterr().out

