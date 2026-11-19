import json

from webchallscan import cli
from webchallscan.model import ScanReport


def test_scan_alias_uses_existing_scanner(monkeypatch, capsys):
    seen = {}
    def fake_scan(target, **kwargs):
        seen["url"] = target
        return ScanReport(target, False, pages_scanned=1)
    monkeypatch.setattr(cli, "scan_profiles", fake_scan)
    assert cli.main(["scan", "http://127.0.0.1/", "--authorized"]) == 0
    assert seen["url"] == "http://127.0.0.1/"
    assert "WEBCHALLSCAN" in capsys.readouterr().out


def test_observe_alias_uses_default_window(monkeypatch, capsys):
    seen = {}
    def fake_observe(endpoint, seconds, limit):
        seen.update(endpoint=endpoint, seconds=seconds, limit=limit)
        return {"schema": "webchallscan/network-inventory-v1", "origin": "http://lab.example",
                "observed_requests": 0, "endpoints": [], "passive_findings": []}
    monkeypatch.setattr(cli, "observe_cdp", fake_observe)
    assert cli.main(["observe", "--authorized", "--cdp", "http://127.0.0.1:9222"]) == 0
    assert seen["seconds"] == 20
    assert seen["endpoint"] == "http://127.0.0.1:9222"
    assert json.loads(capsys.readouterr().out)["endpoints"] == []


def test_contract_alias_uses_existing_validation(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_contract", lambda filename: {"file": filename})
    monkeypatch.setattr(cli, "validate_contract", lambda data, **kwargs: {"result": data["file"]})
    assert cli.main(["contract", "cases.json", "--authorized"]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "cases.json"


def test_replay_alias_uses_existing_procedure(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_profiles", lambda target, **kwargs:
                        ScanReport(target, False, pages_scanned=1))
    monkeypatch.setattr(cli, "render_burp_procedure", lambda report, *args: "replay directions")
    assert cli.main(["replay", "http://127.0.0.1/", "--authorized"]) == 0
    assert "replay directions" in capsys.readouterr().out


def test_legacy_flags_are_preserved(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_profiles", lambda target, **kwargs:
                        ScanReport(target, False, pages_scanned=1))
    assert cli.main(["http://127.0.0.1/", "--authorized"]) == 0
