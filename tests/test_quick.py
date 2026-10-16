import json

from webchallscan import cli


def test_quick_mode_needs_no_manual_contract(monkeypatch, capsys):
    observed = {
        "origin": "https://challenge.example",
        "observed_requests": 1,
        "endpoints": [{"method": "GET", "path": "/api", "parameters": ["q"],
                       "type": "XHR", "statuses": [200], "count": 1}],
        "passive_findings": [],
        "limitations": ["Capture starts with listener"],
    }
    monkeypatch.setattr(cli, "observe_cdp", lambda endpoint, seconds, limit: observed)
    result = cli.main(["--authorized", "--cdp", "http://127.0.0.1:9222", "--quick"])
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "webchallscan/quick-v1"
    assert payload["active_tests_executed"] == 0
    assert payload["triage"][0]["active_test_status"] == "not-executed"


def test_quick_requires_cdp():
    assert cli.main(["--authorized", "--quick"]) == 2
