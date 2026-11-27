from webchallscan.cli import main
from webchallscan.model import ScanReport


def test_explicit_url_is_sufficient_target_selection(capsys, monkeypatch):
    report = ScanReport("http://127.0.0.1/", False, errors=["unreachable"])
    monkeypatch.setattr("webchallscan.cli.scan_profiles", lambda *args, **kwargs: report)
    assert main(["http://127.0.0.1/"]) == 3
    assert "unreachable" in capsys.readouterr().out


def test_browser_session_still_requires_authorization(capsys):
    assert main(["--browser-session"]) == 2
    assert "target URL" in capsys.readouterr().err


def test_extension_path_does_not_require_scan_authorization(capsys):
    assert main(["--extension-path"]) == 0
    assert capsys.readouterr().out.strip().endswith("browser_extension")


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
    assert captured["active"] is True
    assert "Profiles: desktop,mobile" in capsys.readouterr().out


def test_passive_switch_disables_validation_probes(monkeypatch, capsys):
    report = ScanReport("http://127.0.0.1/", False, pages_scanned=1,
                        profiles=("desktop", "mobile"))
    captured = {}

    def fake_scan(*args, **kwargs):
        captured.update(kwargs)
        return report

    monkeypatch.setattr("webchallscan.cli.scan_profiles", fake_scan)
    assert main(["http://127.0.0.1/", "--passive"]) == 0
    assert captured["active"] is False
    capsys.readouterr()


def test_proxy_is_forwarded_to_scanner_without_changing_defaults(monkeypatch, capsys):
    captured = {}
    def fake_scan(*args, **kwargs):
        captured.update(kwargs)
        return ScanReport("http://127.0.0.1/", False, pages_scanned=1)
    monkeypatch.setattr("webchallscan.cli.scan_profiles", fake_scan)
    assert main(["http://127.0.0.1/", "--authorized", "--proxy",
                 "http://127.0.0.1:8080"]) == 0
    assert captured["proxy"] == "http://127.0.0.1:8080"


def test_proxy_is_forwarded_to_contract_mode(monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr("webchallscan.cli.load_contract", lambda name: {"name": name})
    def fake_validate(data, **kwargs):
        captured.update(kwargs)
        return {"schema": "test"}
    monkeypatch.setattr("webchallscan.cli.validate_contract", fake_validate)
    assert main(["--authorized", "--validate-api-contract", "cases.json",
                 "--proxy", "http://127.0.0.1:8080"]) == 0
    assert captured["proxy"] == "http://127.0.0.1:8080"


def test_proxy_forwarded_to_json_case_mode(monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr("webchallscan.cli.load_json_cases", lambda name: {"name": name})
    def fake_json(data, **kwargs):
        captured.update(kwargs)
        return {"schema": "test"}
    monkeypatch.setattr("webchallscan.cli.run_json_cases", fake_json)
    assert main(["--authorized", "--active", "--check-json-cases", "cases.json",
                 "--proxy", "http://localhost:8080"]) == 0
    assert captured["proxy"] == "http://localhost:8080"


def test_from_inventory_cli_only_seeds_explicit_same_origin(monkeypatch, tmp_path, capsys):
    import json
    captured = {}
    def fake_scan(*args, **kwargs):
        captured.update(kwargs)
        return ScanReport("https://ctf.example/", False, pages_scanned=1)
    monkeypatch.setattr("webchallscan.cli.scan_profiles", fake_scan)
    inventory = {
        "schema": "webchallscan/network-inventory-v1",
        "origin": "https://ctf.example",
        "endpoints": [
            {"method": "GET", "path": "/api/items", "parameters": ["q"]},
            {"method": "POST", "path": "/api/write", "parameters": ["id"]},
        ],
    }
    file = tmp_path / "inventory.json"
    file.write_text(json.dumps(inventory))
    assert main(["https://ctf.example/", "--authorized",
                 "--from-inventory", str(file)]) == 0
    assert captured["inventory_urls"] == ("https://ctf.example/api/items?q=WCSBASE",)
    assert main(["https://wrong.example/", "--authorized",
                 "--from-inventory", str(file)]) == 2
    assert "differs" in capsys.readouterr().err


def test_burp_raw_requires_burp_procedure(capsys):
    assert main(["http://127.0.0.1/", "--authorized", "--burp-raw"]) == 2
    assert "--burp-procedure" in capsys.readouterr().err
