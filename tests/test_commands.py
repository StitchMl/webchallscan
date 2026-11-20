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


def test_subparser_routes_all_commands_to_legacy_parser():
    from webchallscan.cli import _command_arguments, parser

    examples = (
        (["scan", "http://127.0.0.1/", "--authorized"], "http://127.0.0.1/", None),
        (["observe", "--cdp", "http://127.0.0.1:9222"], None, 20.0),
        (["contract", "contract.json"], None, None),
        (["replay", "http://127.0.0.1/", "--authorized"], "http://127.0.0.1/", None),
    )
    for argv, target, duration in examples:
        parsed = parser().parse_args(_command_arguments(argv))
        assert parsed.url == target
        assert parsed.observe_network == duration
    assert parser().parse_args(_command_arguments(["contract", "contract.json"])).validate_api_contract == "contract.json"
    assert parser().parse_args(_command_arguments(["replay", "http://127.0.0.1/"])).burp_procedure


def test_root_flags_stay_unchanged_with_subparsers():
    from webchallscan.cli import _command_arguments

    argv = ["http://127.0.0.1/", "--authorized", "--max-requests", "3"]
    assert _command_arguments(argv) == argv
    assert _command_arguments(["--version"]) == ["--version"]
    assert _command_arguments(["scan", "--help"]) == ["--help"]
    assert _command_arguments(["observe", "--observe-network", "2", "--authorized"]) == [
        "--observe-network", "2", "--authorized",
    ]


def test_json_command_reuses_explicit_authorized_active_mode(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(cli, "load_json_cases", lambda path: {"filename": path})
    monkeypatch.setattr(cli, "run_json_cases", lambda cases, **kwargs:
                        calls.append((cases, kwargs)) or {"requests_sent": 0, "cases": []})
    assert cli.main(["json", "cases.json", "--authorized"]) == 2
    assert cli.main(["json", "cases.json", "--active"]) == 2
    assert calls == []
    assert cli.main(["json", "cases.json", "--authorized", "--active"]) == 0
    assert calls[0][0] == {"filename": "cases.json"}
    assert calls[0][1]["verify_tls"] is True
    assert "requests_sent" in capsys.readouterr().out


def test_json_command_preserves_legacy_equivalent_arguments():
    from webchallscan.cli import _command_arguments, parser

    args = parser().parse_args(_command_arguments([
        "json", "cases.json", "--authorized", "--active", "--insecure",
    ]))
    assert args.check_json_cases == "cases.json"
    assert args.authorized
    assert args.active
    assert args.insecure
    assert parser().parse_args(_command_arguments([
        "--check-json-cases", "cases.json", "--authorized", "--active",
    ])).check_json_cases == "cases.json"
