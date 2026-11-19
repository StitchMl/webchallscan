import json
import re

import pytest

from webchallscan import cli
from webchallscan.structured_report import render_structured_text


def inventory():
    return {
        "schema": "webchallscan/network-inventory-v1",
        "origin": "https://lab.example",
        "observed_requests": 2,
        "active_tests_executed": 0,
        "endpoints": [
            {"method": "GET", "path": "/api/search", "parameters": ["q", "token"]},
            {"method": "POST", "path": "/api/update", "parameters": []},
        ],
        "passive_findings": [{
            "rule": "HEADER-CSP", "severity": "info",
            "evidence": "Missing Content-Security-Policy"
        }],
        "limitations": ["No active requests were performed."],
    }


def test_inventory_color_and_plain_are_equivalent():
    plain = render_structured_text(inventory(), "never")
    colored = render_structured_text(inventory(), "always")
    assert "NETWORK INVENTORY" in plain
    assert "Observed requests: 2" in plain
    assert "ENDPOINTS  (2)" in plain
    assert "/api/search" in plain
    assert "FINDINGS" in plain
    assert "\x1b[" not in plain
    assert "\x1b[" in colored
    assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain


def test_large_inventory_is_compact_by_default_and_verbose_shows_all():
    result = inventory()
    result["endpoints"] = [
        {"method": "GET", "path": "/api/item-" + str(i), "parameters": []}
        for i in range(40)
    ]
    plain = render_structured_text(result, "never")
    assert "/api/item-11" in plain
    assert "/api/item-39" not in plain
    assert "28 more" in plain
    assert "/api/item-39" in render_structured_text(result, "never", verbose=True)


def test_audits_show_only_metadata_not_value_fields():
    report = {
        "schema": "webchallscan/jwt-audit-v1",
        "algorithm": "HS256", "header_names": ["alg", "kid"],
        "claim_names": ["role", "sub"],
        "signals": [{"rule": "JWT-HMAC-REVIEW", "evidence": "safe"},
                    {"rule": "JWT-KEY-REFERENCE"}],
        "raw_token": "SECRET_JWT_MATERIAL",
        "private_value": "SECRET_VALUE",
    }
    text = render_structured_text(report, "never")
    assert "OFFLINE JWT AUDIT" in text
    assert "Algorithm: HS256" in text
    assert "JWT-HMAC-REVIEW" in text
    assert "SECRET" not in text


def test_api_contract_and_json_result_views():
    contract = {
        "schema": "webchallscan/api-contract-results-v1",
        "origin": "https://lab.example",
        "requests_sent": 1,
        "cases": [{"id": "case-1", "path": "/status", "kind": "business",
                   "checks": [{"outcome": "passed"}]}],
    }
    text = render_structured_text(contract, "never")
    assert "API CONTRACT VALIDATION" in text
    assert "#case-1 /status" in text
    assert "passed" in text
    json_result = {
        "schema": "webchallscan/json-results-v1", "requests_sent": 3,
        "cases": [{"case": 1, "path": "/api/json", "outcome": "arithmetic-observed"}],
    }
    assert "arithmetic-observed" in render_structured_text(json_result, "never")


def test_cli_human_is_opt_in_and_default_remains_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_contract", lambda _: {})
    monkeypatch.setattr(cli, "validate_contract", lambda *args, **kwargs: {
        "schema": "webchallscan/api-contract-results-v1", "requests_sent": 1,
        "origin": "https://lab.example",
        "cases": [{"id": "case-1", "path": "/a", "checks": [{"outcome": "passed"}]}],
    })
    flags = ["--authorized", "--validate-api-contract", "cases.json"]
    assert cli.main(flags) == 0
    assert json.loads(capsys.readouterr().out)["requests_sent"] == 1
    assert cli.main(flags + ["--human", "--color", "never"]) == 0
    output = capsys.readouterr().out
    assert "API CONTRACT VALIDATION" in output
    assert "Requests sent: 1" in output
    assert cli.main(flags + ["--human", "--format", "json"]) == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_invalid_schema_is_not_silently_dumped():
    with pytest.raises(ValueError):
        render_structured_text({"schema": "test", "password": "secret"})
