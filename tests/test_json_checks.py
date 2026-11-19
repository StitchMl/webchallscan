import json
from copy import deepcopy

import pytest

from webchallscan import cli
from webchallscan.json_checks import load_json_cases, run_json_cases


def data(kind="ssti"):
    return {
        "schema": "webchallscan/json-cases-v1",
        "origin": "https://lab.example",
        "cases": [{
            "path": "/api/evaluate",
            "kind": kind,
            "body": {"context": {"input": "SAFE"}, "private": "NEVER_PRINT"},
            "field": ["context", "input"],
            "headers": {"Authorization": "Bearer SUPERSECRET"},
        }],
    }


def test_json_ssti_nested_body_preserved_and_bounded():
    sent = []
    def fake(url, body, headers, timeout):
        sent.append((url, deepcopy(body)))
        value = body["context"]["input"]
        response = b'{"result":"22020"}' if value == "{{7340*3}}" else b'{"result":"safe"}'
        return {"status": 200, "digest": "same" if value == "{{7340*3}}" else "base",
                "body": response}
    original = data()
    result = run_json_cases(original, send=fake)
    assert result["requests_sent"] == 3
    assert result["findings"][0]["rule"] == "API-JSON-SSTI-REVIEW"
    assert result["findings"][0]["status"] == "manual-validation-required"
    assert sent[1][1]["context"]["input"] == "{{7340*3}}"
    assert sent[1][1]["private"] == "NEVER_PRINT"
    assert original["cases"][0]["body"]["context"]["input"] == "SAFE"
    assert all(url == "https://lab.example/api/evaluate" for url, _ in sent)
    assert "SUPERSECRET" not in repr(result)
    assert "NEVER_PRINT" not in repr(result)


def test_nosql_differential_is_review_not_proven_exploit():
    sent = []
    def fake(url, body, headers, timeout):
        sent.append(deepcopy(body))
        marker = body["context"]["input"]
        response = b'{"result":"different"}' if isinstance(marker, dict) else b'{"result":"baseline"}'
        return {"status": 200, "digest": "not-used", "body": response}
    result = run_json_cases(data("nosql"), send=fake)
    assert result["requests_sent"] == 4
    assert result["cases"][0]["outcome"] == "differential-review"
    assert result["findings"][0]["confidence"] == "low"
    assert sent[2]["context"]["input"] == {"$ne": "WCS_NONMATCH_7340"}
    assert result["findings"][0]["status"] == "manual-validation-required"


def test_nosql_reflection_is_not_differential():
    def fake(url, body, headers, timeout):
        val = body["context"]["input"]
        if isinstance(val, dict):
            # Echoes the marker; output after stripping marker is still
            # structurally different, so the result must never claim proof.
            raw = b'{"input":{"$ne":"WCS_NONMATCH_7340"}}'
        else:
            raw = b'{"input":"WCSBASE"}'
        return {"status": 200, "digest": "echo", "body": raw}
    result = run_json_cases(data("nosql"), send=fake)
    assert all(item["status"] != "confirmed" for item in result["findings"])


@pytest.mark.parametrize("bad_path", ["//other/path", "/x?private=yes", "/../admin", "/%2e%2e/x"])
def test_json_rejects_unsafe_paths_before_sending(bad_path):
    source = data()
    source["cases"][0]["path"] = bad_path
    with pytest.raises(ValueError):
        run_json_cases(source, send=lambda *args: pytest.fail("network called"))


def test_json_rejects_missing_nested_field_and_invalid_header():
    source = data()
    source["cases"][0]["field"] = ["context", "missing"]
    with pytest.raises(ValueError):
        run_json_cases(source)
    source = data()
    source["cases"][0]["headers"]["Host"] = "other.example"
    with pytest.raises(ValueError):
        run_json_cases(source)


def test_json_cli_requires_explicit_authorization_and_active(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "json-cases.json"
    f.write_text(json.dumps(data()))
    assert cli.main(["--check-json-cases", str(f), "--authorized"]) == 2
    assert cli.main(["--check-json-cases", str(f), "--active"]) == 2
    calls = []
    monkeypatch.setattr(cli, "run_json_cases", lambda contract, **kw:
                        calls.append(kw) or {"requests_sent": 0, "cases": []})
    assert cli.main(["--check-json-cases", str(f), "--authorized", "--active"]) == 0
    assert calls[0]["verify_tls"] is True
    assert cli.main(["--check-json-cases", str(f), "--authorized",
                     "--active", "--insecure"]) == 0
    assert calls[1]["verify_tls"] is False
    assert "requests_sent" in capsys.readouterr().out
