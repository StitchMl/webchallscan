import json
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


class _LocalJsonHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_POST(self):
        type(self).requests += 1
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        if (self.path != "/api/evaluate"
                or self.headers.get("Content-Type") != "application/json"
                or self.headers.get("Authorization") != "Bearer PRIVATE_TOKEN"
                or payload.get("private") != "PRIVATE_BODY"):
            self.send_error(400)
            return
        value = payload["context"]["input"]
        body = json.dumps({
            "result": "22020" if value == "{{7340*3}}" else "safe",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def test_json_ssti_real_local_http_respects_budgets_and_redacts_secrets(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalJsonHandler)
    monkeypatch.setattr(_LocalJsonHandler, "requests", 0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        case = data()
        case["origin"] = f"http://127.0.0.1:{server.server_port}"
        case["cases"][0]["body"]["private"] = "PRIVATE_BODY"
        case["cases"][0]["headers"]["Authorization"] = "Bearer PRIVATE_TOKEN"
        result = run_json_cases(case, timeout=3.0)
        assert result["requests_sent"] == 3
        assert result["active_tests_executed"] == 3
        assert _LocalJsonHandler.requests == 3
        assert result["cases"][0]["outcome"] == "arithmetic-observed"
        assert result["findings"][0]["status"] == "manual-validation-required"
        serialized = json.dumps(result)
        assert "PRIVATE_TOKEN" not in serialized
        assert "PRIVATE_BODY" not in serialized
    finally:
        server.shutdown()
        worker.join()
        server.server_close()
