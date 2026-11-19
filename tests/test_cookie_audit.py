import base64
import json

from webchallscan.cli import main
from webchallscan.cookie_audit import audit_session_file


def encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def fixture_session(tmp_path):
    jwt = encode({"alg": "none", "typ": "JWT"}) + "." + encode({
        "sub": "private@example.com", "role": "ADMINSECRET",
    }) + ".signature"
    hex_value = json.dumps({"role": "private"}).encode().hex()
    b64_value = base64.urlsafe_b64encode(
        json.dumps({"uid": "PRIVATE"}).encode()
    ).decode()
    source = {
        "url": "https://lab.example/account",
        "cookies": [
            {"name": "auth", "value": jwt},
            {"name": "flask", "value": "eyJzZXNzIjoxfQ.aGk.signature"},
            {"name": "hex_secret", "value": hex_value},
            {"name": "b64_secret", "value": b64_value},
            {"name": "ordinary", "value": "short"},
        ],
    }
    file = tmp_path / "session.json"
    file.write_text(json.dumps(source))
    return file, jwt, hex_value, b64_value


def test_aggregate_cookie_format_audit_never_exposes_names_or_values(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file, jwt, hex_value, b64_value = fixture_session(tmp_path)
    report = audit_session_file(str(file))
    assert report["cookie_count"] == 5
    assert report["active_tests_executed"] == 0
    assert report["format_categories"] == {
        "base64-json-like": 1,
        "hex-json-like": 1,
        "jwt-like": 1,
        "signed-session-like": 1,
        "unknown": 1,
    }
    assert report["jwt_review_signals"]["JWT-ALG-NONE"] == 1
    output = json.dumps(report)
    for secret in (jwt, hex_value, b64_value,
                   "private@example.com", "ADMINSECRET",
                   "hex_secret", "ordinary", "auth"):
        assert secret not in output


def test_session_audit_cli_is_exclusive_and_offline(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file, _, _, _ = fixture_session(tmp_path)
    assert main(["--audit-session-file", str(file)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["cookie_count"] == 5
    assert main(["--audit-session-file", str(file),
                 "--active"]) == 2
    assert "exclusive offline mode" in capsys.readouterr().err
