import hashlib
import hmac
import base64
import json

import pytest

from webchallscan.cli import main
from webchallscan.jwt_audit import audit_jwt, audit_jwt_file


def token(header, payload):
    def encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return encode(header) + "." + encode(payload) + ".signature"


def test_audit_does_not_return_values_or_secrets():
    original = token({"alg": "none", "kid": "SECRET-KEY-ID"},
                     {"sub": "private@example.com", "role": "admin", "debug": "PRIVATE"})
    report = audit_jwt(original)
    assert report["algorithm"] == "none"
    assert {item["rule"] for item in report["signals"]} == {
        "JWT-ALG-NONE", "JWT-KEY-REFERENCE", "JWT-AUTHORIZATION-CLAIMS"
    }
    assert report["active_tests_executed"] == 0
    assert "PRIVATE" not in repr(report)
    assert "private@example.com" not in repr(report)
    assert "SECRET-KEY-ID" not in repr(report)
    assert "c2lnbmF0dXJl" not in repr(report)  # raw base64url signature bytes


def test_hmac_is_review_not_claimed_crack():
    report = audit_jwt(token({"alg": "HS256"}, {"is_admin": False}))
    assert [item["rule"] for item in report["signals"]] == [
        "JWT-HMAC-REVIEW", "JWT-AUTHORIZATION-CLAIMS"
    ]
    assert all(item["severity"] == "info" for item in report["signals"])


@pytest.mark.parametrize("raw", ["", "missing-dots", "a.b.c", "!!..x",
                                  "e30.e30." + "x" * 9000])
def test_malformed_token_is_rejected(raw):
    with pytest.raises(ValueError):
        audit_jwt(raw)


def test_file_mode_is_exclusive_offline(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "jwt.txt"
    file.write_text(token({"alg": "none"}, {"sub": "SECRET_VALUE"}))
    assert audit_jwt_file(str(file))["algorithm"] == "none"
    assert main(["--audit-jwt-file", str(file)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["algorithm"] == "none"
    assert "SECRET_VALUE" not in json.dumps(result)
    assert main(["https://lab.example", "--audit-jwt-file", str(file)]) == 2


@pytest.mark.parametrize("unsafe", [
    "../private.jwt", "folder/secret.txt", "./token.jwt",
    "/etc/passwd", "bad token.txt", "session.json",
])
def test_jwt_file_refuses_unsafe_cli_paths(tmp_path, monkeypatch, unsafe):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        audit_jwt_file(unsafe)


def test_jwt_file_rejects_symlink_and_too_large_input(tmp_path, monkeypatch,
                                                      make_symlink):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "token.jwt"
    file.write_text("valid-looking.jwt.value")
    alias = tmp_path / "alias.jwt"
    make_symlink(alias, file)
    with pytest.raises(ValueError, match="regular"):
        audit_jwt_file("alias.jwt")
    file.write_bytes(b" " * 16_385)
    with pytest.raises(ValueError, match="too large"):
        audit_jwt_file("token.jwt")


def test_jwt_file_refuses_outside_workspace_and_invalid_encoding(tmp_path, monkeypatch):
    outer = tmp_path / "jwt.txt"
    outer.write_text(token({"alg": "HS256"}, {"sub": "PRIVATE"}))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    with pytest.raises(ValueError, match="working directory"):
        audit_jwt_file(str(outer))
    malformed = workspace / "malformed.jwt"
    malformed.write_bytes(bytes([255, 254]))
    with pytest.raises(ValueError, match="encoding"):
        audit_jwt_file("malformed.jwt")


def test_offline_hmac_verifies_only_known_weak_signing_keys():
    def sign(key, algorithm="HS256"):
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
        message = encode({"alg": algorithm}) + "." + encode({"sub": "PRIVATE_SUBJECT"})
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                  "HS512": hashlib.sha512}[algorithm]
        signature = base64.urlsafe_b64encode(
            hmac.new(key, message.encode(), digest).digest(),
        ).decode().rstrip("=")
        return message + "." + signature

    for algorithm in ("HS256", "HS384", "HS512"):
        weak = sign(b"secret", algorithm)
        strong = sign(b"an-independently-generated-long-test-secret", algorithm)
        weak_report = audit_jwt(weak)
        strong_report = audit_jwt(strong)
        assert "JWT-HMAC-KNOWN-WEAK-KEY" in {item["rule"] for item in weak_report["signals"]}
        assert "JWT-HMAC-KNOWN-WEAK-KEY" not in {item["rule"] for item in strong_report["signals"]}
        assert weak_report["active_tests_executed"] == 0
        assert weak not in repr(weak_report)
        assert "PRIVATE_SUBJECT" not in repr(weak_report)
        assert "secret" not in repr(weak_report)


def test_hmac_wrong_signature_and_unsupported_algorithms_do_not_trigger_weak_key():
    invalid = token({"alg": "HS256"}, {"role": "PRIVATE"})
    unknown = token({"alg": "HS1024"}, {"role": "PRIVATE"})
    for raw in (invalid, unknown):
        report = audit_jwt(raw)
        assert "JWT-HMAC-KNOWN-WEAK-KEY" not in {item["rule"] for item in report["signals"]}
