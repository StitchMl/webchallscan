"""JWT cookie metadata hints must remain strictly passive and redact secrets."""
import base64
import json

from webchallscan.posture import inspect_response
from webchallscan.scanner import Response, Scanner
from webchallscan.burp_import import import_burp_xml


def jwt(header, claims):
    def section(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":")).encode()
        ).decode().rstrip("=")
    return section(header) + "." + section(claims) + ".signature"


def test_multiple_cookie_jwts_yield_redacted_deduplicated_review_hints():
    token = jwt({"alg": "none", "kid": "PRIVATE-KEY-ID"},
                {"role": "admin", "sub": "PRIVATE-MAIL", "note": "TOPSECRET"})
    raw = (
        "session=" + token + "; Path=/; Secure; HttpOnly; SameSite=Lax",
        "another=" + token + "; Secure; HttpOnly; SameSite=Lax",
        "theme=dark; Secure; HttpOnly; SameSite=Lax",
    )
    signals = inspect_response("GET", "/", "Other", 200, {}, True,
                               cookie_headers=raw)
    rules = [signal["rule"] for signal in signals]
    assert set(rules) == {
        "COOKIE-JWT-ALG-NONE",
        "COOKIE-JWT-KEY-REFERENCE",
        "COOKIE-JWT-AUTHZ-CLAIMS",
    }
    assert all(rules.count(name) == 1 for name in set(rules))
    assert all(signal["severity"] in {"info", "low"} for signal in signals)
    public = repr(signals)
    for secret in ("PRIVATE-KEY-ID", "PRIVATE-MAIL", "TOPSECRET",
                   "session=", token, "role", "sub"):
        assert secret not in public


def test_hmac_and_malformed_cookie_metadata_are_non_exploitable():
    value = jwt({"alg": "HS256"}, {"hello": "SECRET"})
    signals = inspect_response("GET", "/", "Other", 200, {}, False,
                               cookie_headers=("token=" + value + "; HttpOnly; SameSite=Lax",))
    assert [signal["rule"] for signal in signals] == ["COOKIE-JWT-HMAC-REVIEW"]
    assert "SECRET" not in repr(signals)
    malformed = inspect_response("GET", "/", "Other", 200, {}, False,
                                cookie_headers=("token=xx.yy.zz; HttpOnly; SameSite=Lax",))
    assert not any("JWT" in signal["rule"] for signal in malformed)


def test_scanner_inherits_cookie_jwt_posture_without_extra_requests():
    scanner = Scanner("https://lab.example/", max_requests=1)
    token = jwt({"alg": "none"}, {"is_admin": False})
    response = Response("https://lab.example/", 200,
                        {"content-type": "text/plain"}, "",
                        ("auth=" + token + "; Secure; HttpOnly; SameSite=Lax",))
    findings = scanner._posture_findings(response)
    assert {"COOKIE-JWT-ALG-NONE", "COOKIE-JWT-AUTHZ-CLAIMS"} <= {
        finding.rule for finding in findings
    }
    assert scanner.requests_sent == 0
    assert token not in repr([finding.to_dict() for finding in findings])


def test_burp_history_jwt_cookie_hints_are_zero_request_and_redacted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    token = jwt({"alg": "none"}, {"role": "SUPERSECRET"})
    raw = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        "Set-Cookie: auth=" + token + "; Secure; HttpOnly; SameSite=Lax\r\n"
        "\r\n<html></html>"
    )
    encoded = base64.b64encode(raw.encode()).decode()
    xml = (
        '<?xml version="1.0"?><items><item>'
        '<url>https://lab.example/</url><method>GET</method><status>200</status>'
        '<response base64="true">' + encoded + '</response></item></items>'
    )
    path = tmp_path / "history.xml"
    path.write_text(xml)
    report = import_burp_xml(str(path), "https://lab.example")
    assert "COOKIE-JWT-ALG-NONE" in {
        finding["rule"] for finding in report["passive_findings"]
    }
    assert report["active_tests_executed"] == 0
    assert "SUPERSECRET" not in repr(report)
    assert token not in repr(report)
