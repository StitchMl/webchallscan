"""Multi-Set-Cookie handling must not lose early weak cookies or expose values."""
import base64
from email.message import Message

from webchallscan.burp_import import import_burp_xml
from webchallscan.posture import inspect_response
from webchallscan.scanner import Scanner


def test_posture_checks_every_independent_cookie_and_deduplicates_rules():
    headers = {"Content-Type": "text/html"}
    output = inspect_response(
        "GET", "/", "Document", 200, headers, True,
        cookie_headers=(
            "safe=FIRSTSECRET; Secure; HttpOnly; SameSite=Lax",
            "unsafe=SECONDSECRET; Path=/; SameSite=None",
            "also-unsafe=THIRDSECRET; Path=/",
        ),
    )
    rules = [row["rule"] for row in output]
    assert set(rules) >= {
        "COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE",
        "COOKIE-SAMESITE-NONE",
    }
    assert all(rules.count(rule) == 1 for rule in set(rules))
    assert not any(secret in repr(output) for secret in
                   ("FIRSTSECRET", "SECONDSECRET", "THIRDSECRET", "safe=", "unsafe="))


def test_scanner_reads_all_set_cookie_headers_without_additional_requests():
    class FakeResponse:
        status = 200
        def __init__(self):
            self.headers = Message()
            self.headers["Content-Type"] = "text/html"
            self.headers["Set-Cookie"] = "first=SAFE; Secure; HttpOnly; SameSite=Lax"
            self.headers["Set-Cookie"] = "second=SECRET; Path=/"
        def geturl(self):
            return "https://lab.example/"
        def read(self, cap):
            return b"<html>ok</html>"
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse()

    scanner = Scanner("https://lab.example/", max_requests=1)
    scanner.opener = FakeOpener()
    response = scanner._request("https://lab.example/")
    assert len(response.cookie_headers) == 2
    findings = scanner._posture_findings(response)
    rules = {finding.rule for finding in findings}
    assert {"COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"} <= rules
    assert scanner.requests_sent == 1
    assert "SECRET" not in repr([f.to_dict() for f in findings])


def test_burp_import_checks_multiple_cookie_lines_offline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    raw = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        "Set-Cookie: first=SAFE; Secure; HttpOnly; SameSite=Lax\r\n"
        "Set-Cookie: second=SECRET; SameSite=None\r\n"
        "\r\n<html>ok</html>"
    )
    encoded = base64.b64encode(raw.encode()).decode()
    data = f"""<?xml version="1.0"?>
<items><item>
  <url>https://lab.example/</url><method>GET</method><status>200</status>
  <response base64="true">{encoded}</response>
</item></items>"""
    file = tmp_path / "history.xml"
    file.write_text(data)
    result = import_burp_xml(str(file), "https://lab.example")
    rules = {f["rule"] for f in result["passive_findings"]}
    assert {"COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE-NONE"} <= rules
    assert result["active_tests_executed"] == 0
    assert "SECRET" not in repr(result)
    assert "first=" not in repr(result)
    assert "second=" not in repr(result)
