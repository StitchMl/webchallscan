from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from webchallscan.scanner import CMD_PROBE, CMD_RESULT, Scanner


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200, location: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        if location:
            self.send_header("Location", location)
        if self.path.startswith("/session"):
            self.send_header("Set-Cookie", "wcs_session=valid; Path=/")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body.encode())

    def do_HEAD(self): self._send("")
    def do_OPTIONS(self): self._send("")
    def do_GET(self):
        p = urlsplit(self.path)
        values = parse_qs(p.query)
        if p.path == "/":
            self._send('<html><a href="/search?q=x">search</a><a href="/session">session</a><a href="/form">form</a><form action="/run" method="get"><input name="cmd"></form></html>')
        elif p.path == "/search":
            value = values.get("q", [""])[0]
            self._send("SQL syntax near quote" if value == "'" else "ok")
        elif p.path == "/run":
            value = values.get("cmd", [""])[0]
            self._send(CMD_RESULT if value == CMD_PROBE else "ok")
        elif p.path == "/reflect":
            self._send(values.get("cmd", [""])[0])
        elif p.path == "/sanitize":
            value = values.get("cmd", [""])[0]
            self._send("".join(ch for ch in value if ch.isalnum()))
        elif p.path == "/session":
            self._send('<html><a href="/protected">protected</a></html>')
        elif p.path == "/protected":
            self._send("session-ok" if "wcs_session=valid" in self.headers.get("Cookie", "") else "denied", 200 if "wcs_session=valid" in self.headers.get("Cookie", "") else 403)
        elif p.path == "/form":
            self._send('<html><form action="/postrun" method="post"><input type="hidden" name="csrf" value="token-42"><input name="cmd" value="default"></form></html>')
        elif p.path == "/flag":
            self._send("CTF{unit_test_only}")
        elif p.path == "/out":
            self._send("", 302, "http://example.invalid/wcs")
        else:
            self._send("missing", 404)
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        values = parse_qs(self.rfile.read(length).decode())
        if self.path == "/postrun" and values.get("csrf") == ["token-42"] and values.get("cmd") == [CMD_PROBE]:
            self._send(CMD_RESULT)
        else:
            self._send("denied", 403)
    def log_message(self, *_): pass


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown(); thread.join()


def test_passive_is_deterministic_and_stays_hypothetical(server):
    one = Scanner(server, max_pages=5).scan()
    two = Scanner(server, max_pages=5).scan()
    assert [f.to_dict() for f in one.findings] == [f.to_dict() for f in two.findings]
    assert {f.rule for f in one.findings} >= {"WEB-SQLI-001", "WEB-CMDI-001"}
    assert all(f.exploit_status == "validation-only" for f in one.findings)


def test_active_confirms_without_flag_extraction(server):
    report = Scanner(server, active=True, max_pages=5).scan()
    sql = [f for f in report.findings if f.title == "SQL injection error behavior confirmed"]
    cmd = [f for f in report.findings if f.title == "Command injection arithmetic execution confirmed"]
    assert sql and sql[0].confidence == "high"
    assert cmd and cmd[0].exploit_status == "payload-ready"
    assert "cat /flag" in cmd[0].vector
    assert CMD_PROBE in cmd[0].vector
    assert all("unit_test_only" not in f.evidence for f in report.findings)


def test_passive_flag_is_only_a_candidate(server):
    report = Scanner(server + "/flag", max_pages=1).scan()
    found = [f for f in report.findings if f.rule == "WEB-FLAG-CANDIDATE-001"]
    assert found and found[0].exploit_status == "validation-only"


def test_rejects_cross_origin_and_non_http(server):
    scanner = Scanner(server)
    assert not scanner._in_scope("http://example.invalid/")
    with pytest.raises(ValueError):
        Scanner("file:///etc/passwd")


def test_cross_origin_redirect_is_not_followed(server):
    scanner = Scanner(server)
    response = scanner._request(server + "/out")
    assert response.status == 302
    assert response.url.startswith(server)


def test_headers_are_normalized_and_cookie_session_is_kept(server):
    scanner = Scanner(server)
    first = scanner._request(server + "/session")
    assert "set-cookie" in first.headers
    protected = scanner._request(server + "/protected")
    assert protected.status == 200
    assert protected.text == "session-ok"


def test_hidden_post_defaults_are_preserved(server):
    report = Scanner(server + "/form", active=True, max_pages=1).scan()
    ready = [f for f in report.findings if f.rule == "WEB-CMDI-001" and f.exploit_status == "payload-ready"]
    assert ready
    assert ("csrf", "token-42") in ready[0].request_fields
    assert ready[0].method == "POST"


@pytest.mark.parametrize("path", ["/reflect?cmd=x", "/sanitize?cmd=x"])
def test_reflection_does_not_fake_command_execution(server, path):
    report = Scanner(server + path, active=True, max_pages=1).scan()
    assert not any(f.rule == "WEB-CMDI-001" and f.exploit_status == "payload-ready" for f in report.findings)

