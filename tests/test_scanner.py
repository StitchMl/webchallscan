from __future__ import annotations

import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from webchallscan.scanner import (
    CMD_PROBE, CMD_RESULT, PROFILES, SSTI_PROBE, SSTI_RESULT, Scanner, scan_profiles,
)


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
        mobile = self.headers.get("Sec-CH-UA-Mobile") == "?1"
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
        elif p.path == "/opaque-sql":
            value = values.get("x7", [""])[0]
            self._send("rows:42" if value == "' OR '1'='1'-- " else
                       "rows:0" if value == "' OR '1'='2'-- " else "rows:42")
        elif p.path == "/template":
            value = values.get("message", [""])[0]
            self._send(SSTI_RESULT if value == SSTI_PROBE else value)
        elif p.path == "/escaped":
            self._send(escape(values.get("x7", [""])[0]))
        elif p.path == "/session":
            self._send('<html><a href="/protected">protected</a></html>')
        elif p.path == "/protected":
            self._send("session-ok" if "wcs_session=valid" in self.headers.get("Cookie", "") else "denied", 200 if "wcs_session=valid" in self.headers.get("Cookie", "") else 403)
        elif p.path == "/form":
            self._send('<html><form action="/postrun" method="post"><input type="hidden" name="csrf" value="token-42"><input name="cmd" value="default"></form></html>')
        elif p.path == "/flag":
            self._send("CTF{unit_test_only}")
        elif p.path == "/profiles":
            if mobile:
                self._send('<html><form action="/mobile-run" method="get"><input name="cmd"></form></html>')
            else:
                self._send('<html><form action="/desktop-search" method="get"><input name="q"></form></html>')
        elif p.path == "/mobile-run":
            value = values.get("cmd", [""])[0]
            self._send(CMD_RESULT if mobile and value == CMD_PROBE else "mobile-ok")
        elif p.path == "/desktop-search":
            value = values.get("q", [""])[0]
            self._send("SQL syntax near quote" if not mobile and value == "'" else "desktop-ok")
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


def test_boolean_sqli_is_found_with_an_opaque_parameter_name(server):
    report = Scanner(server + "/opaque-sql?x7=hello", active=True, max_pages=1,
                     max_requests=12).scan()
    found = [f for f in report.findings if f.title == "SQL injection boolean behavior confirmed"]
    assert found and found[0].parameter == "x7"
    assert found[0].confidence == "high"
    assert found[0].exploit_status == "validation-only"


def test_html_escaped_reflection_is_not_boolean_sqli(server):
    report = Scanner(server + "/escaped?x7=hello", active=True, max_pages=1,
                     max_requests=12).scan()
    assert not any(f.title == "SQL injection boolean behavior confirmed"
                   for f in report.findings)


def test_ssti_requires_a_server_computed_result(server):
    confirmed = Scanner(server + "/template?message=hello", active=True, max_pages=1,
                        max_requests=12).scan()
    ready = [f for f in confirmed.findings if f.rule == "WEB-SSTI-001"
             and f.exploit_status == "payload-ready"]
    assert ready and "cat /flag" in ready[0].recovery_payload

    reflected = Scanner(server + "/reflect?message=hello", active=True, max_pages=1,
                        max_requests=12).scan()
    assert not any(f.rule == "WEB-SSTI-001" and f.exploit_status == "payload-ready"
                   for f in reflected.findings)


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


def test_fixed_profile_headers_and_isolated_cookie_jars(server):
    desktop = Scanner(server, profile="desktop")
    mobile = Scanner(server, profile="mobile")
    assert desktop.cookies is not mobile.cookies
    assert PROFILES["desktop"]["Sec-CH-UA-Mobile"] == "?0"
    assert PROFILES["mobile"]["Sec-CH-UA-Mobile"] == "?1"
    assert "Windows" in PROFILES["desktop"]["Sec-CH-UA-Platform"]
    assert "Android" in PROFILES["mobile"]["Sec-CH-UA-Platform"]


def test_both_profiles_find_distinct_surfaces_and_are_deterministic(server):
    kwargs = dict(profiles=("desktop", "mobile"), active=True, max_pages=1, max_requests=12)
    first = scan_profiles(server + "/profiles", **kwargs)
    second = scan_profiles(server + "/profiles", **kwargs)
    assert first.to_dict() == second.to_dict()
    assert first.profiles == ("desktop", "mobile")
    assert {finding.profile for finding in first.findings} >= {"desktop", "mobile", "comparison"}
    desktop_sql = [finding for finding in first.findings
                   if finding.profile == "desktop" and finding.title == "SQL injection error behavior confirmed"]
    mobile_cmd = [finding for finding in first.findings
                  if finding.profile == "mobile" and finding.title == "Command injection arithmetic execution confirmed"]
    assert desktop_sql
    assert mobile_cmd and mobile_cmd[0].exploit_status == "payload-ready"
    difference = next(finding for finding in first.findings if finding.rule == "WEB-PROFILE-DIFF-001")
    assert "sha256:" in difference.evidence
    assert "parameters desktop=['q'], mobile=['cmd']" in difference.evidence
    assert "<html" not in difference.evidence


def test_static_route_discovery_only_accepts_literal_get_paths():
    source = """
    fetch('/api/search?q=one');
    axios.get('/api/items');
    xhr.open('GET', '/api/health');
    fetch('/api/delete', {method: 'POST'});
    axios.post('/api/post');
    fetch(`/api/${id}`);
    fetch('https://other.example/data');
    """
    assert Scanner._static_get_routes(source) == [
        "/api/health", "/api/items", "/api/search?q=one",
        "https://other.example/data",
    ]


def test_parser_discovers_get_forms_frames_and_scripts():
    from webchallscan.scanner import PageParser
    parser = PageParser()
    parser.feed("""
    <form method="get" action="/search"><input name="q"></form>
    <form method="post" action="/delete"><input name="id"></form>
    <iframe src="/frame"></iframe>
    <script src="/app.js"></script>
    <link rel="canonical" href="/home">
    """)
    assert "/search" in parser.links
    assert "/frame" in parser.links
    assert "/home" in parser.links
    assert "/delete" not in parser.links
    assert parser.scripts == ["/app.js"]
