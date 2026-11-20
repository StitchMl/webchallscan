from __future__ import annotations

import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from webchallscan.scanner import (
    CMD_PROBE,
    CMD_RESULT,
    PROFILES,
    SSTI_PROBE,
    SSTI_RESULT,
    Scanner,
    scan_profiles,
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
        elif p.path == "/template-alt":
            value = values.get("message", [""])[0]
            self._send(SSTI_RESULT if value == "${7340*3}" else value)
        elif p.path == "/nosql":
            self._send("candidate" if "q[$ne]" in values else "baseline")
        elif p.path == "/escaped":
            self._send(escape(values.get("x7", [""])[0]))
        elif p.path == "/session":
            self._send('<html><a href="/protected">protected</a></html>')
        elif p.path == "/protected":
            self._send("session-ok" if "wcs_session=valid" in self.headers.get("Cookie", "") else "denied", 200 if "wcs_session=valid" in self.headers.get("Cookie", "") else 403)
        elif p.path == "/form":
            self._send('<html><form action="/postrun" method="post"><input type="hidden" name="csrf" value="token-42"><input name="cmd" value="default"></form></html>')
        elif p.path == "/repeated-get-form":
            self._send('<html><form action="/repeated-get-run?source=action" method="get">'
                       '<input name="cmd" value="default">'
                       '<input type="hidden" name="scope" value="read">'
                       '<input type="hidden" name="scope" value="write">'
                       '</form></html>')
        elif p.path == "/repeated-get-run":
            if (values.get("source") == ["action"]
                    and values.get("scope") == ["read", "write"]
                    and values.get("cmd") == [CMD_PROBE]):
                self._send(CMD_RESULT)
            else:
                self._send("denied", 403)
        elif p.path == "/repeated-post-form":
            self._send('<html><form action="/repeated-post-run" method="post">'
                       '<input name="cmd" value="default">'
                       '<input type="hidden" name="scope" value="read">'
                       '<input type="hidden" name="scope" value="write">'
                       '<input type="hidden" name="csrf" value="token-42">'
                       '</form></html>')
        elif p.path == "/textarea-form":
            self._send('<html><form action="/textarea-run" method="post">'
                       '<input type="hidden" name="csrf" value="token-42">'
                       '<textarea name="note">hello &amp; goodbye</textarea>'
                       '<input name="cmd" value="default"></form></html>')
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
        if (self.path == "/repeated-post-run"
                and values.get("scope") == ["read", "write"]
                and values.get("csrf") == ["token-42"]
                and values.get("cmd") == [CMD_PROBE]):
            self._send(CMD_RESULT)
        elif self.path == "/repeated-post-run":
            self._send("denied", 403)
        elif (self.path == "/textarea-run" and values.get("csrf") == ["token-42"]
                and values.get("note") == ["hello & goodbye"]
                and values.get("cmd") == [CMD_PROBE]):
            self._send(CMD_RESULT)
        elif self.path == "/textarea-run":
            self._send("denied", 403)
        elif self.path == "/postrun" and values.get("csrf") == ["token-42"] and values.get("cmd") == [CMD_PROBE]:
            self._send(CMD_RESULT)
        else:
            self._send("denied", 403)
    def log_message(self, *_): pass


@pytest.fixture
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
    assert sql
    assert sql[0].confidence == "high"
    assert cmd
    assert cmd[0].exploit_status == "payload-ready"
    assert "cat /flag" in cmd[0].vector
    assert CMD_PROBE in cmd[0].vector
    assert all("unit_test_only" not in f.evidence for f in report.findings)


def test_passive_flag_is_only_a_candidate(server):
    report = Scanner(server + "/flag", max_pages=1).scan()
    found = [f for f in report.findings if f.rule == "WEB-FLAG-CANDIDATE-001"]
    assert found
    assert found[0].exploit_status == "validation-only"


def test_boolean_sqli_is_found_with_an_opaque_parameter_name(server):
    report = Scanner(server + "/opaque-sql?x7=hello", active=True, max_pages=1,
                     max_requests=12).scan()
    found = [f for f in report.findings if f.title == "SQL injection boolean behavior confirmed"]
    assert found
    assert found[0].parameter == "x7"
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
    assert ready
    assert "cat /flag" in ready[0].recovery_payload

    reflected = Scanner(server + "/reflect?message=hello", active=True, max_pages=1,
                        max_requests=12).scan()
    assert not any(f.rule == "WEB-SSTI-001" and f.exploit_status == "payload-ready"
                   for f in reflected.findings)


def test_reflected_xss_confirmed_on_unencoded_reflection(server):
    report = Scanner(server + "/template?message=hello", active=True, max_pages=1,
                     max_requests=20).scan()
    xss = [f for f in report.findings if f.rule == "WEB-XSS-001"
           and f.title == "Reflected HTML/script injection confirmed"]
    assert xss
    assert xss[0].severity == "high"
    assert xss[0].confidence == "high"
    assert xss[0].parameter == "message"


def test_html_escaped_reflection_is_not_xss(server):
    report = Scanner(server + "/escaped?x7=hello", active=True, max_pages=1,
                     max_requests=12).scan()
    assert not any(f.rule == "WEB-XSS-001"
                   and f.title == "Reflected HTML/script injection confirmed"
                   for f in report.findings)


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
    kwargs = {"profiles": ("desktop", "mobile"), "active": True, "max_pages": 1, "max_requests": 12}
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
    assert mobile_cmd
    assert mobile_cmd[0].exploit_status == "payload-ready"
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


def test_no_routes_explains_scan_coverage(server):
    report = Scanner(server + "/protected", active=True, max_pages=3).scan()
    assert report.pages_scanned == 1
    assert any("No navigable links" in note for note in report.coverage)
    assert any("No eligible query or form parameters" in note for note in report.coverage)
    assert "coverage" in report.to_dict()

def test_select_defaults_preserve_first_or_explicit_option():
    from webchallscan.scanner import PageParser

    parser = PageParser()
    parser.feed("""
    <form method="post" action="/submit">
      <select name="first"><option value="a">A</option><option value="b">B</option></select>
      <select name="chosen"><option value="a">A</option><option selected value="b">B</option></select>
      <select name="empty"><option value="">None</option><option value="x">X</option></select>
      <select name="text"><option> Guest </option><option>Admin</option></select>
      <select name="selected-text"><option>User</option><option selected> Site  admin </option></select>
      <input name="other" value="kept">
    </form>
    """)
    assert parser.forms[0].inputs == [
        ("first", "select", "a"),
        ("chosen", "select", "b"),
        ("empty", "select", ""),
        ("text", "select", "Guest"),
        ("selected-text", "select", "Site admin"),
        ("other", "text", "kept"),
    ]


def test_select_without_name_does_not_affect_following_form_controls():
    from webchallscan.scanner import PageParser

    parser = PageParser()
    parser.feed("""
    <form><select><option selected value="ignore"></option></select>
    <input name="q" value="ok"></form>
    <form><select name="role"><option value="guest"></option></select></form>
    """)
    assert parser.forms[0].inputs == [("q", "text", "ok")]
    assert parser.forms[1].inputs == [("role", "select", "guest")]

def test_posture_checks_use_existing_http_responses_without_extra_requests(server):
    scanner = Scanner(server + "/form", max_pages=1, max_requests=3)
    report = scanner.scan()
    assert report.requests_sent == 3  # HEAD, OPTIONS, GET; no extra checks
    assert {f.rule for f in report.findings} >= {
        "HEADER-CSP", "HEADER-NOSNIFF", "HEADER-FRAMING",
    }
    assert "HEADER-HSTS" not in {f.rule for f in report.findings}
    assert all(f.exploit_status == "validation-only"
               for f in report.findings if f.rule.startswith("HEADER-"))


def test_posture_document_rules_skip_non_html_and_error_responses(server):
    scanner = Scanner(server)
    from webchallscan.scanner import Response
    assert scanner._posture_findings(
        Response(server + "/api", 200, {"content-type": "application/json"}, "{}")
    ) == []
    assert scanner._posture_findings(
        Response(server + "/missing", 404, {"content-type": "text/html"}, "<html></html>")
    ) == []
    cors = scanner._posture_findings(Response(
        server + "/api", 200,
        {"content-type": "application/json",
         "access-control-allow-origin": "*",
         "access-control-allow-credentials": "true",
         "set-cookie": "session=PRIVATE"},
        "{}",
    ))
    assert {item.rule for item in cors} == {"HEADER-CORS-CONFLICT", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"}
    assert "PRIVATE" not in repr(cors)

def test_proxy_requires_explicit_loopback_http_endpoint(server):
    for proxy in (
        "https://127.0.0.1:8080", "http://example.com:8080",
        "http://user:pass@127.0.0.1:8080", "http://127.0.0.1:8080/extra",
        "http://127.0.0.1", "http://127.0.0.1:invalid",
        "http://127.0.0.1:8080/?q=1",
    ):
        with pytest.raises(ValueError):
            Scanner(server, proxy=proxy)
    scanner = Scanner(server, proxy="http://127.0.0.1:8080")
    assert scanner.proxy == "http://127.0.0.1:8080"
    assert any(type(handler).__name__ == "ProxyHandler" for handler in scanner.opener.handlers)


def test_inventory_seeds_discover_unlinked_get_endpoints_within_budget(server):
    url = server + "/search?q=WCSBASE"
    baseline = Scanner(server + "/protected", max_pages=2, max_requests=4).scan()
    assert baseline.pages_scanned == 1
    scanner = Scanner(server + "/protected", max_pages=2, max_requests=4,
                      inventory_urls=(url,))
    report = scanner.scan()
    assert report.requests_sent == 4
    assert report.pages_scanned == 2
    assert any(f.parameter == "q" for f in report.findings)
    assert any("Seeded 1 GET endpoint" in note for note in report.coverage)


def test_inventory_seeds_reject_external_origin_and_remain_opt_in(server):
    with pytest.raises(ValueError):
        Scanner(server, inventory_urls=("https://other.example/path",))
    report = Scanner(server + "/protected", max_pages=1, max_requests=3).scan()
    assert not any("Seeded" in note for note in report.coverage)


def test_source_map_hint_is_passive_same_origin_and_redacted(server):
    from webchallscan.scanner import Response

    scanner = Scanner(server, max_pages=1, max_requests=3)
    js = Response(server + "/bundle.js?token=PRIVATE", 200,
                  {"content-type": "application/javascript"},
                  "//# sourceMappingURL=/assets/bundle.js.map?key=SECRET")
    findings = scanner._source_map_hints(js)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "WEB-SOURCEMAP-HINT-001"
    assert finding.severity == "info"
    assert finding.exploit_status == "validation-only"
    assert scanner.requests_sent == 0
    assert "SECRET" not in repr(finding.to_dict())
    assert "PRIVATE" not in repr(finding.to_dict())
    assert scanner._source_map_hints(Response(
        server + "/bundle.js", 200, {}, "//# sourceMappingURL=data:application/json,abc"
    )) == []
    assert scanner._source_map_hints(Response(
        server + "/bundle.js", 200, {}, "//# sourceMappingURL=https://outside.example/x.map"
    )) == []
    assert scanner._source_map_hints(Response(
        server + "/bundle.js", 404, {}, "//# sourceMappingURL=app.js.map"
    )) == []


def test_source_map_block_comment_support(server):
    from webchallscan.scanner import Response

    scanner = Scanner(server)
    assert scanner._source_map_hints(Response(
        server + "/app.min.js", 200, {},
        "/*# sourceMappingURL=app.min.js.map */"
    ))

def test_html_comment_hints_do_not_disclose_values(server):
    from webchallscan.scanner import PageParser, Response
    parser = PageParser()
    parser.feed('<html><!-- TODO: password=ULTRASECRET, FLAG{hidden} --><h1>ok</h1></html>')
    assert parser.comment_hints == {"TODO", "PASSWORD", "FLAG"}
    scanner = Scanner(server)
    findings = scanner._passive_findings(Response(server + "/comments", 200,
        {"content-type": "text/html"}, "<html>ok</html>"), parser)
    comment = next(f for f in findings if f.rule == "WEB-COMMENT-HINT-001")
    assert comment.severity == "info"
    assert "ULTRASECRET" not in repr(comment.to_dict())
    assert "FLAG{hidden}" not in repr(comment.to_dict())


def test_js_comment_hints_are_bounded_and_do_not_include_literals(server):
    from webchallscan.scanner import Response
    scanner = Scanner(server)
    comments = "// FIXME secret token=VERYPRIVATE\nconst x = 1;\n/* debug for admin */"
    result = scanner._js_comment_hints(Response(server + "/bundle.js", 200,
        {"content-type": "application/javascript"}, comments))
    assert len(result) == 1
    assert "FIXME" in result[0].evidence
    assert "SECRET" in result[0].evidence
    assert "DEBUG" in result[0].evidence
    assert "VERYPRIVATE" not in repr(result[0].to_dict())
    assert scanner.requests_sent == 0
    assert scanner._js_comment_hints(Response(server + "/bundle.js", 404, {}, comments)) == []

def test_metadata_headers_summarized_without_banner_values(server):
    from webchallscan.scanner import Response
    scanner = Scanner(server)
    metadata = Response(server + "/", 200,
        {"allow": "GET, POST, OPTIONS, X-SECRET",
         "server": "TOPSECRET server build",
         "x-powered-by": "SECRET version"}, "")
    findings = scanner._metadata_findings(metadata, "OPTIONS")
    assert {f.rule for f in findings} == {"WEB-HTTP-ALLOW-001", "WEB-TECH-BANNER-001"}
    public = repr([f.to_dict() for f in findings])
    assert "GET, OPTIONS, POST" in public
    assert "TOPSECRET" not in public
    assert "SECRET version" not in public
    assert all(f.exploit_status == "validation-only" for f in findings)


def test_javascript_discovery_explicit_get_only():
    source = """
    fetch('/api/get', {method: 'GET'});
    fetch('/api/create', {method: 'POST'});
    $.get('/v1/search?q=x');
    $.getJSON('/api/json');
    $.ajax({url: '/api/list', type: 'GET'});
    $.ajax({url: '/api/remove', type: 'DELETE'});
    axios({method:'get',url:'/api/info'});
    axios.post('/api/post');
    """
    assert Scanner._static_get_routes(source) == [
        "/api/get", "/api/info", "/api/json", "/api/list",
        "/v1/search?q=x",
    ]

def test_alt_ssti_arithmetic_needs_repeated_identical_evidence(server):
    report = Scanner(server + "/template-alt?message=hello", active=True,
                     ssti_alternates=True, max_pages=1, max_requests=12).scan()
    found = [f for f in report.findings
             if f.title == "Alternative template arithmetic syntax evaluated"]
    assert found
    assert found[0].proof_payload == "${7340*3}"
    assert found[0].expected_evidence == "22020"
    assert found[0].exploit_status == "validation-only"
    assert not found[0].recovery_payload
    assert report.requests_sent <= 12


def test_alt_ssti_respects_budget_and_does_not_claim_reflection(server):
    # Initial HEAD/OPTIONS/GET and two baseline/probe requests fit; no
    # additional pair can run when the request budget is exactly five.
    report = Scanner(server + "/template-alt?message=hello", active=True,
                     ssti_alternates=True, max_pages=1, max_requests=5).scan()
    assert report.requests_sent == 5
    assert not any(f.title == "Alternative template arithmetic syntax evaluated"
                   for f in report.findings)
    echo = Scanner(server + "/reflect?cmd=hello", active=True,
                   max_pages=1, max_requests=12).scan()
    assert not any(f.title == "Alternative template arithmetic syntax evaluated"
                   for f in echo.findings)

def test_alternate_ssti_is_off_by_default_and_requires_cli_opt_in(server, capsys):
    report = Scanner(server + "/template-alt?message=hello", active=True,
                     max_pages=1, max_requests=20).scan()
    assert not any(f.title == "Alternative template arithmetic syntax evaluated"
                   for f in report.findings)
    from webchallscan.cli import main
    assert main([server, "--authorized", "--ssti-alternates"]) == 2
    assert "requires --active" in capsys.readouterr().err

def test_opt_in_nosql_query_differential_is_review_only(server):
    url = server + "/nosql?q=WCSBASE"
    passive = Scanner(url, max_pages=1, max_requests=40).scan()
    assert not any(f.rule == "WEB-NOSQL-REVIEW-001" for f in passive.findings)
    default_active = Scanner(url, active=True, max_pages=1, max_requests=40).scan()
    assert not any(f.rule == "WEB-NOSQL-REVIEW-001" for f in default_active.findings)
    report = Scanner(url, active=True, nosql_query=True, max_pages=1,
                     max_requests=40).scan()
    found = [f for f in report.findings if f.rule == "WEB-NOSQL-REVIEW-001"]
    assert len(found) == 1
    assert found[0].severity == "info"
    assert found[0].confidence == "low"
    assert found[0].exploit_status == "validation-only"
    assert report.requests_sent <= 40


def test_nosql_query_budget_and_cli_mode_restrictions(server, capsys):
    from webchallscan.cli import main
    assert main([server, "--authorized", "--nosql-query"]) == 2
    assert "only to --active" in capsys.readouterr().err
    report = Scanner(server + "/nosql?q=good", active=True,
                     nosql_query=True, max_pages=1, max_requests=3).scan()
    assert report.requests_sent == 3
    assert not any(f.rule == "WEB-NOSQL-REVIEW-001" for f in report.findings)

def test_nonget_js_routes_are_only_informational_hints(server):
    from webchallscan.scanner import Response
    source = """
    axios.post('/api/write?token=PRIVATE', {v: 1});
    axios.delete('/api/remove');
    fetch('/admin/apply', {method: 'PATCH', body: '{}'});
    $.ajax({url: '/v1/delete', type: 'DELETE'});
    var x="/internal/health";
    axios.post('https://elsewhere.example/attack');
    """
    scanner = Scanner(server)
    hints = scanner._js_api_findings(Response(server + "/app.js", 200,
        {"content-type": "application/javascript"}, source))
    pairs = {(f.method, f.url.split("?")[0]) for f in hints}
    assert pairs == {
        ("POST", server + "/api/write"),
        ("DELETE", server + "/api/remove"),
        ("PATCH", server + "/admin/apply"),
        ("DELETE", server + "/v1/delete"),
        ("UNKNOWN", server + "/internal/health"),
    }
    assert all(f.severity == "info" and f.exploit_status == "validation-only"
               for f in hints)
    assert "PRIVATE" not in repr([f.to_dict() for f in hints])
    assert scanner.requests_sent == 0
    assert not any("/api/write" in path for path in
                   Scanner._static_get_routes(source))


def test_nonget_js_hints_ignore_dynamic_and_external_routes(server):
    from webchallscan.scanner import Response
    scanner = Scanner(server)
    hints = scanner._js_api_findings(Response(
        server + "/app.js", 200, {},
        "axios.post(`/api/${id}`); axios.post('https://evil.example/');"
        "fetch('/api/write', {method: 'POST'});"
    ))
    assert [f.url for f in hints] == [server + "/api/write"]

def test_passive_jwt_discovery_from_response_and_cookies_redacts_values(server):
    import base64
    import json
    from types import SimpleNamespace

    from webchallscan.scanner import Response

    def encode(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    jwt = (encode({"alg": "none"}) + "." +
           encode({"sub": "private@example.com", "role": "ADMINSECRET"}) +
           ".SIG_PRIVATE_7253")
    scanner = Scanner(server + "/jwt?secret=PRIVATE")
    scanner.cookies = [SimpleNamespace(value=jwt)]
    response = Response(server + "/jwt?secret=PRIVATE", 200,
        {"content-type": "text/html"}, "<script>const token='" + jwt + "';</script>")
    findings = scanner._jwt_metadata_hints(response)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "WEB-JWT-METADATA-001"
    assert finding.severity == "info"
    assert finding.exploit_status == "validation-only"
    assert "JWT-ALG-NONE" in finding.evidence
    assert "cookie" in finding.evidence
    assert "response" in finding.evidence
    public = repr(finding.to_dict())
    for secret in (jwt, "private@example.com", "ADMINSECRET", "PRIVATE", "SIG_PRIVATE_7253"):
        assert secret not in public
    assert finding.to_dict()["replay"]["cookie_names"] == []
    assert scanner.requests_sent == 0


def test_passive_jwt_discovery_ignores_invalid_strings(server):
    from webchallscan.scanner import Response
    scanner = Scanner(server)
    assert scanner._jwt_metadata_hints(Response(
        server + "/", 200, {}, "eyJinvalid.eyJinvalid.signature"
    )) == []


def test_textarea_defaults_preserve_content_and_form_boundaries():
    from webchallscan.scanner import PageParser

    parser = PageParser()
    parser.feed("""
    <form method="post" action="/submit">
      <textarea name="note">hello &amp; goodbye\n  second line</textarea>
      <textarea name="blank"></textarea>
      <input name="token" value="kept">
    </form>
    <form method="get" action="/other">
      <textarea name="other">another value</textarea>
    </form>
    """)
    assert parser.forms[0].inputs == [
        ("note", "textarea", "hello & goodbye\n  second line"),
        ("blank", "textarea", ""),
        ("token", "text", "kept"),
    ]
    assert parser.forms[1].inputs == [("other", "textarea", "another value")]


def test_active_post_preserves_textarea_defaults_without_exceeding_request_budget(server):
    scanner = Scanner(server + "/textarea-form", active=True,
                      max_pages=1, max_requests=24)
    report = scanner.scan()
    confirmed = [finding for finding in report.findings
                 if finding.rule == "WEB-CMDI-001"
                 and finding.exploit_status == "payload-ready"
                 and finding.parameter == "cmd"]
    assert confirmed
    assert confirmed[0].method == "POST"
    assert ("note", "hello & goodbye") in confirmed[0].request_fields
    assert ("csrf", "token-42") in confirmed[0].request_fields
    assert report.requests_sent <= 24
    assert report.pages_scanned == 1


def test_form_parser_submits_only_checked_checkbox_and_radio_defaults():
    from webchallscan.scanner import PageParser

    parser = PageParser()
    parser.feed("""
    <form method="post" action="/submit">
      <input type="checkbox" name="optout" value="no">
      <input type="checkbox" name="enabled" checked>
      <input type="checkbox" name="mode" checked value="fast">
      <input type="radio" name="plan" value="basic">
      <input type="radio" name="plan" checked value="pro">
      <input type="hidden" name="csrf" value="token-42">
      <input type="text" name="cmd" value="default">
    </form>
    """)
    assert parser.forms[0].inputs == [
        ("enabled", "checkbox", "on"),
        ("mode", "checkbox", "fast"),
        ("plan", "radio", "pro"),
        ("csrf", "hidden", "token-42"),
        ("cmd", "text", "default"),
    ]


def test_checked_boolean_html_attribute_counts_as_selected():
    from webchallscan.scanner import PageParser

    parser = PageParser()
    parser.feed('<form><input type="radio" name="role" checked="false" value="admin"></form>')
    assert parser.forms[0].inputs == [("role", "radio", "admin")]


def test_active_post_preserves_repeated_form_fields_and_request_budget(server):
    scanner = Scanner(server + "/repeated-post-form", active=True,
                      max_pages=1, max_requests=80)
    report = scanner.scan()
    confirmed = [finding for finding in report.findings
                 if finding.rule == "WEB-CMDI-001"
                 and finding.parameter == "cmd"
                 and finding.exploit_status == "payload-ready"]
    assert confirmed
    assert confirmed[0].method == "POST"
    assert confirmed[0].request_fields.count(("scope", "read")) == 1
    assert confirmed[0].request_fields.count(("scope", "write")) == 1
    assert ("csrf", "token-42") in confirmed[0].request_fields
    assert report.requests_sent <= 80
    assert report.pages_scanned == 1


def test_active_get_preserves_repeated_fields_and_action_query(server):
    scanner = Scanner(server + "/repeated-get-form", active=True,
                      max_pages=1, max_requests=80)
    report = scanner.scan()
    confirmed = [finding for finding in report.findings
                 if finding.rule == "WEB-CMDI-001"
                 and finding.parameter == "cmd"
                 and finding.exploit_status == "payload-ready"]
    assert confirmed
    assert confirmed[0].method == "GET"
    assert confirmed[0].request_fields.count(("scope", "read")) == 1
    assert confirmed[0].request_fields.count(("scope", "write")) == 1
    assert report.requests_sent <= 80
    assert report.pages_scanned == 1


def test_get_query_probe_preserves_repeated_query_parameters(server):
    from webchallscan.scanner import Response

    scanner = Scanner(server + "/run?scope=read&scope=write&cmd=default")
    finding = scanner._parameter_hypotheses(
        scanner.target, "GET", "cmd",
        (("scope", "read"), ("scope", "write"), ("cmd", "default")),
        generic=True,
    )[0]
    captured = []

    def capture(url, method="GET", data=None):
        captured.append((url, method, data))
        return Response(url, 200, {}, "ok")

    scanner._request = capture
    scanner._send_probe(finding, CMD_PROBE)
    assert parse_qs(urlsplit(captured[0][0]).query) == {
        "scope": ["read", "write"], "cmd": [CMD_PROBE],
    }
    assert captured[0][1:] == ("GET", None)


def test_starttag_dispatch_preserves_links_scripts_and_mixed_form_controls():
    from webchallscan.scanner import PageParser

    parser = PageParser()
    parser.feed("""
    <a href="/next">next</a>
    <link rel="canonical" href="/home">
    <iframe src="/frame"></iframe>
    <script src="/bundle.js"></script>
    <form method="post" action="/submit">
      <input name="token" type="hidden" value="keep">
      <input name="ignored" type="checkbox" value="no">
      <input name="enabled" type="checkbox" checked>
      <select name="mode"><option value="a">A</option><option selected value="b">B</option></select>
      <textarea name="note">hello &amp; world</textarea>
      <input name="cmd" value="default">
    </form>
    """)
    assert parser.links == ["/next", "/home", "/frame"]
    assert parser.scripts == ["/bundle.js"]
    assert parser.forms[0].method == "POST"
    assert parser.forms[0].action == "/submit"
    assert parser.forms[0].inputs == [
        ("token", "hidden", "keep"),
        ("enabled", "checkbox", "on"),
        ("mode", "select", "b"),
        ("note", "textarea", "hello & world"),
        ("cmd", "text", "default"),
    ]
