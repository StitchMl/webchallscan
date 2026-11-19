"""CDP HTTP discovery must stay on loopback without redirects or proxy leaks."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from webchallscan.session import SessionCaptureError, _json_get


@pytest.fixture()
def local_cdp():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://outside.example/private")
                self.end_headers()
            elif self.path == "/oversize":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b" " * 2_000_001)
            elif self.path == "/bad":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{not JSON")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"webSocketDebuggerUrl":"ws://127.0.0.1:12345/devtools"}')
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_cdp_http_json_can_be_read_from_loopback(local_cdp):
    url, seen = local_cdp
    result = _json_get(url + "/json/version", 2.0)
    assert result["webSocketDebuggerUrl"].startswith("ws://127.0.0.1:")
    assert seen == ["/json/version"]


def test_cdp_http_redirect_is_not_followed(local_cdp):
    url, seen = local_cdp
    with pytest.raises(SessionCaptureError, match="cannot read local"):
        _json_get(url + "/redirect", 2.0)
    assert seen == ["/redirect"]


def test_environment_proxy_does_not_intercept_local_cdp(local_cdp, monkeypatch):
    url, seen = local_cdp
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    assert _json_get(url + "/json/list", 2.0)
    assert seen == ["/json/list"]


@pytest.mark.parametrize("url", [
    "http://outside.example/json/version",
    "http://user:pass@127.0.0.1:9222/json/version",
    "file:///etc/passwd",
    "http://127.0.0.1:9222/path#frag",
])
def test_cdp_http_rejects_untrusted_endpoints_before_network(url):
    with pytest.raises(SessionCaptureError):
        _json_get(url, 0.5)


def test_cdp_http_bounds_body_and_normalizes_parser_errors(local_cdp):
    url, _ = local_cdp
    with pytest.raises(SessionCaptureError, match="exceeds 2 MB"):
        _json_get(url + "/oversize", 2.0)
    with pytest.raises(SessionCaptureError, match="invalid local"):
        _json_get(url + "/bad", 2.0)
