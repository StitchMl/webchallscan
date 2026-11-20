"""Local-only HTTP integration coverage for the optional API upstream proxy."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urllib_request

import pytest

from webchallscan import api_contract, json_checks


@pytest.fixture
def local_proxy(monkeypatch):
    # Guarantee the .invalid test origin does not bypass the test proxy.
    monkeypatch.setattr(urllib_request, "proxy_bypass", lambda host: False)
    requests = []

    class ProxyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(("GET", self.path, b""))
            if self.path.endswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "http://never-contact.invalid/")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(("POST", self.path, raw))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_real_get_reaches_local_proxy_and_redirect_is_not_followed(local_proxy):
    proxy, sent = local_proxy
    result = api_contract._fetch(
        "http://wcs-proxy-target.invalid/redirect", {}, 5, proxy=proxy,
    )
    assert result["status"] == 302
    assert len(sent) == 1
    assert sent[0][:2] == ("GET", "http://wcs-proxy-target.invalid/redirect")


def test_get_contract_uses_loopback_proxy_without_extra_requests(local_proxy):
    proxy, sent = local_proxy
    contract = {
        "schema": "webchallscan/api-contract-v1",
        "origin": "http://wcs-proxy-target.invalid",
        "roles": {"owner": {}},
        "cases": [{"kind": "business", "path": "/health", "role": "owner",
                   "expected_statuses": [200]}],
    }
    result = api_contract.validate_contract(contract, proxy=proxy)
    assert result["requests_sent"] == 1
    assert result["cases"][0]["checks"][0]["outcome"] == "passed"
    assert sent == [("GET", "http://wcs-proxy-target.invalid/health", b"")]


def test_explicit_json_cases_post_through_loopback_proxy(local_proxy):
    proxy, sent = local_proxy
    cases = {
        "schema": "webchallscan/json-cases-v1",
        "origin": "http://wcs-proxy-target.invalid",
        "cases": [{
            "path": "/api/validate", "kind": "ssti",
            "body": {"context": {"q": "original"}},
            "field": ["context", "q"], "headers": {},
        }],
    }
    result = json_checks.run_json_cases(cases, proxy=proxy)
    assert result["requests_sent"] == 3
    assert len(sent) == 3
    assert all(method == "POST" and path ==
               "http://wcs-proxy-target.invalid/api/validate"
               for method, path, _ in sent)
    fields = [json.loads(body)["context"]["q"] for _, _, body in sent]
    assert fields == ["WCSBASE", "{{7340*3}}", "{{7340*3}}"]
