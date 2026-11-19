from urllib.request import HTTPSHandler, ProxyHandler

import pytest

from webchallscan import access_checks, api_contract, json_checks
from webchallscan.http_client import NoRedirect, api_handlers


LOCAL_PROXY = "http://127.0.0.1:8080"


def test_api_proxy_is_local_only_and_does_not_follow_redirects():
    handlers = api_handlers(proxy=LOCAL_PROXY)
    assert handlers[0] is NoRedirect
    proxy = next(x for x in handlers if isinstance(x, ProxyHandler))
    assert proxy.proxies == {"http": LOCAL_PROXY, "https": LOCAL_PROXY}
    assert not any(isinstance(x, HTTPSHandler) for x in handlers)
    assert api_handlers() == [NoRedirect]
    for invalid in ("http://remote.example:8080", "http://127.0.0.1",
                    "http://user:pass@localhost:8080", "file:///proxy"):
        with pytest.raises(ValueError):
            api_handlers(proxy=invalid)


def test_api_contract_propagates_proxy_without_changing_mock_signature(monkeypatch):
    forwarded = []
    def fake_fetch(url, headers, timeout, *, verify_tls=True, proxy=None):
        forwarded.append((verify_tls, proxy))
        return {"status": 200, "length": 2, "digest": "same", "body": b"{}"}
    monkeypatch.setattr(api_contract, "_fetch", fake_fetch)
    data = {
        "schema": "webchallscan/api-contract-v1",
        "origin": "https://lab.example",
        "roles": {"owner": {}},
        "cases": [{"kind": "business", "path": "/health",
                   "role": "owner", "expected_statuses": [200]}],
    }
    assert api_contract.validate_contract(data, proxy=LOCAL_PROXY)["requests_sent"] == 1
    assert forwarded == [(True, LOCAL_PROXY)]
    with pytest.raises(ValueError):
        api_contract.validate_contract(data, proxy="http://outside.example:8080")


def test_access_comparison_propagates_proxy(monkeypatch):
    forwarded = []
    def fake_digest(url, headers, timeout, *, proxy=None):
        forwarded.append(proxy)
        return {"status": 403, "content_type": "text/plain",
                "length": 0, "sha256": "none"}
    monkeypatch.setattr(access_checks, "_digest_response", fake_digest)
    data = {
        "schema": "webchallscan/read-only-cases-v1",
        "origin": "https://lab.example",
        "cases": [{"path": "/safe", "owner_headers": {}, "other_headers": {}}],
    }
    assert access_checks.run_readonly_cases(data, proxy=LOCAL_PROXY)["requests_sent"] == 2
    assert forwarded == [LOCAL_PROXY, LOCAL_PROXY]


def test_json_case_runner_propagates_proxy_and_keeps_default(monkeypatch):
    forwarded = []
    def fake_json(url, body, headers, timeout, *, verify_tls=True, proxy=None):
        forwarded.append(proxy)
        return {"status": 200, "digest": "same", "body": b"{}"}
    monkeypatch.setattr(json_checks, "_send_json", fake_json)
    data = {
        "schema": "webchallscan/json-cases-v1",
        "origin": "https://lab.example",
        "cases": [{"path": "/eval", "kind": "ssti",
                   "body": {"q": "safe"}, "field": ["q"], "headers": {}}],
    }
    assert json_checks.run_json_cases(data, proxy=LOCAL_PROXY)["requests_sent"] == 3
    assert forwarded == [LOCAL_PROXY] * 3
    forwarded.clear()
    assert json_checks.run_json_cases(data)["requests_sent"] == 3
    assert forwarded == [None] * 3
