"""Invalid later API cases must never cause earlier authenticated requests."""
import pytest

from webchallscan import api_contract, access_checks


def _contract(cases):
    return {
        "schema": "webchallscan/api-contract-v1",
        "origin": "https://lab.example",
        "roles": {"owner": {"Authorization": "Bearer EXAMPLE"}},
        "cases": cases,
    }


def test_contract_rejects_invalid_later_case_before_network():
    calls = []
    def fake_fetch(*args):
        calls.append(args)
        raise AssertionError("No request should be sent on invalid contract")
    data = _contract([
        {"kind": "business", "path": "/read-only", "role": "owner",
         "expected_statuses": [200]},
        {"kind": "fuzz", "path": "/search", "role": "owner",
         "query": {"q": "safe"}, "parameter": "missing"},
    ])
    with pytest.raises(ValueError, match="fuzz case"):
        api_contract.validate_contract(data, fetch=fake_fetch)
    assert calls == []


def test_contract_rejects_bad_marker_even_if_request_would_be_denied():
    calls = []
    def fake_fetch(*args):
        calls.append(args)
        raise AssertionError("No request should be sent on invalid contract")
    data = _contract([
        {"kind": "business", "path": "/safe", "role": "owner",
         "expected_statuses": [200]},
        {"kind": "idor", "path": "/resource", "owner": "owner", "outsider": "owner",
         "expected_marker": "x"},
    ])
    with pytest.raises(ValueError):
        api_contract.validate_contract(data, fetch=fake_fetch)
    assert calls == []


def test_access_checker_rejects_bad_later_headers_without_requests(monkeypatch):
    calls = []
    def fake_digest(*args, **kwargs):
        calls.append(args)
        raise AssertionError("No request should be sent on invalid cases")
    monkeypatch.setattr(access_checks, "_digest_response", fake_digest)
    payload = {
        "schema": "webchallscan/read-only-cases-v1",
        "origin": "https://lab.example",
        "cases": [
            {"path": "/safe", "owner_headers": {}, "other_headers": {}},
            {"path": "/unsafe", "owner_headers": {"X-Extra": "bad"},
             "other_headers": {}},
        ],
    }
    with pytest.raises(ValueError, match="role headers"):
        access_checks.run_readonly_cases(payload)
    assert calls == []


def test_valid_access_checker_still_sends_exactly_two_requests(monkeypatch):
    calls = []
    def fake_digest(*args, **kwargs):
        calls.append(args)
        return {"status": 403, "content_type": "text/plain",
                "length": 0, "sha256": "example"}
    monkeypatch.setattr(access_checks, "_digest_response", fake_digest)
    payload = {
        "schema": "webchallscan/read-only-cases-v1",
        "origin": "https://lab.example",
        "cases": [{"path": "/safe", "owner_headers": {}, "other_headers": {}}],
    }
    result = access_checks.run_readonly_cases(payload)
    assert result["requests_sent"] == 2
    assert len(calls) == 2
