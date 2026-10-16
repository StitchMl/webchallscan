import pytest
from webchallscan.api_contract import validate_contract


def source(cases):
    return {"schema": "webchallscan/api-contract-v1",
            "origin": "https://lab.example",
            "roles": {"owner": {"Authorization": "Bearer A"},
                      "other": {"Authorization": "Bearer B"}},
            "cases": cases}


def test_confirmed_idor_requires_private_marker_and_both_roles():
    calls = []
    def fake(url, headers, timeout):
        calls.append((url, headers))
        return {"status": 200, "length": 22, "digest": "aa",
                "body": b'{"resource":"OWNED_1234"}'}
    data = source([{"kind": "idor", "path": "/resource/42",
                    "owner": "owner", "outsider": "other",
                    "expected_marker": "OWNED_1234"}])
    result = validate_contract(data, fetch=fake)
    assert result["findings"][0]["rule"] == "AUTHZ-IDOR-001"
    assert result["requests_sent"] == 2
    assert "Bearer" not in repr(result)
    assert len(calls) == 2


def test_idor_same_response_without_marker_is_not_confirmed():
    def fake(*args):
        return {"status": 200, "length": 2, "digest": "same", "body": b"{}"}
    result = validate_contract(source([
        {"kind": "idor", "path": "/public", "owner": "owner", "outsider": "other"}
    ]), fetch=fake)
    assert result["findings"] == []
    assert result["cases"][0]["checks"][0]["outcome"] == "review"


def test_fuzz_bounded_and_reports_5xx_as_uncertain():
    urls = []
    def fake(url, headers, timeout):
        urls.append(url)
        return {"status": 500 if "WCS_TEST_0123" in url else 200,
                "length": 2, "digest": "hash", "body": b"{}"}
    result = validate_contract(source([
        {"kind": "fuzz", "path": "/search", "role": "owner",
         "parameter": "q", "query": {"q": "safe"}}
    ]), fetch=fake)
    assert result["requests_sent"] == 6
    assert len(urls) == 6
    assert result["findings"][0]["rule"] == "API-INPUT-500"
    assert "WCS_TEST_0123" not in repr(result)


def test_business_status_invariant():
    def fake(*args):
        return {"status": 403, "length": 0, "digest": "empty", "body": b""}
    result = validate_contract(source([
        {"kind": "business", "path": "/api/read-only",
         "role": "other", "expected_statuses": [200]}
    ]), fetch=fake)
    assert result["findings"][0]["rule"] == "LOGIC-INVARIANT-001"


def test_cross_origin_path_and_write_operations_not_supported():
    with pytest.raises(ValueError):
        validate_contract(source([{"kind": "business", "path": "//evil.test/",
                                   "role": "owner", "expected_statuses": [200]}]))
