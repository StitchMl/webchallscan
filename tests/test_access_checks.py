import pytest
from webchallscan import access_checks


def test_role_comparison_is_not_claimed_as_proven_idor(monkeypatch):
    calls = []
    def fake(url, headers, timeout):
        calls.append((url, headers, timeout))
        return {"status": 200, "content_type": "application/json", "length": 2,
                "sha256": "same"}
    monkeypatch.setattr(access_checks, "_digest_response", fake)
    report = access_checks.run_readonly_cases({
        "schema": "webchallscan/read-only-cases-v1",
        "origin": "https://lab.example",
        "cases": [{"path": "/api/resource/owned-by-a", "owner_headers": {"Authorization": "Bearer A"},
                   "other_headers": {"Authorization": "Bearer B"}}],
    })
    assert report["requests_sent"] == 2
    assert report["findings"][0]["status"] == "manual-validation-required"
    assert "Bearer A" not in repr(report) and "Bearer B" not in repr(report)
    assert len(calls) == 2


@pytest.mark.parametrize("bad_path", ["//host/path", "/x?token=1", "/x#part", "/x\\foo"])
def test_rejects_paths_not_fixed_to_origin(bad_path):
    with pytest.raises(ValueError):
        access_checks.run_readonly_cases({
            "schema": "webchallscan/read-only-cases-v1",
            "origin": "https://lab.example",
            "cases": [{"path": bad_path, "owner_headers": {}, "other_headers": {}}],
        })


def test_rejects_more_than_twelve_cases():
    with pytest.raises(ValueError):
        access_checks.run_readonly_cases({
            "schema": "webchallscan/read-only-cases-v1",
            "origin": "https://lab.example",
            "cases": [{"path": "/safe", "owner_headers": {}, "other_headers": {}}] * 13,
        })
