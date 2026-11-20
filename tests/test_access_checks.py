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
    assert "Bearer A" not in repr(report)
    assert "Bearer B" not in repr(report)
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

def test_readonly_client_tls_opt_in(monkeypatch):
    import ssl

    seen = []
    class Headers:
        def get(self, *args): return "application/json"
    class FakeResponse:
        status = 200
        headers = Headers()
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size): return b"ok"
    class FakeOpener:
        def open(self, *args, **kwargs): return FakeResponse()
    def fake_build(*handlers):
        seen.append(handlers)
        return FakeOpener()
    monkeypatch.setattr(access_checks, "build_opener", fake_build)
    access_checks._digest_response("https://lab.example/", {}, 5)
    access_checks._digest_response("https://lab.example/", {}, 5, verify_tls=False)
    assert not any(isinstance(h, access_checks.HTTPSHandler) for h in seen[0])
    contexts = [h._context for h in seen[1] if isinstance(h, access_checks.HTTPSHandler)]
    assert len(contexts) == 1
    assert contexts[0].verify_mode == ssl.CERT_NONE
