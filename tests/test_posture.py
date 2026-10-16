from webchallscan.posture import inspect_response


def test_document_metadata_findings():
    out = inspect_response("GET", "/home", "Document", 200, {}, True)
    assert {x["rule"] for x in out} == {
        "HEADER-HSTS", "HEADER-CSP", "HEADER-NOSNIFF", "HEADER-FRAMING",
    }
    assert all(x["confidence"] == "medium" for x in out)


def test_not_applied_to_non_documents_or_errors():
    assert inspect_response("POST", "/api/graphql", "XHR", 200, {}, True) == []
    assert inspect_response("GET", "/", "Document", 404, {}, True) == []


def test_valid_protective_headers_and_non_sensitive_output():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Set-Cookie": "session=TOPSECRET",
        "Authorization": "Bearer PRIVATE",
    }
    out = inspect_response("GET", "/", "Document", 200, headers, True)
    assert out == []
    assert "TOPSECRET" not in repr(out)
    assert "PRIVATE" not in repr(out)


def test_cors_conflict_is_configuration_note_not_exploit_confirmation():
    out = inspect_response("GET", "/api", "XHR", 200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }, True)
    assert [x["rule"] for x in out] == ["HEADER-CORS-CONFLICT"]
    assert out[0]["severity"] == "low"
