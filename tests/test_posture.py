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

def test_cookie_attribute_observations_never_include_secrets():
    out = inspect_response("GET", "/login", "Other", 200, {
        "Set-Cookie": "session=ULTRASECRET; Path=/; SameSite=None",
    }, True)
    assert {f["rule"] for f in out} == {
        "COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE-NONE",
    }
    assert "ULTRASECRET" not in repr(out)
    assert "session" not in repr(out).lower()


def test_cookie_flags_are_context_sensitive_and_non_session_values_not_retained():
    out = inspect_response("GET", "/", "Document", 200, {
        "Set-Cookie": "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax",
    }, True)
    assert not any(f["rule"].startswith("COOKIE-") for f in out)
    out = inspect_response("GET", "/", "Other", 200, {
        "Set-Cookie": "session=SECRET; Path=/",
    }, False)
    assert {f["rule"] for f in out} == {"COOKIE-HTTPONLY", "COOKIE-SAMESITE"}
    assert "SECRET" not in repr(out)
