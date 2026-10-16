from webchallscan.network import _safe_request


def test_inventory_strips_query_values_and_credentials():
    origin = ("https", "lab.example")
    entry = _safe_request("POST", "https://lab.example/graphql?doc_id=123&token=secret", origin)
    assert entry == {
        "method": "POST",
        "path": "/graphql",
        "parameters": ["doc_id", "token"],
    }
    assert "secret" not in repr(entry)
    assert _safe_request("GET", "https://foreign.example/api", origin) is None
    assert _safe_request("GET", "https://user:pass@lab.example/api", origin) is None
    assert _safe_request("GET", "file:///etc/passwd", origin) is None


def test_inventory_handles_empty_and_duplicate_parameters():
    assert _safe_request("GET", "https://lab.example/?a=1&a=2&empty=", ("https", "lab.example")) == {
        "method": "GET",
        "path": "/",
        "parameters": ["a", "empty"],
    }
