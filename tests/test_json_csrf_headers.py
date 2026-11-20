"""Explicit JSON cases may carry CSRF headers only with deliberate active opt-in."""
import pytest

from webchallscan.json_checks import run_json_cases


def sample(headers):
    return {"schema": "webchallscan/json-cases-v1", "origin": "https://lab.example",
            "cases": [{"path": "/api/check", "kind": "ssti", "field": ["input"],
                       "body": {"input": "SAFE", "csrf": "PRIVATE-BODY-TOKEN"},
                       "headers": headers}]}


def test_explicit_csrf_headers_survive_nested_json_checks_without_reporting_values():
    received = []
    headers = {"Cookie": "session=PRIVATECOOKIE",
               "X-CSRF-Token": "PRIVATE-HEADER-TOKEN"}
    def send(url, body, sent_headers, timeout):
        received.append((url, body, dict(sent_headers)))
        return {"status": 200, "digest": "fixed", "body": b"no computation"}
    result = run_json_cases(sample(headers), send=send)
    assert len(received) == 3
    assert all(item[2]["X-CSRF-Token"] == "PRIVATE-HEADER-TOKEN" for item in received)
    assert all(item[1]["csrf"] == "PRIVATE-BODY-TOKEN" for item in received)
    assert result["requests_sent"] == 3
    assert "PRIVATE" not in repr(result)


@pytest.mark.parametrize("header,value", [
    ("X-XSRF-Token", "valid"),
    ("X-CSRFToken", "valid"),
])
def test_other_explicit_csrf_header_names_are_accepted(header, value):
    result = run_json_cases(sample({header: value}),
                            send=lambda *a: {"status": 200, "digest": "a", "body": b"test"})
    assert result["requests_sent"] == 3


@pytest.mark.parametrize("header,value", [
    ("Host", "outside.example"),
    ("X-CSRF-Token", "a\r\nX-Injected: yes"),
    ("X-XSRF-Token", "A" * 4097),
])
def test_untrusted_headers_are_rejected_before_network(header, value):
    contract = sample({header: value})

    def forbidden_send(*args):
        pytest.fail("network called")

    with pytest.raises(ValueError):
        run_json_cases(contract, send=forbidden_send)
