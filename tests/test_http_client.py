"""Regression tests for the shared HTTP response layer."""
from email.message import Message
from io import BytesIO
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from webchallscan.http_client import NoRedirect, read_bounded


class FakeResponse:
    status = 200
    def __init__(self, data=b"abcdef"):
        self.stream = BytesIO(data)
        self.headers = Message()
        self.headers["Content-Type"] = "text/plain; charset=utf-8"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return "http://127.0.0.1/final"

    def read(self, limit):
        return self.stream.read(limit)


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response, self.error = response, error
        self.calls = []

    def open(self, request, *, timeout):
        self.calls.append((request.full_url, timeout))
        if self.error:
            raise self.error
        return self.response


def test_success_response_is_bounded_and_preserves_redirected_url():
    opener = FakeOpener(response=FakeResponse())
    result = read_bounded(opener, Request("http://127.0.0.1/"), 4.0, 3)
    assert result.status == 200
    assert result.url == "http://127.0.0.1/final"
    assert result.body == b"abc"
    assert result.headers.get_content_charset() == "utf-8"
    assert not result.http_error
    assert opener.calls == [("http://127.0.0.1/", 4.0)]


def test_http_error_is_returned_without_retry_and_is_capped():
    headers = Message()
    headers["Content-Type"] = "application/json"
    error = HTTPError("http://127.0.0.1/missing", 404, "Not Found",
                      headers, BytesIO(b"too long"))
    opener = FakeOpener(error=error)
    result = read_bounded(opener, Request("http://127.0.0.1/missing"), 5, 4)
    assert (result.status, result.body, result.http_error) == (404, b"too ", True)
    assert len(opener.calls) == 1


def test_limits_and_redirect_policy():
    with pytest.raises(ValueError):
        read_bounded(FakeOpener(), Request("http://localhost/"), 3, -1)
    handler = NoRedirect()
    assert handler.redirect_request(None, None, 302, "redirect", {},
                                    "http://elsewhere.invalid/") is None
