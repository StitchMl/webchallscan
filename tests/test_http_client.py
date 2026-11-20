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
    opener = FakeOpener()
    request = Request("http://localhost/")
    with pytest.raises(ValueError):
        read_bounded(opener, request, 3, -1)
    handler = NoRedirect()
    assert handler.redirect_request(None, None, 302, "redirect", {},
                                    "http://elsewhere.invalid/") is None

def test_shared_scanner_handlers_preserve_proxy_tls_cookie_and_redirect_policy():
    import ssl
    from http.cookiejar import CookieJar
    from urllib.request import HTTPCookieProcessor, HTTPSHandler, ProxyHandler
    from webchallscan.http_client import (
        SameOriginRedirectHandler, scanner_handlers,
    )

    cookies = CookieJar()
    handlers = scanner_handlers(
        ("https", "lab.example"), cookies, verify_tls=True,
        proxy="http://127.0.0.1:8080",
    )
    assert isinstance(handlers[0], ProxyHandler)
    assert isinstance(handlers[1], SameOriginRedirectHandler)
    assert handlers[1].origin == ("https", "lab.example")
    assert any(isinstance(h, HTTPCookieProcessor) and h.cookiejar is cookies
               for h in handlers)
    tls = next(h for h in handlers if isinstance(h, HTTPSHandler))
    assert tls._context.verify_mode == ssl.CERT_REQUIRED
    insecure = scanner_handlers(
        ("https", "lab.example"), cookies, verify_tls=False,
    )
    assert not any(isinstance(h, ProxyHandler) for h in insecure)
    assert next(h for h in insecure if isinstance(h, HTTPSHandler))._context.verify_mode == ssl.CERT_NONE


def test_shared_api_handlers_retain_verified_default_and_explicit_opt_out():
    import ssl
    from urllib.request import HTTPSHandler
    from webchallscan.http_client import api_handlers, validate_loopback_proxy

    assert api_handlers() == [NoRedirect]
    insecure = api_handlers(verify_tls=False)
    assert insecure[0] is NoRedirect
    assert len(insecure) == 2
    assert isinstance(insecure[1], HTTPSHandler)
    assert insecure[1]._context.verify_mode == ssl.CERT_NONE
    assert validate_loopback_proxy("http://localhost:8080") == "http://localhost:8080"
    for invalid in ("http://example.com:8080", "https://127.0.0.1:8080",
                    "http://user:secret@localhost:8080", "http://localhost/other"):
        with pytest.raises(ValueError):
            validate_loopback_proxy(invalid)
