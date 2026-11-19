"""Shared, bounded stdlib HTTP response handling.

The caller owns its opener, redirect/TLS/cookie policy and request budget.
This module handles successful and HTTP error responses uniformly without
introducing retries, redirects or extra requests.
"""
from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar
import ssl
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, ProxyHandler


class NoRedirect(HTTPRedirectHandler):
    """Do not follow redirects in explicit read-only API checks."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SameOriginRedirectHandler(HTTPRedirectHandler):
    """Allow only relative or exact same-origin redirects in crawler mode."""

    def __init__(self, origin: tuple[str, str]) -> None:
        self.origin = origin
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self.origin:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_loopback_proxy(proxy: str | None) -> str | None:
    if proxy is None:
        return None
    p = urlsplit(proxy)
    if (p.scheme != "http" or p.hostname not in {"127.0.0.1", "localhost", "::1"}
            or p.username or p.password or p.path not in {"", "/"}
            or p.query or p.fragment):
        raise ValueError("--proxy must be an HTTP loopback URL without credentials or path")
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("--proxy requires a valid port") from exc
    if port is None:
        raise ValueError("--proxy requires an explicit port")
    return proxy


def scanner_handlers(origin: tuple[str, str], cookies: CookieJar,
                     *, verify_tls: bool, proxy: str | None = None) -> list:
    """Retain explicit verified SSL context, cookie jar and origin-only redirects."""
    proxy = validate_loopback_proxy(proxy)
    context = (ssl.create_default_context() if verify_tls
               else ssl._create_unverified_context())  # NOSONAR: caller explicitly opts out of verification
    handlers = []
    if proxy:
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    handlers.extend([
        SameOriginRedirectHandler(origin),
        HTTPCookieProcessor(cookies),
        HTTPSHandler(context=context),
    ])
    return handlers


def api_handlers(*, verify_tls: bool = True, proxy: str | None = None) -> list:
    """Keep redirects blocked; optionally route requests via a local proxy."""
    proxy = validate_loopback_proxy(proxy)
    handlers = [NoRedirect]
    if proxy:
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    if not verify_tls:
        handlers.append(HTTPSHandler(context=ssl._create_unverified_context()))  # NOSONAR: explicit opt-in
    return handlers


@dataclass(frozen=True)
class BoundedResponse:
    url: str
    status: int
    headers: object
    body: bytes
    http_error: bool


def read_bounded(opener, request, timeout: float, max_bytes: int) -> BoundedResponse:
    """Read at most max_bytes, including for HTTPError responses.

    This function never retries requests. API callers can request cap+1 bytes
    to detect oversized bodies; the crawler intentionally truncates at its
    existing 1 MB cap.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    try:
        with opener.open(request, timeout=timeout) as response:
            return BoundedResponse(
                response.geturl() if hasattr(response, "geturl") else request.full_url,
                response.status,
                getattr(response, "headers", {}),
                response.read(max_bytes),
                False,
            )
    except HTTPError as exc:
        return BoundedResponse(
            request.full_url, exc.code, exc.headers, exc.read(max_bytes), True,
        )
