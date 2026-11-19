"""Shared, bounded stdlib HTTP response handling.

The caller owns its opener, redirect/TLS/cookie policy and request budget.
This module handles successful and HTTP error responses uniformly without
introducing retries, redirects or extra requests.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    """Do not follow redirects in explicit read-only API checks."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
