"""Explicit-case, read-only API and access-control checks.

A case must identify an owned test resource and an expected denied role.
The tool never enumerates identifiers, fuzzes parameters, or sends writes.
"""
from __future__ import annotations

import hashlib
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, Request, build_opener

from .http_client import NoRedirect, api_handlers, read_bounded


_NoRedirect = NoRedirect


def _digest_response(url: str, headers: dict[str, str], timeout: float, *, verify_tls: bool = True, proxy: str | None = None) -> dict:
    req = Request(url, method="GET", headers={**headers, "Accept": "application/json, text/plain, */*"})  # NOSONAR: authorized black-box request to the user-specified target
    handlers = api_handlers(verify_tls=verify_tls, proxy=proxy)
    response = read_bounded(build_opener(*handlers), req, timeout, 65537)
    raw, status = response.body, response.status
    typ = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if len(raw) > 65536:
        raise ValueError("response exceeds 64 KiB validation cap")
    return {"status": status, "content_type": typ,
            "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def run_readonly_cases(data: dict, timeout: float = 5.0, *, verify_tls: bool = True, proxy: str | None = None) -> dict:
    from .http_client import validate_loopback_proxy
    validate_loopback_proxy(proxy)
    if data.get("schema") != "webchallscan/read-only-cases-v1":
        raise ValueError("invalid case schema")
    origin = data.get("origin")
    p = urlsplit(origin) if isinstance(origin, str) else None
    if not p or p.scheme not in {"http", "https"} or not p.netloc or p.username or p.password or p.path or p.query or p.fragment:
        raise ValueError("origin must be an exact HTTP(S) origin")
    cases = data.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 12 or not 0.2 <= timeout <= 15:
        raise ValueError("maximum 12 cases and timeout 0.2-15 seconds")
    findings = []
    results = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {"path", "owner_headers", "other_headers"}:
            raise ValueError("each case needs path and both role header sets")
        path = case["path"]
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(c in path for c in ("?", "#", "\\", "\r", "\n")):
            raise ValueError("case path must be a fixed local path without query")
        header_sets = []
        for role in ("owner_headers", "other_headers"):
            h = case[role]
            if not isinstance(h, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                or k.lower() not in {"authorization", "cookie", "x-api-key"}
                or "\r" in v or "\n" in v for k, v in h.items()
            ):
                raise ValueError("role headers must be authorization, cookie or x-api-key only")
            header_sets.append(h)
        url = origin + path
        kwargs = {}
        if not verify_tls:
            kwargs["verify_tls"] = False
        if proxy is not None:
            kwargs["proxy"] = proxy
        owner = _digest_response(url, header_sets[0], timeout, **kwargs)
        other = _digest_response(url, header_sets[1], timeout, **kwargs)
        # A matching 2xx digest is a review candidate, not an IDOR proof:
        # generic success responses and public resources can match.
        suspected = 200 <= owner["status"] < 300 and 200 <= other["status"] < 300 and (
            owner["sha256"] == other["sha256"]
        )
        results.append({"case": index + 1, "path": path, "owner": owner, "other": other,
                        "authorization_review": "candidate" if suspected else "inconclusive"})
        if suspected:
            findings.append({"rule": "AUTHZ-REVIEW-001", "path": path,
                             "severity": "info", "confidence": "low",
                             "evidence": "Two caller-supplied roles received identical successful responses.",
                             "status": "manual-validation-required"})
    return {"schema": "webchallscan/read-only-results-v1", "origin": origin,
            "requests_sent": 2 * len(cases), "findings": findings, "cases": results,
            "limitations": ["No mutations, payload injection or ID enumeration.",
                            "Equal response hashes do not prove unauthorized data access.",
                            "Credentials are never included in output."]}


def load_cases(path: str) -> dict:
    f = Path(path)
    if f.stat().st_size > 500_000:
        raise ValueError("case file too large")
    data = json.loads(f.read_text(encoding="utf-8"))  # NOSONAR: reads a local cases file the user passes on the CLI
    if not isinstance(data, dict):
        raise ValueError("case file must contain an object")
    return data
