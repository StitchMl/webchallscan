"""Bounded contract-based API validation for controlled labs.

GET-only, no discovery of identifiers, no redirects, no credential output.
Contracts define which role owns a resource, expected deny statuses, and
non-sensitive response invariants. Fuzz cases operate only on explicit
non-secret query parameters.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPSHandler, Request, build_opener

from .http_client import NoRedirect, api_handlers, read_bounded


ALLOWED_HEADERS = {"authorization", "cookie", "x-api-key"}
PROBES = ("", "WCS_TEST_0123", "0", "-1", "a" * 64)

def _fetch(url, headers, timeout, *, verify_tls=True, proxy=None):
    request = Request(url, method="GET", headers={**headers, "Accept": "application/json"})
    handlers = api_handlers(verify_tls=verify_tls, proxy=proxy)
    response = read_bounded(build_opener(*handlers), request, timeout, 65537)
    raw, status = response.body, response.status
    if len(raw) > 65536:
        raise ValueError("response exceeded 64 KiB limit")
    return {"status": status, "length": len(raw), "digest": hashlib.sha256(raw).hexdigest(),
            "body": raw}

def _validate_headers(value):
    if not isinstance(value, dict) or any(
        not isinstance(k, str) or k.lower() not in ALLOWED_HEADERS
        or not isinstance(v, str) or "\r" in v or "\n" in v for k, v in value.items()
    ):
        raise ValueError("invalid role authentication headers")
    return value

def _validate_path(value):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or any(
        x in value for x in ("?", "#", "\\", "\r", "\n")
    ):
        raise ValueError("paths must be literal same-origin paths")

def _public(response):
    return {k: response[k] for k in ("status", "length", "digest")}

def _validate_query(query) -> None:
    if not isinstance(query, dict) or len(query) > 10 or any(
        not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", k)
        or not isinstance(v, str) or len(v) > 200 for k, v in query.items()
    ):
        raise ValueError("only bounded non-secret query values are accepted")


def _preflight_idor(case: dict, roles: dict) -> None:
    owner, outsider = case.get("owner"), case.get("outsider")
    if (not isinstance(owner, str) or not isinstance(outsider, str)
            or owner == outsider or owner not in roles or outsider not in roles):
        raise ValueError("IDOR needs distinct, known owner and outsider roles")
    denied = case.get("denied_statuses", [401, 403, 404])
    if (not isinstance(denied, list) or not denied or
            any(type(code) is not int or code not in (401, 403, 404)
                for code in denied)):
        raise ValueError("invalid denied statuses")
    marker = case.get("expected_marker")
    if marker is not None and (not isinstance(marker, str)
                               or not 4 <= len(marker) <= 80):
        raise ValueError("invalid expected marker")


def _preflight_fuzz(case: dict, roles: dict, query: dict) -> None:
    role, field = case.get("role"), case.get("parameter")
    if not isinstance(role, str) or role not in roles or not isinstance(field, str) or field not in query:
        raise ValueError("fuzz case needs an existing query parameter and role")


def _preflight_business(case: dict, roles: dict) -> None:
    role, expected = case.get("role"), case.get("expected_statuses")
    if (not isinstance(role, str) or role not in roles
            or not isinstance(expected, list) or not expected
            or any(type(code) is not int or not 100 <= code <= 599
                   for code in expected)):
        raise ValueError("business case requires explicit role and expected statuses")


def _preflight_contract_cases(cases: list, roles: dict) -> None:
    """Reject malformed cases before any authenticated HTTP request is sent."""
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("invalid case")
        _validate_path(case.get("path"))
        kind = case.get("kind")
        query = case.get("query", {})
        _validate_query(query)
        if kind == "idor":
            _preflight_idor(case, roles)
        elif kind == "fuzz":
            _preflight_fuzz(case, roles, query)
        elif kind == "business":
            _preflight_business(case, roles)
        else:
            raise ValueError("supported case kinds: idor, fuzz, business")


def _validate_origin(origin) -> None:
    p = urlsplit(origin) if isinstance(origin, str) else None
    if not p or p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password or p.path or p.query or p.fragment or p.netloc.endswith("."):
        raise ValueError("origin must contain only scheme and authority")


def _validate_roles(roles) -> None:
    if not isinstance(roles, dict) or len(roles) not in range(1, 6):
        raise ValueError("provide 1-5 named roles")
    for key, headers in roles.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,30}", key):
            raise ValueError("invalid role name")
        _validate_headers(headers)


def _run_idor(case: dict, roles: dict, url: str, timeout, client, identifier: str, findings: list) -> tuple[dict, int]:
    owner, outsider = case.get("owner"), case.get("outsider")
    # Only an expected deny response can make a positive confirmation possible.
    denied = case.get("denied_statuses", [401, 403, 404])
    a = client(url, roles[owner], timeout)
    b = client(url, roles[outsider], timeout)
    status = "inconclusive"
    if 200 <= a["status"] < 300 and b["status"] in denied:
        status = "enforced"
    elif 200 <= a["status"] < 300 and 200 <= b["status"] < 300:
        # Strict confirmation requires a caller-supplied, non-sensitive
        # resource marker present in both responses.
        marker = case.get("expected_marker")
        if marker and marker.encode() in a["body"] and marker.encode() in b["body"]:
            status = "confirmed"
            findings.append({"rule": "AUTHZ-IDOR-001", "case": identifier,
                             "severity": "high", "confidence": "high",
                             "evidence": "Both roles retrieved the caller-designated private resource marker."})
        else:
            status = "review"
    return {"check": "ownership", "outcome": status,
            "owner": _public(a), "outsider": _public(b)}, 2


def _run_fuzz(case: dict, roles: dict, url: str, timeout, client, identifier: str, findings: list,
              origin: str, path: str, query: dict) -> tuple[dict, int]:
    role, field = case.get("role"), case.get("parameter")
    baseline = client(url, roles[role], timeout)
    requests = 1
    variations = []
    for payload in PROBES:
        mutated = dict(query)
        mutated[field] = payload
        mutated_url = origin + path + "?" + urlencode(sorted(mutated.items()))
        response = client(mutated_url, roles[role], timeout)
        requests += 1
        variations.append({"probe_class": ("empty", "marker", "zero", "negative", "length")[len(variations)],
                           "status": response["status"], "changed": response["digest"] != baseline["digest"]})
    server_error = any(x["status"] >= 500 for x in variations)
    check = {"check": "bounded-input-fuzz",
             "outcome": "review" if server_error else "observed",
             "baseline": _public(baseline), "variations": variations}
    if server_error:
        findings.append({"rule": "API-INPUT-500", "case": identifier,
                         "severity": "medium", "confidence": "medium",
                         "evidence": "A bounded input variation produced an HTTP 5xx; cause not established."})
    return check, requests


def _run_business(case: dict, roles: dict, url: str, timeout, client, identifier: str, findings: list) -> tuple[dict, int]:
    role = case.get("role")
    allowed = case.get("expected_statuses")
    response = client(url, roles[role], timeout)
    outcome = "passed" if response["status"] in allowed else "failed"
    check = {"check": "status-invariant", "outcome": outcome,
             "expected_statuses": allowed, "observed": _public(response)}
    if outcome == "failed":
        findings.append({"rule": "LOGIC-INVARIANT-001", "case": identifier,
                         "severity": "medium", "confidence": "high",
                         "evidence": "HTTP response violates the explicitly declared status invariant."})
    return check, 1


def _run_case(case: dict, identifier: str, origin: str, roles: dict, timeout, client, findings: list) -> tuple[dict, int]:
    path = case.get("path")
    kind = case.get("kind")
    query = case.get("query", {})
    url = origin + path + (("?" + urlencode(sorted(query.items()))) if query else "")
    result = {"id": identifier, "path": path, "kind": kind, "checks": []}
    if kind == "idor":
        check, sent = _run_idor(case, roles, url, timeout, client, identifier, findings)
    elif kind == "fuzz":
        check, sent = _run_fuzz(case, roles, url, timeout, client, identifier, findings, origin, path, query)
    else:
        check, sent = _run_business(case, roles, url, timeout, client, identifier, findings)
    result["checks"].append(check)
    return result, sent


def validate_contract(data, *, timeout=5.0, fetch=None, verify_tls=True, proxy=None):
    """Run explicit low-impact GET contracts. Maximum 30 HTTP requests."""
    if not isinstance(data, dict) or data.get("schema") != "webchallscan/api-contract-v1":
        raise ValueError("invalid API contract schema")
    origin = data.get("origin")
    _validate_origin(origin)
    if not 0.2 <= timeout <= 15:
        raise ValueError("invalid timeout")
    roles = data.get("roles")
    _validate_roles(roles)
    cases = data.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 10:
        raise ValueError("provide 1-10 cases")
    estimated = sum({"idor": 2, "fuzz": 6, "business": 1}.get(case.get("kind"), 31)
                    if isinstance(case, dict) else 31 for case in cases)
    if estimated > 30:
        raise ValueError("request budget would exceed 30; split the contract")
    _preflight_contract_cases(cases, roles)
    # Reject unsafe proxy settings even when an injected test transport is used.
    from .http_client import validate_loopback_proxy
    validate_loopback_proxy(proxy)
    client = fetch or (lambda url, headers, timeout: _fetch(
        url, headers, timeout, verify_tls=verify_tls, proxy=proxy))
    requests = 0
    findings, results = [], []
    for index, case in enumerate(cases):
        result, sent = _run_case(case, f"case-{index+1}", origin, roles, timeout, client, findings)
        requests += sent
        if requests > 30:
            raise ValueError("request budget exceeded")
        results.append(result)
    return {"schema": "webchallscan/api-contract-results-v1", "origin": origin,
            "requests_sent": requests, "findings": findings, "cases": results,
            "limitations": ["GET only, no resource enumeration or state mutation.",
                            "Business checks validate declared HTTP invariants, not arbitrary workflows.",
                            "IDOR confirmation requires a caller-designated private marker and two roles."]}


def load_contract(path):
    f = Path(path)
    if f.stat().st_size > 200_000:
        raise ValueError("contract file too large")
    value = json.loads(f.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("contract must be an object")
    return value
