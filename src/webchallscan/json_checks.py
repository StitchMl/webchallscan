"""Explicit, bounded JSON API validation for authorized lab endpoints.

No auto-discovery, no credential/body output, and no redirects. Only cases
listed by the operator are requested. POSTs may mutate state: opt-in required.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
import ssl
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, Request, build_opener

from .http_client import NoRedirect, api_handlers, read_bounded
from .safe_files import read_input_file


SCHEMA = "webchallscan/json-cases-v1"
MAX_CASES = 6
MAX_REQUESTS = 24
MAX_BODY = 16_384
MAX_RESPONSE = 65_536
FIELDS = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
PROBE_SSTI = "{{7340*3}}"
PROBE_NOSQL = {"$ne": "WCS_NONMATCH_7340"}


def _send_json(url: str, body: dict, headers: dict[str, str], timeout: float,
               *, verify_tls: bool = True, proxy: str | None = None) -> dict:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_BODY:
        raise ValueError("JSON request exceeds 16 KiB")
    req = Request(url, method="POST", data=encoded, headers={
        **headers, "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    })
    handlers = api_handlers(verify_tls=verify_tls, proxy=proxy)
    res = read_bounded(build_opener(*handlers), req, timeout, MAX_RESPONSE + 1)
    if len(res.body) > MAX_RESPONSE:
        raise ValueError("JSON response exceeds 64 KiB")
    return {"status": res.status, "digest": sha256(res.body).hexdigest(),
            "body": res.body}


def _field_body(body: dict, path: list[str], replacement: object) -> dict:
    modified = deepcopy(body)
    current = modified
    for name in path[:-1]:
        current = current[name]
    current[path[-1]] = replacement
    return modified


def _signature(result: dict, values: list[str]) -> tuple[int, str]:
    """Ignore simple reflected input before differential comparisons."""
    payload = result["body"].decode("utf-8", "replace")
    for value in values:
        payload = payload.replace(value, "[INPUT]")
        # JSON string escaping may turn the probe into a quoted literal.
        payload = payload.replace(json.dumps(value)[1:-1], "[INPUT]")
    return (result["status"], sha256(payload.encode("utf-8")).hexdigest())


_HEADER_NAMES = frozenset({
    "authorization", "cookie", "x-api-key", "x-csrf-token",
    "x-xsrf-token", "x-csrftoken",
})


def _validate_origin(origin: object) -> str:
    if not isinstance(origin, str):
        raise ValueError("missing JSON case origin")
    parsed = urlsplit(origin)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.path or parsed.query
            or parsed.fragment):
        raise ValueError("origin must be an exact HTTP(S) origin")
    return origin


def _validate_headers(headers: object) -> None:
    if not isinstance(headers, dict) or any(
        not isinstance(k, str) or k.lower() not in _HEADER_NAMES
        or not isinstance(v, str) or len(v) > 4096
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in v)
        for k, v in headers.items()
    ):
        raise ValueError("JSON case headers may contain authentication and CSRF tokens only")


def _validate_target_field(body: dict, field: list) -> None:
    cursor = body
    try:
        for name in field[:-1]:
            cursor = cursor[name]
            if not isinstance(cursor, dict):
                raise ValueError("JSON field parent is not an object")
        original = cursor[field[-1]]
    except (KeyError, TypeError) as exc:
        raise ValueError("field must exist in the supplied body") from exc
    if not isinstance(original, str):
        raise ValueError("target field must be a string for baseline comparison")


def _prepare_case(item: object) -> tuple:
    if not isinstance(item, dict) or set(item) != {
        "path", "kind", "body", "field", "headers",
    }:
        raise ValueError("JSON case must define path/kind/body/field/headers")
    path, kind, body, field, headers = (item[key] for key in (
        "path", "kind", "body", "field", "headers"))
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or any(c in path for c in ("?", "#", "\\", "\r", "\n"))
            or "%" in path or ".." in path):
        raise ValueError("JSON case path must be a literal same-origin path")
    if kind not in {"ssti", "nosql"}:
        raise ValueError("JSON case kind must be ssti or nosql")
    if not isinstance(body, dict) or not isinstance(field, list) or not 1 <= len(field) <= 8:
        raise ValueError("JSON case requires object body and field name path")
    if not all(isinstance(name, str) and FIELDS.fullmatch(name) for name in field):
        raise ValueError("invalid JSON field names")
    _validate_headers(headers)
    _validate_target_field(body, field)
    if len(json.dumps(body, ensure_ascii=True)) > MAX_BODY:
        raise ValueError("JSON body exceeds input cap")
    return path, kind, body, field, headers


def _collect_samples(client, origin: str, path: str, body: dict, field: list,
                     headers: dict, timeout: float, probes: list[str]) -> list[dict]:
    samples = []
    for value in probes:
        mutated = _field_body(body, field, value)
        # Check size before sending, including oversized replacement.
        if len(json.dumps(mutated).encode("utf-8")) > MAX_BODY:
            raise ValueError("JSON probe exceeds request size limit")
        result = client(origin + path, mutated, headers, timeout)
        if not isinstance(result, dict) or not {
            "status", "digest", "body",
        }.issubset(result):
            raise ValueError("invalid JSON test response")
        samples.append(result)
    return samples


def _ssti_finding(samples: list[dict], number: int) -> dict | None:
    baseline, first, second = samples
    if (b"22020" in first["body"] and b"22020" in second["body"]
            and b"22020" not in baseline["body"]
            and first["status"] == second["status"]
            and first["digest"] == second["digest"]
            and b"22020" not in PROBE_SSTI.encode()):
        return {
            "rule": "API-JSON-SSTI-REVIEW", "case": number, "severity": "medium",
            "confidence": "medium", "status": "manual-validation-required",
            "evidence": "Repeated JSON arithmetic probe produced computed marker absent from baseline.",
        }
    return None


def _nosql_finding(samples: list[dict], number: int) -> dict | None:
    first, second, probe_a, probe_b = samples
    scalar = _signature(first, ["WCSBASE"])
    object_probe = _signature(probe_a, ["WCS_NONMATCH_7340"])
    if (scalar == _signature(second, ["WCSBASE"])
            and object_probe == _signature(probe_b, ["WCS_NONMATCH_7340"])
            and scalar != object_probe):
        return {
            "rule": "API-NOSQL-DIFFERENTIAL", "case": number, "severity": "info",
            "confidence": "low", "status": "manual-validation-required",
            "evidence": "Stable scalar/object response differential; schema/type validation may explain it.",
        }
    return None


def _run_case(client, origin: str, case: tuple, number: int, timeout: float,
              sent: int) -> tuple[dict, int, dict | None]:
    path, kind, body, field, headers = case
    probes = (
        ["WCSBASE", PROBE_SSTI, PROBE_SSTI]
        if kind == "ssti" else
        ["WCSBASE", "WCSBASE", PROBE_NOSQL, PROBE_NOSQL]
    )
    if sent + len(probes) > MAX_REQUESTS:
        raise ValueError("JSON request budget exceeded")
    samples = _collect_samples(client, origin, path, body, field, headers, timeout, probes)
    finding = (_ssti_finding if kind == "ssti" else _nosql_finding)(samples, number)
    outcome = "inconclusive"
    if finding:
        outcome = "arithmetic-observed" if kind == "ssti" else "differential-review"
    return ({"case": number, "path": path, "kind": kind,
             "field_names": field, "requests_sent": len(probes),
             "outcome": outcome}, len(samples), finding)


def run_json_cases(data: dict, *, timeout: float = 5.0,
                   verify_tls: bool = True, proxy: str | None = None, send=None) -> dict:
    from .http_client import validate_loopback_proxy
    validate_loopback_proxy(proxy)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("unsupported JSON case schema")
    origin = _validate_origin(data.get("origin"))
    cases = data.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("JSON cases must contain 1-6 explicit entries")
    if not isinstance(timeout, (float, int)) or not 0.2 <= timeout <= 15:
        raise ValueError("timeout must be 0.2-15 seconds")

    prepared = [_prepare_case(item) for item in cases]
    sent = 0
    findings = []
    outcomes = []
    client = send or (lambda url, body, headers, timeout: _send_json(
        url, body, headers, timeout, verify_tls=verify_tls, proxy=proxy))
    for number, case in enumerate(prepared, 1):
        outcome, sent_now, finding = _run_case(client, origin, case, number, timeout, sent)
        sent += sent_now
        if finding:
            findings.append(finding)
        outcomes.append(outcome)
    return {
        "schema": "webchallscan/json-results-v1", "origin": origin,
        "requests_sent": sent, "active_tests_executed": sent,
        "findings": findings, "cases": outcomes,
        "limitations": [
            "POST requests can mutate application state; only explicitly authorized test endpoints should be provided.",
            "No request/response bodies, credentials, or field values are returned.",
            "Differential JSON behavior does not prove NoSQL injection or unauthorized access.",
        ],
    }


def load_json_cases(path: str) -> dict:
    raw = read_input_file(path, "JSON case file", 200_000, "JSON case file is too large")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSON case file must contain an object")
    return data
