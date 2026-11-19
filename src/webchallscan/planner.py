"""Deterministic, offline audit plan from a redacted CDP inventory.

Never replays traffic. Describes which evidence is available and which tests
require additional authorized context.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit


_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}\Z")
_PRIVATE_FIELD = re.compile(
    r"password|passwd|secret|token|csrf|xsrf|auth|cookie|session|"
    r"key|bearer|credential|otp|nonce|signature|private", re.I,
)


def _safe_json_field_paths(candidate_fields: object) -> list[list[str]]:
    """Validate metadata paths only; never accept secret-bearing field names."""
    if not isinstance(candidate_fields, list) or len(candidate_fields) > 12:
        raise ValueError("invalid JSON field hints")
    result = []
    for names in candidate_fields:
        if not isinstance(names, list) or not 1 <= len(names) <= 5:
            raise ValueError("invalid nested JSON field hints")
        for name in names:
            if (not isinstance(name, str) or not _FIELD.fullmatch(name)
                    or _PRIVATE_FIELD.search(name)):
                raise ValueError("unsafe JSON field name")
        result.append(names)
    return result


def _review_categories(method: str, path: str, params: list[str],
                       fields: list[list[str]]) -> list[str]:
    categories = ["response-header-review"]
    if fields and method == "POST":
        categories.append("manual-json-body-field-review")
    if params:
        categories.append("input-validation-review")
    if "graphql" in path.lower():
        categories.append("graphql-operation-discovery")
    if method != "GET":
        categories.append("manual-state-change-review")
    if any(marker in path.lower() for marker in ("password", "login", "session", "reset")):
        categories.append("authentication-flow-review")
    return categories


def _plan_endpoint(entry: object) -> dict:
    """Validate and summarize one endpoint without generating any request."""
    if not isinstance(entry, dict):
        raise ValueError("invalid endpoint entry")
    method, path = entry.get("method"), entry.get("path")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path or "\\" in path:
        raise ValueError("unsafe or invalid inventory path")
    params = entry.get("parameters")
    if not isinstance(params, list) or any(not isinstance(p, str) for p in params):
        raise ValueError("invalid parameter names")
    resource_type = entry.get("type", "Other")
    # Retain *names only* from the already-redacted inventory.
    # Untrusted inventory files cannot inject raw JSON values into plans.
    fields = _safe_json_field_paths(entry.get("json_fields", []))
    categories = _review_categories(method, path, params, fields)
    return {
        "method": method, "path": path, "resource_type": str(resource_type)[:30],
        "parameter_names": sorted(set(params)),
        "json_field_paths": sorted(fields) if method == "POST" else [],
        "checks": categories,
        "active_test_status": "not-executed",
        "reason": "Redacted inventory has no replayable request bodies, tokens, or baseline."
    })


def plan_inventory(data: dict, expected_origin: str | None = None) -> dict:
    if data.get("schema") != "webchallscan/network-inventory-v1":
        raise ValueError("unsupported inventory schema")
    origin = data.get("origin")
    if not isinstance(origin, str):
        raise ValueError("inventory origin missing")
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("invalid inventory origin")
    if expected_origin is not None and expected_origin.rstrip("/") != origin.rstrip("/"):
        raise ValueError("inventory origin differs from explicitly selected target")
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, list) or len(endpoints) > 10000:
        raise ValueError("invalid inventory endpoints")
    checks = []
    for entry in endpoints:
        checks.append(_plan_endpoint(entry))
    checks.sort(key=lambda e: (e["path"], e["method"], e["parameter_names"]))
    return {
        "schema": "webchallscan/audit-plan-v1",
        "origin": origin,
        "endpoint_count": len(checks),
        "active_tests_executed": 0,
        "checks": checks,
        "limitations": [
            "Planning only: no HTTP requests or payloads were sent.",
            "POST/GraphQL operations need schema and baseline context before safe validation.",
            "Zero confirmed findings is not evidence of security."
        ]
    }


def load_inventory(path: str) -> dict:
    file = Path(path)
    if file.stat().st_size > 5_000_000:
        raise ValueError("inventory too large")
    raw = json.loads(file.read_text(encoding="utf-8"))  # NOSONAR: reads a local inventory file the user passes on the CLI
    if not isinstance(raw, dict):
        raise ValueError("inventory must be a JSON object")
    return raw


def inventory_get_urls(data: dict, target: str, limit: int = 20) -> tuple[str, ...]:
    """Build safe GET discovery seeds from an existing redacted inventory.

    This never reconstructs captured parameter values or replays methods
    other than GET. The scanner still enforces its own page/request budgets.
    """
    parsed = urlsplit(target)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password):
        raise ValueError("target must be an absolute HTTP(S) URL")
    expected = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    plan_inventory(data, expected)
    if not 1 <= limit <= 100:
        raise ValueError("inventory route limit must be 1-100")
    routes: set[str] = set()
    for entry in data["endpoints"]:
        if entry["method"] != "GET":
            continue
        path = entry["path"]
        # Avoid reconstructing paths with traversal, encodings or controls.
        if (not path.startswith("/") or path.startswith("//")
                or "%" in path or ".." in path
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)):
            continue
        params = entry["parameters"]
        if len(params) > 12 or any(
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,59}", name)
            for name in params
        ):
            continue
        query = urlencode([(name, "WCSBASE") for name in sorted(set(params))])
        routes.add(urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(),
                              path, query, "")))
    return tuple(sorted(routes)[:limit])
