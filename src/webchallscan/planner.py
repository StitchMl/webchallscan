"""Deterministic, offline audit plan from a redacted CDP inventory.

Never replays traffic. Describes which evidence is available and which tests
require additional authorized context.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit


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
        if not isinstance(entry, dict):
            raise ValueError("invalid endpoint entry")
        method, path = entry.get("method"), entry.get("path")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path or "\\" in path:
            raise ValueError("unsafe or invalid inventory path")
        params = entry.get("parameters")
        if not isinstance(params, list) or any(not isinstance(p, str) for p in params):
            raise ValueError("invalid parameter names")
        resource_type = entry.get("type", "Other")
        categories = ["response-header-review"]
        if params:
            categories.append("input-validation-review")
        if path.lower().endswith("/graphql") or "graphql" in path.lower():
            categories.append("graphql-operation-discovery")
        if method != "GET":
            categories.append("manual-state-change-review")
        if any(marker in path.lower() for marker in ("password", "login", "session", "reset")):
            categories.append("authentication-flow-review")
        checks.append({
            "method": method, "path": path, "resource_type": str(resource_type)[:30],
            "parameter_names": sorted(set(params)),
            "checks": categories,
            "active_test_status": "not-executed",
            "reason": "Redacted inventory has no replayable request bodies, tokens, or baseline."
        })
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
    raw = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("inventory must be a JSON object")
    return raw
