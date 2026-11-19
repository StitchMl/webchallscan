"""Bounded, read-only CDP network inventory. Never stores payloads or credentials."""
from __future__ import annotations

import json
import socket
import time
from urllib.parse import parse_qsl, urlsplit

from .posture import inspect_response
from .session import (
    _CDP,
    SessionCaptureError,
    _json_get,
    _loopback_url,
    _valid_http_url,
)


def _safe_request(method: object, url: object, origin: tuple[str, str]) -> dict[str, object] | None:
    if not isinstance(method, str) or not isinstance(url, str):
        return None
    try:
        p = urlsplit(url)
        if (p.scheme.lower(), p.netloc.lower()) != origin:
            return None
        if p.username or p.password:
            return None
        # Query values may contain credentials: retain only parameter names.
        names = sorted({k[:100] for k, _ in parse_qsl(p.query, keep_blank_values=True)})[:100]
        return {"method": method.upper()[:16], "path": p.path or "/", "parameters": names}
    except ValueError:
        return None


def _tab_facts(item: dict) -> dict | None:
    """Return focus/visibility facts for a CDP page target, or None if unreadable."""
    try:
        _valid_http_url(item.get("url"))
        client = _CDP(str(item["webSocketDebuggerUrl"]), 2.0)
        try:
            state = client.call("Runtime.evaluate", {
                "expression": "JSON.stringify({focus:document.hasFocus(),visible:document.visibilityState==='visible'})",
                "returnByValue": True,
            })
            return json.loads(state.get("result", {}).get("value", "{}"))
        finally:
            client.close()
    except (KeyError, ValueError, OSError):
        return None


def _foreground_tab(targets: list) -> dict:
    selected = []
    visible = []
    for item in targets:
        if not isinstance(item, dict) or item.get("type") != "page":
            continue
        facts = _tab_facts(item)
        if facts is None:
            continue
        if facts.get("focus"):
            selected.append(item)
        if facts.get("visible"):
            visible.append(item)
    candidates = selected if len(selected) == 1 else visible
    if len(candidates) != 1:
        raise SessionCaptureError("cannot identify a unique foreground HTTP(S) tab; close other browser windows or focus the test tab")
    return candidates[0]


class _Observation:
    """Mutable state for one bounded CDP observation window."""

    def __init__(self, origin: tuple[str, str]) -> None:
        self.origin = origin
        self.inflight: dict[str, dict[str, object]] = {}
        self.observations: dict[tuple[str, str, tuple[str, ...]], dict[str, object]] = {}
        self.counted = 0
        self.posture_findings: dict[tuple[str, str, str], dict[str, str]] = {}

    def on_request(self, data: dict) -> None:
        request = data.get("request", {})
        if not isinstance(request, dict):
            return
        item = _safe_request(request.get("method"), request.get("url"), self.origin)
        if item is None:
            return
        self.counted += 1
        item["type"] = str(data.get("type") or "Other")[:30]
        self.inflight[str(data.get("requestId", ""))] = item
        identity = (str(item["method"]), str(item["path"]), tuple(item["parameters"]))
        observed = self.observations.setdefault(identity, {
            **item, "statuses": [], "count": 0,
        })
        observed["count"] = int(observed["count"]) + 1

    def on_response(self, data: dict) -> None:
        item = self.inflight.get(str(data.get("requestId", "")))
        response = data.get("response", {})
        if item is None or not isinstance(response, dict):
            return
        identity = (str(item["method"]), str(item["path"]), tuple(item["parameters"]))
        status = response.get("status")
        if not isinstance(status, (int, float)) or isinstance(status, bool):
            return
        statuses = self.observations[identity]["statuses"]
        code = int(status)
        if code not in statuses:
            statuses.append(code)
        raw_headers = response.get("headers", {})
        if isinstance(raw_headers, dict):
            for issue in inspect_response(
                str(item["method"]), str(item["path"]), str(item["type"]),
                code, raw_headers, self.origin[0] == "https"
            ):
                self.posture_findings[(issue["rule"], issue["method"], issue["path"])] = issue

    def on_event(self, event: object) -> None:
        if not isinstance(event, dict):
            return
        kind, data = event.get("method"), event.get("params", {})
        if not isinstance(data, dict):
            return
        if kind == "Network.requestWillBeSent":
            self.on_request(data)
        elif kind == "Network.responseReceived":
            self.on_response(data)
        elif kind in {"Network.loadingFinished", "Network.loadingFailed"}:
            self.inflight.pop(str(data.get("requestId", "")), None)


def observe_cdp(endpoint: str, seconds: float = 20.0, limit: int = 500) -> dict[str, object]:
    """Observe the single focused same-origin CDP page while the operator navigates."""
    _loopback_url(endpoint, {"http", "https"})
    if not 1 <= seconds <= 300 or not 1 <= limit <= 10000:
        raise SessionCaptureError("observation requires 1-300 seconds and 1-10000 events")
    endpoint = endpoint.rstrip("/")
    try:
        targets = _json_get(endpoint + "/json/list", 3.0)
    except (OSError, ValueError) as exc:
        raise SessionCaptureError("cannot enumerate local CDP tabs") from exc
    if not isinstance(targets, list):
        raise SessionCaptureError("invalid CDP targets")
    tab = _foreground_tab(targets)
    target = _valid_http_url(tab["url"])
    p = urlsplit(target)
    origin = (p.scheme.lower(), p.netloc.lower())
    client = _CDP(str(tab["webSocketDebuggerUrl"]), 1.0)
    state = _Observation(origin)
    try:
        client.call("Network.enable", {"maxTotalBufferSize": 0, "maxResourceBufferSize": 0})
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and state.counted < limit:
            try:
                event = client.ws.recv_json()
            except socket.timeout:
                continue
            state.on_event(event)
    finally:
        client.close()
    observations = state.observations
    posture_findings = state.posture_findings
    counted = state.counted
    return {
        "schema": "webchallscan/network-inventory-v1",
        "origin": f"{origin[0]}://{origin[1]}",
        "observed_requests": counted,
        "endpoints": [
            {**value, "statuses": sorted(value["statuses"])}
            for _, value in sorted(observations.items())
        ],
        "passive_findings": [posture_findings[k] for k in sorted(posture_findings)],
        "limitations": [
            "Only traffic emitted after observation starts is visible.",
            "No request or response bodies, headers, cookies or query values are recorded.",
            "Findings are passive policy observations, not verified exploitable vulnerabilities.",
            "No active probes or automatic request replay are performed.",
        ],
    }
