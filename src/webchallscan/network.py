"""Bounded, read-only CDP network inventory. Never stores payloads or credentials."""
from __future__ import annotations

import json
import socket
import time
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from .session import _CDP, _json_get, _loopback_url, _valid_http_url, SessionCaptureError


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
    selected = []
    for item in targets:
        if not isinstance(item, dict) or item.get("type") != "page":
            continue
        try:
            url = _valid_http_url(item.get("url"))
            client = _CDP(str(item["webSocketDebuggerUrl"]), 2.0)
            try:
                state = client.call("Runtime.evaluate", {
                    "expression": "JSON.stringify({focus:document.hasFocus(),visible:document.visibilityState==='visible'})",
                    "returnByValue": True,
                })
                facts = json.loads(state.get("result", {}).get("value", "{}"))
            finally:
                client.close()
            if facts.get("focus"):
                selected.append(item)
        except (KeyError, ValueError, OSError, SessionCaptureError, json.JSONDecodeError):
            continue
    if len(selected) != 1:
        raise SessionCaptureError("focus exactly one HTTP(S) tab before starting CDP observation")
    tab = selected[0]
    target = _valid_http_url(tab["url"])
    p = urlsplit(target)
    origin = (p.scheme.lower(), p.netloc.lower())
    client = _CDP(str(tab["webSocketDebuggerUrl"]), 1.0)
    inflight: dict[str, dict[str, object]] = {}
    observations: dict[tuple[str, str, tuple[str, ...]], dict[str, object]] = {}
    counted = 0
    try:
        client.call("Network.enable", {"maxTotalBufferSize": 0, "maxResourceBufferSize": 0})
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and counted < limit:
            try:
                event = client.ws.recv_json()
            except socket.timeout:
                continue
            if not isinstance(event, dict):
                continue
            kind, data = event.get("method"), event.get("params", {})
            if not isinstance(data, dict):
                continue
            if kind == "Network.requestWillBeSent":
                request = data.get("request", {})
                if not isinstance(request, dict):
                    continue
                item = _safe_request(request.get("method"), request.get("url"), origin)
                if item is None:
                    continue
                counted += 1
                item["type"] = str(data.get("type") or "Other")[:30]
                key = str(data.get("requestId", ""))
                inflight[key] = item
                identity = (str(item["method"]), str(item["path"]), tuple(item["parameters"]))
                observed = observations.setdefault(identity, {
                    **item, "statuses": [], "count": 0,
                })
                observed["count"] = int(observed["count"]) + 1
            elif kind == "Network.responseReceived":
                item = inflight.get(str(data.get("requestId", "")))
                response = data.get("response", {})
                if item is None or not isinstance(response, dict):
                    continue
                identity = (str(item["method"]), str(item["path"]), tuple(item["parameters"]))
                status = response.get("status")
                if isinstance(status, (int, float)) and not isinstance(status, bool):
                    statuses = observations[identity]["statuses"]
                    code = int(status)
                    if code not in statuses:
                        statuses.append(code)
            elif kind in {"Network.loadingFinished", "Network.loadingFailed"}:
                inflight.pop(str(data.get("requestId", "")), None)
    finally:
        client.close()
    return {
        "schema": "webchallscan/network-inventory-v1",
        "origin": f"{origin[0]}://{origin[1]}",
        "observed_requests": counted,
        "endpoints": [
            {**value, "statuses": sorted(value["statuses"])}
            for _, value in sorted(observations.items())
        ],
        "limitations": [
            "Only traffic emitted after observation starts is visible.",
            "No request or response bodies, headers, cookies or query values are recorded.",
            "No vulnerability testing or automatic request replay is performed.",
        ],
    }
