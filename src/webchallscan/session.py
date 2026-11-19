from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, ProxyHandler, build_opener

from .http_client import NoRedirect

SAFE_HEADERS = {"user-agent", "accept-language"}
COMMON_CDP_ENDPOINTS = {
    "chrome": ("http://127.0.0.1:9222", "http://127.0.0.1:9229"),
    "edge": ("http://127.0.0.1:9223", "http://127.0.0.1:9333"),
}


class SessionCaptureError(ValueError):
    pass


@dataclass(frozen=True)
class SessionCookie:
    name: str
    value: str = field(repr=False)
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    expires: int | None = None


@dataclass(frozen=True)
class BrowserSession:
    url: str
    cookies: tuple[SessionCookie, ...] = field(default_factory=tuple, repr=False)
    headers: tuple[tuple[str, str], ...] = field(default_factory=tuple, repr=False)
    profile: str = "desktop"
    source: str = "browser-session"


def _json_get(url: str, timeout: float) -> Any:
    """Read only a bounded local CDP JSON endpoint without redirect/proxy leaks."""
    _loopback_url(url, {"http", "https"})
    parsed = urlsplit(url)
    if parsed.fragment or parsed.username or parsed.password:
        raise SessionCaptureError("invalid local CDP JSON endpoint")
    request = Request(url, headers={"Accept": "application/json", "Cache-Control": "no-store"})
    # Ignore HTTP_PROXY/HTTPS_PROXY and NO_PROXY from the environment. Never
    # follow a redirect to an external site with local browser context.
    opener = build_opener(ProxyHandler({}), NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(2_000_001)
    except OSError as exc:
        raise SessionCaptureError("cannot read local CDP JSON endpoint") from exc
    if len(raw) > 2_000_000:
        raise SessionCaptureError("CDP JSON response exceeds 2 MB")
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise SessionCaptureError("invalid local CDP JSON response") from exc


def _loopback_url(value: str, schemes: set[str]) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password:
        raise SessionCaptureError("CDP endpoint must be an unauthenticated loopback URL")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    if not loopback:
        raise SessionCaptureError("CDP endpoint must use 127.0.0.1, ::1, or localhost")


class _WebSocket:
    """Small RFC 6455 client for local CDP JSON-RPC endpoints."""

    def __init__(self, url: str, timeout: float) -> None:
        _loopback_url(url, {"ws", "wss"})
        parsed = urlsplit(url)
        if parsed.scheme not in {"ws", "wss"} or parsed.hostname is None:
            raise SessionCaptureError("CDP returned an invalid WebSocket endpoint")
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname) if parsed.scheme == "wss" else raw
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if any(ord(char) < 33 or ord(char) > 126 for char in path):
            self.close()
            raise SessionCaptureError("invalid CDP WebSocket request path")
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        try:
            self.sock.sendall(request.encode("ascii"))
            self._validate_upgrade(self._read_headers(), key)
        except (OSError, UnicodeEncodeError, SessionCaptureError):
            self.close()
            raise

    @staticmethod
    def _parse_upgrade_headers(response: bytes) -> dict[bytes, list[bytes]]:
        lines = response.split(b"\r\n")
        if not lines or not lines[0].startswith(b"HTTP/1.1 101 "):
            raise SessionCaptureError("CDP WebSocket upgrade was rejected")
        headers: dict[bytes, list[bytes]] = {}
        for line in lines[1:]:
            if not line:
                break
            name, separator, value = line.partition(b":")
            if not separator:
                raise SessionCaptureError("invalid CDP WebSocket upgrade headers")
            headers.setdefault(name.strip().lower(), []).append(value.strip())
        return headers

    @staticmethod
    def _header_tokens(headers: dict[bytes, list[bytes]], name: bytes) -> set[bytes]:
        return {token.strip().lower()
                for value in headers.get(name, [])
                for token in value.split(b",")}

    def _validate_upgrade(self, response: bytes, key: str) -> None:
        headers = self._parse_upgrade_headers(response)
        if (b"websocket" not in self._header_tokens(headers, b"upgrade")
                or b"upgrade" not in self._header_tokens(headers, b"connection")):
            raise SessionCaptureError("CDP WebSocket upgrade headers are incomplete")
        # RFC 6455 section 4.2.2 mandates SHA-1 of a public nonce and fixed GUID.
        # This is NOT password hashing, signing or security-grade hashing.
        handshake = (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        digest = hashlib.sha1(handshake, usedforsecurity=False).digest()
        expected = base64.b64encode(digest)
        accept = headers.get(b"sec-websocket-accept", [])
        if len(accept) != 1 or accept[0] != expected:
            raise SessionCaptureError("CDP WebSocket handshake validation failed")

    def _read_headers(self) -> bytes:
        # A single recv(4096) can consume the first WebSocket frame as well
        # as the upgrade response, losing that frame. Read only through CRLFCRLF.
        data = bytearray()
        while not data.endswith(b"\r\n\r\n") and len(data) < 65536:
            chunk = self.sock.recv(1)
            if not chunk:
                break
            data.extend(chunk)
        if not data.endswith(b"\r\n\r\n"):
            raise SessionCaptureError("CDP WebSocket upgrade headers are incomplete")
        return bytes(data)

    def _exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise SessionCaptureError("CDP WebSocket closed unexpectedly")
            data.extend(chunk)
        return bytes(data)

    def send_json(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        mask = os.urandom(4)
        length = len(data)
        header = bytearray([0x81])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.extend((0x80 | 126,)); header.extend(struct.pack("!H", length))
        else:
            header.extend((0x80 | 127,)); header.extend(struct.pack("!Q", length))
        encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
        self.sock.sendall(bytes(header) + mask + encoded)

    def _read_frame_header(self) -> tuple[int, int]:
        # Local debugging ports can still be occupied by untrusted services.
        # Validate each announced frame size *before* allocating/reading it.
        max_frame = 2_000_000
        first, second = self._exact(2)
        opcode, length = first & 0x0F, second & 0x7F
        complete = bool(first & 0x80)
        if first & 0x70:
            raise SessionCaptureError("CDP WebSocket uses unsupported frame extensions")
        if second & 0x80:
            raise SessionCaptureError("CDP WebSocket server frames must be unmasked")
        if length == 126:
            length = struct.unpack("!H", self._exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._exact(8))[0]
        if length > max_frame:
            raise SessionCaptureError("CDP WebSocket frame exceeds the 2 MB limit")
        if opcode in (0x8, 0x9, 0xA):
            if not complete or length > 125:
                raise SessionCaptureError("invalid CDP WebSocket control frame")
        elif opcode != 0x1 or not complete:
            # A fragmented or binary frame must not silently be processed
            # as JSON; CDP's JSON-RPC transport uses complete text frames.
            raise SessionCaptureError("unsupported CDP WebSocket data frame")
        return opcode, length

    @staticmethod
    def _decode_message(data: bytes) -> dict[str, Any]:
        try:
            message = json.loads(data.decode("utf-8"))
        except ValueError as exc:
            raise SessionCaptureError("invalid CDP WebSocket JSON response") from exc
        if not isinstance(message, dict):
            raise SessionCaptureError("CDP WebSocket JSON response must be an object")
        return message

    def recv_json(self) -> dict[str, Any]:
        while True:
            opcode, length = self._read_frame_header()
            data = self._exact(length)
            if opcode == 0x8:
                raise SessionCaptureError("CDP WebSocket closed unexpectedly")
            if opcode == 0x9:
                self._send_control(0xA, data)
                continue
            if opcode == 0xA:
                continue
            return self._decode_message(data)

    def _send_control(self, opcode: int, data: bytes) -> None:
        mask = os.urandom(4)
        encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(data)]) + mask + encoded)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


class _CDP:
    def __init__(self, websocket_url: str, timeout: float) -> None:
        self.ws = _WebSocket(websocket_url, timeout)
        self.next_id = 1

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        call_id = self.next_id
        self.next_id += 1
        self.ws.send_json({"id": call_id, "method": method, "params": params or {}})
        while True:
            message = self.ws.recv_json()
            if message.get("id") != call_id:
                continue
            if "error" in message:
                raise SessionCaptureError(f"CDP method {method} failed")
            result = message.get("result", {})
            return result if isinstance(result, dict) else {}

    def close(self) -> None:
        self.ws.close()


def _valid_http_url(value: object) -> str:
    if not isinstance(value, str):
        raise SessionCaptureError("session URL must be a string")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise SessionCaptureError("session URL must be an absolute HTTP(S) URL")
    return value


_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_COOKIE_DOMAIN = re.compile(r"^\.?[A-Za-z0-9.-]{1,253}$")


def validate_session_cookie(name: str, value: str,
                            domain: str = "", path: str = "/") -> None:
    """Reject cookie scope/header injection before constructing HTTP cookies."""
    if not isinstance(name, str) or not _COOKIE_NAME.fullmatch(name):
        raise SessionCaptureError("invalid cookie name")
    if (not isinstance(value, str) or len(value) > 4096
            or any(ord(ch) < 32 or ord(ch) > 126 or ch == ";" for ch in value)):
        raise SessionCaptureError("invalid cookie value")
    if (not isinstance(domain, str)
            or (domain and (not _COOKIE_DOMAIN.fullmatch(domain)
                            or ".." in domain or domain.endswith(".")))):
        raise SessionCaptureError("invalid cookie domain")
    if (not isinstance(path, str) or not path.startswith("/")
            or len(path) > 2048
            or any(ord(ch) < 32 or ord(ch) > 126 or ch == ";" for ch in path)):
        raise SessionCaptureError("invalid cookie path")


_COOKIE_FIELDS = {"name", "value", "domain", "path", "secure", "httpOnly", "sameSite", "expires"}


def _parse_cookie(item: object) -> SessionCookie:
    if not isinstance(item, dict) or set(item) - _COOKIE_FIELDS or not {"name", "value"} <= set(item):
        raise SessionCaptureError("each cookie needs name/value and only documented fields")
    if not isinstance(item["name"], str) or not isinstance(item["value"], str):
        raise SessionCaptureError("cookie name and value must be strings")
    validate_session_cookie(item["name"], item["value"],
                            item.get("domain", ""), item.get("path", "/"))
    if (type(item.get("secure", False)) is not bool
            or type(item.get("httpOnly", False)) is not bool
            or not isinstance(item.get("sameSite", ""), str)):
        raise SessionCaptureError("invalid cookie security attributes")
    expires = item.get("expires")
    if expires is not None and not isinstance(expires, (int, float)):
        raise SessionCaptureError("cookie expires must be a number or null")
    return SessionCookie(
        name=item["name"], value=item["value"], domain=str(item.get("domain", "")),
        path=str(item.get("path", "/")), secure=bool(item.get("secure", False)),
        http_only=bool(item.get("httpOnly", False)), same_site=str(item.get("sameSite", "")),
        expires=int(expires) if expires and expires > 0 else None,
    )


def _parse_cookies(value: object) -> tuple[SessionCookie, ...]:
    if not isinstance(value, list) or len(value) > 500:
        raise SessionCaptureError("cookies must be a JSON array with at most 500 entries")
    return tuple(_parse_cookie(item) for item in value)


def _safe_headers(value: object) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise SessionCaptureError("headers must be a string-to-string JSON object")
    if any(name.lower() not in SAFE_HEADERS for name in value):
        raise SessionCaptureError("only User-Agent and Accept-Language session headers are accepted")
    return tuple(sorted(value.items(), key=lambda item: item[0].lower()))


def load_session_file(path: str) -> BrowserSession:
    file = Path(path)
    try:
        if file.stat().st_size > 2_000_000:
            raise SessionCaptureError("session file exceeds 2 MB")
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionCaptureError("cannot read a valid session JSON file") from exc
    if isinstance(data, dict) and data.get("schema") == "webchallscan/browser-session-v1":
        return parse_extension_session(data, "session-file")
    allowed = {"url", "cookies", "headers", "profile"}
    if not isinstance(data, dict) or set(data) - allowed or "url" not in data:
        raise SessionCaptureError("session file must contain url and only documented fields")
    profile = data.get("profile", "desktop")
    if profile not in {"desktop", "mobile"}:
        raise SessionCaptureError("session profile must be desktop or mobile")
    return BrowserSession(
        url=_valid_http_url(data["url"]), cookies=_parse_cookies(data.get("cookies", [])),
        headers=_safe_headers(data.get("headers")), profile=profile, source="session-file",
    )


_EXTENSION_COOKIE_FIELDS = {"name", "value", "domain", "path", "secure", "http_only", "same_site", "session", "expiration_date", "store_id", "partition_key"}


def _check_extension_tab(tab: object) -> str:
    if not isinstance(tab, dict) or set(tab) != {"url", "origin", "incognito"}:
        raise SessionCaptureError("active_tab has an invalid shape")
    url = _valid_http_url(tab.get("url"))
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if tab.get("origin") != origin or not isinstance(tab.get("incognito"), bool):
        raise SessionCaptureError("active_tab origin or incognito value is invalid")
    return url


def _check_extension_browser(browser: object) -> None:
    if not isinstance(browser, dict) or set(browser) != {"user_agent", "accept_language", "platform", "mobile"}:
        raise SessionCaptureError("browser context has an invalid shape")
    if any(not isinstance(browser[key], str) for key in ("user_agent", "accept_language", "platform")) or not isinstance(browser["mobile"], bool):
        raise SessionCaptureError("browser context values have invalid types")


def _check_partition_key(partition: object) -> None:
    if partition is None:
        return
    if not isinstance(partition, dict) or set(partition) != {"top_level_site", "has_cross_site_ancestor"}:
        raise SessionCaptureError("browser cookie partition key is invalid")
    if not isinstance(partition["top_level_site"], str) or not isinstance(partition["has_cross_site_ancestor"], bool):
        raise SessionCaptureError("browser cookie partition key values are invalid")


def _check_extension_cookie(raw: object) -> None:
    if not isinstance(raw, dict) or set(raw) != _EXTENSION_COOKIE_FIELDS:
        raise SessionCaptureError("browser cookie has an invalid shape")
    _check_partition_key(raw["partition_key"])
    if any(not isinstance(raw[key], str) for key in ("name", "value", "domain", "path", "same_site", "store_id")):
        raise SessionCaptureError("browser cookie string fields are invalid")
    if any(not isinstance(raw[key], bool) for key in ("secure", "http_only", "session")):
        raise SessionCaptureError("browser cookie boolean fields are invalid")
    expiry = raw["expiration_date"]
    if expiry is not None and not isinstance(expiry, (int, float)):
        raise SessionCaptureError("browser cookie expiration is invalid")


def _normalize_extension_cookies(cookies: object) -> list[dict[str, Any]]:
    if not isinstance(cookies, list) or len(cookies) > 500:
        raise SessionCaptureError("cookies must be an array with at most 500 entries")
    normalized = []
    seen = set()
    for raw in cookies:
        _check_extension_cookie(raw)
        key = (raw["name"], raw["domain"], raw["path"], raw["store_id"],
               json.dumps(raw["partition_key"], sort_keys=True))
        if key in seen:
            raise SessionCaptureError("browser session contains duplicate cookies")
        seen.add(key)
        normalized.append({
            "name": raw["name"], "value": raw["value"], "domain": raw["domain"],
            "path": raw["path"], "secure": raw["secure"], "httpOnly": raw["http_only"],
            "sameSite": raw["same_site"], "expires": raw["expiration_date"],
        })
    return normalized


def parse_extension_session(data: object, source: str = "browser-extension") -> BrowserSession:
    if not isinstance(data, dict) or set(data) != {"schema", "active_tab", "browser", "cookies"}:
        raise SessionCaptureError("browser session object has an invalid top-level shape")
    if data.get("schema") != "webchallscan/browser-session-v1":
        raise SessionCaptureError("unsupported browser session schema")
    tab, browser, cookies = data["active_tab"], data["browser"], data["cookies"]
    url = _check_extension_tab(tab)
    _check_extension_browser(browser)
    normalized = _normalize_extension_cookies(cookies)
    headers = {}
    if browser["user_agent"]:
        headers["User-Agent"] = browser["user_agent"]
    if browser["accept_language"]:
        headers["Accept-Language"] = browser["accept_language"]
    return BrowserSession(
        url=url, cookies=_parse_cookies(normalized), headers=_safe_headers(headers),
        profile="mobile" if browser["mobile"] else "desktop", source=source,
    )


def listen_for_extension(timeout: float = 120.0) -> BrowserSession:
    token = secrets.token_urlsafe(32)
    state: dict[str, BrowserSession] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/v1/session/import" or self.headers.get("X-Webchallscan-Token") != token:
                self.send_error(403); return
            if self.headers.get_content_type() != "application/json":
                self.send_error(415); return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if length < 0 or length > 2_000_000:
                    raise SessionCaptureError("invalid browser session body size")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                state["session"] = parse_extension_session(payload)
            except ValueError:
                self.send_error(400); return
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, *_: object) -> None:
            # Stay silent: request logging would echo the one-shot token endpoint traffic.
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    deadline = time.monotonic() + max(0.1, timeout)
    print(f"Session endpoint: http://127.0.0.1:{server.server_port}/v1/session/import", file=sys.stderr, flush=True)
    print(f"One-shot token: {token}", file=sys.stderr, flush=True)
    try:
        while "session" not in state:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            server.timeout = remaining
            server.handle_request()
    finally:
        server.server_close()
    if "session" not in state:
        raise SessionCaptureError("no valid browser session was received before timeout")
    return state["session"]


def discover_cdp(browser: str, timeout: float = 0.6) -> str:
    names = ("chrome", "edge") if browser == "auto" else (browser,)
    for name in names:
        for endpoint in COMMON_CDP_ENDPOINTS[name]:
            try:
                version = _json_get(endpoint + "/json/version", timeout)
                if isinstance(version, dict) and version.get("webSocketDebuggerUrl"):
                    return endpoint
            except (OSError, ValueError):
                continue
    raise SessionCaptureError(
        "no debuggable Chrome/Edge session found; start the browser with --remote-debugging-port=9222 "
        "or pass --cdp http://127.0.0.1:PORT"
    )


def _probe_page_tab(index: int, target: object, timeout: float):
    """Return a ranked candidate tuple for a usable page tab, else None."""
    if not isinstance(target, dict) or target.get("type") != "page":
        return None
    try:
        url = _valid_http_url(target.get("url"))
        websocket = str(target["webSocketDebuggerUrl"])
        client = _CDP(websocket, timeout)
        state = client.call("Runtime.evaluate", {"expression": (
            "JSON.stringify({focus:document.hasFocus(),visibility:document.visibilityState,"
            "ua:navigator.userAgent,language:navigator.language})"), "returnByValue": True})
        raw = state.get("result", {}).get("value", "{}")
        facts = json.loads(raw) if isinstance(raw, str) else {}
        client.close()
        rank = (0 if facts.get("focus") else 1, 0 if facts.get("visibility") == "visible" else 1)
        return (rank, index, {**target, "url": url}, facts)
    except (KeyError, OSError, ValueError):
        return None


def _page_cookies(target: dict[str, Any], timeout: float) -> tuple[SessionCookie, ...]:
    client = _CDP(str(target["webSocketDebuggerUrl"]), timeout)
    try:
        raw_cookies = client.call("Network.getCookies", {"urls": [target["url"]]}).get("cookies", [])
    finally:
        client.close()
    return _parse_cookies([{
        key: item[key] for key in ("name", "value", "domain", "path", "secure", "httpOnly", "sameSite", "expires")
        if key in item
    } for item in raw_cookies if isinstance(item, dict)])


def capture_cdp_session(endpoint: str, timeout: float = 2.0) -> BrowserSession:
    _loopback_url(endpoint, {"http", "https"})
    endpoint = endpoint.rstrip("/")
    try:
        targets = _json_get(endpoint + "/json/list", timeout)
    except Exception as exc:
        raise SessionCaptureError("cannot query the local CDP endpoint") from exc
    if not isinstance(targets, list):
        raise SessionCaptureError("CDP target list is invalid")
    probed = (_probe_page_tab(index, target, timeout) for index, target in enumerate(targets))
    candidates = [candidate for candidate in probed if candidate is not None]
    if not candidates:
        raise SessionCaptureError("CDP exposes no accessible HTTP(S) page tabs")
    candidates.sort(key=lambda item: (item[0], item[1]))
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        raise SessionCaptureError("CDP cannot identify one active page; focus the challenge tab and retry")
    _, _, target, facts = candidates[0]
    cookies = _page_cookies(target, timeout)
    ua = facts.get("ua") if isinstance(facts.get("ua"), str) else ""
    language = facts.get("language") if isinstance(facts.get("language"), str) else ""
    headers = {}
    if ua:
        headers["User-Agent"] = ua
    if language:
        headers["Accept-Language"] = language
    mobile = bool(" mobile" in ua.lower() or "android" in ua.lower())
    return BrowserSession(
        url=str(target["url"]), cookies=cookies, headers=_safe_headers(headers),
        profile="mobile" if mobile else "desktop", source="browser-session",
    )
