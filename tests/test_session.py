from __future__ import annotations

import json
import contextlib
import io
import queue
import threading
import time
from urllib.request import Request, urlopen

import pytest

from webchallscan.session import SessionCaptureError, listen_for_extension, load_session_file, parse_extension_session


def extension_payload(url="https://challenge.example/account?token=secret-query"):
    return {
        "schema": "webchallscan/browser-session-v1",
        "active_tab": {
            "url": url,
            "origin": "https://challenge.example",
            "incognito": False,
        },
        "browser": {
            "user_agent": "Browser/1.0",
            "accept_language": "en-US",
            "platform": "Win32",
            "mobile": False,
        },
        "cookies": [{
            "name": "session",
            "value": "secret-cookie",
            "domain": "challenge.example",
            "path": "/",
            "secure": True,
            "http_only": True,
            "same_site": "lax",
            "session": True,
            "expiration_date": None,
            "store_id": "0",
            "partition_key": {
                "top_level_site": "https://challenge.example",
                "has_cross_site_ancestor": False,
            },
        }],
    }


def test_extension_session_preserves_active_url_and_http_only_cookie():
    session = parse_extension_session(extension_payload())
    assert session.url.endswith("/account?token=secret-query")
    assert session.profile == "desktop"
    assert session.cookies[0].value == "secret-cookie"
    assert session.cookies[0].http_only is True
    assert dict(session.headers)["User-Agent"] == "Browser/1.0"


def test_session_file_accepts_extension_contract(tmp_path):
    path = tmp_path / "session.json"
    path.write_text(json.dumps(extension_payload()), encoding="utf-8")
    assert load_session_file(str(path)).source == "session-file"


def test_session_rejects_credentials_in_url():
    payload = extension_payload("https://user:password@challenge.example/account")
    payload["active_tab"]["origin"] = "https://challenge.example"
    with pytest.raises(SessionCaptureError):
        parse_extension_session(payload)


def test_one_shot_extension_listener_accepts_contract(monkeypatch):
    monkeypatch.setattr("webchallscan.session.secrets.token_urlsafe", lambda _: "A" * 43)
    stderr = io.StringIO()
    result = queue.Queue()

    def listen():
        try:
            with contextlib.redirect_stderr(stderr):
                result.put(listen_for_extension(3.0))
        except Exception as exc:  # pragma: no cover - surfaced by assertion below
            result.put(exc)

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    endpoint = ""
    for _ in range(100):
        text = stderr.getvalue()
        if "Session endpoint: " in text:
            endpoint = text.split("Session endpoint: ", 1)[1].splitlines()[0]
            break
        time.sleep(0.01)
    assert endpoint
    body = json.dumps(extension_payload()).encode()
    request = Request(endpoint, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Webchallscan-Token": "A" * 43,
    })
    with urlopen(request, timeout=2) as response:
        assert response.status == 204
    thread.join(2)
    captured = result.get_nowait()
    assert not isinstance(captured, Exception)
    assert captured.cookies[0].name == "session"

