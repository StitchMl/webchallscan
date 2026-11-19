"""Session cookies cannot inject HTTP headers or expand scope through malformed input."""
import json

import pytest

from webchallscan.scanner import Scanner
from webchallscan.session import (
    BrowserSession, SessionCaptureError, SessionCookie,
    load_session_file, validate_session_cookie,
)


@pytest.mark.parametrize("field,value", [
    ("name", "sid\r\nX-Evil"),
    ("name", "sid;evil"),
    ("name", ""),
    ("value", "good\r\nX-Evil: injected"),
    ("value", "good;another=secret"),
    ("value", "unicode-\u2713"),
    ("domain", ".example..com"),
    ("domain", "example.com:8080"),
    ("path", "relative/path"),
    ("path", "/safe\r\nInjected: 1"),
    ("path", "/safe;ignored=true"),
])
def test_invalid_cookie_components_are_rejected(field, value):
    data = {"name": "sid", "value": "COOKIE_PRIVATE",
            "domain": ".lab.example", "path": "/account"}
    data[field] = value
    with pytest.raises(SessionCaptureError):
        validate_session_cookie(**data)


@pytest.mark.parametrize("attribute,value", [
    ("secure", "false"),
    ("httpOnly", 1),
    ("sameSite", False),
])
def test_session_file_rejects_non_boolean_security_attributes(tmp_path, attribute, value, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "session.json"
    cookie = {"name": "sid", "value": "PRIVATE", "domain": "lab.example",
              "path": "/", "secure": True, "httpOnly": True, "sameSite": "Lax"}
    cookie[attribute] = value
    file.write_text(json.dumps({"url": "https://lab.example", "cookies": [cookie]}))
    with pytest.raises(SessionCaptureError):
        load_session_file(str(file))


def test_session_file_rejects_cookie_header_injection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "session.json"
    file.write_text(json.dumps({"url": "https://lab.example", "cookies": [{
        "name": "sid", "value": "PRIVATE\r\nX-Evil: 1",
        "domain": "lab.example", "path": "/",
    }]}))
    with pytest.raises(SessionCaptureError):
        load_session_file(str(file))


def test_direct_session_import_uses_same_validation():
    session = BrowserSession(
        url="https://lab.example", cookies=(SessionCookie(
            name="sid", value="PRIVATE\r\nX-Evil: injected",
            domain="lab.example", path="/",
        ),),
    )
    with pytest.raises(SessionCaptureError):
        Scanner("https://lab.example", session=session)


def test_valid_scoped_cookie_still_loads_without_network(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "session.json"
    file.write_text(json.dumps({"url": "https://lab.example", "cookies": [{
        "name": "__Host-id", "value": "ABC123==",
        "domain": "lab.example", "path": "/", "secure": True,
        "httpOnly": True, "sameSite": "Lax",
    }]}))
    session = load_session_file(str(file))
    assert session.cookies[0].value == "ABC123=="
    scanner = Scanner("https://lab.example", session=session, max_requests=2)
    assert scanner.requests_sent == 0
    assert len(list(scanner.cookies)) == 1


def test_session_file_rejects_oversize_before_json_parse(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "session.json"
    file.write_bytes(b" " * 2_000_001)
    with pytest.raises(SessionCaptureError, match="exceeds 2 MB"):
        load_session_file(str(file))


def test_session_file_refuses_symlink_to_other_user_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    original = tmp_path / "real.json"
    original.write_text(json.dumps({"url": "https://lab.example", "cookies": []}))
    alias = tmp_path / "alias.json"
    alias.symlink_to(original)
    with pytest.raises(SessionCaptureError, match="regular file"):
        load_session_file(str(alias))
    assert load_session_file(str(original)).url == "https://lab.example"


def test_session_file_rejects_non_regular_and_invalid_utf8(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / "folder.json"
    directory.mkdir()
    with pytest.raises(SessionCaptureError, match="regular file"):
        load_session_file(str(directory))
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(bytes([255, 254]))
    with pytest.raises(SessionCaptureError, match="valid session JSON"):
        load_session_file(str(malformed))


def test_session_file_rejects_explicit_external_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "safe.json"
    source.write_text(json.dumps({"url": "https://lab.example", "cookies": []}))
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    with pytest.raises(SessionCaptureError, match="working directory"):
        load_session_file(str(source))
