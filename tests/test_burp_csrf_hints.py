"""Burp request CSRF hints identify only known categories, never values."""
import base64
import json

from webchallscan.burp_import import import_burp_xml, _csrf_request_sources


def xml_export(path, method, raw):
    encoded = base64.b64encode(raw).decode()
    return ('<?xml version="1.0"?><items><item>'
            f'<url>https://lab.example{path}</url>'
            f'<method>{method}</method><status>200</status>'
            f'<request base64="true">{encoded}</request>'
            '</item></items>')


def form_request():
    return (b"POST /submit HTTP/1.1\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Cookie: session=PRIVATECOOKIE\r\n"
            b"X-CSRF-Token: VERYSECRET_HEADER\r\n\r\n"
            b"username=alice&csrf_token=PRIVATE-FORM-TOKEN")


def test_burp_form_marker_and_header_are_offline_and_redacted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "history.xml"
    file.write_text(xml_export("/submit", "POST", form_request()))
    result = import_burp_xml(str(file), "https://lab.example")
    hints = [f for f in result["passive_findings"]
             if f["rule"] == "BURP-CSRF-MARKER-001"]
    assert len(hints) == 1
    assert hints[0]["severity"] == "info"
    assert "form-field" in hints[0]["evidence"]
    assert "header" in hints[0]["evidence"]
    assert result["active_tests_executed"] == 0
    assert result["observed_requests"] == 1
    for secret in ("PRIVATECOOKIE", "PRIVATE-FORM-TOKEN", "VERYSECRET_HEADER",
                   "csrf_token", "alice"):
        assert secret not in repr(result)


def test_json_marker_presence_and_ordinary_field_absence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "history.xml"
    raw = (b"PATCH /api/edit HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
           b'{"csrf":"JSONVERYSECRET","payload":{"name":"PRIVATE"}}')
    file.write_text(xml_export("/api/edit", "PATCH", raw))
    result = import_burp_xml(str(file), "https://lab.example")
    hints = [f for f in result["passive_findings"] if f["rule"] == "BURP-CSRF-MARKER-001"]
    assert len(hints) == 1
    assert "json-field" in hints[0]["evidence"]
    assert "JSONVERYSECRET" not in repr(result)
    raw = (b"PATCH /api/edit HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
           b'{"session":"SECRET","payload":{"name":"PRIVATE"}}')
    file.write_text(xml_export("/api/edit", "PATCH", raw))
    assert not any(f["rule"] == "BURP-CSRF-MARKER-001"
                   for f in import_burp_xml(str(file), "https://lab.example")["passive_findings"])


def test_get_and_malformed_or_oversize_requests_are_never_csrf_confirmations(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import xml.etree.ElementTree as ET
    item = ET.fromstring(xml_export("/submit", "GET", form_request())).find("item")
    assert _csrf_request_sources(item, "GET") == ()
    body = form_request() + b"A" * 201_000
    file = tmp_path / "history.xml"
    file.write_text(xml_export("/submit", "POST", body))
    result = import_burp_xml(str(file), "https://lab.example")
    assert not any(f["rule"] == "BURP-CSRF-MARKER-001"
                   for f in result["passive_findings"])
    assert result["active_tests_executed"] == 0
