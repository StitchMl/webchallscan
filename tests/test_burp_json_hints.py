"""Offline Burp JSON POST field hints are bounded, value-free and inert."""
import base64
import json
import xml.etree.ElementTree as ET

from webchallscan.burp_import import import_burp_xml
from webchallscan.burp_json_hints import json_string_field_hints


def _item(method="POST", body=None, content_type="application/json"):
    if body is None:
        body = {
            "input": "PRIVATE_INPUT", "profile": {"name": "VERYSECRET"},
            "csrf_token": "PRIVATE_CSRF", "authorization": "PRIVATE_AUTH",
            "credentials": {"nested": "PRIVATE_NESTED"},
            "arr": [{"field": "DONT_INCLUDE_ARRAY"}],
            "count": 14,
        }
    raw = (f"{method} /api/search HTTP/1.1\r\nHost: lab.example\r\n"
           f"Content-Type: {content_type}\r\n"
           f"Cookie: session=PRIVATECOOKIE\r\n\r\n").encode() + json.dumps(body).encode()
    encoded = base64.b64encode(raw).decode()
    return ET.fromstring(
        f'<item><url>https://lab.example/api/search</url>'
        f'<method>{method}</method><status>200</status>'
        f'<request base64="true">{encoded}</request></item>'
    )


def test_field_paths_from_json_post_never_reflect_secret_values():
    paths = json_string_field_hints(_item(), "POST")
    assert paths == [["input"], ["profile", "name"]]
    report = repr(paths)
    for secret in ("PRIVATE", "csrf_token", "authorization", "credentials",
                   "session", "DONT_INCLUDE_ARRAY"):
        assert secret not in report


def test_non_post_malformed_and_non_json_have_no_hints():
    assert json_string_field_hints(_item(method="PUT"), "PUT") == []
    assert json_string_field_hints(_item(content_type="text/plain"), "POST") == []
    assert json_string_field_hints(_item(body=[]), "POST") == []
    item = _item()
    item.find("request").text = "!!!notbase64"
    assert json_string_field_hints(item, "POST") == []


def test_limit_field_count_and_nested_depth():
    body = {f"field_{i}": "VALUE" for i in range(100)}
    assert len(json_string_field_hints(_item(body=body), "POST")) == 12
    nested = {"a": {"b": {"c": {"d": {"e": {"f": "NEVER"}}}}}}
    assert not json_string_field_hints(_item(body=nested), "POST")
    names = {"authorization": {"normal": "SECRET"}, "safe": {"token": "SECRET"},
             "valid": {"input": "SAFE"}}
    assert json_string_field_hints(_item(body=names), "POST") == [["valid", "input"]]


def test_burp_inventory_adds_only_paths_deduped_and_no_replays(tmp_path):
    root = ET.Element("items")
    root.append(_item())
    root.append(_item())
    file = tmp_path / "history.xml"
    file.write_bytes(ET.tostring(root))
    report = import_burp_xml(str(file), "https://lab.example")
    assert report["observed_requests"] == 2
    assert report["active_tests_executed"] == 0
    assert report["endpoints"][0]["json_fields"] == [["input"], ["profile", "name"]]
    assert "PRIVATE" not in json.dumps(report)
    assert "csrf_token" not in json.dumps(report)


def test_no_invented_json_fields_for_get_history(tmp_path):
    root = ET.Element("items")
    root.append(_item(method="GET"))
    file = tmp_path / "history.xml"
    file.write_bytes(ET.tostring(root))
    report = import_burp_xml(str(file), "https://lab.example")
    assert "json_fields" not in report["endpoints"][0]
