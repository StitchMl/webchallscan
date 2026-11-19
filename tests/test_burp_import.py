import base64
import json

import pytest

from webchallscan.burp_import import import_burp_xml
from webchallscan.cli import main
from webchallscan.planner import plan_inventory


def _xml(response):
    encoded = base64.b64encode(response.encode()).decode()
    return f"""<?xml version="1.0"?>
<items burpVersion="2026.1">
  <item><url>https://lab.example/search?q=PRIVATE&amp;token=SECRET</url>
    <method>GET</method><status>200</status>
    <response base64="true">{encoded}</response>
  </item>
  <item><url>https://outside.example/account?password=PRIVATE</url>
    <method>POST</method><status>200</status></item>
  <item><url>https://lab.example/api/private</url>
    <method>POST</method><status>403</status></item>
</items>"""


def test_import_redacts_and_reuses_planner(tmp_path):
    path = tmp_path / "history.xml"
    path.write_text(_xml(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        "Set-Cookie: session=TOPSECRET\r\n\r\n<html>PRIVATE</html>"
    ))
    result = import_burp_xml(str(path), "https://lab.example")
    assert result["schema"] == "webchallscan/network-inventory-v1"
    assert result["observed_requests"] == 2
    assert result["skipped_items"] == 1
    assert result["endpoints"][0]["path"] == "/api/private"
    assert result["endpoints"][1]["parameters"] == ["q", "token"]
    assert {"HEADER-HSTS", "HEADER-CSP", "HEADER-FRAMING"} <= {
        item["rule"] for item in result["passive_findings"]
    }
    assert result["active_tests_executed"] == 0
    assert "PRIVATE" not in repr(result)
    assert "TOPSECRET" not in repr(result)
    plan = plan_inventory(result, "https://lab.example")
    assert plan["active_tests_executed"] == 0
    assert plan["endpoint_count"] == 2


def test_import_rejects_dtd_oversize_and_unexpected_root(tmp_path):
    file = tmp_path / "bad.xml"
    for raw in (
        '<!DOCTYPE items [<!ENTITY x "secret">]><items><item>&x;</item></items>',
        "<wrong><item/></wrong>",
    ):
        file.write_text(raw)
        with pytest.raises(ValueError):
            import_burp_xml(str(file))
    file.write_bytes(b" " * 5_000_001)
    with pytest.raises(ValueError):
        import_burp_xml(str(file))


def test_import_requires_valid_expected_origin(tmp_path):
    file = tmp_path / "history.xml"
    file.write_text(_xml("HTTP/1.1 200 OK\r\n\r\n"))
    with pytest.raises(ValueError):
        import_burp_xml(str(file), "file:///etc/passwd")
    report = import_burp_xml(str(file), "https://other.example")
    assert report["observed_requests"] == 1
    assert report["origin"] == "https://other.example"


def test_cli_burp_mode_is_offline_and_requires_authorization(tmp_path, capsys):
    file = tmp_path / "history.xml"
    file.write_text(_xml("HTTP/1.1 200 OK\r\n\r\n"))
    assert main(["--import-burp", str(file)]) == 2
    assert main(["--authorized", "--import-burp", str(file),
                 "--expect-origin", "https://lab.example"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["observed_requests"] == 2
    assert main(["https://lab.example", "--authorized", "--import-burp", str(file)]) == 2
