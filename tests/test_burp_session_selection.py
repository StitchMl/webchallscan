"""Select exact authorized Burp session request without leaking cookies."""
import base64
import json

import pytest

from webchallscan.burp_session import export_burp_session
from webchallscan.cli import main
from webchallscan.session import load_session_file


def history():
    def item(url, cookie):
        raw = ("GET /api/" + url.split("/api/", 1)[1] +
               " HTTP/1.1\r\nHost: lab.example\r\n"
               "Cookie: session=" + cookie + "\r\n\r\n")
        encoded = base64.b64encode(raw.encode()).decode()
        return ("<item><url>" + url + "</url><method>GET</method>"
                '<request base64="true">' + encoded + "</request></item>")
    return ("<?xml version='1.0'?><items>"
            + item("https://lab.example/api/a", "FIRSTPRIVATE")
            + item("https://lab.example/api/b", "SECONDPRIVATE")
            + item("https://lab.example/api/b", "THIRDPRIVATE")
            + "</items>")


def test_default_selection_remains_first(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "history.xml", tmp_path / "one.json"
    source.write_text(history())
    data = export_burp_session(str(source), str(dest), "https://lab.example")
    assert data["cookies_exported"] == 1
    assert data["selected_request_index"] == 1
    loaded = load_session_file(str(dest))
    assert loaded.url == "https://lab.example/api/a"
    assert loaded.cookies[0].value == "FIRSTPRIVATE"
    assert "FIRSTPRIVATE" not in repr(data)


def test_exact_path_and_index_select_specific_request(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "history.xml", tmp_path / "second.json"
    source.write_text(history())
    data = export_burp_session(str(source), str(dest), "https://lab.example",
                               request_path="/api/b", request_index=2)
    loaded = load_session_file(str(dest))
    assert loaded.url == "https://lab.example/api/b"
    assert loaded.cookies[0].value == "THIRDPRIVATE"
    assert data["selected_request_index"] == 2
    assert "THIRDPRIVATE" not in repr(data)


@pytest.mark.parametrize("path", ["/api/notfound", "//elsewhere", "/api/../a",
                                  "/api/%2f", "/api/a?token=x", "/api/a#fragment"])
def test_invalid_or_unmatched_path_never_creates_session_file(tmp_path, path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "history.xml", tmp_path / "secret.json"
    source.write_text(history())
    with pytest.raises(ValueError):
        export_burp_session(str(source), str(dest), "https://lab.example",
                            request_path=path)
    assert not dest.exists()


@pytest.mark.parametrize("index", [0, -1, 501, "2", True, 4])
def test_invalid_or_unmatched_request_index_refused(tmp_path, index, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "history.xml", tmp_path / "secret.json"
    source.write_text(history())
    with pytest.raises(ValueError):
        export_burp_session(str(source), str(dest), "https://lab.example",
                            request_path="/api/b", request_index=index)
    assert not dest.exists()


def test_cli_selected_session_and_flag_isolation(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "history.xml", tmp_path / "selected.json"
    source.write_text(history())
    arguments = [
        "--authorized", "--burp-session-from", str(source),
        "--burp-session-out", str(dest),
        "--expect-origin", "https://lab.example", "--allow-secret-export",
        "--burp-session-path", "/api/b", "--burp-session-index", "2",
    ]
    assert main(arguments) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["selected_request_index"] == 2
    assert "THIRDPRIVATE" not in output.out + output.err
    assert main(["--burp-session-path", "/api/a"]) == 2
    assert "require --burp-session-from" in capsys.readouterr().err
    assert main(["--burp-session-index", "2"]) == 2
    assert "require --burp-session-from" in capsys.readouterr().err
