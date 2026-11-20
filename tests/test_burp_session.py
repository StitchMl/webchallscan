import base64
import json
import os

import pytest

from webchallscan.burp_session import export_burp_session
from webchallscan.cli import main
from webchallscan.session import load_session_file


def burp_xml():
    def entry(url, method, request):
        encoded = base64.b64encode(request.encode()).decode()
        return f"""<item><url>{url}</url><method>{method}</method>
        <request base64="true">{encoded}</request></item>"""
    return ("<?xml version='1.0'?><items>" +
        entry("https://external.example/private", "GET",
              "GET /private HTTP/1.1\r\nCookie: evil=OTHER\r\n\r\n") +
        entry("https://lab.example/api/write", "POST",
              "POST /api/write HTTP/1.1\r\nCookie: write=SECRET\r\n\r\n") +
        entry("https://lab.example/api/account", "GET",
              "GET /api/account HTTP/1.1\r\nHost: lab.example\r\n"
              "Cookie: session=VERYPRIVATE; theme=dark\r\n"
              "Authorization: Bearer MUST_NOT_EXPORT\r\n\r\n") +
        "</items>")


def test_burp_session_export_private_scope_and_loader_compat(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "burp.xml", tmp_path / "session.json"
    source.write_text(burp_xml())
    result = export_burp_session(str(source), str(dest), "https://lab.example")
    assert result["cookies_exported"] == 2
    assert "VERYPRIVATE" not in repr(result)
    assert "MUST_NOT_EXPORT" not in repr(result)
    assert dest.exists()
    if os.name == "posix":
        assert (dest.stat().st_mode & 0o777) == 0o600
    loaded = load_session_file(str(dest))
    assert loaded.url == "https://lab.example/api/account"
    assert {c.name for c in loaded.cookies} == {"session", "theme"}
    assert all(c.domain == "lab.example" and c.path == "/api/account"
               and c.secure for c in loaded.cookies)
    assert "MUST_NOT_EXPORT" not in dest.read_text()


def test_burp_session_rejects_overwrite_and_origin_mismatch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "burp.xml", tmp_path / "session.json"
    source.write_text(burp_xml())
    with pytest.raises(ValueError):
        export_burp_session(str(source), str(dest), "https://other.example")
    assert not dest.exists()
    export_burp_session(str(source), str(dest), "https://lab.example")
    with pytest.raises(FileExistsError):
        export_burp_session(str(source), str(dest), "https://lab.example")


def test_burp_session_cli_requires_explicit_secret_export(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source, dest = tmp_path / "burp.xml", tmp_path / "session.json"
    source.write_text(burp_xml())
    args = ["--burp-session-from", str(source), "--burp-session-out", str(dest),
            "--expect-origin", "https://lab.example", "--authorized"]
    assert main(args) == 2
    assert not dest.exists()
    assert main(args + ["--allow-secret-export"]) == 0
    visible = capsys.readouterr()
    response = json.loads(visible.out)
    assert response["session_file_created"] is True
    assert "VERYPRIVATE" not in visible.out + visible.err
    assert "MUST_NOT_EXPORT" not in visible.out + visible.err


def test_burp_session_rejects_dtd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "bad.xml"
    source.write_text('<!DOCTYPE items [<!ENTITY x "secret">]><items>&x;</items>')
    with pytest.raises(ValueError):
        export_burp_session(str(source), str(tmp_path / "session.json"),
                            "https://lab.example")


def test_session_export_refuses_input_outside_working_directory(
        tmp_path, monkeypatch, make_symlink):
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external = tmp_path / "outside.xml"
    external.write_text(burp_xml())
    monkeypatch.chdir(workspace)
    output = workspace / "private.json"
    for source in (str(external), "../outside.xml"):
        with pytest.raises(ValueError, match="working directory"):
            export_burp_session(source, str(output), "https://lab.example")
        assert not output.exists()
    symlink = workspace / "alias.xml"
    make_symlink(symlink, external)
    with pytest.raises(ValueError, match="working directory"):
        export_burp_session(str(symlink), str(output), "https://lab.example")
    assert not output.exists()


def test_session_export_rejects_non_xml_and_oversize_without_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "private.json"
    not_xml = tmp_path / "bad.txt"
    not_xml.write_text(burp_xml())
    with pytest.raises(ValueError, match="regular .xml"):
        export_burp_session(str(not_xml), str(output), "https://lab.example")
    oversized = tmp_path / "large.xml"
    oversized.write_bytes(b" " * 5_000_001)
    with pytest.raises(ValueError, match="5 MB"):
        export_burp_session(str(oversized), str(output), "https://lab.example")
    directory = tmp_path / "directory.xml"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular .xml"):
        export_burp_session(str(directory), str(output), "https://lab.example")
    assert not output.exists()
