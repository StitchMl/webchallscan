"""Source map v3 metadata audit must stay offline, bounded and value-redacted."""
import json

import pytest

from webchallscan.cli import main
from webchallscan.source_map_audit import audit_source_map, audit_source_map_file
from webchallscan.structured_report import render_structured_text


def valid_map():
    return {
        "version": 3,
        "file": "SECRET-bundle.js",
        "sources": ["webpack://private/VERYSECRET/auth.ts",
                    "src/components/App.tsx",
                    "https://user:password@outside.example/private.css"],
        "sourcesContent": [
            "// TODO keep this secret\nconst password='VERYSECRET';",
            "// FIXME remove DEBUG before release",
            None,
        ],
        "mappings": "AAAA;AACA",
        "names": ["PRIVATE_FUNCTION"],
        "sourceRoot": "https://outside.example/PRIVATE",
    }


def test_offline_source_map_audit_only_reports_fixed_metadata():
    info = audit_source_map(valid_map())
    assert info["schema"] == "webchallscan/source-map-audit-v1"
    assert info["source_count"] == 3
    assert info["embedded_source_count"] == 2
    assert info["extension_categories"] == {"css": 1, "ts": 1, "tsx": 1}
    assert {"TODO", "FIXME", "DEBUG", "PASSWORD"} <= set(info["comment_hint_categories"])
    assert info["active_tests_executed"] == 0
    for secret in ("VERYSECRET", "PRIVATE_FUNCTION", "outside.example",
                   "auth.ts", "password", "SECRET-bundle.js"):
        assert secret not in repr(info)


def test_human_audit_view_is_redacted_and_readable():
    info = audit_source_map(valid_map())
    output = render_structured_text(info, "never")
    assert "OFFLINE SOURCE MAP AUDIT" in output
    assert "Sources: 3" in output
    assert "Embedded source contents: 2" in output
    assert "SOURCE TYPES" in output
    assert "VERYSECRET" not in output
    assert "\x1b[" not in output


def test_rejects_bad_source_map_structure():
    cases = [
        {"version": 2, "sources": []},
        {"version": 3, "sources": "private.js"},
        {"version": 3, "sources": ["a"], "sourcesContent": ["a", "b"]},
        {"version": 3, "sources": ["a"], "sourcesContent": [12]},
        {"version": 3, "sources": ["a"] * 501},
        {"version": 3, "sources": [], "mappings": 6},
    ]
    for data in cases:
        with pytest.raises(ValueError):
            audit_source_map(data)


def test_file_limit_and_invalid_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "asset.js.map"
    file.write_bytes(b" " * 2_000_001)
    with pytest.raises(ValueError, match="2 MB"):
        audit_source_map_file(str(file))
    file.write_text("{wrong")
    with pytest.raises(ValueError, match="invalid source-map"):
        audit_source_map_file(str(file))


def test_cli_source_map_file_default_json_and_opt_in_human(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "asset.js.map"
    file.write_text(json.dumps(valid_map()))
    cmd = ["--audit-source-map-file", str(file)]
    assert main(cmd) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["source_count"] == 3
    assert "VERYSECRET" not in repr(report)
    assert main(cmd + ["--human", "--color", "never"]) == 0
    output = capsys.readouterr().out
    assert "OFFLINE SOURCE MAP AUDIT" in output
    assert "VERYSECRET" not in output
    assert main(cmd + ["--active"]) == 2
    assert "exclusive offline mode" in capsys.readouterr().err
    assert main(cmd + ["--format", "markdown"]) == 2
    assert "only to scanner" in capsys.readouterr().err


def test_source_map_rejects_outside_workspace_file_and_symlink(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.js.map"
    outside.write_text(json.dumps(valid_map()))
    monkeypatch.chdir(workspace)
    with pytest.raises(ValueError, match="working directory"):
        audit_source_map_file(str(outside))
    with pytest.raises(ValueError, match="working directory"):
        audit_source_map_file("../outside.js.map")
    alias = workspace / "alias.js.map"
    alias.symlink_to(outside)
    with pytest.raises(ValueError, match="working directory"):
        audit_source_map_file(str(alias))


def test_source_map_only_accepts_regular_map_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    txt = tmp_path / "asset.txt"
    txt.write_text(json.dumps(valid_map()))
    with pytest.raises(ValueError, match="extension"):
        audit_source_map_file(str(txt))
    directory = tmp_path / "directory.map"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular"):
        audit_source_map_file(str(directory))
    valid = tmp_path / "asset.js.map"
    valid.write_text(json.dumps(valid_map()))
    assert audit_source_map_file("asset.js.map")["source_count"] == 3
