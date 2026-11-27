import json

import pytest

from webchallscan.cli import main
from webchallscan.planner import inventory_get_urls, plan_inventory
from webchallscan.source_inventory import source_inventory


def test_local_site_source_builds_redacted_inventory_and_get_seeds(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    site = tmp_path / "dist"
    (site / "account").mkdir(parents=True)
    (site / "index.html").write_text(
        '<a href="/search?q=private">Search</a>'
        '<form action="/lookup" method="get"><input name="term"></form>'
        '<form action="/account/update" method="post">'
        '<input name="display_name"><input name="csrf_token"></form>'
        '<script src="/assets/app.js"></script>', encoding="utf-8")
    (site / "account" / "index.html").write_text(
        '<a href="https://outside.example/private">outside</a>', encoding="utf-8")
    assets = site / "assets"
    assets.mkdir()
    (assets / "app.js").write_text(
        'fetch("/api/items?id=7"); '
        'fetch("/api/update", {method:"POST", body:"ignored"});', encoding="utf-8")

    inventory = source_inventory("dist", "https://challenge.example")
    plan = plan_inventory(inventory, "https://challenge.example")
    assert inventory["observed_requests"] == 0
    assert inventory["active_tests_executed"] == 0
    assert inventory["source_files"] == 3
    assert plan["endpoint_count"] == 7
    assert not any("private" in repr(item) for item in inventory["endpoints"])
    assert inventory_get_urls(inventory, "https://challenge.example/") == (
            "https://challenge.example/",
            "https://challenge.example/account/",
        "https://challenge.example/api/items?id=WCSBASE",
        "https://challenge.example/lookup?term=WCSBASE",
        "https://challenge.example/search?q=WCSBASE",
    )


def test_local_source_cli_emits_json_without_network(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "index.html").write_text('<a href="/flag">hint</a>', encoding="utf-8")

    assert main(["--source", "index.html", "--source-origin",
                 "https://challenge.example", "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["endpoints"][0]["path"] == "/"
    assert result["endpoints"][1]["path"] == "/flag"
    assert result["active_tests_executed"] == 0


@pytest.mark.parametrize("origin", [
    "file:///etc/passwd", "https://user:pass@challenge.example",
    "https://challenge.example/path", "https://challenge.example/?x=1",
])
def test_local_source_rejects_non_origin_values(tmp_path, monkeypatch, origin):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    with pytest.raises(ValueError, match="origin"):
        source_inventory("index.html", origin)


def test_local_source_requires_contained_path_and_supported_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "notes.txt").write_text("not a web asset", encoding="utf-8")
    with pytest.raises(ValueError, match="no HTML or JavaScript"):
        source_inventory("notes.txt", "https://challenge.example")
    with pytest.raises(ValueError, match="inside the working directory"):
        source_inventory("../outside", "https://challenge.example")
