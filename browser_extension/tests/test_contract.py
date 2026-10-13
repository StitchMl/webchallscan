import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_manifest_uses_explicit_click_and_loopback_only():
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["manifest_version"] == 3
    assert set(manifest["permissions"]) == {"activeTab", "cookies"}
    assert manifest["host_permissions"] == [
        "http://127.0.0.1/*",
        "http://localhost/*",
    ]
    assert "default_popup" in manifest["action"]
    assert "storage" not in manifest["permissions"]


def test_worker_enforces_one_shot_contract_and_deterministic_payload():
    worker = (ROOT / "service_worker.js").read_text(encoding="utf-8")

    assert 'const SCHEMA = "webchallscan/browser-session-v1"' in worker
    assert 'endpoint.pathname !== "/v1/session/import"' in worker
    assert '"X-Webchallscan-Token": validateToken(token)' in worker
    assert 'cache: "no-store"' in worker
    assert 'credentials: "omit"' in worker
    assert "cookies.sort(" in worker
    assert "chrome.cookies.getAllCookieStores()" in worker
    assert "chrome.cookies.getAll({ url: url.href, storeId })" in worker
    assert "partitionKey: { topLevelSite: url.origin }" in worker
    assert "Date.now" not in worker
    assert "Math.random" not in worker
    assert "localeCompare" not in worker
    assert "chrome.storage" not in worker
    assert "console." not in worker
    assert "userAgent: navigator.userAgent" in worker
    assert "http_only: Boolean(cookie.httpOnly)" in worker


def test_popup_does_not_print_captured_context():
    popup_script = (ROOT / "popup.js").read_text(encoding="utf-8")

    assert "response.result.url" not in popup_script
    assert "response.result" not in popup_script


def test_extension_has_no_remote_or_inline_script():
    popup = (ROOT / "popup.html").read_text(encoding="utf-8")
    files = [
        ROOT / "manifest.json",
        ROOT / "service_worker.js",
        ROOT / "popup.html",
        ROOT / "popup.js",
        ROOT / "popup.css",
    ]
    source = "\n".join(path.read_text(encoding="utf-8") for path in files)

    assert '<script src="popup.js"></script>' in popup
    assert "<script>" not in popup
    assert "https://" not in source
    assert "eval(" not in source
