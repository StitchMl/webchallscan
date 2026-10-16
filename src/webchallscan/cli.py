from __future__ import annotations

import argparse
import json
import site
import sys
import sysconfig
from pathlib import Path

from .access_checks import load_cases, run_readonly_cases
from .network import observe_cdp
from .planner import load_inventory, plan_inventory
from . import __version__
from .report import render_json, render_text
from .replay import select_burp_request, write_burp_output
from .scanner import scan_profiles
from .session import BrowserSession, SessionCaptureError, capture_cdp_session, discover_cdp, listen_for_extension, load_session_file


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webchallscan", description="Deterministic black-box scanner for authorized CTF web challenges.")
    p.add_argument("url", nargs="?", help="absolute HTTP(S) challenge URL; optional with a session source")
    p.add_argument("--authorized", action="store_true", help="required acknowledgment that you may test this target")
    p.add_argument("--active", action="store_true", help="enable bounded, low-impact validation probes; never extracts flags")
    p.add_argument("--profile", choices=("desktop", "mobile", "both"), default="both",
                   help="HTTP client profile; both uses isolated cookies and budgets (default: both)")
    session = p.add_mutually_exclusive_group()
    session.add_argument("--browser-session", nargs="?", const="auto", choices=("auto", "chrome", "edge"),
                         help="use the focused visible tab and its cookies from a local CDP-enabled browser")
    session.add_argument("--cdp", metavar="URL", help="use a local Chrome DevTools endpoint, for example http://127.0.0.1:9222")
    session.add_argument("--session-file", metavar="JSON", help="load exact URL, cookies and safe headers from a local JSON file")
    session.add_argument("--listen-session", action="store_true", help="wait once for the bundled browser extension")
    p.add_argument("--observe-network", type=float, metavar="SECONDS", help="read-only CDP traffic inventory while you navigate (requires --cdp)")
    p.add_argument("--check-api-cases", metavar="JSON", help="explicit read-only GET comparisons with two lab roles")
    p.add_argument("--plan-inventory", metavar="JSON", help="offline security review plan from a CDP inventory; no requests")
    p.add_argument("--expect-origin", metavar="ORIGIN", help="require exact inventory origin in --plan-inventory mode")
    p.add_argument("--observe-limit", type=int, default=500, help="maximum observed requests (default: 500)")
    p.add_argument("--session-wait", type=float, default=120.0, help="seconds to wait for --listen-session (default: 120)")
    burp = p.add_mutually_exclusive_group()
    burp.add_argument("--burp-output", metavar="DIR", help="create a directory of raw Burp Repeater proof/recovery requests")
    burp.add_argument("--burp-request", metavar="ID[:KIND]",
                      help="print one raw request; accepts an ID, first-proof, or first-ready")
    p.add_argument("--include-session-secrets", action="store_true",
                   help="include cookies and hidden values in Burp output/request only")
    p.add_argument("--max-pages", type=int, default=20)
    p.add_argument("--max-requests", type=int, default=80)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--extension-path", action="store_true", help="print the bundled Chromium extension directory and exit")
    return p


def _extension_path() -> Path:
    candidates = (
        Path(__file__).resolve().parents[2] / "browser_extension",
        Path(site.USER_BASE) / "share" / "webchallscan" / "browser_extension",
        Path(sysconfig.get_path("data")) / "share" / "webchallscan" / "browser_extension",
    )
    for candidate in candidates:
        if (candidate / "manifest.json").is_file():
            return candidate
    raise ValueError("bundled browser extension directory was not found")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.extension_path:
        try:
            print(_extension_path())
            return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.check_api_cases is not None:
        if not args.authorized or args.cdp or args.url or args.session_file or args.listen_session or args.browser_session or args.observe_network is not None or args.plan_inventory:
            print("error: --check-api-cases requires --authorized and excludes browser/scan modes", file=sys.stderr)
            return 2
        try:
            print(json.dumps(run_readonly_cases(load_cases(args.check_api_cases), args.timeout), indent=2))
            return 0
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.plan_inventory is not None:
        if not args.authorized or args.observe_network is not None or args.cdp or args.url or args.listen_session or args.session_file or args.browser_session:
            print("error: --plan-inventory requires --authorized and cannot be combined with a browser source", file=sys.stderr)
            return 2
        try:
            print(json.dumps(plan_inventory(load_inventory(args.plan_inventory), args.expect_origin), indent=2))
            return 0
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.expect_origin:
        print("error: --expect-origin only applies to --plan-inventory", file=sys.stderr)
        return 2
    if args.observe_network is not None:
        if not args.authorized:
            print("error: --authorized is required", file=sys.stderr)
            return 2
        if not args.cdp or args.url or args.listen_session or args.session_file or args.browser_session:
            print("error: --observe-network requires --cdp and no positional URL/session source", file=sys.stderr)
            return 2
        try:
            print("Observing focused tab: interact with it now...", file=sys.stderr, flush=True)
            print(json.dumps(observe_cdp(args.cdp, args.observe_network, args.observe_limit), indent=2))
            return 0
        except (ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if not args.authorized:
        print("error: --authorized is required; scan only targets you are permitted to test", file=sys.stderr)
        return 2
    if args.include_session_secrets and not (args.burp_output or args.burp_request):
        print("error: --include-session-secrets requires --burp-output or --burp-request", file=sys.stderr)
        return 2
    try:
        captured = None
        if args.session_file:
            print("warning: session files contain secrets; restrict file access and delete them after use", file=sys.stderr)
            captured = load_session_file(args.session_file)
        elif args.listen_session:
            captured = listen_for_extension(args.session_wait)
        elif args.cdp:
            captured = capture_cdp_session(args.cdp, min(args.timeout, 3.0))
        elif args.browser_session:
            endpoint = discover_cdp(args.browser_session)
            captured = capture_cdp_session(endpoint, min(args.timeout, 3.0))
        if captured:
            if args.url:
                from urllib.parse import urlsplit
                requested = urlsplit(args.url)
                selected = urlsplit(captured.url)
                if (requested.scheme.lower(), requested.netloc.lower()) != (selected.scheme.lower(), selected.netloc.lower()):
                    raise ValueError("the supplied URL and active browser tab have different origins")
            target = captured.url
            if args.profile != "both" and args.profile != captured.profile:
                raise ValueError(f"captured tab is {captured.profile}; --profile {args.profile} would mislabel its session")
        else:
            if not args.url:
                raise ValueError("URL is required unless --browser-session, --cdp, or --session-file is used")
            target = args.url
        profiles = ("desktop", "mobile") if args.profile == "both" else (args.profile,)
        sessions = None
        if captured:
            sessions = {captured.profile: captured}
            if args.profile == "both":
                other = "mobile" if captured.profile == "desktop" else "desktop"
                sessions[other] = BrowserSession(
                    url=captured.url, cookies=captured.cookies, headers=(), profile=other,
                    source=captured.source + "-cookie-clone",
                )
        report = scan_profiles(target, profiles=profiles, active=args.active,
                               max_pages=args.max_pages, max_requests=args.max_requests,
                               timeout=args.timeout, verify_tls=not args.insecure,
                               sessions=sessions)
        if args.burp_output:
            if args.include_session_secrets:
                print("warning: replay files will contain live session secrets; protect and delete them after use", file=sys.stderr)
            write_burp_output(report, args.burp_output, args.include_session_secrets)
        if args.burp_request:
            if args.include_session_secrets:
                print("warning: raw request contains live session secrets; clear the clipboard after use", file=sys.stderr)
            sys.stdout.write(select_burp_request(report, args.burp_request, args.include_session_secrets))
            return 0
    except (ValueError, SessionCaptureError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render_json(report) if args.format == "json" else render_text(report, args.color))
    if report.pages_scanned == 0:
        return 3
    return 1 if any(f.severity in {"critical", "high"} for f in report.findings) else 0

