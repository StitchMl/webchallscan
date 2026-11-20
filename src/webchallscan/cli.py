from __future__ import annotations

import argparse
import json
import site
import sys
import sysconfig
from pathlib import Path

from . import __version__
from .access_checks import load_cases, run_readonly_cases
from .api_contract import load_contract, validate_contract
from .burp_import import import_burp_xml
from .burp_session import export_burp_session
from .cookie_audit import audit_session_file
from .jwt_audit import audit_jwt_file
from .json_checks import load_json_cases, run_json_cases
from .markdown_report import render_markdown
from .network import observe_cdp
from .planner import inventory_get_urls, load_inventory, plan_inventory
from .replay import render_burp_procedure
from .report import render_json, render_text
from .scanner import scan_profiles
from .snippets import render_snippets
from .source_map_audit import audit_source_map_file
from .structured_report import render_structured_text
from .session import (
    BrowserSession,
    capture_cdp_session,
    discover_cdp,
    listen_for_extension,
    load_session_file,
)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webchallscan", description="Deterministic black-box scanner for authorized CTF web challenges.")
    p.add_argument("url", nargs="?", help="absolute HTTP(S) challenge URL; optional with a session source")
    p.add_argument("--authorized", action="store_true", help="required acknowledgment that you may test this target")
    p.add_argument("--active", action="store_true", help="enable bounded, low-impact validation probes; never extracts flags")
    p.add_argument("--ssti-alternates", action="store_true", help="opt into additional bounded SSTI arithmetic syntaxes (requires --active)")
    p.add_argument("--nosql-query", action="store_true", help="opt into bounded GET bracket-operator differential checks (requires --active)")
    p.add_argument("--profile", choices=("desktop", "mobile", "both"), default="both",
                   help="HTTP client profile; both uses isolated cookies and budgets (default: both)")
    session = p.add_mutually_exclusive_group()
    session.add_argument("--browser-session", nargs="?", const="auto", choices=("auto", "chrome", "edge"),
                         help="use the focused visible tab and its cookies from a local CDP-enabled browser")
    session.add_argument("--cdp", metavar="URL", help="use a local Chrome DevTools endpoint, for example http://127.0.0.1:9222")
    session.add_argument("--session-file", metavar="JSON", help="load exact URL, cookies and safe headers from a local JSON file")
    session.add_argument("--listen-session", action="store_true", help="wait once for the bundled browser extension")
    p.add_argument("--quick", action="store_true", help="one-command CDP observation and audit triage; no contract files")
    p.add_argument("--observe-network", type=float, metavar="SECONDS", help="read-only CDP traffic inventory while you navigate (requires --cdp)")
    p.add_argument("--validate-api-contract", metavar="JSON", help="bounded GET-only IDOR, fuzz and business invariant checks")
    p.add_argument("--check-api-cases", metavar="JSON", help="explicit read-only GET comparisons with two lab roles")
    p.add_argument("--check-json-cases", metavar="JSON", help="explicit active JSON POST validation cases; requires --active")
    p.add_argument("--plan-inventory", metavar="JSON", help="offline security review plan from a CDP inventory; no requests")
    p.add_argument("--import-burp", metavar="XML", help="offline redacted inventory from a Burp Suite XML HTTP history export")
    p.add_argument("--burp-session-from", metavar="XML", help="select a Burp XML GET request with Cookie for private session export")
    p.add_argument("--burp-session-out", metavar="JSON", help="exclusive new private session-file path")
    p.add_argument("--burp-session-path", metavar="PATH", help="select a Burp GET with this exact, same-origin URL path")
    p.add_argument("--burp-session-index", type=int, metavar="N", help="select the Nth matching Burp GET request (1-500, default 1)")
    p.add_argument("--allow-secret-export", action="store_true", help="acknowledge the new session file contains live cookie values")
    p.add_argument("--audit-jwt-file", metavar="FILE", help="offline JWT structure and metadata audit without printing token values")
    p.add_argument("--audit-session-file", metavar="JSON", help="offline aggregate cookie encoding and JWT audit for existing session JSON")
    p.add_argument("--audit-source-map-file", metavar="MAP", help="offline bounded source-map v3 audit without disclosing source paths/content")
    p.add_argument("--from-inventory", metavar="JSON", help="seed scan with same-origin GET routes from redacted inventory")
    p.add_argument("--expect-origin", metavar="ORIGIN", help="require exact inventory origin in --plan-inventory mode")
    p.add_argument("--observe-limit", type=int, default=500, help="maximum observed requests (default: 500)")
    p.add_argument("--session-wait", type=float, default=120.0, help="seconds to wait for --listen-session (default: 120)")
    p.add_argument("--burp-procedure", action="store_true",
                   help="print a manual Burp Repeater procedure for each reproducible finding instead of the report")
    p.add_argument("--burp-raw", action="store_true", help="include redacted Raw HTTP request templates in --burp-procedure")
    p.add_argument("--export-curl", action="store_true", help="print redacted curl reproductions for high-confidence findings")
    p.add_argument("--export-python", action="store_true", help="print redacted urllib reproductions for high-confidence findings")
    p.add_argument("--include-session-secrets", action="store_true",
                   help="print cookie values in the Burp procedure instead of hiding them")
    p.add_argument("--max-pages", type=int, default=20)
    p.add_argument("--max-requests", type=int, default=80)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    p.add_argument("--proxy", metavar="HTTP_URL", help="route scan requests through a local Burp HTTP proxy")
    p.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="terminal colors: auto, always or never")
    p.add_argument("--verbose", action="store_true", help="show full finding vectors, replay and recovery details in text reports")
    p.add_argument("--human", action="store_true", help="human-readable colored view of inventories and API/offline JSON reports (opt-in)")
    p.add_argument("--top", type=int, metavar="N", help="show up to N scanner finding details in text reports (default: 20)")
    p.add_argument("--min-severity", choices=("critical", "high", "medium", "low", "info"),
                   default="info", help="minimum scanner text finding severity (default: info)")
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


def _command_arguments(argv: list[str]) -> list[str]:
    """Parse optional subcommands while retaining legacy root-level options."""
    if not argv or argv[0] not in {"scan", "observe", "contract", "replay"}:
        return argv
    commands = argparse.ArgumentParser(prog="webchallscan", add_help=False)
    subparsers = commands.add_subparsers(dest="command", required=True)
    for command in ("scan", "observe", "contract", "replay"):
        subparser = subparsers.add_parser(command, add_help=False)
        subparser.add_argument("arguments", nargs=argparse.REMAINDER)
    parsed = commands.parse_args(argv[:1])
    return _normalize_command([parsed.command, *argv[1:]])


def _normalize_command(argv: list[str]) -> list[str]:
    """Translate optional command-style syntax to the legacy argparse flags.

    Keeping one parser and one execution path prevents divergence between the
    original flags and the new ergonomic command aliases.
    """
    if not argv:
        return argv
    command, *rest = argv
    if command == "scan":
        return rest
    if command == "observe":
        return rest if "--observe-network" in rest else [
            "--observe-network", "20", *rest,
        ]
    if command == "contract":
        return ["--validate-api-contract", *rest]
    if command == "replay":
        return rest if "--burp-procedure" in rest else ["--burp-procedure", *rest]
    return argv


def _truthy(args, *names) -> bool:
    return any(getattr(args, name) for name in names)


def _present(args, *names) -> bool:
    return any(getattr(args, name) is not None for name in names)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _format_result(args, result: dict, indent: int = 2) -> str:
    if args.human:
        return render_structured_text(result, args.color, verbose=args.verbose)
    return json.dumps(result, indent=indent)


_REPORT_ONLY_FLAGS = (
    "quick", "plan_inventory", "import_burp", "burp_session_from", "audit_jwt_file",
    "audit_session_file", "audit_source_map_file", "validate_api_contract",
    "check_api_cases", "check_json_cases", "burp_procedure", "export_curl", "export_python",
)


def _check_report_options(args) -> int | None:
    if args.human and args.format != "text":
        return _fail("error: --human and --format json/markdown are mutually exclusive; use --format text")
    if args.format == "markdown" and (
            _truthy(args, *_REPORT_ONLY_FLAGS) or args.observe_network is not None):
        return _fail("error: --format markdown applies only to scanner reports")
    if args.top is not None and not 1 <= args.top <= 1000:
        return _fail("error: --top must be 1-1000")
    if (args.top is not None or args.min_severity != "info") and (
            args.format == "json" or args.human
            or _truthy(args, *_REPORT_ONLY_FLAGS) or args.observe_network is not None):
        return _fail("error: --top and --min-severity apply only to scanner text reports")
    return None


def _check_nosql_option(args) -> int | None:
    if args.nosql_query and (
            not args.active
            or _truthy(args, "quick", "validate_api_contract", "check_api_cases", "check_json_cases",
                       "import_burp", "burp_session_from", "plan_inventory", "audit_jwt_file")
            or args.observe_network is not None):
        return _fail("error: --nosql-query applies only to --active scanner mode")
    return None


def _handle_extension_path(args) -> int | None:
    if not args.extension_path:
        return None
    try:
        print(_extension_path())
        return 0
    except ValueError as exc:
        return _fail(f"error: {exc}")


def _check_proxy_option(args) -> int | None:
    if args.proxy and (
            _truthy(args, "quick", "plan_inventory", "import_burp", "audit_jwt_file",
                    "audit_session_file", "audit_source_map_file", "burp_session_from")
            or args.observe_network is not None):
        return _fail("error: --proxy is supported only in scanner mode")
    return None


def _handle_source_map_audit(args) -> int | None:
    if args.audit_source_map_file is None:
        return None
    if (_truthy(args, "url", "quick", "active", "cdp", "browser_session", "session_file",
                "listen_session", "plan_inventory", "import_burp", "burp_session_from",
                "burp_session_out", "allow_secret_export", "check_json_cases",
                "validate_api_contract", "check_api_cases", "audit_jwt_file",
                "audit_session_file", "from_inventory", "burp_procedure", "burp_raw",
                "include_session_secrets", "export_curl", "export_python", "expect_origin",
                "nosql_query", "ssti_alternates", "proxy", "insecure")
            or _present(args, "observe_network", "burp_session_path", "burp_session_index")):
        return _fail("error: --audit-source-map-file is an exclusive offline mode")
    try:
        print(_format_result(args, audit_source_map_file(args.audit_source_map_file), indent=2))
        return 0
    except (ValueError, OSError):
        return _fail("error: source-map audit failed: invalid or oversized input file")


def _handle_session_audit(args) -> int | None:
    if args.audit_session_file is None:
        return None
    if (_truthy(args, "url", "quick", "active", "cdp", "browser_session", "session_file",
                "listen_session", "plan_inventory", "import_burp", "burp_session_from",
                "burp_session_out", "allow_secret_export", "check_json_cases",
                "validate_api_contract", "check_api_cases", "audit_jwt_file", "from_inventory",
                "burp_procedure", "burp_raw", "include_session_secrets", "export_curl",
                "export_python", "expect_origin", "nosql_query")
            or args.observe_network is not None):
        return _fail("error: --audit-session-file is an exclusive offline mode")
    try:
        print(_format_result(args, audit_session_file(args.audit_session_file), indent=2))
        return 0
    except (ValueError, OSError):
        return _fail("error: session-format audit failed: invalid input file")


def _handle_burp_session_export(args) -> int | None:
    if args.burp_session_from is not None:
        if (not args.authorized or not args.allow_secret_export
                or not args.expect_origin or not args.burp_session_out
                or _truthy(args, "url", "quick", "active", "cdp", "browser_session",
                           "session_file", "listen_session", "plan_inventory", "import_burp",
                           "validate_api_contract", "check_api_cases", "check_json_cases",
                           "audit_jwt_file", "from_inventory", "burp_procedure", "burp_raw",
                           "include_session_secrets", "export_curl", "export_python")
                or args.observe_network is not None):
            return _fail("error: --burp-session-from requires --authorized --allow-secret-export --expect-origin and --burp-session-out; excludes other modes")
        try:
            result = export_burp_session(
                args.burp_session_from, args.burp_session_out, args.expect_origin,
                request_path=args.burp_session_path,
                request_index=1 if args.burp_session_index is None else args.burp_session_index)
            print("warning: new session file contains live cookies; restrict access and delete it after use", file=sys.stderr)
            print(_format_result(args, result, indent=2))
            return 0
        except (ValueError, OSError):
            return _fail("error: Burp session export failed; check origin, source and output path")
    if args.burp_session_out or args.allow_secret_export or _present(
            args, "burp_session_path", "burp_session_index"):
        return _fail("error: Burp session selection/output flags require --burp-session-from")
    return None


def _handle_jwt_audit(args) -> int | None:
    if args.audit_jwt_file is None:
        return None
    if (_truthy(args, "url", "active", "cdp", "browser_session", "session_file",
                "listen_session", "quick", "plan_inventory", "validate_api_contract",
                "check_api_cases", "check_json_cases", "import_burp", "from_inventory",
                "burp_procedure", "burp_raw", "include_session_secrets", "export_curl",
                "export_python", "expect_origin")
            or args.observe_network is not None):
        return _fail("error: --audit-jwt-file is an exclusive offline mode")
    try:
        print(_format_result(args, audit_jwt_file(args.audit_jwt_file), indent=2))
        return 0
    except (ValueError, OSError):
        return _fail("error: JWT audit failed: invalid input file or token")


def _handle_burp_import(args) -> int | None:
    if args.import_burp is None:
        return None
    if (not args.authorized
            or _truthy(args, "url", "active", "cdp", "browser_session", "session_file",
                       "listen_session", "quick", "plan_inventory", "validate_api_contract",
                       "check_api_cases", "from_inventory", "check_json_cases",
                       "audit_jwt_file", "include_session_secrets", "burp_procedure",
                       "burp_raw", "export_curl", "export_python")
            or args.observe_network is not None):
        return _fail("error: --import-burp requires --authorized and excludes scan/browser modes")
    try:
        print(_format_result(args, import_burp_xml(args.import_burp, args.expect_origin), indent=2))
        return 0
    except (ValueError, OSError) as exc:
        return _fail(f"error: Burp XML import failed: {exc}")


def _handle_json_cases(args) -> int | None:
    if args.check_json_cases is None:
        return None
    if (not args.authorized or not args.active
            or _truthy(args, "url", "quick", "cdp", "browser_session", "session_file",
                       "listen_session", "plan_inventory", "import_burp", "from_inventory",
                       "validate_api_contract", "check_api_cases", "audit_jwt_file",
                       "burp_procedure", "burp_raw", "include_session_secrets",
                       "export_curl", "export_python")
            or args.observe_network is not None):
        return _fail("error: --check-json-cases requires --authorized --active and excludes other scan modes")
    try:
        print(_format_result(args, run_json_cases(
            load_json_cases(args.check_json_cases), timeout=args.timeout,
            verify_tls=not args.insecure, proxy=args.proxy), indent=2))
        return 0
    except (ValueError, OSError):
        return _fail("error: JSON validation failed; check contract and connectivity")


def _handle_quick(args) -> int | None:
    if not args.quick:
        return None
    if (args.from_inventory or not args.authorized
            or not args.cdp
            or _truthy(args, "url", "listen_session", "session_file", "browser_session",
                       "plan_inventory", "check_api_cases", "validate_api_contract")
            or args.observe_network is not None):
        return _fail("error: --quick requires --authorized --cdp and no other scan mode")
    try:
        print("Quick discovery running: use the selected lab tab now...", file=sys.stderr, flush=True)
        observed = observe_cdp(args.cdp, 20.0, args.observe_limit)
        plan = plan_inventory(observed)
        print(_format_result(args, {
            "schema": "webchallscan/quick-v1",
            "origin": observed["origin"],
            "observed_requests": observed["observed_requests"],
            "endpoints": observed["endpoints"],
            "passive_findings": observed["passive_findings"],
            "triage": plan["checks"],
            "active_tests_executed": 0,
            "limitations": observed["limitations"] + [
                "No replayable bodies or independent roles were captured; IDOR and business-logic checks remain unverified."
            ]
        }, indent=2))
        return 0
    except (ValueError, OSError):
        return _fail("error: quick discovery failed; check the focused CDP tab")


def _handle_api_contract(args) -> int | None:
    if args.validate_api_contract is None:
        return None
    if (args.from_inventory or not args.authorized
            or _truthy(args, "cdp", "url", "session_file", "listen_session", "browser_session",
                       "plan_inventory", "check_api_cases")
            or args.observe_network is not None):
        return _fail("error: --validate-api-contract requires --authorized and excludes other modes")
    try:
        print(_format_result(args, validate_contract(
            load_contract(args.validate_api_contract), timeout=args.timeout,
            verify_tls=not args.insecure, proxy=args.proxy), indent=2))
        return 0
    except (ValueError, OSError):
        return _fail("error: contract validation failed; check inputs and connectivity")


def _handle_api_cases(args) -> int | None:
    if args.check_api_cases is None:
        return None
    if (args.from_inventory or not args.authorized
            or _truthy(args, "cdp", "url", "session_file", "listen_session", "browser_session",
                       "plan_inventory")
            or args.observe_network is not None):
        return _fail("error: --check-api-cases requires --authorized and excludes browser/scan modes")
    try:
        print(_format_result(args, run_readonly_cases(
            load_cases(args.check_api_cases), args.timeout,
            verify_tls=not args.insecure, proxy=args.proxy), indent=2))
        return 0
    except (ValueError, OSError) as exc:
        return _fail(f"error: API check failed: {type(exc).__name__}")


def _handle_plan_inventory(args) -> int | None:
    if args.plan_inventory is None:
        return None
    if (args.from_inventory or not args.authorized or args.observe_network is not None
            or _truthy(args, "cdp", "url", "listen_session", "session_file", "browser_session")):
        return _fail("error: --plan-inventory requires --authorized and cannot be combined with a browser source")
    try:
        print(_format_result(args, plan_inventory(
            load_inventory(args.plan_inventory), args.expect_origin), indent=2))
        return 0
    except (ValueError, OSError) as exc:
        return _fail(f"error: {exc}")


def _handle_observe_network(args) -> int | None:
    if args.expect_origin:
        return _fail("error: --expect-origin only applies to --plan-inventory")
    if args.observe_network is None:
        return None
    if args.from_inventory or not args.authorized:
        return _fail("error: --authorized is required")
    if not args.cdp or _truthy(args, "url", "listen_session", "session_file", "browser_session"):
        return _fail("error: --observe-network requires --cdp and no positional URL/session source")
    try:
        print("Observing focused tab: interact with it now...", file=sys.stderr, flush=True)
        print(_format_result(args, observe_cdp(args.cdp, args.observe_network, args.observe_limit), indent=2))
        return 0
    except (ValueError, OSError) as exc:
        return _fail(f"error: {exc}")


def _check_scan_options(args) -> int | None:
    if not args.authorized:
        return _fail("error: --authorized is required; scan only targets you are permitted to test")
    if (args.export_curl and args.export_python) or (args.burp_procedure and (args.export_curl or args.export_python)):
        return _fail("error: choose only one of --burp-procedure, --export-curl or --export-python")
    if args.ssti_alternates and not args.active:
        return _fail("error: --ssti-alternates requires --active")
    if args.burp_raw and not args.burp_procedure:
        return _fail("error: --burp-raw requires --burp-procedure")
    if args.include_session_secrets and not args.burp_procedure:
        return _fail("error: --include-session-secrets requires --burp-procedure")
    return None


def _capture_session(args):
    if args.session_file:
        print("warning: session files contain secrets; restrict file access and delete them after use", file=sys.stderr)
        return load_session_file(args.session_file)
    if args.listen_session:
        return listen_for_extension(args.session_wait)
    if args.cdp:
        return capture_cdp_session(args.cdp, min(args.timeout, 3.0))
    if args.browser_session:
        endpoint = discover_cdp(args.browser_session)
        return capture_cdp_session(endpoint, min(args.timeout, 3.0))
    return None


def _scan_target(args, captured) -> str:
    if not captured:
        if not args.url:
            raise ValueError("URL is required unless --browser-session, --cdp, or --session-file is used")
        return args.url
    if args.url:
        from urllib.parse import urlsplit
        requested = urlsplit(args.url)
        selected = urlsplit(captured.url)
        if (requested.scheme.lower(), requested.netloc.lower()) != (selected.scheme.lower(), selected.netloc.lower()):
            raise ValueError("the supplied URL and active browser tab have different origins")
    if args.profile != "both" and args.profile != captured.profile:
        raise ValueError(f"captured tab is {captured.profile}; --profile {args.profile} would mislabel its session")
    return captured.url


def _scan_sessions(args, captured) -> dict | None:
    if not captured:
        return None
    sessions = {captured.profile: captured}
    if args.profile == "both":
        other = "mobile" if captured.profile == "desktop" else "desktop"
        sessions[other] = BrowserSession(
            url=captured.url, cookies=captured.cookies, headers=(), profile=other,
            source=captured.source + "-cookie-clone",
        )
    return sessions


def _exit_code(report) -> int:
    return 1 if any(f.severity in {"critical", "high"} for f in report.findings) else 0


def _run_scan(args) -> tuple[object, int | None]:
    """Return (report, early_exit_code); the code is set when output was already printed."""
    captured = _capture_session(args)
    target = _scan_target(args, captured)
    profiles = ("desktop", "mobile") if args.profile == "both" else (args.profile,)
    sessions = _scan_sessions(args, captured)
    inventory_urls = inventory_get_urls(load_inventory(args.from_inventory), target) if args.from_inventory else ()
    report = scan_profiles(target, profiles=profiles, active=args.active,
                           max_pages=args.max_pages, max_requests=args.max_requests,
                           timeout=args.timeout, verify_tls=not args.insecure,
                           sessions=sessions, proxy=args.proxy, inventory_urls=inventory_urls,
                           ssti_alternates=args.ssti_alternates,
                           nosql_query=args.nosql_query)
    if args.export_curl or args.export_python:
        print(render_snippets(report, "curl" if args.export_curl else "python"))
        return report, _exit_code(report)
    if args.burp_procedure:
        if args.include_session_secrets:
            print("warning: the procedure will print live session cookie values; clear your terminal after use", file=sys.stderr)
        print(render_burp_procedure(report, args.include_session_secrets, args.burp_raw))
        return report, _exit_code(report)
    return report, None


def _print_report(args, report) -> None:
    if args.format == "json":
        print(render_json(report))
    elif args.format == "markdown":
        print(render_markdown(report, verbose=args.verbose,
                              top=args.top, min_severity=args.min_severity))
    else:
        print(render_text(report, args.color, verbose=args.verbose,
                          top=args.top, min_severity=args.min_severity))


_MODE_STEPS = (
    _check_report_options,
    _check_nosql_option,
    _handle_extension_path,
    _check_proxy_option,
    _handle_source_map_audit,
    _handle_session_audit,
    _handle_burp_session_export,
    _handle_jwt_audit,
    _handle_burp_import,
    _handle_json_cases,
    _handle_quick,
    _handle_api_contract,
    _handle_api_cases,
    _handle_plan_inventory,
    _handle_observe_network,
    _check_scan_options,
)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(_command_arguments(list(sys.argv[1:] if argv is None else argv)))
    for step in _MODE_STEPS:
        code = step(args)
        if code is not None:
            return code
    try:
        report, early = _run_scan(args)
    except (ValueError, OSError) as exc:
        return _fail(f"error: {exc}")
    if early is not None:
        return early
    _print_report(args, report)
    if report.pages_scanned == 0:
        return 3
    return _exit_code(report)
