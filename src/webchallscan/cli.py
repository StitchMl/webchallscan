from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import render_json, render_text
from .scanner import Scanner


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webchallscan", description="Deterministic black-box scanner for authorized CTF web challenges.")
    p.add_argument("url", help="absolute HTTP(S) challenge URL")
    p.add_argument("--authorized", action="store_true", help="required acknowledgment that you may test this target")
    p.add_argument("--active", action="store_true", help="enable bounded, low-impact validation probes; never extracts flags")
    p.add_argument("--max-pages", type=int, default=20)
    p.add_argument("--max-requests", type=int, default=80)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.authorized:
        print("error: --authorized is required; scan only targets you are permitted to test", file=sys.stderr)
        return 2
    try:
        report = Scanner(args.url, active=args.active, max_pages=args.max_pages,
                         max_requests=args.max_requests, timeout=args.timeout,
                         verify_tls=not args.insecure).scan()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render_json(report) if args.format == "json" else render_text(report, args.color))
    if report.pages_scanned == 0:
        return 3
    return 1 if any(f.severity in {"critical", "high"} for f in report.findings) else 0

