# webchallscan

Deterministic, offline/no-AI black-box analysis for **authorized CTF Jeopardy web challenges** when backend source is unavailable. It accepts a URL, stays on the exact origin, crawls with fixed budgets, extracts forms and parameters, records evidence, and prints tailored validation vectors and defensive patches.

It does not promise complete coverage. Passive parameter-name matches are labeled `validation-only`. `payload-ready` appears only after an active marker produces target-derived evidence. The scanner does not brute-force credentials, enumerate the Internet, submit destructive requests, or automatically retrieve protected data or flags.

## Install

```powershell
py -m pip install -e C:\Users\matte\Desktop\webchallscan
webchallscan --help
```

No virtual environment is required. Runtime uses only Python's standard library and keeps no cache.
JSON reports use the `webchallscan/v2` schema; every finding includes its
desktop, mobile, or comparison profile.

## Use

Authorization acknowledgment is mandatory:

```powershell
webchallscan https://challenge.example/ --authorized
webchallscan https://challenge.example/ --authorized --active --format text --color always
webchallscan https://challenge.example/ --authorized --profile mobile
webchallscan https://challenge.example/ --authorized --format json > report.json
```

Default mode sends `HEAD`, `OPTIONS`, and bounded `GET` requests. `--active` adds at most two low-impact requests per discovered candidate: a baseline and a validation probe. It can detect database error differentials, delimited shell arithmetic output, redirect behavior, and path-response differentials. Forms retain hidden/default fields and session cookies. Active mode still does not extract a flag. Review `Evidence`, `Exploit`, and `Flag path` before manually using a proposed recovery vector.

The default `--profile both` runs isolated desktop and mobile scans with separate cookie jars. Fixed browser headers include distinct user agents, `Sec-CH-UA-Mobile`, and platform values. The report tags every finding and summarizes status, body digest/length, form, parameter, and finding differences without printing response bodies. `--max-pages` and `--max-requests` apply to each profile.

Useful controls:

- `--max-pages 20`: deterministic crawl bound.
- `--max-requests 80`: hard request budget, including probes.
- `--timeout 5`: per-request timeout.
- `--insecure`: only for challenge servers with intentionally invalid TLS.
- `NO_COLOR=1`: disable automatic ANSI color.

## Scope and interpretation

- Exact scheme + host + port only. Cross-origin links and form actions are blocked.
- HTTP responses only. The scanner does not run JavaScript or emulate layout, touch events, service workers, or browser APIs. Client-side-only mobile behavior requires a browser engine and remains outside this version.
- URL fragments are removed; normalized URLs are visited once.
- Responses are capped at 1 MB.
- Cache bypass headers are sent and no response is stored after the process exits.
- A flag-shaped value from passive crawling is only a candidate: it can be a decoy or example. `flag-recovered` is reserved for a value returned by an explicit, verified recovery probe; this version never sends one automatically.
- A hypothesis is not a confirmed vulnerability. Low confidence means inspect and validate.

Exit code `0` means the scan completed without high/critical findings, `1` means high/critical evidence exists, `2` means invalid usage, and `3` means no page could be scanned.

## Tests

```powershell
py -m pytest
```

