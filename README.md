# webchallscan

Deterministic, offline/no-AI black-box analysis for **authorized CTF Jeopardy web challenges** when backend source is unavailable. It accepts a URL, stays on the exact origin, crawls with fixed budgets, extracts forms and parameters, records evidence, and prints tailored validation vectors and defensive patches.

It does not promise complete coverage. Passive parameter-name matches are labeled `validation-only`. `payload-ready` appears only after an active marker produces target-derived evidence. The scanner does not brute-force credentials, enumerate the Internet, submit destructive requests, or automatically retrieve protected data or flags.

## Install

```powershell
py -m pip install -e C:\Users\matte\Desktop\webchallscan
webchallscan --help
```

No virtual environment is required. Runtime uses only Python's standard library and keeps no cache.
JSON reports use the `webchallscan/v3` schema; every finding includes its
desktop, mobile, or comparison profile.

## Use

Authorization acknowledgment is mandatory:

```powershell
webchallscan https://challenge.example/ --authorized
webchallscan https://challenge.example/ --authorized --active --format text --color always
webchallscan https://challenge.example/ --authorized --profile mobile
webchallscan https://challenge.example/ --authorized --format json > report.json
```

### Current browser session

For a normally opened Chrome or Edge window, load the bundled unpacked
extension. Locate it with `webchallscan --extension-path`, open
`chrome://extensions` or `edge://extensions`, enable Developer mode, and choose
**Load unpacked**. Then run:

```powershell
webchallscan --authorized --listen-session --active
```

The CLI prints a loopback endpoint and one-shot token. Keep the intended
challenge tab active, open the extension, paste both values, and click
**Capture active tab**. The scan starts from that exact URL with its current
cookies, including `HttpOnly` cookies. The listener accepts one capture, keeps
it only in memory, and sends nothing over the Internet.

If Chrome or Edge was started with a local DevTools port, the CLI can attach
without the extension:

```powershell
webchallscan --authorized --browser-session auto --active
webchallscan --authorized --cdp http://127.0.0.1:9222 --active
```

A normally opened browser does not expose DevTools; use the extension in that
case. `--session-file session.json` is also supported for the documented local
JSON format. Session files contain credentials and should be protected and
deleted after use.

### Read-only live network inventory (Chrome DevTools)

The cookie-capture extension cannot see live Fetch/XHR requests. To observe
real browser traffic on an authorized test environment, start a **separate**
Chrome instance with a dedicated debugging profile (Windows PowerShell):

```powershell
& "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --remote-debugging-port=9222 --user-data-dir="$env:TEMP\\webchallscan-cdp"
```

Log into your authorized test app in that Chrome window, select its tab,
then start the inventory from PowerShell:

```powershell
webchallscan --authorized --cdp http://127.0.0.1:9222 --observe-network 30 --observe-limit 500 > inventory.json
```

**While the 30-second observation is running**, refresh the target page and
use its features. The output inventories same-origin URL paths, query
parameter **names**, HTTP methods, event counts, Chrome resource types and
response status codes (including POST /graphql). It deliberately never
records request/response bodies, headers, cookies, or parameter **values**.
No active probes or POST replays are performed in this mode. It does **not**
produce vulnerability findings or feed the existing scan engine yet.

Chrome 136+ requires a non-default user-data directory for remote debugging.
Keep port 9222 bound to loopback and do not use this profile for sensitive
personal browsing. Do not expose CDP to another device or the internet.

### Burp Repeater context

Every finding contains a redacted replay block with method, request target,
form-field names, browser profile, cookie names, proof payload, expected
evidence, and a recovery payload only when it is proven. Export one raw HTTP
request per proof/recovery action:

```powershell
webchallscan --authorized --listen-session --active --burp-output .\burp-requests
```

The default files redact query values, hidden fields, CSRF values, and cookies.
For a local replay that must preserve the live authenticated session, opt in:

```powershell
webchallscan --authorized --listen-session --active `
  --burp-output .\burp-private --include-session-secrets
```

The output directory must not already exist. Secret-bearing files are never
created implicitly; protect and delete them after use.

Burp Suite Community does not need a saved project for Repeater. After an
initial scan, copy one proof or recovery request directly to the clipboard:

```powershell
webchallscan --authorized --listen-session --active `
  --burp-request first-ready --include-session-secrets | Set-Clipboard
```

Then use **Paste from clipboard** in Repeater. Omit
`--include-session-secrets` for a redacted template. Clear the clipboard after
using a live session request. `first-ready` selects the first proven recovery
request in stable report order; `first-proof` selects the first validation
request. A specific `FINDING_ID:proof` or `FINDING_ID:recovery` is also accepted.

Default mode sends `HEAD`, `OPTIONS`, and bounded `GET` requests. `--active` adds bounded validation requests within `--max-requests`. It tests every user-controlled form and query field for SQL and Jinja-style template evaluation instead of relying on parameter names. SQL confirmation requires either a new database error or two repeatable tautology/contradiction pairs after reflection removal. Template and command confirmation require a computed result absent from both the request payload and baseline. Sink-oriented names still guide command, path, and redirect probes. Forms retain hidden/default fields and session cookies. Active mode does not submit recovery payloads or extract a flag. Review `Evidence`, `Exploit`, and `Flag path` before manually using a proposed recovery vector.

The default `--profile both` runs isolated desktop and mobile scans with separate cookie jars. Fixed browser headers include distinct user agents, `Sec-CH-UA-Mobile`, and platform values. The report tags every finding and summarizes status, body digest/length, form, parameter, and finding differences without printing response bodies. `--max-pages` and `--max-requests` apply to each profile.

Useful controls:

- `--max-pages 20`: deterministic crawl bound.
- `--max-requests 80`: hard request budget, including probes.
- `--timeout 5`: per-request timeout.
- `--session-wait 120`: extension capture timeout.
- `--burp-output DIR`: create raw proof/recovery requests for Burp Repeater.
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
- Probe order is fixed (command, template, SQL, path, redirect), so a tight request budget produces the same partial result on each run.

Exit code `0` means the scan completed without high/critical findings, `1` means high/critical evidence exists, `2` means invalid usage, and `3` means no page could be scanned.

## Tests

```powershell
py -m pytest
```

