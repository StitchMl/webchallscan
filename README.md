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
No active probes or POST replays are performed in this mode. It now also emits
`passive_findings` for observable response policy weaknesses (HSTS, CSP,
framing protections, MIME sniffing and conflicting CORS headers). These are
configuration signals, **not confirmed exploitable vulnerabilities**; no\nrequest/response bodies or sensitive header values are retained. The inventory
does not yet feed the existing active injection engine.

Chrome 136+ requires a non-default user-data directory for remote debugging.
Keep port 9222 bound to loopback and do not use this profile for sensitive
personal browsing. Do not expose CDP to another device or the internet.

### Offline Burp Suite XML history import

Export selected items from Burp Suite's HTTP history or Site Map as XML.
Import the local file without generating **any** requests or replaying POSTs:

```powershell
webchallscan --authorized --import-burp .\\history.xml --expect-origin https://challenge.example > burp-inventory.json
webchallscan --authorized --plan-inventory .\\burp-inventory.json --expect-origin https://challenge.example > audit-plan.json
```

The importer accepts up to 5 MB of XML and 500 items, rejects DTD/entity
declarations, and limits processing to one exact HTTP(S) origin. It retains
methods, paths, query **parameter names**, status codes, event counts, and
redacted response-header configuration signals. Request headers, cookies,
query values, raw response bodies and credentials are never included in output.
An item without a readable response is still inventoried but cannot contribute
header observations. Reports are planning evidence, not proofs of exploitation.
Store the original Burp export securely: it may contain live secrets.

### Offline audit plan from the observed endpoints

Turn any saved CDP inventory into a structured review plan without making
additional network requests:

```powershell
webchallscan --authorized --plan-inventory inventory.json > audit-plan.json
```

Optionally ensure that the inventory refers to the lab you intend to inspect:

```powershell
webchallscan --authorized --plan-inventory inventory.json --expect-origin https://challenge.example > audit-plan.json
```

The origin is *not* hardcoded: the inventory determines it, and `--expect-origin`
is a caller-supplied consistency check. The plan categorizes GraphQL operations,
authentication flows, endpoint parameters and state-changing methods. Each
planned check is marked `not-executed`; no vulnerability claim is produced
without real validation. This stage never replays captured HTTP traffic.

### Offline JWT metadata audit

Store a JWT from an authorized test in a private local file and run:

```bash
webchallscan --audit-jwt-file ./jwt.txt
```

This mode sends **zero network requests**. It parses the compact JWT header
and payload, reports algorithm and **claim names only**, and flags review
candidates such as `alg: none`, key-selection headers, HMAC configuration,
and authorization-related claims. Neither the token, signature, signing key,
header values nor claim values are included in output. It does **not**
validate signatures, try signing keys or claim that the server accepts a
modified token. Keep the input file private and delete it after review.
Unlike network scanning, this offline operation needs no `--authorized` flag.

### Bounded multi-syntax SSTI arithmetic checks

With `--active`, SSTI validation tries the existing Jinja/Twig
`{{7340*3}}` probe first. With the additional opt-in `--ssti-alternates`, the scanner may
also test `${7340*3}`, `<%= 7340*3 %>`, and `#{7340*3}`
(in that deterministic order). Alternate syntax needs **two identical
computed responses** absent from the baseline. Each probe pair respects
`--max-requests`; no destructive payloads or recovery attempts are sent.
Alternate-engine matches are validation-only observations that require
manual confirmation of the engine and exploitability. The extra probes are
**off by default** to preserve current request-budget priorities and scan results.

### Passive session cookie attributes

The existing response-header posture checks also inspect `Set-Cookie`
attributes for missing `Secure` on HTTPS, `HttpOnly`, and `SameSite`,
including the incompatible combination `SameSite=None` without `Secure`.
Cookie **names and values are never reported**, and these checks are
configuration hints rather than a claim that a cookie contains a session.
Imported Burp XML exports are also examined without extra requests.
When multiple Set-Cookie header lines are collapsed by a source, only the
available header value can be inspected; absence of a signal is not proof
of a safe session configuration.

### HTTP metadata and explicit GET JavaScript discovery

Existing `HEAD` and `OPTIONS` responses now produce informational notes
for the allowed HTTP methods in `Allow` and the presence of
`Server` / `X-Powered-By` banners. Their values and version strings
are not copied into findings. This requires no additional requests.

JavaScript static route detection also supports explicit GET calls in
`fetch(url, {method: 'GET'})`, `$.get`, `$.getJSON`,
`$.ajax({url, type: 'GET'})` and `axios({method: 'GET', url})`.
Non-GET calls are **not** converted into automatic scanner requests.

### Passive source-comment hints

HTML comments on visited pages and line/block comments in JavaScript files
already fetched by the crawler are inspected for review keywords such as
`TODO`, `FIXME`, `SECRET`, `PASSWORD`, `ADMIN`, and `DEBUG`.
Only keyword **categories** are included in the report; the comment text
and possible secrets are never copied to findings. These are informational
hints, not confirmed vulnerabilities. No additional network requests occur.

### Passive JavaScript source-map hints

When the crawler already fetches same-origin JavaScript assets linked from HTML,
it now inspects `sourceMappingURL` annotations in those responses. A valid
same-origin reference yields an informational `WEB-SOURCEMAP-HINT-001` finding.
The scanner **does not fetch the map**, read original source files, or claim
that source code is exposed. Map URLs and query secrets are not printed.
This check does not consume any extra request budget.

### Scan observed GET endpoints (opt-in)

An inventory produced by `--observe-network` or `--import-burp` can seed
an otherwise linkless SPA/API scanner. The origin of the explicit scan URL
must match the inventory exactly:

```powershell
webchallscan https://challenge.example/ --authorized --from-inventory .\\inventory.json --max-pages 20 --max-requests 80
webchallscan https://challenge.example/ --authorized --from-inventory .\\inventory.json --active --max-requests 80
```

Only same-origin **GET** paths are used (up to 20 discovery seeds).
Query values are never replayed; their parameter names receive a harmless
fixed placeholder (`WCSBASE`). Captured POST/PUT/PATCH/DELETE requests
are never replayed. Existing request/page budgets and session policies
remain in effect. This is explicit opt-in network scanning, unlike the
zero-request `--plan-inventory` mode. Inspect state-changing GET endpoints
before using it on any environment.

### Quick CTF workflow (no JSON setup)

With a dedicated Chrome CDP window on the intended lab tab, run:

```powershell
webchallscan --authorized --cdp http://127.0.0.1:9222 --quick > quick-report.json
```

Interact with the challenge during the 20-second capture. This one command
combines same-origin request discovery, passive HTTP policy findings and an
automatic endpoint review plan. No manually authored `contract.json` is
needed. The quick path **does not replay POST requests, fuzz inputs, or
confirm IDOR/business-logic vulnerabilities**: a redacted traffic inventory
cannot establish those conclusions. Advanced explicit-case validation remains
available separately when a challenge provides two controlled roles.

### Explicit read-only API / cross-role authorization checks

For an **authorized lab**, create a local JSON file containing test-resource
paths and the credentials of two lab accounts. Example structure (placeholders
only; do not commit real credentials):

```json
{
  "schema": "webchallscan/read-only-cases-v1",
  "origin": "https://lab.example",
  "cases": [
    {
      "path": "/api/test-resource-owned-by-a",
      "owner_headers": {"Authorization": "Bearer ROLE_A_TOKEN"},
      "other_headers": {"Authorization": "Bearer ROLE_B_TOKEN"}
    }
  ]
}
```

Run at most 12 two-role comparisons (24 requests), using GET exclusively:

```powershell
webchallscan --authorized --check-api-cases .\\cases.json --timeout 5 > access-results.json
```

The origin and resources are supplied by the operator: **no domain hardcoding**.
The checker does not enumerate IDs, replay captured requests, mutate resources,
or submit injection payloads. It reports response status, size, content type
and hash, but never includes credentials or response bodies. Matching successful
responses are labeled low-confidence **manual review candidates** rather than
confirmed IDOR findings; public or generic content can match legitimately.
Store case files securely and delete them after the exercise.

### Controlled API contracts: IDOR, input fuzz and logic invariants

Create a local `contract.json` using **owned lab test resources** and dedicated
test credentials. This mode uses GET only and at most 30 requests per run.
It does not enumerate identifiers, run exploitation payloads, or replay POST
operations; all origins are user-supplied and no lab is hardcoded.

```json
{
  "schema": "webchallscan/api-contract-v1",
  "origin": "https://your-lab.example",
  "roles": {
    "owner": {"Authorization": "Bearer OWNER_TEST_TOKEN"},
    "other": {"Authorization": "Bearer OTHER_TEST_TOKEN"}
  },
  "cases": [
    {
      "kind": "idor",
      "path": "/api/private-test-resource/123",
      "owner": "owner",
      "outsider": "other",
      "expected_marker": "OWNED_TEST_RESOURCE_123"
    },
    {
      "kind": "fuzz",
      "path": "/api/search",
      "role": "owner",
      "query": {"q": "test"},
      "parameter": "q"
    },
    {
      "kind": "business",
      "path": "/api/read-only-resource",
      "role": "other",
      "expected_statuses": [403, 404]
    }
  ]
}
```

```powershell
webchallscan --authorized --validate-api-contract .\\contract.json --timeout 5 > contract-results.json
```

IDOR is marked confirmed only if an explicitly designated **private test
resource marker** is returned to both roles. This verifies the observed
resource-access violation under the caller's ownership assumption, not the
whole authorization model. Fuzzing changes only the specified GET query
parameter using five bounded, non-destructive classes. An HTTP 5xx is an
investigation signal, not an injection confirmation. Business rules are
declarative **HTTP status invariants**, not automatic reasoning about
multi-step purchases or transactions. The report excludes tokens, cookies,
query values and raw response bodies. Keep test credentials out of version
control and remove the local contract after use.

### Burp Repeater procedure

Every finding contains a redacted replay block with method, request target,
form-field names, browser profile, cookie names, proof payload, expected
evidence, and a recovery payload only when it is proven. Instead of writing
importable request files, the scanner prints a manual, Community-friendly
procedure for Burp Repeater:

```powershell
webchallscan --authorized --listen-session --active --burp-procedure
```

For each reproducible finding it lists the request line and host, which
parameter to edit and where (query string or request body), the exact proof
payload and the response evidence that confirms it, and, when proven, the
recovery payload. Query values, hidden fields, CSRF values, and cookie values
stay hidden. Work entirely inside Burp Suite Community: capture the request in
**Proxy > HTTP history**, right-click **Send to Repeater**, edit the named
parameter to the printed payload, and send.

### Optional command-style CLI aliases

The legacy flag-based CLI is unchanged. The following aliases provide
a shorter interface while using the **same** validation and execution paths:

```bash
webchallscan scan https://challenge.example/ --authorized
webchallscan observe --cdp http://127.0.0.1:9222 --authorized
webchallscan contract ./contract.json --authorized
webchallscan replay https://challenge.example/ --authorized --active
```

`observe` defaults to a 20-second window, overridable with
`--observe-network SECONDS`. `replay` maps to the existing
`--burp-procedure` mode. Existing scripts without a subcommand still work.

### Export reproducible curl / Python snippets

To render **text only** for findings with high confidence and proof payloads:

```bash
webchallscan https://challenge.example/ --authorized --active --export-curl
webchallscan https://challenge.example/ --authorized --active --export-python
```

These flags are mutually exclusive with each other and with
`--burp-procedure`. They do not execute generated requests. Query values,
hidden POST defaults, and session cookies are replaced with
`[REDACTED]` placeholders; the specific proof payload is inserted only into
the reported parameter. Replace placeholders from your own authorized lab
session before running a snippet. Only URL-encoded form POSTs and GETs are
currently rendered.

To print a **redacted Raw HTTP/1.1 request template** alongside the existing
manual Repeater steps, add `--burp-raw`:

```powershell
webchallscan --authorized --listen-session --active --burp-procedure --burp-raw
```

This is a **template**, not an exact capture: query values, CSRF tokens,
hidden form defaults and cookie values are masked by default. The proven
probe value is placed into its parameter, and the form `Content-Length` is
recalculated. Replace redacted placeholders with the values from Burp's
live HTTP history before sending in Repeater. With `--include-session-secrets`,
the Cookie header and original non-probe query values can be printed; form
defaults remain redacted.

When a local replay must preserve the live authenticated session, print the
cookie values too:

```powershell
webchallscan --authorized --listen-session --active `
  --burp-procedure --include-session-secrets
```

Clear your terminal afterwards; the procedure then contains live session
cookies.

Default mode sends `HEAD`, `OPTIONS`, and bounded `GET` requests. Existing HTTP responses are inspected for passive header posture (HTML document policies and conflicting CORS settings) without additional requests. These signals are configuration observations, not exploit proofs. `--active` adds bounded validation requests within `--max-requests`. It tests every user-controlled form and query field for SQL, Jinja-style template evaluation, and reflected HTML/script injection instead of relying on parameter names. SQL confirmation requires either a new database error or two repeatable tautology/contradiction pairs after reflection removal. Template and command confirmation require a computed result absent from both the request payload and baseline. Reflected-XSS confirmation requires an unencoded `<...>` marker in an HTML response that is absent from the baseline. Sink-oriented names still guide command, path, and redirect probes. Forms retain hidden/default fields and session cookies. Active mode does not submit recovery payloads or extract a flag. Review `Evidence`, `Exploit`, and `Flag path` before manually using a proposed recovery vector.

The default `--profile both` runs isolated desktop and mobile scans with separate cookie jars. Fixed browser headers include distinct user agents, `Sec-CH-UA-Mobile`, and platform values. The report tags every finding and summarizes status, body digest/length, form, parameter, and finding differences without printing response bodies. `--max-pages` and `--max-requests` apply to each profile.

Useful controls:

To inspect scan traffic in Burp Suite Community, run `webchallscan https://challenge.example/ --authorized --proxy http://127.0.0.1:8080`. The optional `--proxy` accepts **only** an unauthenticated loopback HTTP proxy and applies to scanner requests, not offline inventory or API contract modes. Configure Burp to listen at that address. For HTTPS interception, trust Burp's CA in a dedicated test environment or explicitly opt into `--insecure` for disposable authorized challenges. Environment `NO_PROXY` can cause urllib to bypass the proxy for local targets; adjust it for your lab.



- `--max-pages 20`: deterministic crawl bound.
- `--max-requests 80`: hard request budget, including probes.
- `--timeout 5`: per-request timeout.
- `--session-wait 120`: extension capture timeout.
- `--burp-procedure`: print a manual Burp Repeater procedure instead of the report.
- `--insecure`: only for challenge servers with intentionally invalid TLS; applies to scanner, `--validate-api-contract` and `--check-api-cases` (TLS verification remains enabled by default).
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

