from __future__ import annotations

import re
import ssl
from collections import deque
from http.cookiejar import CookieJar
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, Request, build_opener

from .model import Finding, ScanReport

CMD_PROBE = ";printf WCSA;printf $((7321+19));printf WCSZ"
CMD_RESULT = "WCSA7340WCSZ"
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


@dataclass
class Form:
    action: str
    method: str
    inputs: list[tuple[str, str, str]] = field(default_factory=list)


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag.lower() == "form":
            self._form = Form(data.get("action", ""), data.get("method", "get").upper())
            self.forms.append(self._form)
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
                 timeout: float = 5.0, max_requests: int = 80, verify_tls: bool = True) -> None:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target must be an absolute http:// or https:// URL")
        self.target = self._clean_url(target)
        self.origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self.active = active
        self.max_pages = max(1, max_pages)
        self.timeout = max(0.1, timeout)
        self.max_requests = max(1, max_requests)
        self.requests_sent = 0
        context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.cookies = CookieJar()
        self.opener = build_opener(
            SameOriginRedirectHandler(self.origin),
            HTTPCookieProcessor(self.cookies),
            HTTPSHandler(context=context),
        )

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
            "User-Agent": "webchallscan/0.1 (+authorized-ctf)",
            "Accept": "text/html,application/json,text/plain,*/*;q=0.5",
            "Cache-Control": "no-store, no-cache, max-age=0",
            "Pragma": "no-cache",
        }
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

    def _finding(self, **kwargs: str) -> Finding:
        return Finding(**kwargs)

    def _passive_findings(self, response: Response, parser: PageParser) -> list[Finding]:
        out: list[Finding] = []
        low = response.text.lower()
        if any(token in low for token in DEBUG_ERRORS):
            out.append(self._finding(rule="WEB-DEBUG-001", title="Debug or stack-trace disclosure",
                severity="medium", confidence="high", url=response.url,
                evidence="The response contains a deterministic debug/stack-trace signature.",
                vector=f"GET {response.url}",
                patch="Disable production debug mode; return generic errors and keep traces in server-side logs."))
        if re.search(r"<title>\s*index of /", response.text, re.I):
            out.append(self._finding(rule="WEB-LIST-001", title="Directory listing exposed",
                severity="medium", confidence="high", url=response.url,
                evidence="HTML title matches an automatic directory index.", vector=f"GET {response.url}",
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
                vector=f"GET {response.url} and verify that the value is accepted by the challenge.",
                flag_path="The value may be a decoy, example, or real flag. Passive text alone cannot distinguish them.",
                patch="Remove secrets from public responses and enforce authorization at the data boundary."))
        for form in parser.forms:
            names = [name for name, _, _ in form.inputs]
            defaults = tuple((name, value) for name, input_type, value in form.inputs
                             if input_type not in {"submit", "button", "image", "reset", "file"})
            action = self._clean_url(urljoin(response.url, form.action or response.url))
            if not self._in_scope(action):
                continue
            for name in names:
                out.extend(self._parameter_hypotheses(action, form.method, name, defaults))
        for name, _ in parse_qsl(urlsplit(response.url).query, keep_blank_values=True):
            out.extend(self._parameter_hypotheses(response.url, "GET", name, tuple(parse_qsl(urlsplit(response.url).query, keep_blank_values=True))))
        return out

    def _parameter_hypotheses(self, url: str, method: str, name: str,
                              defaults: tuple[tuple[str, str], ...] = ()) -> list[Finding]:
        key = name.lower()
        rules = []
        if re.search(r"(?:^|_)(?:id|q|query|search|user|name|item)(?:$|_)", key):
            rules.append(("WEB-SQLI-001", "Possible SQL injection input", "'", "Use a parameterized query; never concatenate input into SQL."))
        if re.search(r"(?:^|_)(?:cmd|command|exec|host|ip|ping)(?:$|_)", key):
            rules.append(("WEB-CMDI-001", "Possible command injection input", CMD_PROBE, "Avoid shell invocation; use fixed argument arrays and strict allowlists."))
        if re.search(r"(?:^|_)(?:file|path|page|include|template|view)(?:$|_)", key):
            rules.append(("WEB-FILE-001", "Possible file/path injection input", "../WCS_NONEXISTENT", "Map identifiers to fixed server-side resources; canonicalize and enforce a root."))
        if re.search(r"(?:^|_)(?:next|url|uri|redirect|return|continue)(?:$|_)", key):
            rules.append(("WEB-REDIR-001", "Possible open redirect or server-side URL input", "https://example.invalid/wcs", "Allowlist destinations and reject absolute or cross-origin URLs."))
        return [self._finding(rule=rule, title=title, severity="info", confidence="low", url=url,
            parameter=name, evidence=f"Parameter name '{name}' in a {method} form/query matches a sink-oriented heuristic; no vulnerability is claimed.",
            vector=f"{method} {url} with {name}={payload!r}", patch=patch,
            method=method, request_fields=defaults) for rule, title, payload, patch in rules]

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
                vector=f"{method} {finding.url} with {finding.parameter}=' confirms parser reachability; derive a DB-specific read-only UNION/boolean payload manually.",
                patch="Use prepared statements with bound parameters and a least-privileged database account.",
                flag_path="The parameter reaches a SQL parser. Recovering the flag still requires schema/context discovery; this scan does not extract data.")
        if finding.rule == "WEB-CMDI-001" and CMD_RESULT in tested.text and CMD_RESULT not in baseline.text and CMD_RESULT not in CMD_PROBE:
            recovery = ";printf WCSA;cat /flag 2>/dev/null || cat /flag.txt 2>/dev/null;printf WCSZ"
            return self._finding(rule=finding.rule, title="Command injection arithmetic execution confirmed", severity="critical", confidence="high",
                url=finding.url, parameter=finding.parameter,
                evidence=f"The response contains delimited computed output {CMD_RESULT}; that result is absent from both payload and baseline.",
                vector=f"Proof: {method} {finding.url} with {finding.parameter}={CMD_PROBE!r}. Recovery: same request with {finding.parameter}={recovery!r}.",
                patch="Remove shell execution; call the intended program with a fixed argument vector and allowlisted values.",
                exploit_status="payload-ready",
                flag_path=f"The verified shell syntax supports the recovery payload for {finding.parameter}; the scanner does not submit it automatically.",
                method=method, request_fields=finding.request_fields)
        location = tested.headers.get("location", "")
        if finding.rule == "WEB-REDIR-001" and location and urlsplit(urljoin(finding.url, location)).netloc == "example.invalid":
            return self._finding(rule=finding.rule, title="Cross-origin redirect confirmed", severity="medium", confidence="high",
                url=finding.url, parameter=finding.parameter,
                evidence="The response navigation reaches the supplied external origin.", vector=f"Set {finding.parameter}=https://example.invalid/wcs",
                patch="Resolve redirects against a strict same-origin path allowlist.")
        if finding.rule == "WEB-FILE-001" and tested.status != baseline.status:
            return self._finding(rule=finding.rule, title="Path input changes resource behavior", severity="low", confidence="medium",
                url=finding.url, parameter=finding.parameter,
                evidence=f"A traversal-shaped nonexistent path changes HTTP status {baseline.status} -> {tested.status}; no file was read.",
                vector=f"Set {finding.parameter}=../WCS_NONEXISTENT_7f31a9 to reproduce the differential.", patch=finding.patch)
        return None

    def scan(self) -> ScanReport:
        report = ScanReport(self.target, self.active)
        queue = deque([self.target])
        seen: set[str] = set()
        successful_pages = 0
        candidates: list[Finding] = []
        try:
            self._request(self.target, "HEAD")
            self._request(self.target, "OPTIONS")
        except (URLError, OSError, RuntimeError, ValueError) as exc:
            report.errors.append(f"metadata request: {exc}")
        while queue and len(seen) < self.max_pages and self.requests_sent < self.max_requests:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                response = self._request(url)
            except (URLError, OSError, RuntimeError, ValueError) as exc:
                report.errors.append(f"{url}: {exc}")
                continue
            successful_pages += 1
            parser = PageParser()
            ctype = response.headers.get("content-type", "")
            if "html" in ctype or "<html" in response.text[:500].lower():
                parser.feed(response.text)
            items = self._passive_findings(response, parser)
            report.findings.extend(items)
            candidates.extend(item for item in items if item.rule in {"WEB-SQLI-001", "WEB-CMDI-001", "WEB-FILE-001", "WEB-REDIR-001"})
            for href in parser.links:
                nxt = self._clean_url(urljoin(response.url, href))
                if self._in_scope(nxt) and nxt not in seen and nxt not in queue:
                    queue.append(nxt)
        if self.active:
            for finding in candidates:
                if self.requests_sent + 2 > self.max_requests:
                    break
                try:
                    confirmed = self._active_probe(finding)
                    if confirmed:
                        report.findings.append(confirmed)
                except (URLError, OSError, RuntimeError, ValueError) as exc:
                    report.errors.append(f"active {finding.url}#{finding.parameter}: {exc}")
        unique = {item.id: item for item in report.findings}
        severity = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report.findings = sorted(unique.values(), key=lambda f: (severity.get(f.severity, 9), f.url, f.rule, f.parameter, f.id))
        report.pages_scanned = successful_pages
        report.requests_sent = self.requests_sent
        return report
