from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"


def redact_url(url: str) -> str:
    """Keep route and parameter names while removing query values and fragments."""
    parsed = urlsplit(url)
    query = urlencode([(name, REDACTED) for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


@dataclass(frozen=True)
class Finding:
    rule: str
    title: str
    severity: str
    confidence: str
    url: str
    profile: str = "desktop"
    parameter: str = ""
    evidence: str = ""
    vector: str = ""
    patch: str = ""
    exploit_status: str = "validation-only"
    flag_path: str = "Manual validation is required before a flag-recovery request exists."
    method: str = "GET"
    request_fields: tuple[tuple[str, str], ...] = field(default_factory=tuple, repr=False)
    content_type: str = "application/x-www-form-urlencoded"
    client_headers: tuple[tuple[str, str], ...] = ()
    session_cookies: tuple[tuple[str, str], ...] = field(default_factory=tuple, repr=False)
    proof_payload: str = ""
    expected_evidence: str = ""
    recovery_payload: str = ""

    @property
    def id(self) -> str:
        seed = f"{self.rule}\0{self.profile}\0{self.url}\0{self.parameter}\0{self.evidence}"
        return sha256(seed.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        public = asdict(self)
        public.pop("request_fields", None)
        public.pop("session_cookies", None)
        public["url"] = redact_url(self.url)
        parsed = urlsplit(self.url)
        public["replay"] = {
            "method": self.method,
            "path": parsed.path or "/",
            "query": [{"name": name, "value": REDACTED} for name, _ in parse_qsl(parsed.query, keep_blank_values=True)],
            "body": [{"name": name, "value": REDACTED} for name, _ in self.request_fields] if self.method == "POST" else [],
            "content_type": self.content_type if self.method == "POST" else "",
            "client_headers": dict(self.client_headers),
            "cookie_names": sorted({name for name, _ in self.session_cookies}),
            "proof_payload": self.proof_payload,
            "expected_evidence": self.expected_evidence,
            "recovery_request": (
                {"parameter": self.parameter, "payload": self.recovery_payload}
                if self.exploit_status == "payload-ready" and self.recovery_payload else None
            ),
        }
        return {"id": self.id, **public}


@dataclass
class ScanReport:
    target: str
    active: bool
    pages_scanned: int = 0
    requests_sent: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    profiles: tuple[str, ...] = ("desktop",)
    session_source: str = "none"
    schema: str = "webchallscan/v3"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "target": redact_url(self.target),
            "active": self.active,
            "profiles": list(self.profiles),
            "session_source": self.session_source,
            "pages_scanned": self.pages_scanned,
            "requests_sent": self.requests_sent,
            "findings": [item.to_dict() for item in self.findings],
            "errors": [redact_url(value) if "://" in value else value for value in self.errors],
        }

