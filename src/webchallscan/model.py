from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any


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
    request_fields: tuple[tuple[str, str], ...] = ()

    @property
    def id(self) -> str:
        seed = f"{self.rule}\0{self.profile}\0{self.url}\0{self.parameter}\0{self.evidence}"
        return sha256(seed.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, **asdict(self)}


@dataclass
class ScanReport:
    target: str
    active: bool
    pages_scanned: int = 0
    requests_sent: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    profiles: tuple[str, ...] = ("desktop",)
    schema: str = "webchallscan/v2"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "target": self.target,
            "active": self.active,
            "profiles": list(self.profiles),
            "pages_scanned": self.pages_scanned,
            "requests_sent": self.requests_sent,
            "findings": [item.to_dict() for item in self.findings],
            "errors": self.errors,
        }

