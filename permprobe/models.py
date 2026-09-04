from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    EXISTS_DENIED = "EXISTS_DENIED"
    METHOD_BLOCKED = "METHOD_BLOCKED"
    REDIRECT = "REDIRECT"
    INFERRED = "INFERRED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class Capability(str, Enum):
    EXISTS = "EXISTS"
    LIST = "LIST"
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ACL_READ = "ACL_READ"
    POLICY_READ = "POLICY_READ"
    CORS = "CORS"
    METADATA = "METADATA"
    TAGS = "TAGS"
    MULTIPART = "MULTIPART"


@dataclass
class ProbeResult:
    action: str
    capability: str
    method: str
    url: str
    status: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    verdict: Verdict = Verdict.ERROR
    evidence: str = ""
    interesting_headers: dict = field(default_factory=dict)
    signed: bool = False
    mutated: bool = False
    elapsed_ms: float = 0.0
    note: str = ""
    origin: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


@dataclass
class ResourceReport:
    target: str
    kind: str  # s3 | gcs | azure | http
    resolved_url: str
    region: Optional[str] = None
    identity: str = "anonymous"
    probes: list[ProbeResult] = field(default_factory=list)
    capabilities: dict[str, str] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "resolved_url": self.resolved_url,
            "region": self.region,
            "identity": self.identity,
            "capabilities": self.capabilities,
            "findings": self.findings,
            "warnings": self.warnings,
            "probes": [p.to_dict() for p in self.probes],
        }
