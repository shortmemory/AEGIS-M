from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeResult:
    probe_id: str
    category: str
    title: str
    status: str
    request_sha256: str
    response_sha256: str | None = None
    latency_ms: int | None = None
    findings: list[Finding] = field(default_factory=list)
    response_excerpt: Any = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

