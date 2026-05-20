"""Shared structured result models for bounded Red-agent probes."""

from __future__ import annotations

from typing import Any, Mapping, Optional, Protocol

from pydantic import BaseModel, Field


class RawHttpMetadata(BaseModel):
    """Safe request/response metadata captured without storing secrets."""

    method: str
    url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    redirect_location: Optional[str] = None
    response_size: int = 0


class ProbeFinding(BaseModel):
    """One structured vulnerability finding emitted by a safe probe."""

    probe_name: str
    target_url: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    category: str
    cwe: Optional[str] = None
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str
    raw_http: list[RawHttpMetadata] = Field(default_factory=list)


class ProbeResult(BaseModel):
    """Result for one bounded probe execution."""

    probe_name: str
    target_url: str
    ok: bool = True
    findings: list[ProbeFinding] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class HttpResponse(BaseModel):
    """Minimal HTTP response abstraction used by probes and tests."""

    status_code: int
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    text: str = ""
    content: bytes = b""

    @property
    def response_size(self) -> int:
        return len(self.content or self.text.encode("utf-8", errors="ignore"))


class AsyncHttpClient(Protocol):
    """Protocol for bounded async HTTP clients used by probe modules."""

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: float = 5.0,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        ...
