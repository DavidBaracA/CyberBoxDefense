"""Safe open-redirect probe for controlled cyber-range targets.

The probe never follows redirects. It only checks whether bounded requests cause
the target to point at documentation/test domains supplied by the probe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from .http_client import UrllibAsyncHttpClient
from .models import AsyncHttpClient, HttpResponse, ProbeFinding, ProbeResult, RawHttpMetadata


PROBE_NAME = "open_redirect_probe"
COMMON_PATHS = ("/redirect", "/login", "/logout", "/next", "/return", "/callback", "/continue")
COMMON_PARAMETERS = (
    "next",
    "url",
    "target",
    "redirect",
    "redirect_uri",
    "return",
    "returnUrl",
    "return_to",
    "continue",
    "destination",
    "goto",
)
REDIRECT_PAYLOADS = (
    "https://example.com/",
    "//example.com/",
    "https://evil.example/",
    "/\\example.com",
    "https:%2f%2fexample.com%2f",
)
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
REMEDIATION = (
    "Use relative paths only, allow-list redirect destinations, map redirect IDs "
    "server-side, validate scheme and host, and show an interstitial warning for "
    "external destinations."
)


@dataclass(frozen=True)
class RedirectCandidate:
    url: str
    parameter: str


@dataclass(frozen=True)
class OpenRedirectProbeConfig:
    urls: tuple[str, ...] = ()
    paths: tuple[str, ...] = COMMON_PATHS
    parameters: tuple[str, ...] = COMMON_PARAMETERS
    payloads: tuple[str, ...] = REDIRECT_PAYLOADS
    timeout: float = 5.0
    max_requests: int = 120


def normalize_redirect_location(target_url: str, location: str) -> Optional[str]:
    """Resolve a Location value and return an absolute URL when it is external."""
    if not location:
        return None
    resolved = urljoin(target_url, location.strip())
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return resolved


def is_external_redirect(target_url: str, location: str) -> bool:
    """Return true only when a redirect leaves the target host."""
    resolved = normalize_redirect_location(target_url, location)
    if not resolved:
        return False
    target_host = (urlparse(target_url).hostname or "").lower()
    redirect_host = (urlparse(resolved).hostname or "").lower()
    return bool(redirect_host and target_host and redirect_host != target_host)


def build_candidate_url(base_url: str, path_or_url: str, parameter: str, payload: str) -> str:
    candidate_url = urljoin(base_url, path_or_url)
    parsed = urlparse(candidate_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[parameter] = payload
    return urlunparse(parsed._replace(query=urlencode(query)))


def discover_redirect_candidates(base_url: str, config: OpenRedirectProbeConfig) -> list[RedirectCandidate]:
    """Build a conservative candidate list from configured URLs or common paths."""
    configured = config.urls or tuple(urljoin(base_url, path) for path in config.paths)
    candidates: list[RedirectCandidate] = []
    for item in configured:
        parsed = urlparse(urljoin(base_url, item))
        existing_params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        parameters = existing_params or list(config.parameters)
        for parameter in parameters:
            candidates.append(RedirectCandidate(url=urlunparse(parsed._replace(query="")), parameter=parameter))
    return candidates


def detect_client_side_redirect(target_url: str, body: str) -> Optional[str]:
    """Conservatively detect obvious meta-refresh or JS location redirects."""
    patterns = (
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
        r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, body or "", flags=re.IGNORECASE)
        if match and is_external_redirect(target_url, match.group(1)):
            return normalize_redirect_location(target_url, match.group(1))
    return None


def _raw_metadata(method: str, url: str, response: HttpResponse) -> RawHttpMetadata:
    return RawHttpMetadata(
        method=method,
        url=url,
        status_code=response.status_code,
        headers=dict(response.headers),
        redirect_location=response.headers.get("Location") or response.headers.get("location"),
        response_size=response.response_size,
    )


class OpenRedirectProbe:
    """Bounded open-redirect probe with redirects explicitly disabled."""

    name = PROBE_NAME

    def __init__(
        self,
        config: Optional[OpenRedirectProbeConfig] = None,
        client: Optional[AsyncHttpClient] = None,
    ) -> None:
        self.config = config or OpenRedirectProbeConfig()
        self.client = client or UrllibAsyncHttpClient()

    async def run(self, target_url: str) -> ProbeResult:
        result = ProbeResult(probe_name=self.name, target_url=target_url)
        requests_sent = 0
        for candidate in discover_redirect_candidates(target_url, self.config):
            for payload in self.config.payloads:
                if requests_sent >= self.config.max_requests:
                    return result
                tested_url = build_candidate_url(target_url, candidate.url, candidate.parameter, payload)
                try:
                    response = await self.client.request(
                        "GET",
                        tested_url,
                        timeout=self.config.timeout,
                        follow_redirects=False,
                    )
                except Exception as exc:  # pragma: no cover - transport-specific
                    result.errors.append(f"{tested_url}: {exc}")
                    continue

                requests_sent += 1
                raw = _raw_metadata("GET", tested_url, response)
                location = raw.redirect_location or ""
                if response.status_code in REDIRECT_STATUSES and is_external_redirect(target_url, location):
                    resolved = normalize_redirect_location(target_url, location) or location
                    result.findings.append(
                        ProbeFinding(
                            probe_name=self.name,
                            target_url=target_url,
                            severity="medium",
                            confidence=0.92,
                            category="navigation_flow",
                            cwe="CWE-601",
                            description="The target reflected an untrusted redirect destination into the Location header.",
                            evidence={
                                "tested_url": tested_url,
                                "parameter": candidate.parameter,
                                "payload": payload,
                                "http_status": response.status_code,
                                "location": location,
                                "resolved_external_host": urlparse(resolved).hostname,
                            },
                            remediation=REMEDIATION,
                            raw_http=[raw],
                        )
                    )
                    continue

                client_side_url = detect_client_side_redirect(target_url, response.text)
                if client_side_url:
                    result.findings.append(
                        ProbeFinding(
                            probe_name=self.name,
                            target_url=target_url,
                            severity="low",
                            confidence=0.7,
                            category="navigation_flow",
                            cwe="CWE-601",
                            description="The response body contained a client-side redirect to an untrusted host.",
                            evidence={
                                "tested_url": tested_url,
                                "parameter": candidate.parameter,
                                "payload": payload,
                                "http_status": response.status_code,
                                "resolved_external_host": urlparse(client_side_url).hostname,
                            },
                            remediation=REMEDIATION,
                            raw_http=[raw],
                        )
                    )
        return result
