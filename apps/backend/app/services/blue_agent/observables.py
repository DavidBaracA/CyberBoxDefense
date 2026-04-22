"""Semantic Blue-side observable events derived from normalized telemetry.

This layer sits between normalized TelemetryEvent rows and the higher-level
detectors/reasoners. It gives the Blue pipeline a cleaner, more thesis-friendly
representation of what was observed without exposing Red-side ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ...models import TelemetryEvent


@dataclass(frozen=True)
class SemanticObservableEvent:
    """One semantic observable derived from normalized telemetry."""

    observable_type: str
    event_id: str
    run_id: str | None
    app_id: str | None
    timestamp: str
    path: str | None
    http_status: int | None
    severity: str
    summary: str
    evidence: list[str]
    metadata: dict[str, Any]


def telemetry_text(event: TelemetryEvent) -> str:
    """Flatten normalized telemetry into one lowercase searchable text blob."""
    parts = [
        event.message,
        event.path or "",
        str(event.http_status or ""),
        str(event.service_name or ""),
        str(event.container_name or ""),
    ]
    for value in event.metadata.values():
        parts.append(str(value))
    return " ".join(parts).lower()


class SemanticTelemetryInterpreter:
    """Interpret normalized telemetry into cleaner semantic observable events."""

    def interpret(self, event: TelemetryEvent) -> list[SemanticObservableEvent]:
        observables: list[SemanticObservableEvent] = []
        lowered_path = (event.path or "").lower()
        lowered_text = telemetry_text(event)
        method = str(event.metadata.get("method", "")).upper()

        if "login" in lowered_path:
            if method == "POST" and event.http_status == 302:
                observables.append(
                    self._observable(
                        event,
                        "login_submit_redirect",
                        "Observed a login-form submission followed by redirect.",
                        [event.message],
                    )
                )
            elif event.http_status == 200:
                observables.append(
                    self._observable(
                        event,
                        "login_page_render",
                        "Observed login-page render or return to login form.",
                        [event.message],
                    )
                )

        if lowered_path.endswith("/index.php") and event.http_status == 200:
            observables.append(
                self._observable(
                    event,
                    "post_login_navigation",
                    "Observed navigation beyond the login page into the main application.",
                    [event.message],
                )
            )

        if event.http_status and event.http_status >= 500:
            observables.append(
                self._observable(
                    event,
                    "internal_error_response",
                    "Observed internal server error response from the target.",
                    [event.message],
                )
            )

        if any(marker in lowered_text for marker in ("<script", "javascript:", "onerror=", "alert(")):
            observables.append(
                self._observable(
                    event,
                    "xss_marker",
                    "Observed XSS-like marker in request-visible telemetry.",
                    [event.message],
                )
            )

        if any(marker in lowered_text for marker in ("../", "..\\", "%2e%2e%2f", "/etc/passwd", "win.ini")):
            observables.append(
                self._observable(
                    event,
                    "path_traversal_marker",
                    "Observed path-traversal-like marker in request-visible telemetry.",
                    [event.message],
                )
            )

        if any(marker in lowered_text for marker in ("union select", "sleep(", "benchmark(", "information_schema", "' or '1'='1")):
            observables.append(
                self._observable(
                    event,
                    "sqli_marker",
                    "Observed SQL-injection-like marker in request-visible telemetry.",
                    [event.message],
                )
            )

        if not observables:
            observables.append(
                self._observable(
                    event,
                    "http_request_observed",
                    "Observed routine HTTP/application activity from the target.",
                    [event.message],
                )
            )
        return observables

    def interpret_many(self, events: Iterable[TelemetryEvent]) -> list[SemanticObservableEvent]:
        """Interpret a sequence of normalized telemetry events."""
        observables: list[SemanticObservableEvent] = []
        for event in events:
            observables.extend(self.interpret(event))
        return observables

    def _observable(
        self,
        event: TelemetryEvent,
        observable_type: str,
        summary: str,
        evidence: list[str],
    ) -> SemanticObservableEvent:
        return SemanticObservableEvent(
            observable_type=observable_type,
            event_id=event.event_id,
            run_id=event.run_id,
            app_id=event.app_id,
            timestamp=event.timestamp.isoformat(),
            path=event.path,
            http_status=event.http_status,
            severity=event.severity.value,
            summary=summary,
            evidence=evidence,
            metadata={
                "source_type": event.source_type,
                "kind": event.kind.value,
                "service_name": event.service_name,
                "container_name": event.container_name,
            },
        )


def serialize_observable(event: SemanticObservableEvent) -> dict[str, Any]:
    """Convert one semantic observable into a graph-friendly dictionary."""
    return {
        "observable_type": event.observable_type,
        "event_id": event.event_id,
        "run_id": event.run_id,
        "app_id": event.app_id,
        "timestamp": event.timestamp,
        "path": event.path,
        "http_status": event.http_status,
        "severity": event.severity,
        "summary": event.summary,
        "evidence": list(event.evidence),
        "metadata": dict(event.metadata),
    }
