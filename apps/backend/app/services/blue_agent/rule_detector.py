"""Deterministic rule-based Blue-side detector over normalized telemetry.

The detector operates only on normalized TelemetryEvent records and keeps a
small sliding window per run so detections can be correlated without requiring
LLM reasoning.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from typing import Deque, Iterable, Optional

from ...models import DetectionEvent, Severity, TelemetryEvent
from .observables import SemanticObservableEvent, SemanticTelemetryInterpreter, telemetry_text


SQLI_PATTERNS = (
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "union select",
    "information_schema",
    "sleep(",
    "benchmark(",
    "order by",
    "select * from",
)
XSS_PATTERNS = (
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "<img",
)
PATH_TRAVERSAL_PATTERNS = (
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "..%5c",
    "/etc/passwd",
    "win.ini",
)
LOGIN_PATH_HINTS = ("login", "signin", "auth", "session", "account")
LOGIN_FAILURE_HINTS = ("invalid", "unauthorized", "forbidden", "login failed", "authentication failed")
DETECTION_COOLDOWN_SECONDS = 30


@dataclass(frozen=True)
class RuleMatch:
    """Internal rule match payload before a DetectionEvent is emitted."""

    classification: str
    confidence: float
    severity: Severity
    summary: str
    supporting_evidence: list[str]
    evidence_event_ids: list[str]
    signature: str

def contains_any(text: str, patterns: Iterable[str]) -> bool:
    """Return true when any candidate pattern appears in the text."""
    return any(pattern in text for pattern in patterns)


def is_login_related(event: TelemetryEvent) -> bool:
    """Return true when a telemetry event likely concerns login/auth."""
    text = telemetry_text(event)
    return contains_any(text, LOGIN_PATH_HINTS)


def is_login_failure(event: TelemetryEvent) -> bool:
    """Return true when a telemetry event likely represents failed auth."""
    text = telemetry_text(event)
    if event.http_status in {401, 403, 429}:
        return True
    return contains_any(text, LOGIN_FAILURE_HINTS)


def is_login_post_redirect(event: TelemetryEvent) -> bool:
    """Return true for login-form POST redirects common in apps like DVWA."""
    return bool(event.path and "login" in event.path.lower() and event.http_status == 302 and "post " in event.message.lower())


def is_post_login_navigation(event: TelemetryEvent) -> bool:
    """Return true when telemetry suggests navigation past the login form."""
    path = (event.path or "").lower()
    return path not in {"", "/", "/login", "/login.php"} and event.http_status == 200


def dedupe_preserve_order(values: list[str]) -> list[str]:
    """Deduplicate string values while keeping their original order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


class RuleBasedBlueDetector:
    """Deterministic sliding-window detector over normalized telemetry."""

    def __init__(
        self,
        *,
        window_seconds: int = 60,
        burst_threshold: int = 3,
        brute_force_threshold: int = 5,
    ) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._burst_threshold = burst_threshold
        self._brute_force_threshold = brute_force_threshold
        self._events_by_run_id: dict[str, Deque[TelemetryEvent]] = defaultdict(deque)
        self._last_emitted_at: dict[str, datetime] = {}
        self._interpreter = SemanticTelemetryInterpreter()
        self._lock = threading.RLock()

    def process_event(self, event: TelemetryEvent) -> list[DetectionEvent]:
        """Update the sliding window and emit zero or more deterministic detections."""
        if not event.run_id:
            return []

        with self._lock:
            window = self._events_by_run_id[event.run_id]
            window.append(event.model_copy(deep=True))
            self._prune(window, anchor=event.timestamp)
            matches = self._evaluate_window(list(window))
            detections: list[DetectionEvent] = []
            for match in matches:
                if not self._should_emit(match.signature, event.timestamp):
                    continue
                self._last_emitted_at[match.signature] = event.timestamp
                detections.append(
                    DetectionEvent(
                        run_id=event.run_id,
                        detector="rule_based_blue_detector",
                        classification=match.classification,
                        confidence=match.confidence,
                        severity=match.severity,
                        summary=match.summary,
                        supporting_evidence=match.supporting_evidence,
                        evidence_event_ids=match.evidence_event_ids,
                        metadata={
                            "app_id": event.app_id,
                            "window_seconds": int(self._window.total_seconds()),
                            "source": "rule_based_blue_detector",
                        },
                    )
                )
            return detections

    def _prune(self, window: Deque[TelemetryEvent], *, anchor: datetime) -> None:
        cutoff = anchor - self._window
        while window and window[0].timestamp < cutoff:
            window.popleft()

    def _should_emit(self, signature: str, now: datetime) -> bool:
        last_emitted = self._last_emitted_at.get(signature)
        if last_emitted is None:
            return True
        return (now - last_emitted).total_seconds() >= DETECTION_COOLDOWN_SECONDS

    def _evaluate_window(self, events: list[TelemetryEvent]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        if not events:
            return matches

        observables = self._interpreter.interpret_many(events)

        direct_rules = (
            self._detect_suspected_sql_injection(events),
            self._detect_suspected_xss(events),
            self._detect_suspected_path_traversal(events),
            self._detect_brute_force(events, observables),
            self._detect_internal_error_burst(events),
        )
        for match in direct_rules:
            if match:
                matches.append(match)
        return matches

    def _detect_suspected_sql_injection(self, events: list[TelemetryEvent]) -> Optional[RuleMatch]:
        evidence = [event for event in events if contains_any(telemetry_text(event), SQLI_PATTERNS)]
        if not evidence:
            return None
        ids = dedupe_preserve_order([event.event_id for event in evidence])[:10]
        lines = dedupe_preserve_order([event.message for event in evidence])[:3]
        return RuleMatch(
            classification="suspected_sql_injection",
            confidence=min(0.98, 0.7 + (0.08 * len(evidence))),
            severity=Severity.HIGH,
            summary="Observed SQL-injection-like request patterns in normalized telemetry.",
            supporting_evidence=lines,
            evidence_event_ids=ids,
            signature=f"sqli:{','.join(ids)}",
        )

    def _detect_suspected_xss(self, events: list[TelemetryEvent]) -> Optional[RuleMatch]:
        evidence = [event for event in events if contains_any(telemetry_text(event), XSS_PATTERNS)]
        if not evidence:
            return None
        ids = dedupe_preserve_order([event.event_id for event in evidence])[:10]
        lines = dedupe_preserve_order([event.message for event in evidence])[:3]
        return RuleMatch(
            classification="suspected_xss",
            confidence=min(0.97, 0.68 + (0.08 * len(evidence))),
            severity=Severity.HIGH,
            summary="Observed XSS-like payload markers in normalized telemetry.",
            supporting_evidence=lines,
            evidence_event_ids=ids,
            signature=f"xss:{','.join(ids)}",
        )

    def _detect_suspected_path_traversal(self, events: list[TelemetryEvent]) -> Optional[RuleMatch]:
        evidence = [event for event in events if contains_any(telemetry_text(event), PATH_TRAVERSAL_PATTERNS)]
        if not evidence:
            return None
        ids = dedupe_preserve_order([event.event_id for event in evidence])[:10]
        lines = dedupe_preserve_order([event.message for event in evidence])[:3]
        return RuleMatch(
            classification="suspected_path_traversal",
            confidence=min(0.97, 0.7 + (0.09 * len(evidence))),
            severity=Severity.HIGH,
            summary="Observed path-traversal-like path markers in normalized telemetry.",
            supporting_evidence=lines,
            evidence_event_ids=ids,
            signature=f"traversal:{','.join(ids)}",
        )

    def _detect_brute_force(
        self,
        events: list[TelemetryEvent],
        observables: list[SemanticObservableEvent],
    ) -> Optional[RuleMatch]:
        explicit_failures = [
            event
            for event in events
            if is_login_related(event) and is_login_failure(event)
        ]
        if len(explicit_failures) >= self._brute_force_threshold:
            ids = dedupe_preserve_order([event.event_id for event in explicit_failures])[:10]
            lines = dedupe_preserve_order([event.message for event in explicit_failures])[:3]
            path_hint = next((event.path for event in explicit_failures if event.path), "login/auth endpoints")
            return RuleMatch(
                classification="suspected_bruteforce",
                confidence=min(0.96, 0.62 + (0.05 * len(explicit_failures))),
                severity=Severity.HIGH if len(explicit_failures) >= self._brute_force_threshold + 2 else Severity.WARNING,
                summary=f"Observed repeated failed authentication activity against {path_hint}.",
                supporting_evidence=lines,
                evidence_event_ids=ids,
                signature=f"bruteforce:{path_hint}:{len(ids)}",
            )

        redirect_observables = [
            observable
            for observable in observables
            if observable.observable_type == "login_submit_redirect"
        ]
        if len(redirect_observables) < self._brute_force_threshold:
            return None

        success_navigation = next(
            (
                observable
                for observable in reversed(observables)
                if observable.observable_type == "post_login_navigation"
            ),
            None,
        )
        evidence_ids = [observable.event_id for observable in redirect_observables]
        evidence_lines = [observable.summary for observable in redirect_observables]
        if success_navigation:
            evidence_ids.append(success_navigation.event_id)
            evidence_lines.append(success_navigation.summary)

        ids = dedupe_preserve_order(evidence_ids)[:10]
        lines = dedupe_preserve_order(evidence_lines)[:4]
        path_hint = next(
            (observable.path for observable in redirect_observables if observable.path),
            "login/auth endpoints",
        )
        summary = f"Observed repeated login-form redirect churn against {path_hint}."
        confidence = min(0.95, 0.58 + (0.04 * len(redirect_observables)))
        severity = Severity.WARNING
        if success_navigation:
            summary = (
                f"Observed repeated login-form redirects against {path_hint}, "
                f"followed by successful navigation to {success_navigation.path}."
            )
            confidence = min(0.98, confidence + 0.14)
            severity = Severity.HIGH

        return RuleMatch(
            classification="suspected_bruteforce",
            confidence=confidence,
            severity=severity,
            summary=summary,
            supporting_evidence=lines,
            evidence_event_ids=ids,
            signature=f"bruteforce_redirect:{path_hint}:{len(redirect_observables)}:{success_navigation.path if success_navigation else 'no-success'}",
        )

    def _detect_internal_error_burst(self, events: list[TelemetryEvent]) -> Optional[RuleMatch]:
        buckets: dict[str, list[TelemetryEvent]] = defaultdict(list)
        for event in events:
            if (event.http_status or 0) < 500:
                continue
            key = event.path or event.service_name or event.container_name or "unknown"
            buckets[key].append(event)

        for key, grouped_events in buckets.items():
            if len(grouped_events) < self._burst_threshold:
                continue
            ids = dedupe_preserve_order([event.event_id for event in grouped_events])[:10]
            lines = dedupe_preserve_order([event.message for event in grouped_events])[:3]
            return RuleMatch(
                classification="repeated_internal_error_burst",
                confidence=min(0.92, 0.58 + (0.06 * len(grouped_events))),
                severity=Severity.WARNING if len(grouped_events) < self._burst_threshold + 2 else Severity.HIGH,
                summary=f"Observed repeated HTTP 500/internal error telemetry for {key}.",
                supporting_evidence=lines,
                evidence_event_ids=ids,
                signature=f"errorburst:{key}:{len(ids)}",
            )
        return None
