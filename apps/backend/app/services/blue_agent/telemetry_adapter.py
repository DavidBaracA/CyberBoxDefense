"""Blue-safe telemetry adapter for the runtime agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...models import TelemetryEvent
from ...repository import InMemoryRepository
from .observables import (
    SemanticTelemetryInterpreter,
    serialize_observable,
)


@dataclass
class TelemetrySnapshot:
    """One Blue-safe telemetry snapshot for a monitoring cycle."""

    events: list[dict[str, Any]]
    observables: list[dict[str, Any]]
    next_cursor: int
    anomaly_counts: dict[str, int]
    evidence_event_ids: list[str]


class BlueTelemetryAdapter:
    """Adapt repository telemetry into a compact Blue-agent snapshot.

    TODO:
    - Replace this polling adapter with a streaming event bus when the backend
      grows beyond a single-process MVP.
    - Add richer per-target baselining and time-window support.
    """

    def __init__(self, repository: InMemoryRepository) -> None:
        self._repository = repository
        self._interpreter = SemanticTelemetryInterpreter()

    def snapshot_since(
        self,
        cursor: int,
        target_names: list[str],
        limit: int = 25,
    ) -> TelemetrySnapshot:
        """Return telemetry added after the cursor, filtered to running targets."""
        events = self._repository.list_telemetry_events()
        recent_events = events[cursor:]
        serialized_events = [serialize_telemetry_event(event) for event in recent_events]
        if target_names:
            filtered_pairs = [
                (event, serialized)
                for event, serialized in zip(recent_events, serialized_events)
                if (
                    serialized.get("service_name") in target_names
                    or serialized.get("container_name") in target_names
                    or not serialized.get("service_name")
                )
            ]
        else:
            filtered_pairs = list(zip(recent_events, serialized_events))

        if not filtered_pairs and serialized_events:
            # Keep the MVP demo useful even when telemetry producers do not yet
            # tag events with the deployed target's runtime name.
            filtered_pairs = list(zip(recent_events, serialized_events))

        filtered_events = [event for event, _ in filtered_pairs]
        filtered = [serialized for _, serialized in filtered_pairs]
        truncated = filtered[-limit:]
        observables = [
            serialize_observable(observable)
            for observable in self._interpreter.interpret_many(
                filtered_events
            )[-limit:]
        ]
        anomaly_counts = self._compute_anomaly_counts(truncated)
        evidence_event_ids = [event["event_id"] for event in truncated if event["is_anomalous"]]
        return TelemetrySnapshot(
            events=truncated,
            observables=observables,
            next_cursor=len(events),
            anomaly_counts=anomaly_counts,
            evidence_event_ids=evidence_event_ids,
        )

    def _compute_anomaly_counts(self, events: list[dict[str, Any]]) -> dict[str, int]:
        counts = {
            "http_errors": 0,
            "warning_or_high": 0,
            "request_path_spikes": 0,
            "container_signals": 0,
            "system_signals": 0,
        }
        seen_paths: dict[str, int] = {}
        for event in events:
            status = event.get("http_status")
            if isinstance(status, int) and status >= 500:
                counts["http_errors"] += 1

            severity = event.get("severity")
            if severity in {"warning", "high"}:
                counts["warning_or_high"] += 1

            if event.get("kind") in {"container_signal"}:
                counts["container_signals"] += 1
            if event.get("kind") in {"system_signal"}:
                counts["system_signals"] += 1

            path = event.get("path")
            if path:
                seen_paths[path] = seen_paths.get(path, 0) + 1

        counts["request_path_spikes"] = sum(1 for count in seen_paths.values() if count >= 3)
        return counts


def serialize_telemetry_event(event: TelemetryEvent) -> dict[str, Any]:
    """Convert a Pydantic telemetry event into a graph-friendly dict."""
    http_status = event.http_status
    is_anomalous = (
        event.severity.value in {"warning", "high"}
        or (isinstance(http_status, int) and http_status >= 500)
        or event.kind.value in {"container_signal", "system_signal"}
    )
    return {
        "event_id": event.event_id,
        "run_id": event.run_id,
        "app_id": event.app_id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source.value,
        "source_type": event.source_type,
        "kind": event.kind.value,
        "severity": event.severity.value,
        "container_name": event.container_name,
        "service_name": event.service_name,
        "path": event.path,
        "http_status": http_status,
        "message": event.message,
        "metadata": dict(event.metadata),
        "is_anomalous": is_anomalous,
    }
