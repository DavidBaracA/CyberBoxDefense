"""Blue-safe telemetry adapter for the runtime agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...models import TelemetryEvent
from ...repository import InMemoryRepository


@dataclass
class TelemetrySnapshot:
    """One Blue-safe telemetry snapshot for a monitoring cycle."""

    events: list[dict[str, Any]]
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

    def snapshot_since(
        self,
        cursor: int,
        target_names: list[str],
        limit: int = 25,
    ) -> TelemetrySnapshot:
        """Return telemetry added after the cursor, filtered to running targets."""
        events = self._repository.list_telemetry_events()
        serialized_events = [serialize_telemetry_event(event) for event in events[cursor:]]
        if target_names:
            filtered = [
                event
                for event in serialized_events
                if (
                    event.get("service_name") in target_names
                    or event.get("container_name") in target_names
                    or not event.get("service_name")
                )
            ]
        else:
            filtered = serialized_events

        if not filtered and serialized_events:
            # Keep the MVP demo useful even when telemetry producers do not yet
            # tag events with the deployed target's runtime name.
            filtered = serialized_events

        truncated = filtered[-limit:]
        anomaly_counts = self._compute_anomaly_counts(truncated)
        evidence_event_ids = [event["event_id"] for event in truncated if event["is_anomalous"]]
        return TelemetrySnapshot(
            events=truncated,
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
        "timestamp": event.timestamp.isoformat(),
        "source": event.source.value,
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
