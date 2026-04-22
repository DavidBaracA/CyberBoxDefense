"""Shared in-memory run state store for live orchestration snapshots.

The store keeps a bounded, thread-safe runtime view for each run identifier.
It is intentionally modular so the same get/update API can later be backed by
Redis or persistent storage without changing the calling services.
"""

from __future__ import annotations

from datetime import datetime
import threading
from typing import Optional

from ..blue_agent_models import BlueAgentState
from ..models import ActionEvent, DetectionEvent, MetricSnapshot, TelemetryEvent, utc_now
from ..red_agent_models import RedAgentStatus
from ..run_models import Run, RunStatus
from ..run_state_models import (
    EvidenceArtifactReference,
    MetricSnapshotRecord,
    RedTechniqueProgress,
    RunStateSnapshot,
)


ACTIVE_COUNTDOWN_STATUSES = {
    RunStatus.PENDING,
    RunStatus.STARTING,
    RunStatus.RUNNING,
    RunStatus.STOPPING,
}


class RunStateStore:
    """Thread-safe shared in-memory state store keyed by run id."""

    def __init__(
        self,
        *,
        max_recent_events: int = 200,
        max_metric_snapshots: int = 50,
        max_artifacts: int = 50,
    ) -> None:
        self._max_recent_events = max_recent_events
        self._max_metric_snapshots = max_metric_snapshots
        self._max_artifacts = max_artifacts
        self._state_by_run_id: dict[str, RunStateSnapshot] = {}
        self._lock = threading.RLock()

    def _ensure_snapshot(self, run_id: str) -> RunStateSnapshot:
        snapshot = self._state_by_run_id.get(run_id)
        if snapshot is None:
            snapshot = RunStateSnapshot(run_id=run_id)
            self._state_by_run_id[run_id] = snapshot
        return snapshot

    def _trim(self, values: list[object], max_size: int) -> list[object]:
        if len(values) <= max_size:
            return values
        return values[-max_size:]

    def _refresh_remaining_time(self, snapshot: RunStateSnapshot) -> None:
        if not snapshot.run:
            return
        if snapshot.run.status not in ACTIVE_COUNTDOWN_STATUSES:
            return
        remaining = int((snapshot.run.expires_at - utc_now()).total_seconds())
        snapshot.remaining_time_seconds = max(0, remaining)

    def _touch(self, snapshot: RunStateSnapshot) -> None:
        self._refresh_remaining_time(snapshot)
        snapshot.updated_at = utc_now()

    def upsert_run(self, run: Run) -> RunStateSnapshot:
        """Create or update the base run metadata for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run.run_id)
            snapshot.run = run.model_copy(deep=True)
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def get_run_state(self, run_id: str) -> Optional[RunStateSnapshot]:
        """Return a snapshot copy for one run, if known."""
        with self._lock:
            snapshot = self._state_by_run_id.get(run_id)
            if snapshot is None:
                return None
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def list_run_states(self) -> list[RunStateSnapshot]:
        """Return all run state snapshots sorted by last update time."""
        with self._lock:
            snapshots = list(self._state_by_run_id.values())
            for snapshot in snapshots:
                self._touch(snapshot)
            return [
                snapshot.model_copy(deep=True)
                for snapshot in sorted(snapshots, key=lambda item: item.updated_at)
            ]

    def update_blue_status(self, run_id: str, state: BlueAgentState) -> RunStateSnapshot:
        """Store the latest Blue-agent status for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            snapshot.latest_blue_status = state.model_copy(deep=True)
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def update_red_status(self, run_id: str, state: RedAgentStatus) -> RunStateSnapshot:
        """Store the latest Red-agent status and progress for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            copied_state = state.model_copy(deep=True)
            snapshot.latest_red_status = copied_state
            snapshot.remaining_time_seconds = copied_state.remaining_time_budget_seconds
            snapshot.red_technique_progress = RedTechniqueProgress(
                current_technique=copied_state.current_technique,
                completed_techniques=list(copied_state.completed_techniques),
                remaining_techniques=list(copied_state.remaining_techniques),
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def set_remaining_time(self, run_id: str, remaining_time_seconds: Optional[int]) -> RunStateSnapshot:
        """Store the latest shared countdown value for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            snapshot.remaining_time_seconds = remaining_time_seconds
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def replace_telemetry_events(
        self,
        run_id: str,
        events: list[TelemetryEvent],
    ) -> RunStateSnapshot:
        """Replace the bounded telemetry cache for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            copied_events = [event.model_copy(deep=True) for event in events]
            snapshot.latest_telemetry_events = self._trim(
                copied_events,
                self._max_recent_events,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def append_telemetry_event(self, run_id: str, event: TelemetryEvent) -> RunStateSnapshot:
        """Append one telemetry event to the bounded per-run cache."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            snapshot.latest_telemetry_events.append(event.model_copy(deep=True))
            snapshot.latest_telemetry_events = self._trim(
                snapshot.latest_telemetry_events,
                self._max_recent_events,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def replace_detections(
        self,
        run_id: str,
        detections: list[DetectionEvent],
    ) -> RunStateSnapshot:
        """Replace the bounded detection cache for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            copied_detections = [event.model_copy(deep=True) for event in detections]
            snapshot.latest_detections = self._trim(
                copied_detections,
                self._max_recent_events,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def append_detection(self, run_id: str, detection: DetectionEvent) -> RunStateSnapshot:
        """Append one detection to the bounded per-run cache."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            snapshot.latest_detections.append(detection.model_copy(deep=True))
            snapshot.latest_detections = self._trim(
                snapshot.latest_detections,
                self._max_recent_events,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def replace_actions(
        self,
        run_id: str,
        actions: list[ActionEvent],
    ) -> RunStateSnapshot:
        """Replace the bounded action cache for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            copied_actions = [event.model_copy(deep=True) for event in actions]
            snapshot.latest_actions = self._trim(
                copied_actions,
                self._max_recent_events,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def append_action(self, run_id: str, action: ActionEvent) -> RunStateSnapshot:
        """Append one operator or agent action to the bounded per-run cache."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            snapshot.latest_actions.append(action.model_copy(deep=True))
            snapshot.latest_actions = self._trim(
                snapshot.latest_actions,
                self._max_recent_events,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def record_metrics_snapshot(self, run_id: str, metrics: MetricSnapshot) -> RunStateSnapshot:
        """Record one timestamped metrics snapshot for one run."""
        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            snapshot.metrics_snapshots.append(
                MetricSnapshotRecord(snapshot=metrics.model_copy(deep=True))
            )
            snapshot.metrics_snapshots = self._trim(
                snapshot.metrics_snapshots,
                self._max_metric_snapshots,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)

    def record_evidence_artifact(
        self,
        run_id: str,
        *,
        artifact_path: Optional[str] = None,
        artifact_url: Optional[str] = None,
        artifact_type: str = "evidence",
    ) -> RunStateSnapshot:
        """Record one evidence artifact reference for one run."""
        if not artifact_path and not artifact_url:
            return self.get_run_state(run_id) or RunStateSnapshot(run_id=run_id)

        with self._lock:
            snapshot = self._ensure_snapshot(run_id)
            artifact = EvidenceArtifactReference(
                artifact_path=artifact_path,
                artifact_url=artifact_url,
                artifact_type=artifact_type,
            )
            existing_index = next(
                (
                    index
                    for index, existing in enumerate(snapshot.evidence_artifacts)
                    if existing.artifact_path == artifact.artifact_path
                    and existing.artifact_url == artifact.artifact_url
                ),
                None,
            )
            if existing_index is not None:
                snapshot.evidence_artifacts[existing_index] = artifact
            else:
                snapshot.evidence_artifacts.append(artifact)
            snapshot.evidence_artifacts = self._trim(
                snapshot.evidence_artifacts,
                self._max_artifacts,
            )
            self._touch(snapshot)
            return snapshot.model_copy(deep=True)
