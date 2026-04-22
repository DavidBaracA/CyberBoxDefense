"""Shared in-memory run state models for live orchestration snapshots.

These models capture the latest per-run runtime view needed by the backend
while keeping the storage boundary small enough to swap for Redis or a
database-backed state service later.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .blue_agent_models import BlueAgentState
from .models import ActionEvent, DetectionEvent, MetricSnapshot, TelemetryEvent, utc_now
from .red_agent_models import RedAgentStatus
from .run_models import Run


class EvidenceArtifactReference(BaseModel):
    """Reference to one runtime evidence artifact generated during a run."""

    artifact_path: Optional[str] = None
    artifact_url: Optional[str] = None
    artifact_type: str = "evidence"
    recorded_at: datetime = Field(default_factory=utc_now)


class MetricSnapshotRecord(BaseModel):
    """Timestamped metrics snapshot stored for one run."""

    recorded_at: datetime = Field(default_factory=utc_now)
    snapshot: MetricSnapshot = Field(default_factory=MetricSnapshot)


class RedTechniqueProgress(BaseModel):
    """Current Red-agent technique execution progress for a run."""

    current_technique: Optional[str] = None
    completed_techniques: list[str] = Field(default_factory=list)
    remaining_techniques: list[str] = Field(default_factory=list)


class RunStateSnapshot(BaseModel):
    """Latest shared in-memory state for one run."""

    run_id: str
    run: Optional[Run] = None
    latest_red_status: Optional[RedAgentStatus] = None
    latest_blue_status: Optional[BlueAgentState] = None
    latest_telemetry_events: list[TelemetryEvent] = Field(default_factory=list)
    latest_detections: list[DetectionEvent] = Field(default_factory=list)
    latest_actions: list[ActionEvent] = Field(default_factory=list)
    metrics_snapshots: list[MetricSnapshotRecord] = Field(default_factory=list)
    evidence_artifacts: list[EvidenceArtifactReference] = Field(default_factory=list)
    remaining_time_seconds: Optional[int] = None
    red_technique_progress: RedTechniqueProgress = Field(default_factory=RedTechniqueProgress)
    updated_at: datetime = Field(default_factory=utc_now)
