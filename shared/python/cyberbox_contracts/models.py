"""Shared schemas for runtime observability, detections, evaluation, and metrics."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for default model fields."""
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"


class EventType(str, Enum):
    ACCESS_LOG = "access_log"
    HTTP_ERROR = "http_error"
    APP_LOG = "app_log"
    CONTAINER_SIGNAL = "container_signal"
    SYSTEM_SIGNAL = "system_signal"


class ObservableEvent(BaseModel):
    """Indirect telemetry that Blue is allowed to consume at runtime."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    source: str
    event_type: EventType
    severity: Severity = Severity.INFO
    container_name: str | None = None
    path: str | None = None
    http_status: int | None = None
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackExecutionRecord(BaseModel):
    """Offline ground truth for evaluator use only."""

    attack_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    attack_type: str
    target: str
    status: str = "executed"
    notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionRecord(BaseModel):
    """Blue agent output derived only from indirect telemetry."""

    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    detector: str
    predicted_attack_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricSnapshot(BaseModel):
    """Aggregate metrics for research dashboards and offline evaluation."""

    mean_time_to_detection_seconds: float | None = None
    detection_accuracy: float = 0.0
    classification_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    attack_count: int = 0
    detection_count: int = 0
    observable_event_count: int = 0


class TelemetryFeed(BaseModel):
    """Blue-facing telemetry feed with no ground-truth attack data."""

    events: list[ObservableEvent] = Field(default_factory=list)
