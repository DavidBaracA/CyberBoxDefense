"""Pydantic models for the backend core.

TODO:
- Add stricter runtime separation so Blue-facing workflows cannot accidentally
  access evaluation-only ground truth data.
- Introduce LangGraph orchestration adapters after the basic backend contracts
  and lifecycle are stable.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class TelemetrySource(str, Enum):
    VULNERABLE_APP = "vulnerable_app"
    CONTAINER_MONITOR = "container_monitor"
    SYSTEM_MONITOR = "system_monitor"


class TelemetryKind(str, Enum):
    ACCESS_LOG = "access_log"
    HTTP_ERROR = "http_error"
    APP_LOG = "app_log"
    CONTAINER_SIGNAL = "container_signal"
    SYSTEM_SIGNAL = "system_signal"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"


class TelemetryEvent(BaseModel):
    """Indirect observability visible to the Blue side at runtime."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: Optional[str] = None
    app_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    source: TelemetrySource
    source_type: Optional[str] = None
    kind: TelemetryKind
    severity: Severity = Severity.INFO
    container_name: Optional[str] = None
    service_name: Optional[str] = None
    path: Optional[str] = None
    http_status: Optional[int] = None
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionEvent(BaseModel):
    """Detection produced by the Blue pipeline from indirect telemetry."""

    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    detector: str
    classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity = Severity.INFO
    summary: str
    supporting_evidence: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGroundTruth(BaseModel):
    """Offline evaluation record not intended for Blue runtime consumption."""

    attack_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    attack_type: str
    target: str
    status: str = "executed"
    notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricSnapshot(BaseModel):
    """Aggregate metrics for operator dashboards and offline evaluation."""

    mean_time_to_detection_seconds: Optional[float] = None
    detection_accuracy: float = 0.0
    classification_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    telemetry_event_count: int = 0
    detection_count: int = 0
    attack_ground_truth_count: int = 0


class ActionEvent(BaseModel):
    """Persisted operator/agent action record for reporting and audit."""

    action_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str
    action: str
    target_type: str
    target_id: str = ""
    run_id: Optional[str] = None
    status: str = "recorded"
    details: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityFindingStat(BaseModel):
    """One aggregate vulnerability finding count for reporting."""

    classification: str
    count: int


class DeploymentTemplateStat(BaseModel):
    """One aggregate deployed-template count for reporting."""

    template_id: str
    count: int


class ReportSummary(BaseModel):
    """High-level persisted reporting snapshot for thesis demos."""

    generated_at: datetime = Field(default_factory=utc_now)
    total_deployed_apps: int = 0
    running_app_count: int = 0
    total_action_count: int = 0
    most_common_vulnerabilities: list[VulnerabilityFindingStat] = Field(default_factory=list)
    deployment_templates: list[DeploymentTemplateStat] = Field(default_factory=list)
    mean_time_to_detection_seconds: Optional[float] = None
    detection_accuracy: float = 0.0
    classification_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    evaluated_attack_count: int = 0
    matched_attack_count: int = 0
    evaluation_policy: dict[str, Any] = Field(default_factory=dict)
