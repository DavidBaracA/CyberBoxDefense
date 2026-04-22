"""Run-scoped models for experiment-oriented thesis workflows.

These models introduce the backend contracts needed for run-based orchestration
without changing the current MVP endpoint surface yet.

TODO:
- Add a persisted run repository and service once run lifecycle endpoints exist.
- Attach run identifiers to telemetry, detections, and ground truth records.
- Add stronger cross-field validation when attack catalogs become template-aware.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from .blue_agent_models import BlueAgentState
from .models import utc_now
from .red_agent_models import RedAgentStatus


class RunStatus(str, Enum):
    """Lifecycle status for one managed experiment run."""

    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class RunTerminationReason(str, Enum):
    """Why a run ended, if it has terminated."""

    NOT_TERMINATED = "not_terminated"
    COMPLETED_TIMEOUT = "completed_timeout"
    COMPLETED_PLAN_FINISHED = "completed_plan_finished"
    STOPPED_BY_USER = "stopped_by_user"
    FAILED = "failed"
    FIRST_CONFIRMED_VULNERABILITY = "first_confirmed_vulnerability"
    APP_STOPPED = "app_stopped"
    BACKEND_RESTARTED = "backend_restarted"


class AttackDepth(str, Enum):
    """Operator-selected attack intensity/depth for a run."""

    QUICK = "quick"
    BALANCED = "balanced"
    DEEP = "deep"


class BlueMode(str, Enum):
    """Blue-agent operating mode within a run."""

    DETECT_ONLY = "detect_only"
    DETECT_AND_CONTAIN = "detect_and_contain"


class RunConfig(BaseModel):
    """Configuration shared by future run orchestration services."""

    duration_seconds: int = Field(gt=0)
    enabled_attack_types: list[str] = Field(default_factory=list)
    try_all_available: bool = False
    attack_depth: AttackDepth = AttackDepth.BALANCED
    stop_on_first_confirmed_vulnerability: bool = False
    blue_mode: BlueMode = BlueMode.DETECT_ONLY
    red_model_id: Optional[str] = None
    graceful_shutdown_seconds: int = Field(default=10, ge=0)

    @model_validator(mode="after")
    def validate_attack_selection(self) -> "RunConfig":
        """Require an explicit attack list unless the run uses all attacks."""
        if not self.try_all_available and not self.enabled_attack_types:
            raise ValueError(
                "enabled_attack_types must contain at least one attack type when "
                "try_all_available is false."
            )
        return self


class Run(BaseModel):
    """High-level contract for one bounded experiment run."""

    run_id: str = Field(default_factory=lambda: str(uuid4()))
    app_id: str
    started_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    status: RunStatus = RunStatus.PENDING
    termination_reason: Optional[RunTerminationReason] = RunTerminationReason.NOT_TERMINATED
    config: RunConfig


class CreateRunRequest(BaseModel):
    """Request payload for creating a new bounded experiment run."""

    app_id: str
    config: RunConfig


class RunSummary(BaseModel):
    """Run-scoped evaluation summary for experiment reporting."""

    run_id: str
    app_id: str
    status: RunStatus
    termination_reason: Optional[RunTerminationReason] = None
    started_at: datetime
    expires_at: datetime
    telemetry_event_count: int = 0
    detection_count: int = 0
    attack_ground_truth_count: int = 0
    mean_time_to_detection_seconds: Optional[float] = None
    detection_accuracy: float = 0.0
    classification_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    evaluated_attack_count: int = 0
    matched_attack_count: int = 0
    evaluation_policy: dict[str, Any] = Field(default_factory=dict)
    notes: str = (
        "Run summary uses offline evaluation only. Blue runtime remains zero-awareness "
        "and does not consume Red-side ground truth."
    )


class EvaluationMatchRecord(BaseModel):
    """One offline evaluation match between a Red outcome and a Blue detection."""

    attack_id: str
    attack_label: str
    canonical_attack_label: str
    attack_timestamp: datetime
    detection_id: Optional[str] = None
    detection_label: Optional[str] = None
    canonical_detection_label: Optional[str] = None
    detection_timestamp: Optional[datetime] = None
    detected: bool = False
    correctly_classified: bool = False
    time_to_detection_seconds: Optional[float] = None
    notes: str = ""


class EvaluationSummary(BaseModel):
    """Detailed offline evaluation result for one run."""

    run_id: str
    metrics: dict[str, Union[float, int, None]]
    matches: list[EvaluationMatchRecord] = Field(default_factory=list)
    evaluation_policy: dict[str, Any] = Field(default_factory=dict)


class RunStartResponse(BaseModel):
    """Combined response for run-level experiment startup orchestration."""

    success: bool
    message: str
    run: Run
    blue_state: Optional[BlueAgentState] = None
    red_state: Optional[RedAgentStatus] = None
