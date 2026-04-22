"""Pydantic models for bounded Red-agent control and runtime output.

The Red agent is an operator-only local lab component. Ground truth recorded by
these models must not be surfaced to the Blue runtime stream.

TODO:
- Persist Red runs and ground-truth events across backend restarts.
- Add experiment/run identifiers once repeated scenario batches are managed.
- Expand scenario metadata when the target catalog grows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RedAgentRunStatus(str, Enum):
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    COMPLETED = "completed"
    ERROR = "error"


class AttackScenario(BaseModel):
    """One predefined safe local attack scenario."""

    scenario_id: str
    display_name: str
    description: str
    execution_mode: str = "http"
    enabled: bool = True
    notes: Optional[str] = None


class RedReasonerOption(BaseModel):
    """One selectable Red planning model option for operator experiments."""

    model_id: str
    label: str
    ollama_model: str
    description: str


class AttackTechniquePlan(BaseModel):
    """One planned Red-agent technique step before execution begins."""

    technique_id: str
    technique_name: str
    estimated_cost: int = Field(ge=1)
    estimated_difficulty: str
    priority_order: int = Field(ge=1)


class AttackExecutionPlan(BaseModel):
    """Deterministic ordered attack plan generated from a run configuration."""

    techniques: list[AttackTechniquePlan] = Field(default_factory=list)
    planner_name: str = "heuristic"
    planner_rationale: Optional[str] = None


class RedAgentStartRequest(BaseModel):
    """Request to start one bounded Red-agent run."""

    run_id: Optional[str] = None
    target_app_id: Optional[str] = None
    scenario_ids: list[str] = Field(default_factory=list)

    @field_validator("scenario_ids")
    @classmethod
    def normalize_scenarios(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            item = value.strip()
            if item and item not in cleaned:
                cleaned.append(item)
        return cleaned

    @field_validator("run_id", "target_app_id")
    @classmethod
    def normalize_optional_identifiers(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class RedAgentLogEvent(BaseModel):
    """One Red-agent terminal line for the operator UI."""

    timestamp: datetime = Field(default_factory=utc_now)
    level: str = "info"
    message: str


class GroundTruthAttackEvent(BaseModel):
    """Internal/offline ground-truth event for later evaluation."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    run_id: str
    target_app_id: str
    scenario_id: str
    phase: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackRunRecord(BaseModel):
    """Internal Red-agent run record."""

    run_id: str = Field(default_factory=lambda: str(uuid4()))
    target_app_id: Optional[str] = None
    target_name: Optional[str] = None
    target_url: Optional[str] = None
    selected_scenarios: list[str] = Field(default_factory=list)
    selected_model_id: Optional[str] = None
    selected_model_label: Optional[str] = None
    current_technique: Optional[str] = None
    completed_techniques: list[str] = Field(default_factory=list)
    remaining_techniques: list[str] = Field(default_factory=list)
    remaining_time_budget_seconds: Optional[int] = None
    status: RedAgentRunStatus = RedAgentRunStatus.IDLE
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    emitted_events_count: int = 0
    latest_artifact_path: Optional[str] = None
    latest_artifact_url: Optional[str] = None
    message: str = "Red agent is idle."


class RedAgentStatus(AttackRunRecord):
    """Operator-facing Red-agent runtime status."""


class RedAgentActionResponse(BaseModel):
    """Response for start/stop lifecycle actions."""

    success: bool
    message: str
    state: RedAgentStatus


class RedAgentLogsResponse(BaseModel):
    """Buffered Red-agent terminal output."""

    logs: list[RedAgentLogEvent] = Field(default_factory=list)


class RedAgentSessionScreenshot(BaseModel):
    """One screenshot captured during a completed Red-agent session."""

    screenshot_id: str = Field(default_factory=lambda: str(uuid4()))
    scenario_id: Optional[str] = None
    scenario_name: Optional[str] = None
    filename: str
    artifact_path: str
    artifact_url: str
    captured_at: datetime = Field(default_factory=utc_now)
    summary: Optional[str] = None


class RedAgentSessionVulnerability(BaseModel):
    """One vulnerability observed during a completed Red-agent session."""

    vulnerability_id: str = Field(default_factory=lambda: str(uuid4()))
    scenario_id: Optional[str] = None
    type: str
    title: str
    severity: str
    location: Optional[str] = None
    evidence: Optional[str] = None
    discovered_at: datetime = Field(default_factory=utc_now)


class RedAgentSessionSummary(BaseModel):
    """Operator-facing summary for a completed Red-agent session."""

    session_id: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    target_app_id: Optional[str] = None
    target_name: Optional[str] = None
    target_url: Optional[str] = None
    status: RedAgentRunStatus = RedAgentRunStatus.COMPLETED
    vulnerability_count: int = 0
    screenshot_count: int = 0
    is_latest: bool = False
    summary: Optional[str] = None


class RedAgentSessionDetail(RedAgentSessionSummary):
    """Detailed operator view for a completed Red-agent session."""

    selected_scenarios: list[str] = Field(default_factory=list)
    selected_model_id: Optional[str] = None
    selected_model_label: Optional[str] = None
    completed_techniques: list[str] = Field(default_factory=list)
    logs: list[RedAgentLogEvent] = Field(default_factory=list)
    screenshots: list[RedAgentSessionScreenshot] = Field(default_factory=list)
    vulnerabilities: list[RedAgentSessionVulnerability] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
