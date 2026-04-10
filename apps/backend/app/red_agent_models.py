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
    enabled: bool = True
    notes: Optional[str] = None


class RedAgentStartRequest(BaseModel):
    """Request to start one bounded Red-agent run."""

    target_app_id: str = Field(min_length=1)
    scenario_ids: list[str] = Field(min_length=1)

    @field_validator("scenario_ids")
    @classmethod
    def normalize_scenarios(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            item = value.strip()
            if item and item not in cleaned:
                cleaned.append(item)
        if not cleaned:
            raise ValueError("scenario_ids must contain at least one scenario")
        return cleaned


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
    status: RedAgentRunStatus = RedAgentRunStatus.IDLE
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    emitted_events_count: int = 0
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

