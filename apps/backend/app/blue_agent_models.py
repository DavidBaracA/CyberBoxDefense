"""Pydantic models for Blue agent runtime control and terminal output.

TODO:
- Replace polling with WebSocket streaming for richer live terminal output.
- Persist Blue runtime events if experiment replay becomes important.
- Add checkpoint-backed LangGraph state persistence for durable replay.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class BlueAgentStatus(str, Enum):
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


class BlueAgentLogEntry(BaseModel):
    """One Blue-agent terminal line safe for operator/runtime display."""

    timestamp: datetime = Field(default_factory=utc_now)
    level: str = "info"
    message: str


class BlueReasonerOption(BaseModel):
    """One selectable Blue reasoning model option for the operator UI."""

    model_id: str
    label: str
    ollama_model: str
    description: str


class BlueAgentState(BaseModel):
    """Current Blue-agent runtime state."""

    status: BlueAgentStatus = BlueAgentStatus.IDLE
    active_target_count: int = 0
    active_target_names: list[str] = Field(default_factory=list)
    selected_target: Optional[str] = None
    iteration_count: int = 0
    suspicion_score: Optional[float] = None
    predicted_attack_type: Optional[str] = None
    confidence: Optional[float] = None
    selected_model_id: Optional[str] = None
    selected_model_label: Optional[str] = None
    last_started_at: Optional[datetime] = None
    last_stopped_at: Optional[datetime] = None
    message: str = "Blue agent is idle."


class BlueAgentStartRequest(BaseModel):
    """Optional runtime start payload for selecting the Blue reasoning model."""

    model_id: Optional[str] = None


class BlueAgentActionResponse(BaseModel):
    """Response for Blue-agent start/stop actions."""

    success: bool
    message: str
    state: BlueAgentState


class BlueAgentLogsResponse(BaseModel):
    """Buffered Blue-agent terminal output."""

    logs: list[BlueAgentLogEntry] = Field(default_factory=list)
