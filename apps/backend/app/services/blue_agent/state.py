"""State definitions for the LangGraph-backed Blue agent.

The state intentionally contains only Blue-safe observables and inferred values.

TODO:
- Persist graph state with a checkpoint store when replay becomes important.
- Extend the state with multi-target scheduling once the first single-target
  runtime is stable.
"""

from __future__ import annotations

from typing import Any, Optional

from typing_extensions import TypedDict


class BlueTerminalLine(TypedDict):
    """One runtime line emitted during a single monitoring cycle."""

    level: str
    message: str


class BlueDetectionCandidate(TypedDict, total=False):
    """Structured detection candidate emitted by the graph."""

    classification: str
    confidence: float
    summary: str
    evidence_event_ids: list[str]
    metadata: dict[str, Any]


class BlueAgentGraphState(TypedDict, total=False):
    """Shared state passed between LangGraph nodes for one monitoring cycle."""

    agent_status: str
    available_targets: list[dict[str, Any]]
    selected_target: Optional[dict[str, Any]]
    telemetry_cursor: int
    recent_telemetry: list[dict[str, Any]]
    recent_observables: list[dict[str, Any]]
    new_evidence_event_ids: list[str]
    anomaly_summary: str
    suspicion_score: float
    predicted_attack_type: str
    confidence: float
    evidence: list[str]
    last_detection: Optional[BlueDetectionCandidate]
    cycle_terminal_lines: list[BlueTerminalLine]
    iteration_count: int
