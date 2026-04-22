"""Compatibility layer for Blue-agent runtime services.

This module keeps the backend bootable even when optional LangGraph/Ollama
dependencies are not installed. That way the vulnerable-app lifecycle APIs keep
working for local demos, while Blue-agent endpoints return a clear message until
their runtime dependencies are installed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from ..blue_agent_models import (
    BlueAgentActionResponse,
    BlueAgentLogsResponse,
    BlueAgentStartRequest,
    BlueAgentState,
    BlueAgentStatus,
    BlueReasonerOption,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UnavailableBlueAgentService:
    """Fallback service used when optional Blue-agent deps are unavailable."""

    def __init__(self, detail: str) -> None:
        self._detail = detail

    def _state(self) -> BlueAgentState:
        return BlueAgentState(
            status=BlueAgentStatus.ERROR,
            message=(
                "Blue agent runtime is unavailable because optional dependencies "
                f"are missing: {self._detail}"
            ),
            last_stopped_at=utc_now(),
        )

    def status(self) -> BlueAgentState:
        return self._state()

    def start(self, payload: BlueAgentStartRequest | None = None) -> BlueAgentActionResponse:
        _ = payload
        raise HTTPException(
            status_code=503,
            detail=(
                "Blue agent runtime is unavailable because optional dependencies are missing. "
                f"{self._detail}"
            ),
        )

    def stop(self, reason: str = "Blue agent runtime is unavailable.") -> BlueAgentActionResponse:
        return BlueAgentActionResponse(
            success=False,
            message=reason,
            state=self._state(),
        )

    def logs(self) -> BlueAgentLogsResponse:
        return BlueAgentLogsResponse(logs=[])

    def register_stream(self, run_id: str | None = None) -> tuple[str, Any]:
        _ = run_id
        raise HTTPException(
            status_code=503,
            detail=(
                "Blue agent runtime is unavailable because optional dependencies are missing. "
                f"{self._detail}"
            ),
        )

    def model_options(self) -> list[BlueReasonerOption]:
        return [
            BlueReasonerOption(
                model_id="gemma3:4b",
                label="Gemma 3 4B",
                ollama_model="gemma3:4b",
                description="Compact local model for Blue-side telemetry classification.",
            ),
            BlueReasonerOption(
                model_id="deepseek_r1_8b",
                label="DeepSeek R1 8B",
                ollama_model="deepseek-r1:8b",
                description="General reasoning-focused local model for Blue-side telemetry classification.",
            ),
        ]

    def publish_detection(self, detection: Any) -> None:
        _ = detection

    def unregister_stream(self, subscriber_id: str) -> None:
        _ = subscriber_id


def BlueAgentService(*args: Any, **kwargs: Any) -> Any:
    """Return the real Blue-agent manager when available, else a safe fallback."""
    try:
        from .blue_agent.manager import LangGraphBlueAgentManager
    except ModuleNotFoundError as exc:
        return UnavailableBlueAgentService(
            detail=(
                f"Install the missing Python package '{exc.name}' in apps/backend/.venv "
                "to enable the LangGraph-backed Blue runtime."
            )
        )

    return LangGraphBlueAgentManager(*args, **kwargs)
