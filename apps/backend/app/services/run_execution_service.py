"""Run-level experiment execution orchestration.

This service keeps the run API thin while coordinating the existing Blue and
Red agent start flow behind one run-centric entry point.
"""

from __future__ import annotations

from fastapi import HTTPException

from ..red_agent_models import RedAgentStartRequest
from ..run_models import RunStartResponse, RunStatus, RunTerminationReason
from .run_service import RunService


class RunExecutionService:
    """Coordinate run-scoped startup using the existing Red/Blue services."""

    def __init__(
        self,
        run_service: RunService,
        blue_agent_service,
        red_agent_service,
    ) -> None:
        self._run_service = run_service
        self._blue_agent_service = blue_agent_service
        self._red_agent_service = red_agent_service

    def start_run(self, run_id: str) -> RunStartResponse:
        """Start Blue and Red for one run, rolling Blue back if Red fails."""
        run = self._run_service.get_run(run_id)
        if run.status in {
            RunStatus.COMPLETED,
            RunStatus.CANCELLED,
            RunStatus.EXPIRED,
            RunStatus.FAILED,
        }:
            raise HTTPException(
                status_code=409,
                detail=f"Run {run.run_id} is {run.status.value} and cannot be started.",
            )

        self._run_service.update_run(
            run_id,
            status=RunStatus.STARTING,
            termination_reason=RunTerminationReason.NOT_TERMINATED,
        )

        # Blue is a singleton runtime in the current MVP. If it is still alive
        # from a previous run, restart it so the active run's selected target
        # and target-scoped telemetry are rebound cleanly.
        self._blue_agent_service.stop(
            reason="Blue agent restarting to attach to the newly selected experiment run."
        )
        blue_response = self._blue_agent_service.start()
        try:
            red_response = self._red_agent_service.start(
                RedAgentStartRequest(run_id=run_id)
            )
        except Exception:
            self._blue_agent_service.stop(
                reason="Blue agent stopped because run startup failed while starting Red."
            )
            self._run_service.mark_failed(run_id)
            raise

        run = self._run_service.update_run(
            run_id,
            status=RunStatus.RUNNING,
            termination_reason=RunTerminationReason.NOT_TERMINATED,
        )
        return RunStartResponse(
            success=True,
            message="Run started successfully. Blue and Red agents are now active for this run.",
            run=run,
            blue_state=blue_response.state,
            red_state=red_response.state,
        )
