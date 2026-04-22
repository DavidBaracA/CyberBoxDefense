"""In-memory run lifecycle service for experiment-oriented workflows.

This service keeps the first run-management step deliberately small so the
existing MVP can evolve without breaking the current Red/Blue endpoints.

TODO:
- Persist runs once experiment history must survive backend restarts.
- Attach run state to agent orchestration and telemetry generation.
- Add automatic expiration/cleanup workers for time-bounded runs.
"""

from __future__ import annotations

from datetime import timedelta
import threading
from typing import Callable, Optional

from fastapi import HTTPException

from ..models import ActionEvent, utc_now
from ..run_models import (
    CreateRunRequest,
    Run,
    RunStatus,
    RunSummary,
    RunTerminationReason,
)
from ..vulnerable_apps_models import VulnerableAppDetail, VulnerableAppStatus
from .run_state_store import RunStateStore


ACTIVE_RUN_STATUSES = {
    RunStatus.PENDING,
    RunStatus.STARTING,
    RunStatus.RUNNING,
    RunStatus.STOPPING,
}


class RunService:
    """Manage bounded experiment runs in memory for the current backend process."""

    def __init__(
        self,
        app_provider: Callable[[], list[VulnerableAppDetail]],
        action_logger: Optional[Callable[[ActionEvent], ActionEvent]] = None,
        state_store: Optional[RunStateStore] = None,
    ) -> None:
        self._app_provider = app_provider
        self._action_logger = action_logger
        self._state_store = state_store
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()

    def _log_action(self, action: str, run: Run, status: str = "recorded") -> None:
        if not self._action_logger:
            return
        self._action_logger(
            ActionEvent(
                actor="operator",
                action=action,
                target_type="run",
                target_id=run.run_id,
                run_id=run.run_id,
                status=status,
                details={
                    "app_id": run.app_id,
                    "run_status": run.status.value,
                    "termination_reason": (
                        run.termination_reason.value if run.termination_reason else None
                    ),
                },
            )
        )

    def _all_apps(self) -> list[VulnerableAppDetail]:
        return list(self._app_provider())

    def _get_app_or_409(self, app_id: str) -> VulnerableAppDetail:
        app = next((item for item in self._all_apps() if item.app_id == app_id), None)
        if not app:
            raise HTTPException(
                status_code=409,
                detail="Runs may only target a known platform-managed vulnerable app.",
            )
        if app.status != VulnerableAppStatus.RUNNING:
            raise HTTPException(
                status_code=409,
                detail="Runs may only start against a currently running vulnerable app.",
            )
        return app

    def _active_run(self) -> Optional[Run]:
        return next(
            (run for run in self._runs.values() if run.status in ACTIVE_RUN_STATUSES),
            None,
        )

    def get_active_run(self) -> Optional[Run]:
        """Return the currently active run, if any."""
        with self._lock:
            active = self._active_run()
            return active.model_copy(deep=True) if active else None

    def get_active_run_id(self) -> Optional[str]:
        """Return the active run identifier, if any."""
        active = self.get_active_run()
        return active.run_id if active else None

    def create_run(self, payload: CreateRunRequest) -> Run:
        """Create a new run if no other active run currently exists."""
        with self._lock:
            active = self._active_run()
            if active:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Only one active run is supported right now. "
                        f"Run {active.run_id} is currently {active.status.value}."
                    ),
                )

            self._get_app_or_409(payload.app_id)
            started_at = utc_now()
            run = Run(
                app_id=payload.app_id,
                started_at=started_at,
                expires_at=started_at + timedelta(seconds=payload.config.duration_seconds),
                status=RunStatus.RUNNING,
                termination_reason=RunTerminationReason.NOT_TERMINATED,
                config=payload.config,
            )
            self._runs[run.run_id] = run
            if self._state_store:
                self._state_store.upsert_run(run)
            self._log_action("run_created", run)
            return run

    def list_runs(self) -> list[Run]:
        """Return all known runs in chronological order."""
        with self._lock:
            return sorted(
                (run.model_copy(deep=True) for run in self._runs.values()),
                key=lambda item: item.started_at,
            )

    def get_run(self, run_id: str) -> Run:
        """Return one run or raise a 404 if it does not exist."""
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                raise HTTPException(status_code=404, detail=f"Run {run_id} was not found.")
            return run.model_copy(deep=True)

    def update_run(
        self,
        run_id: str,
        *,
        status: Optional[RunStatus] = None,
        termination_reason: Optional[RunTerminationReason] = None,
    ) -> Run:
        """Update a run's lifecycle fields in memory."""
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                raise HTTPException(status_code=404, detail=f"Run {run_id} was not found.")
            if status is not None:
                run.status = status
            if termination_reason is not None:
                run.termination_reason = termination_reason
            self._runs[run_id] = run
            if self._state_store:
                self._state_store.upsert_run(run)
            return run.model_copy(deep=True)

    def stop_run(self, run_id: str) -> Run:
        """Mark a run for stopping without changing existing agent endpoints."""
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                raise HTTPException(status_code=404, detail=f"Run {run_id} was not found.")

            if run.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.EXPIRED, RunStatus.CANCELLED}:
                return run.model_copy(deep=True)

            run.status = RunStatus.STOPPING
            run.termination_reason = RunTerminationReason.STOPPED_BY_USER
            self._runs[run_id] = run
            self._log_action("run_stop_requested", run)
            return run.model_copy(deep=True)

    def is_stop_requested(self, run_id: str) -> bool:
        """Return true when a run has been asked to stop."""
        run = self.get_run(run_id)
        return run.status == RunStatus.STOPPING

    def mark_completed(
        self,
        run_id: str,
        termination_reason: RunTerminationReason = RunTerminationReason.NOT_TERMINATED,
    ) -> Run:
        """Mark a run as completed."""
        run = self.update_run(
            run_id,
            status=RunStatus.COMPLETED,
            termination_reason=termination_reason,
        )
        self._log_action("run_completed", run)
        return run

    def mark_expired(self, run_id: str) -> Run:
        """Mark a run as expired because its duration elapsed."""
        run = self.update_run(
            run_id,
            status=RunStatus.EXPIRED,
            termination_reason=RunTerminationReason.COMPLETED_TIMEOUT,
        )
        self._log_action("run_expired", run)
        return run

    def mark_failed(self, run_id: str) -> Run:
        """Mark a run as failed because an internal error occurred."""
        run = self.update_run(
            run_id,
            status=RunStatus.FAILED,
            termination_reason=RunTerminationReason.FAILED,
        )
        self._log_action("run_failed", run, status="error")
        return run

    def mark_cancelled(
        self,
        run_id: str,
        termination_reason: RunTerminationReason = RunTerminationReason.STOPPED_BY_USER,
    ) -> Run:
        """Mark a run as cancelled by an operator-triggered stop."""
        run = self.update_run(
            run_id,
            status=RunStatus.CANCELLED,
            termination_reason=termination_reason,
        )
        self._log_action("run_cancelled", run)
        return run

    def get_summary(self, run_id: str) -> RunSummary:
        """Return a placeholder summary contract for later run-scoped metrics."""
        run = self.get_run(run_id)
        return RunSummary(
            run_id=run.run_id,
            app_id=run.app_id,
            status=run.status,
            termination_reason=run.termination_reason,
            started_at=run.started_at,
            expires_at=run.expires_at,
        )
