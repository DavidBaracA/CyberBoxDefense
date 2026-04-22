"""Timeout-aware orchestration for run-scoped backend execution.

The orchestrator watches the active run and coordinates shutdown behavior across
the Red and Blue agents when a run expires or is explicitly stopped.

TODO:
- Move orchestration to durable workers if backend restarts must not interrupt runs.
- Add per-run Blue/Red ownership once multiple concurrent runs are supported.
- Emit structured orchestration events for a future experiment timeline view.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from ..run_models import Run, RunStatus, RunTerminationReason
from .run_service import RunService


class RunOrchestrator:
    """Coordinate timeout-aware shutdown for the active run."""

    def __init__(
        self,
        run_service: RunService,
        red_agent_service,
        blue_agent_service,
        poll_interval_seconds: float = 1.0,
    ) -> None:
        self._run_service = run_service
        self._red_agent_service = red_agent_service
        self._blue_agent_service = blue_agent_service
        self._poll_interval_seconds = poll_interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._shutdown_lock = threading.Lock()
        self._active_shutdown_run_id: Optional[str] = None

    def start(self) -> None:
        """Start the background orchestration loop if it is not already running."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="cyberbox-run-orchestrator",
            daemon=True,
        )
        self._thread.start()

    def shutdown(self) -> None:
        """Stop the orchestrator loop."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None

    def _monitor_loop(self) -> None:
        while not self._stop_event.wait(self._poll_interval_seconds):
            run = self._run_service.get_active_run()
            if not run:
                with self._shutdown_lock:
                    self._active_shutdown_run_id = None
                continue

            if run.status == RunStatus.STOPPING:
                self._ensure_shutdown_sequence(run)
                continue

            if run.status == RunStatus.RUNNING and time.time() >= run.expires_at.timestamp():
                self._run_service.update_run(
                    run.run_id,
                    status=RunStatus.STOPPING,
                    termination_reason=RunTerminationReason.COMPLETED_TIMEOUT,
                )
                refreshed = self._run_service.get_run(run.run_id)
                self._ensure_shutdown_sequence(refreshed)

    def _ensure_shutdown_sequence(self, run: Run) -> None:
        with self._shutdown_lock:
            if self._active_shutdown_run_id == run.run_id:
                return
            self._active_shutdown_run_id = run.run_id

        worker = threading.Thread(
            target=self._shutdown_sequence,
            args=(run,),
            name=f"cyberbox-run-shutdown-{run.run_id}",
            daemon=True,
        )
        worker.start()

    def _shutdown_sequence(self, run: Run) -> None:
        termination_reason = run.termination_reason or RunTerminationReason.STOPPED_BY_USER
        try:
            if termination_reason == RunTerminationReason.COMPLETED_TIMEOUT:
                self._red_agent_service.stop(
                    reason="Red agent stopped because the run time budget expired.",
                    termination_reason=RunTerminationReason.COMPLETED_TIMEOUT,
                )
                graceful_seconds = run.config.graceful_shutdown_seconds
                if graceful_seconds > 0:
                    time.sleep(graceful_seconds)
                self._blue_agent_service.stop(
                    reason=(
                        "Blue agent stopped after the configured graceful flush "
                        "period for run timeout."
                    )
                )
                self._run_service.mark_expired(run.run_id)
            elif termination_reason == RunTerminationReason.STOPPED_BY_USER:
                self._red_agent_service.stop(
                    reason="Red agent stopped because the run was stopped by the operator.",
                    termination_reason=RunTerminationReason.STOPPED_BY_USER,
                )
                self._blue_agent_service.stop(
                    reason="Blue agent stopped because the run was stopped by the operator."
                )
        finally:
            with self._shutdown_lock:
                if self._active_shutdown_run_id == run.run_id:
                    self._active_shutdown_run_id = None
