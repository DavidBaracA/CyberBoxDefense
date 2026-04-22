"""API router for run-based experiment lifecycle management."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from ..run_models import CreateRunRequest, Run, RunStartResponse, RunSummary
from ..services.evaluation_service import EvaluationService
from ..services.run_execution_service import RunExecutionService
from ..services.run_service import RunService
from ..services.run_state_store import RunStateStore
from ..run_state_models import RunStateSnapshot


def create_runs_router(
    service: RunService,
    run_state_store: Optional[RunStateStore] = None,
    evaluation_service: Optional[EvaluationService] = None,
    execution_service: Optional[RunExecutionService] = None,
) -> APIRouter:
    """Create the run-management API router.

    TODO:
    - Add auth before exposing experiment control outside localhost.
    - Connect stop requests to Red/Blue/app orchestration once run execution is wired.
    """

    router = APIRouter(prefix="/api/runs", tags=["runs"])

    @router.post("", response_model=Run)
    def create_run(payload: CreateRunRequest) -> Run:
        return service.create_run(payload)

    @router.get("", response_model=list[Run])
    def list_runs() -> list[Run]:
        return service.list_runs()

    @router.get("/{run_id}", response_model=Run)
    def get_run(run_id: str) -> Run:
        return service.get_run(run_id)

    @router.post("/{run_id}/start", response_model=RunStartResponse)
    def start_run(run_id: str) -> RunStartResponse:
        if not execution_service:
            raise RuntimeError("Run execution service is not configured.")
        return execution_service.start_run(run_id)

    @router.get("/{run_id}/state", response_model=RunStateSnapshot)
    def get_run_state(run_id: str) -> RunStateSnapshot:
        run = service.get_run(run_id)
        if not run_state_store:
            return RunStateSnapshot(run_id=run.run_id, run=run)
        snapshot = run_state_store.get_run_state(run_id)
        if snapshot:
            return snapshot
        return run_state_store.upsert_run(run)

    @router.post("/{run_id}/stop", response_model=Run)
    def stop_run(run_id: str) -> Run:
        return service.stop_run(run_id)

    @router.get("/{run_id}/summary", response_model=RunSummary)
    def get_run_summary(run_id: str) -> RunSummary:
        run = service.get_run(run_id)
        if evaluation_service:
            return evaluation_service.run_summary(run)
        return service.get_summary(run_id)

    return router
