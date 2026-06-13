"""FastAPI backend core for telemetry ingestion, detections, and metrics.

TODO:
- Add scenario/run isolation for multi-experiment evaluation.
- Move the Blue-agent runtime onto durable workers if the MVP outgrows a single
  backend process.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api.apps import create_apps_router
from .api.blue_agent import create_blue_agent_router
from .api.config import create_config_router
from .api.red_agent import create_red_agent_router
from .api.run_state import create_run_state_router
from .api.runs import create_runs_router
from .database import Database
from .models import (
    ActionEvent,
    AttackGroundTruth,
    DetectionEvent,
    MetricSnapshot,
    ReportSummary,
    TelemetryEvent,
)
from .repository import InMemoryRepository
from .repositories.app_repository import VulnerableAppRepository
from .services.blue_agent.telemetry_adapter import BlueTelemetryAdapter
from .services.blue_agent.rule_detector import RuleBasedBlueDetector
from .services.blue_agent_service import BlueAgentService
from .services.deployment_service import DeploymentService
from .services.evaluation_service import EvaluationService
from .services.red_agent.manager import RedAgentManager
from .services.red_agent.session_history import RedAgentSessionHistoryStore
from .services.telemetry_collector import TelemetryCollector
from .services.run_execution_service import RunExecutionService
from .services.run_orchestrator import RunOrchestrator
from .services.run_state_store import RunStateStore
from .services.run_state_stream import RunStateStream
from .services.run_service import RunService
from .vulnerable_apps_models import VulnerableAppStatus

app = FastAPI(
    title="CyberBoxDefense Backend",
    description="Research-oriented backend for autonomous cyber defense experiments.",
    version="0.1.0",
)

repo_root = Path(__file__).resolve().parents[3]
red_artifact_dir = repo_root / "apps" / "frontend" / "test-results" / "red-agent"
red_artifact_dir.mkdir(parents=True, exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/artifacts/red-agent", StaticFiles(directory=red_artifact_dir), name="red-agent-artifacts")

database = Database(repo_root / "data" / "cyberbox.db")
vulnerable_app_repository = VulnerableAppRepository(database)
deployment_service = DeploymentService()
run_state_store = RunStateStore()
run_state_stream = RunStateStream(run_state_store)
red_session_history_store = RedAgentSessionHistoryStore(repo_root / "data" / "red_agent_sessions.json")
rule_based_blue_detector = RuleBasedBlueDetector()


def get_running_vulnerable_apps():
    apps = []
    for app in vulnerable_app_repository.list_all():
        refreshed = deployment_service.inspect_status(app)
        vulnerable_app_repository.update(refreshed)
        if refreshed.status == VulnerableAppStatus.RUNNING:
            apps.append(refreshed)
    return apps


def get_all_vulnerable_apps():
    apps = []
    for app in vulnerable_app_repository.list_all():
        refreshed = deployment_service.inspect_status(app)
        vulnerable_app_repository.update(refreshed)
        apps.append(refreshed)
    return apps


def publish_run_state(run):
    snapshot = run_state_store.upsert_run(run)
    run_state_stream.publish_run(run, snapshot)


run_service = RunService(
    app_provider=get_all_vulnerable_apps,
    action_logger=lambda event: record_action_event(event),
    state_store=run_state_store,
    state_publisher=publish_run_state,
)
repository = InMemoryRepository(
    database,
    current_run_id_provider=run_service.get_active_run_id,
)
repository.prune_telemetry_events()
evaluation_service = EvaluationService(repository)


def record_metrics_snapshot_for_run(run_id: Optional[str]) -> None:
    if not run_id:
        return
    snapshot = evaluation_service.metrics_for_run(run_id)
    run_state_store.record_metrics_snapshot(run_id, snapshot)
    run_state_stream.publish_metrics(run_id, snapshot)


def record_action_event(event: ActionEvent) -> ActionEvent:
    stored = repository.log_action(event)
    if stored.run_id:
        run_state_store.append_action(stored.run_id, stored)
        run_state_stream.publish_action(stored)
    return stored


def record_telemetry_event(event: TelemetryEvent) -> TelemetryEvent:
    active_run = run_service.get_active_run()
    resolve_run_id = True
    if active_run and event.app_id != active_run.app_id:
        event.run_id = None
        resolve_run_id = False
    stored = repository.add_telemetry_event(event, resolve_run_id=resolve_run_id)
    if stored is None:
        return event
    if stored.run_id:
        run_state_store.append_telemetry_event(stored.run_id, stored)
        run_state_stream.publish_telemetry(stored)
        for detection in rule_based_blue_detector.process_event(stored):
            record_detection_event(detection)
        record_metrics_snapshot_for_run(stored.run_id)
    return stored


def record_detection_event(event: DetectionEvent) -> DetectionEvent:
    stored = repository.add_detection_event(event)
    if stored.run_id:
        run_state_store.append_detection(stored.run_id, stored)
        run_state_stream.publish_detection(stored)
        if hasattr(blue_agent_service, "publish_detection"):
            blue_agent_service.publish_detection(stored)
        record_metrics_snapshot_for_run(stored.run_id)
    return stored


def record_ground_truth_event(event: AttackGroundTruth) -> AttackGroundTruth:
    stored = repository.add_attack_ground_truth(event)
    if stored.run_id:
        record_metrics_snapshot_for_run(stored.run_id)
    return stored


def get_blue_monitoring_targets():
    """Return Blue-visible targets, scoped to the active run when one exists.

    This keeps the run-based session flow authoritative: when an experiment run
    is active, Blue should monitor only that selected platform-managed target.
    If Blue is started outside a run, it may still observe all running targets.
    """

    running_apps = get_running_vulnerable_apps()
    active_run = run_service.get_active_run()
    if not active_run:
        return running_apps

    return [app for app in running_apps if app.app_id == active_run.app_id]


telemetry_collector = TelemetryCollector(
    deployment_service=deployment_service,
    telemetry_callback=record_telemetry_event,
    run_id_provider=run_service.get_active_run_id,
)


blue_agent_service = BlueAgentService(
    running_targets_provider=get_blue_monitoring_targets,
    telemetry_adapter=BlueTelemetryAdapter(repository),
    detection_callback=record_detection_event,
    action_callback=record_action_event,
    run_id_provider=run_service.get_active_run_id,
    run_state_store=run_state_store,
)
red_agent_service = RedAgentManager(
    running_targets_provider=get_running_vulnerable_apps,
    run_service=run_service,
    ground_truth_callback=record_ground_truth_event,
    action_callback=record_action_event,
    run_state_store=run_state_store,
    session_history_store=red_session_history_store,
)
run_orchestrator = RunOrchestrator(
    run_service=run_service,
    red_agent_service=red_agent_service,
    blue_agent_service=blue_agent_service,
)
run_execution_service = RunExecutionService(
    run_service=run_service,
    blue_agent_service=blue_agent_service,
    red_agent_service=red_agent_service,
)


def resolve_run_id_or_none(requested_run_id: Optional[str]) -> Optional[str]:
    if requested_run_id:
        run_service.get_run(requested_run_id)
        return requested_run_id
    return run_service.get_active_run_id()


app.include_router(
    create_apps_router(
        vulnerable_app_repository,
        deployment_service,
        action_logger=record_action_event,
        telemetry_collector=telemetry_collector,
    )
)
app.include_router(create_config_router(red_agent_service.scenarios, red_agent_service.model_options))
app.include_router(
    create_blue_agent_router(
        blue_agent_service,
        run_state_store=run_state_store,
        run_id_provider=run_service.get_active_run_id,
    )
)
app.include_router(create_red_agent_router(red_agent_service, run_state_store=run_state_store))
app.include_router(create_run_state_router(run_service, run_state_stream))
app.include_router(
    create_runs_router(
        run_service,
        run_state_store=run_state_store,
        evaluation_service=evaluation_service,
        execution_service=run_execution_service,
    )
)


@app.on_event("startup")
def startup_event() -> None:
    telemetry_collector.start()
    telemetry_collector.sync_apps(get_all_vulnerable_apps())
    run_orchestrator.start()


@app.on_event("shutdown")
def shutdown_event() -> None:
    telemetry_collector.shutdown()
    run_orchestrator.shutdown()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/telemetry", response_model=list[TelemetryEvent])
def list_telemetry(run_id: Optional[str] = None) -> list[TelemetryEvent]:
    """Return Blue-safe telemetry events for visualization."""
    resolved_run_id = resolve_run_id_or_none(run_id)
    if not resolved_run_id:
        return []
    events = repository.list_telemetry_events(run_id=resolved_run_id)
    run_state_store.replace_telemetry_events(resolved_run_id, events)
    return events


@app.get("/api/detections", response_model=list[DetectionEvent])
def list_detections(run_id: Optional[str] = None) -> list[DetectionEvent]:
    """Return currently stored detections for the dashboard/operator view."""
    resolved_run_id = resolve_run_id_or_none(run_id)
    if not resolved_run_id:
        return []
    detections = repository.list_detection_events(run_id=resolved_run_id)
    run_state_store.replace_detections(resolved_run_id, detections)
    return detections


@app.get("/api/metrics", response_model=MetricSnapshot)
def get_metrics(run_id: Optional[str] = None) -> MetricSnapshot:
    """Return aggregate evaluation metrics, or run-scoped metrics when requested."""
    snapshot = evaluation_service.metrics_for_run(run_id)
    if run_id:
        run_state_store.record_metrics_snapshot(run_id, snapshot)
    return snapshot


@app.get("/api/actions", response_model=list[ActionEvent])
def list_actions(run_id: Optional[str] = None) -> list[ActionEvent]:
    """Return persisted operator and agent actions for later audit/report views."""
    resolved_run_id = resolve_run_id_or_none(run_id)
    if not resolved_run_id:
        return []
    actions = repository.list_actions(run_id=resolved_run_id)
    run_state_store.replace_actions(resolved_run_id, actions)
    return actions


@app.get("/api/reports/summary", response_model=ReportSummary)
def get_report_summary(run_id: Optional[str] = None) -> ReportSummary:
    """Return a persisted high-level report summary for thesis dashboards."""
    resolved_run_id = resolve_run_id_or_none(run_id)
    if not resolved_run_id:
        return ReportSummary()
    apps = vulnerable_app_repository.list_all()
    running_count = sum(1 for app in apps if app.status == VulnerableAppStatus.RUNNING)
    return evaluation_service.report_summary(
        run_id=resolved_run_id,
        vulnerable_app_count=len(apps),
        running_app_count=running_count,
    )
