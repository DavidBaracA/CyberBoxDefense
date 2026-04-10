"""FastAPI backend core for telemetry ingestion, detections, and metrics.

TODO:
- Add a persistence-backed repository once experiment history must surv- Add scenario/run isolation for multi-experiment evaluation.
- Move the Blue-agent runtime onto durable workers if the MVP outgrows a single
  backend process.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.apps import create_apps_router
from .api.blue_agent import create_blue_agent_router
from .api.red_agent import create_red_agent_router
from .models import (
    AttackGroundTruth,
    DetectionEvent,
    MetricSnapshot,
    TelemetryEvent,
    TelemetryKind,
    TelemetrySource,
)
from .repository import InMemoryRepository
from .repositories.app_repository import VulnerableAppRepository
from .services.blue_agent.telemetry_adapter import BlueTelemetryAdapter
from .services.blue_agent_service import BlueAgentService
from .services.deployment_service import DeploymentService
from .services.red_agent.manager import RedAgentManager

app = FastAPI(
    title="CyberBoxDefense Backend",
    description="Research-oriented backend for autonomous cyber defense experiments.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

repository = InMemoryRepository()
vulnerable_app_repository = VulnerableAppRepository()
deployment_service = DeploymentService()


def get_running_vulnerable_apps():
    apps = []
    for app in vulnerable_app_repository.list_all():
        refreshed = deployment_service.inspect_status(app)
        vulnerable_app_repository.update(refreshed)
        if refreshed.status == "running":
            apps.append(refreshed)
    return apps


blue_agent_service = BlueAgentService(
    running_targets_provider=get_running_vulnerable_apps,
    telemetry_adapter=BlueTelemetryAdapter(repository),
    detection_callback=repository.add_detection_event,
)
red_agent_service = RedAgentManager(
    running_targets_provider=get_running_vulnerable_apps,
    telemetry_callback=repository.add_telemetry_event,
    ground_truth_callback=repository.add_attack_ground_truth,
)


def seed_demo_state() -> None:
    """Seed demo data so the backend has a useful first-run state."""
    if repository.telemetry_events or repository.detection_events or repository.attack_ground_truth:
        return

    baseline_event = TelemetryEvent(
        source=TelemetrySource.VULNERABLE_APP,
        kind=TelemetryKind.ACCESS_LOG,
        container_name="vulnerable_app",
        service_name="vulnerable_app",
        path="/",
        http_status=200,
        message="Baseline request served successfully.",
    )
    suspicious_event = TelemetryEvent(
        source=TelemetrySource.CONTAINER_MONITOR,
        kind=TelemetryKind.HTTP_ERROR,
        severity="warning",
        container_name="vulnerable_app",
        service_name="vulnerable_app",
        path="/search",
        http_status=500,
        message="Container monitor observed a spike in HTTP 500 responses on /search.",
    )
    attack = AttackGroundTruth(
        attack_type="sql_injection",
        target="vulnerable_app/search",
        notes="Seeded offline ground truth for demo mode.",
    )
    detection = DetectionEvent(
        detector="blue_agent_heuristic",
        classification="sql_injection",
        confidence=0.74,
        summary="Detected suspicious error burst consistent with SQL injection probing.",
        evidence_event_ids=[suspicious_event.event_id],
    )

    repository.add_telemetry_event(baseline_event)
    repository.add_telemetry_event(suspicious_event)
    repository.add_attack_ground_truth(attack)
    repository.add_detection_event(detection)


seed_demo_state()
app.include_router(create_apps_router(vulnerable_app_repository, deployment_service))
app.include_router(create_blue_agent_router(blue_agent_service))
app.include_router(create_red_agent_router(red_agent_service))


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/telemetry/events", response_model=TelemetryEvent)
def ingest_telemetry_event(event: TelemetryEvent) -> TelemetryEvent:
    """Ingest indirect telemetry from the vulnerable app or a container monitor."""
    return repository.add_telemetry_event(event)


@app.get("/api/telemetry", response_model=list[TelemetryEvent])
def list_telemetry() -> list[TelemetryEvent]:
    """Return Blue-safe telemetry events for visualization."""
    return repository.list_telemetry_events()


@app.get("/api/detections", response_model=list[DetectionEvent])
def list_detections() -> list[DetectionEvent]:
    """Return currently stored detections for the dashboard/operator view."""
    return repository.list_detection_events()


@app.get("/api/metrics", response_model=MetricSnapshot)
def get_metrics() -> MetricSnapshot:
    """Return simple in-memory evaluation metrics for the current run."""
    return repository.compute_metrics()
