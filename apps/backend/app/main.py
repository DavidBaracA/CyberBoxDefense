"""FastAPI backend for telemetry ingestion, blue detections, and offline evaluation."""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cyberbox_contracts import AttackExecutionRecord, DetectionRecord, ObservableEvent

from .store import RuntimeStore

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

store = RuntimeStore()


def seed_demo_state() -> None:
    """Seed a small demo scenario so the dashboard is useful on first launch."""
    if store.observable_events or store.attack_ground_truth or store.detections:
        return

    baseline_event = ObservableEvent(
        source="vulnerable_app",
        event_type="access_log",
        severity="info",
        container_name="vulnerable_app",
        path="/",
        http_status=200,
        message="Baseline request served successfully.",
    )
    suspicious_event = ObservableEvent(
        source="vulnerable_app",
        event_type="http_error",
        severity="warning",
        container_name="vulnerable_app",
        path="/search?q=' OR '1'='1",
        http_status=500,
        message="Spike in HTTP 500 responses on search endpoint.",
    )
    attack = AttackExecutionRecord(
        attack_type="sql_injection",
        target="vulnerable_app/search",
        notes="Seeded offline ground truth for demo mode.",
    )
    detection = DetectionRecord(
        detector="blue_agent_heuristic",
        predicted_attack_type="sql_injection",
        confidence=0.74,
        summary="Detected suspicious error burst consistent with SQL injection probing.",
        evidence_event_ids=[suspicious_event.event_id],
    )

    store.ingest_event(baseline_event)
    store.ingest_event(suspicious_event)
    store.record_attack(attack)
    store.record_detection(detection)


@app.on_event("startup")
def on_startup() -> None:
    """Initialize demo data for the first-run experience."""
    if os.getenv("CYBERBOX_AUTO_SEED", "true").lower() == "true":
        seed_demo_state()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/telemetry/events", response_model=ObservableEvent)
def ingest_telemetry_event(event: ObservableEvent) -> ObservableEvent:
    """Ingest indirect observability data visible to Blue."""
    return store.ingest_event(event)


@app.get("/api/blue/telemetry")
def blue_telemetry():
    """Blue-facing endpoint that intentionally excludes attack ground truth."""
    return store.blue_telemetry_feed()


@app.post("/api/blue/detections", response_model=DetectionRecord)
def submit_blue_detection(detection: DetectionRecord) -> DetectionRecord:
    """Receive Blue detections derived from indirect telemetry only."""
    return store.record_detection(detection)


@app.get("/api/blue/detections")
def list_blue_detections() -> list[DetectionRecord]:
    return store.detections


@app.post("/api/evaluation/attacks", response_model=AttackExecutionRecord)
def submit_attack_ground_truth(attack: AttackExecutionRecord) -> AttackExecutionRecord:
    """Store ground-truth attack execution results for offline scoring."""
    return store.record_attack(attack)


@app.get("/api/evaluation/attacks")
def list_attack_ground_truth() -> list[AttackExecutionRecord]:
    """Operator/evaluator endpoint. Blue agents should not use this."""
    return store.attack_ground_truth


@app.get("/api/metrics")
def metrics():
    return store.metric_snapshot()


@app.get("/api/dashboard")
def dashboard() -> dict[str, object]:
    """Operator dashboard payload. This may include evaluation data for research demos."""
    return {
        "observability": store.observable_events,
        "detections": store.detections,
        "ground_truth": store.attack_ground_truth,
        "metrics": store.metric_snapshot(),
    }


@app.post("/api/demo/seed")
def reseed_demo() -> dict[str, str]:
    seed_demo_state()
    return {"status": "seeded"}
