"""Minimal Blue agent placeholder that consumes indirect telemetry only.

TODO:
- Replace heuristic logic with an Ollama-backed reasoning loop.
- Maintain strict runtime isolation from any ground-truth attack store.
- Add polling, memory, and scenario-aware detection state.
"""

from __future__ import annotations

import json
from urllib import request

from cyberbox_contracts import DetectionRecord, ObservableEvent

BACKEND_URL = "http://localhost:8000"


def get_json(path: str) -> dict:
    with request.urlopen(f"{BACKEND_URL}{path}") as response:
        return json.loads(response.read().decode("utf-8"))


def post_json(path: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{BACKEND_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req) as response:
        response.read()


def main() -> None:
    """Read Blue-safe telemetry and emit a simple heuristic detection."""

    telemetry = get_json("/api/blue/telemetry")
    events = [ObservableEvent.model_validate(item) for item in telemetry.get("events", [])]

    suspicious_events = [
        event
        for event in events
        if event.http_status and event.http_status >= 500
    ]

    if not suspicious_events:
        print("Blue agent placeholder found no suspicious telemetry.")
        return

    detection = DetectionRecord(
        detector="blue_agent_heuristic",
        predicted_attack_type="sql_injection",
        confidence=0.61,
        summary="Observed HTTP 500 telemetry pattern and inferred possible SQL injection activity.",
        evidence_event_ids=[event.event_id for event in suspicious_events[-3:]],
        metadata={"reasoning_mode": "heuristic_placeholder"},
    )
    post_json("/api/blue/detections", detection.model_dump(mode="json"))
    print("Blue agent placeholder submitted a heuristic detection.")


if __name__ == "__main__":
    main()
