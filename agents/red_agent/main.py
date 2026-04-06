"""Minimal Red agent placeholder for controlled local attack simulation.

TODO:
- Replace synthetic logic with scenario-based local attack playbooks.
- Keep all attack traffic confined to the local vulnerable target container.
- Persist richer execution traces for offline evaluation.
"""

from __future__ import annotations

import json
from urllib import error, request

from cyberbox_contracts import AttackExecutionRecord, EventType, ObservableEvent, Severity

BACKEND_URL = "http://localhost:8000"
TARGET_URL = "http://localhost:8081"


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
    """Trigger the placeholder target and store evaluation data.

    This first version also sends a synthetic observability event to emulate what
    a future log shipper or telemetry collector would extract from the target.
    """

    try:
        with request.urlopen(f"{TARGET_URL}/search?q=' OR '1'='1") as response:
            response.read()
    except error.HTTPError:
        # The target intentionally returns errors for suspicious input.
        pass

    attack = AttackExecutionRecord(
        attack_type="sql_injection",
        target="vulnerable_app/search",
        status="executed",
        notes="Placeholder Red agent executed a local SQLi-style probe.",
        metadata={"agent": "red_agent_placeholder"},
    )
    event = ObservableEvent(
        source="vulnerable_app",
        event_type=EventType.HTTP_ERROR,
        severity=Severity.WARNING,
        container_name="vulnerable_app",
        path="/search",
        http_status=500,
        message="Synthetic HTTP 500 event produced after suspicious search payload.",
        metadata={"collector": "red_agent_placeholder_todo_replace"},
    )

    post_json("/api/evaluation/attacks", attack.model_dump(mode="json"))
    post_json("/api/telemetry/events", event.model_dump(mode="json"))
    print("Red agent placeholder executed local scenario and submitted records.")


if __name__ == "__main__":
    main()
