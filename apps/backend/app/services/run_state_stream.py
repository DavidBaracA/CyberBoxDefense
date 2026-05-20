"""Run-scoped WebSocket broadcaster for live dashboard state."""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Optional
from uuid import uuid4

from ..models import ActionEvent, DetectionEvent, MetricSnapshot, TelemetryEvent, utc_now
from ..run_models import Run
from ..run_state_models import RunStateSnapshot
from .run_state_store import RunStateStore


class RunStateStream:
    """Publish run-state changes to WebSocket subscribers keyed by run id."""

    def __init__(self, state_store: RunStateStore) -> None:
        self._state_store = state_store
        self._subscribers: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]], str]] = {}
        self._lock = threading.Lock()

    def _event(
        self,
        event_type: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "type": event_type,
            "run_id": run_id,
            "timestamp": utc_now().isoformat(),
            **payload,
        }

    def _publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers.items())

        stale_ids: list[str] = []
        event_run_id = event.get("run_id")
        for subscriber_id, (loop, queue, subscriber_run_id) in subscribers:
            if subscriber_run_id != event_run_id:
                continue
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except RuntimeError:
                stale_ids.append(subscriber_id)

        for subscriber_id in stale_ids:
            self.unregister(subscriber_id)

    def register(self, run_id: str) -> tuple[str, asyncio.Queue[dict[str, Any]]]:
        """Register a subscriber and seed it with the latest known snapshot."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        subscriber_id = str(uuid4())
        with self._lock:
            self._subscribers[subscriber_id] = (loop, queue, run_id)

        snapshot = self._state_store.get_run_state(run_id)
        if snapshot:
            queue.put_nowait(self.snapshot_event(snapshot))

        return subscriber_id, queue

    def unregister(self, subscriber_id: str) -> None:
        with self._lock:
            self._subscribers.pop(subscriber_id, None)

    def snapshot_event(self, snapshot: RunStateSnapshot) -> dict[str, Any]:
        return self._event(
            "snapshot",
            snapshot.run_id,
            {"state": snapshot.model_dump(mode="json")},
        )

    def publish_snapshot(self, snapshot: Optional[RunStateSnapshot]) -> None:
        if snapshot:
            self._publish(self.snapshot_event(snapshot))

    def publish_run(self, run: Run, snapshot: Optional[RunStateSnapshot] = None) -> None:
        payload: dict[str, Any] = {"run": run.model_dump(mode="json")}
        if snapshot:
            payload["state"] = snapshot.model_dump(mode="json")
        self._publish(self._event("run_status", run.run_id, payload))

    def publish_telemetry(self, event: TelemetryEvent) -> None:
        if event.run_id:
            self._publish(
                self._event(
                    "telemetry",
                    event.run_id,
                    {"event": event.model_dump(mode="json")},
                )
            )

    def publish_detection(self, event: DetectionEvent) -> None:
        if event.run_id:
            self._publish(
                self._event(
                    "detection",
                    event.run_id,
                    {"event": event.model_dump(mode="json")},
                )
            )

    def publish_action(self, event: ActionEvent) -> None:
        if event.run_id:
            self._publish(
                self._event(
                    "action",
                    event.run_id,
                    {"event": event.model_dump(mode="json")},
                )
            )

    def publish_metrics(self, run_id: str, metrics: MetricSnapshot) -> None:
        self._publish(
            self._event(
                "metrics",
                run_id,
                {"snapshot": metrics.model_dump(mode="json")},
            )
        )
