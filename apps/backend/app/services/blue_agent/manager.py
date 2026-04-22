"""Managed LangGraph-backed Blue-agent runtime."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Callable, Optional
from uuid import uuid4

from fastapi import HTTPException

from ...blue_agent_models import (
    BlueAgentActionResponse,
    BlueAgentLogEntry,
    BlueAgentLogsResponse,
    BlueAgentStartRequest,
    BlueAgentState,
    BlueAgentStatus,
    BlueReasonerOption,
)
from ...models import ActionEvent, DetectionEvent, Severity
from ..run_state_store import RunStateStore
from .graph import build_blue_agent_graph
from .reasoner import (
    BlueReasoner,
    build_blue_reasoner_from_env,
    get_blue_reasoner_model_options,
)
from .state import BlueAgentGraphState
from .telemetry_adapter import BlueTelemetryAdapter


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LangGraphBlueAgentManager:
    """Run the Blue agent as a small background monitoring loop.

    TODO:
    - Move background execution to a dedicated worker/runtime when concurrency
      needs increase beyond the single-process MVP.
    - Add checkpointing and recovery across backend restarts.
    - Support multi-target scheduling rather than picking a single target.
    - Swap in an Ollama-backed reasoner through the same reasoner interface.
    """

    def __init__(
        self,
        running_targets_provider: Callable[[], list[object]],
        telemetry_adapter: BlueTelemetryAdapter,
        detection_callback: Callable[[DetectionEvent], DetectionEvent],
        action_callback: Optional[Callable[[ActionEvent], ActionEvent]] = None,
        reasoner: Optional[BlueReasoner] = None,
        poll_interval_seconds: float = 3.0,
        run_id_provider: Optional[Callable[[], Optional[str]]] = None,
        run_state_store: Optional[RunStateStore] = None,
    ) -> None:
        self._running_targets_provider = running_targets_provider
        self._telemetry_adapter = telemetry_adapter
        self._detection_callback = detection_callback
        self._action_callback = action_callback
        self._poll_interval_seconds = poll_interval_seconds
        self._run_id_provider = run_id_provider
        self._run_state_store = run_state_store
        self._state = BlueAgentState()
        self._logs: list[BlueAgentLogEntry] = []
        self._state_lock = threading.Lock()
        self._stream_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._stream_subscribers: dict[
            str,
            tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, object]], Optional[str]],
        ] = {}
        self._reasoner = reasoner or build_blue_reasoner_from_env()
        self._graph = build_blue_agent_graph(telemetry_adapter, self._reasoner)
        self._graph_state: BlueAgentGraphState = {
            "agent_status": BlueAgentStatus.IDLE.value,
            "telemetry_cursor": 0,
            "iteration_count": 0,
            "cycle_terminal_lines": [],
            "recent_telemetry": [],
            "recent_observables": [],
            "available_targets": [],
        }
        self._last_detection_signature: Optional[str] = None

    def model_options(self) -> list[BlueReasonerOption]:
        """Return the allowlisted Blue model options for the UI."""
        return [
            BlueReasonerOption(
                model_id=option.model_id,
                label=option.label,
                ollama_model=option.ollama_model,
                description=option.description,
            )
            for option in get_blue_reasoner_model_options()
        ]

    def _sync_run_state_store(self) -> None:
        if not self._run_state_store or not self._run_id_provider:
            return
        run_id = self._run_id_provider()
        if not run_id:
            return
        self._run_state_store.update_blue_status(run_id, self._state.model_copy(deep=True))

    def _current_run_id(self) -> Optional[str]:
        if not self._run_id_provider:
            return None
        return self._run_id_provider()

    def _stream_event(
        self,
        event_type: str,
        payload: dict[str, object],
        *,
        legacy: Optional[dict[str, object]] = None,
        run_id: Optional[str] = None,
    ) -> dict[str, object]:
        resolved_run_id = run_id if run_id is not None else self._current_run_id()
        event = {
            "event_type": event_type,
            "run_id": resolved_run_id,
            "timestamp": utc_now().isoformat(),
            "payload": payload,
        }
        if legacy:
            event.update(legacy)
        return event

    def _record_action(
        self,
        action: str,
        status: str = "recorded",
        details: Optional[dict[str, object]] = None,
    ) -> None:
        if not self._action_callback:
            return
        self._action_callback(
            ActionEvent(
                actor="blue_agent",
                action=action,
                target_type="runtime",
                target_id=self._state.selected_target or "",
                status=status,
                details=details or {},
            )
        )

    def _running_targets(self) -> list[object]:
        return self._running_targets_provider()

    def _target_names(self) -> list[str]:
        return [getattr(target, "name", "unknown-target") for target in self._running_targets()]

    def _sync_active_targets(self) -> None:
        names = self._target_names()
        self._state.active_target_names = names
        self._state.active_target_count = len(names)

    def _append_log(self, message: str, level: str = "info") -> None:
        entry = BlueAgentLogEntry(level=level, message=message)
        self._logs.append(entry)
        self._logs = self._logs[-400:]
        self._broadcast_stream_event(
            self._stream_event(
                "log_entry",
                {"entry": entry.model_dump(mode="json")},
                legacy={
                    "type": "log",
                    "entry": entry.model_dump(mode="json"),
                },
            )
        )

    def _broadcast_stream_event(self, event: dict[str, object]) -> None:
        with self._stream_lock:
            subscribers = list(self._stream_subscribers.items())

        stale_ids: list[str] = []
        event_run_id = event.get("run_id")
        for subscriber_id, (loop, queue, subscriber_run_id) in subscribers:
            if subscriber_run_id and event_run_id and subscriber_run_id != event_run_id:
                continue
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except RuntimeError:
                stale_ids.append(subscriber_id)

        for subscriber_id in stale_ids:
            self.unregister_stream(subscriber_id)

    def _broadcast_reset(self) -> None:
        self._broadcast_stream_event(
            self._stream_event(
                "stream_reset",
                {},
                legacy={"type": "reset"},
            )
        )

    def register_stream(
        self,
        run_id: Optional[str] = None,
    ) -> tuple[str, asyncio.Queue[dict[str, object]]]:
        """Register one WebSocket subscriber and seed it with current history.

        TODO:
        - Add auth and per-session tracking if this operator UI ever leaves localhost.
        - Upgrade the stream payloads to typed event objects shared with the frontend.
        """

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        subscriber_id = str(uuid4())
        with self._stream_lock:
            self._stream_subscribers[subscriber_id] = (loop, queue, run_id)

        current_run_id = self._current_run_id()
        history = [entry.model_dump(mode="json") for entry in self._logs]
        if not run_id or not current_run_id or run_id == current_run_id:
            queue.put_nowait(
                self._stream_event(
                    "history_snapshot",
                    {"logs": history},
                    legacy={"type": "history", "logs": history},
                    run_id=current_run_id,
                )
            )
            state = self.status().model_dump(mode="json")
            queue.put_nowait(
                self._stream_event(
                    "status_update",
                    {
                        "state": state,
                        "confidence": state.get("confidence"),
                        "detection_label": state.get("predicted_attack_type"),
                        "containment_decision": None,
                    },
                    legacy={"type": "status", "state": state},
                    run_id=current_run_id,
                )
            )
        return subscriber_id, queue

    def unregister_stream(self, subscriber_id: str) -> None:
        with self._stream_lock:
            self._stream_subscribers.pop(subscriber_id, None)

    def _serialize_targets(self, targets: list[object]) -> list[dict[str, object]]:
        serialized: list[dict[str, object]] = []
        for target in targets:
            serialized.append(
                {
                    "app_id": getattr(target, "app_id", None),
                    "name": getattr(target, "name", "unknown-target"),
                    "template_id": getattr(target, "template_id", None),
                    "status": getattr(target, "status", None),
                    "port": getattr(target, "port", None),
                    "target_url": getattr(target, "target_url", None),
                    "container_name": getattr(target, "container_name", None),
                    "created_at": (
                        getattr(target, "created_at", None).isoformat()
                        if getattr(target, "created_at", None)
                        else None
                    ),
                }
            )
        return serialized

    def _emit_cycle_logs(self, lines: list[dict[str, str]]) -> None:
        for line in lines:
            self._append_log(
                message=line.get("message", "No message available."),
                level=line.get("level", "info"),
            )

    def _maybe_emit_detection(self, state: BlueAgentGraphState) -> None:
        candidate = state.get("last_detection")
        if not candidate:
            return

        evidence_ids = list(candidate.get("evidence_event_ids", []))
        signature = (
            f"{candidate.get('classification')}|"
            f"{','.join(evidence_ids)}|"
            f"{candidate.get('summary')}"
        )
        if signature == self._last_detection_signature:
            return

        detection = DetectionEvent(
            detector="langgraph_blue_agent",
            classification=str(candidate.get("classification", "anomalous_web_activity")),
            confidence=float(candidate.get("confidence", 0.0)),
            severity=Severity.WARNING,
            summary=str(candidate.get("summary", "Blue-agent detection emitted.")),
            supporting_evidence=list(candidate.get("metadata", {}).get("evidence", []))[:5],
            evidence_event_ids=evidence_ids,
            metadata=dict(candidate.get("metadata", {})),
        )
        stored_detection = self._detection_callback(detection)
        self._last_detection_signature = signature
        self.publish_detection(stored_detection)
        self._append_log("Detection emitted to the backend detection store.", level="warning")

    def publish_detection(self, detection: DetectionEvent) -> None:
        """Publish one detection event onto the Blue WebSocket stream."""
        evidence_ids = ", ".join(detection.evidence_event_ids[:5]) or "none"
        self._append_log(
            (
                f"Detection reasoning: {detection.classification} at confidence "
                f"{detection.confidence:.2f}; severity {detection.severity.value}; "
                f"evidence ids {evidence_ids}."
            ),
            level="warning" if detection.severity.value in {"warning", "high"} else "info",
        )
        self._broadcast_stream_event(
            self._stream_event(
                "detection_emitted",
                {
                    "detection": detection.model_dump(mode="json"),
                    "confidence": detection.confidence,
                    "containment_decision": None,
                },
                legacy={
                    "type": "detection",
                    "detection": detection.model_dump(mode="json"),
                },
                run_id=detection.run_id,
            )
        )

    def _apply_graph_state_to_public_state(self, state: BlueAgentGraphState) -> None:
        selected_target = state.get("selected_target") or {}
        self._state.selected_target = selected_target.get("name")
        self._state.iteration_count = int(state.get("iteration_count", 0))
        self._state.suspicion_score = float(state["suspicion_score"]) if "suspicion_score" in state else None
        self._state.predicted_attack_type = state.get("predicted_attack_type")
        self._state.confidence = float(state["confidence"]) if "confidence" in state else None
        reasoner_name = getattr(self._reasoner, "name", "unknown")
        if self._state.status == BlueAgentStatus.STARTING:
            self._state.status = BlueAgentStatus.RUNNING
            self._state.message = (
                f"Blue agent is running and reasoning over indirect telemetry via {reasoner_name}."
            )
        elif self._state.status == BlueAgentStatus.RUNNING:
            self._state.message = (
                f"Blue agent monitoring cycle completed successfully via {reasoner_name}."
            )
        self._broadcast_stream_event(
            self._stream_event(
                "status_update",
                {
                    "state": self._state.model_dump(mode="json"),
                    "confidence": self._state.confidence,
                    "detection_label": self._state.predicted_attack_type,
                    "containment_decision": None,
                },
                legacy={
                    "type": "status",
                    "state": self._state.model_dump(mode="json"),
                },
            )
        )
        self._sync_run_state_store()

    def _run_cycle(self) -> None:
        targets = self._running_targets()
        if not targets:
            self.stop(reason="Blue agent stopped because no vulnerable targets remain running.")
            return

        self._graph_state["available_targets"] = self._serialize_targets(targets)
        result = self._graph.invoke(self._graph_state)
        self._graph_state = dict(result)
        self._emit_cycle_logs(list(self._graph_state.get("cycle_terminal_lines", [])))
        fallback_error = getattr(self._reasoner, "last_error", None)
        if fallback_error:
            self._append_log(
                f"Ollama reasoning unavailable for this cycle; used heuristic fallback. Reason: {fallback_error}",
                level="warning",
            )
        self._maybe_emit_detection(self._graph_state)
        self._apply_graph_state_to_public_state(self._graph_state)
        self._sync_active_targets()

    def _run_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                with self._state_lock:
                    if self._state.status not in {BlueAgentStatus.STARTING, BlueAgentStatus.RUNNING}:
                        return
                self._run_cycle()
                if self._stop_event.wait(self._poll_interval_seconds):
                    break
        except Exception as exc:
            with self._state_lock:
                self._state.status = BlueAgentStatus.ERROR
                self._state.message = f"Blue agent runtime error: {exc}"
            self._append_log(f"Blue agent runtime error: {exc}", level="error")
            self._broadcast_stream_event(
                self._stream_event(
                    "status_update",
                    {
                        "state": self._state.model_dump(mode="json"),
                        "confidence": self._state.confidence,
                        "detection_label": self._state.predicted_attack_type,
                        "containment_decision": None,
                    },
                    legacy={
                        "type": "status",
                        "state": self._state.model_dump(mode="json"),
                    },
                )
            )
            self._sync_run_state_store()
        finally:
            self._thread = None

    def status(self) -> BlueAgentState:
        should_stop = False
        with self._state_lock:
            self._sync_active_targets()
            if (
                self._state.status == BlueAgentStatus.RUNNING
                and self._state.active_target_count == 0
            ):
                should_stop = True
            state_copy = self._state.model_copy(deep=True)

        if should_stop:
            self.stop(reason="Blue agent stopped because no vulnerable targets remain running.")
            return self._state.model_copy(deep=True)
        self._sync_run_state_store()
        return state_copy

    def start(self, payload: BlueAgentStartRequest | None = None) -> BlueAgentActionResponse:
        running_targets = self._running_targets()
        if not running_targets:
            raise HTTPException(
                status_code=409,
                detail="Blue agent cannot start because no vulnerable app is currently running.",
            )

        with self._state_lock:
            if self._thread and self._thread.is_alive() and self._state.status in {
                BlueAgentStatus.STARTING,
                BlueAgentStatus.RUNNING,
            }:
                return BlueAgentActionResponse(
                    success=True,
                    message="Blue agent is already running.",
                    state=self._state.model_copy(deep=True),
                )

            requested_model_id = payload.model_id if payload else None
            self._reasoner = build_blue_reasoner_from_env(requested_model_id)
            self._graph = build_blue_agent_graph(self._telemetry_adapter, self._reasoner)
            target_names = [getattr(target, "name", "unknown-target") for target in running_targets]
            self._stop_event = threading.Event()
            self._logs = []
            self._last_detection_signature = None
            self._broadcast_reset()
            self._graph_state = {
                "agent_status": BlueAgentStatus.STARTING.value,
                "telemetry_cursor": 0,
                "iteration_count": 0,
                "cycle_terminal_lines": [],
                "recent_telemetry": [],
                "recent_observables": [],
                "available_targets": self._serialize_targets(running_targets),
                "selected_target": None,
                "last_detection": None,
            }
            self._state = BlueAgentState(
                status=BlueAgentStatus.STARTING,
                active_target_count=len(target_names),
                active_target_names=target_names,
                selected_model_id=getattr(self._reasoner, "selected_model_id", None),
                selected_model_label=getattr(self._reasoner, "selected_model_label", None),
                last_started_at=utc_now(),
                last_stopped_at=self._state.last_stopped_at,
                message="Blue agent is starting and preparing the LangGraph monitoring loop.",
            )
            self._append_log("Blue agent start requested.", level="info")
            self._append_log(
                f"Attached to {len(target_names)} running target(s): {', '.join(target_names)}.",
                level="info",
            )
            self._append_log(
                "Runtime scope is restricted to indirect telemetry and inferred behavior only.",
                level="info",
            )
            self._append_log(
                f"Reasoning backend selected: {getattr(self._reasoner, 'name', 'unknown')}.",
                level="info",
            )
            if self._state.selected_model_label:
                self._append_log(
                    f"Reasoning model selected: {self._state.selected_model_label}.",
                    level="info",
                )
            self._broadcast_stream_event(
                self._stream_event(
                    "status_update",
                    {
                        "state": self._state.model_dump(mode="json"),
                        "confidence": self._state.confidence,
                        "detection_label": self._state.predicted_attack_type,
                        "containment_decision": None,
                    },
                    legacy={
                        "type": "status",
                        "state": self._state.model_dump(mode="json"),
                    },
                )
            )
            self._sync_run_state_store()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="cyberbox-blue-agent",
                daemon=True,
            )
            self._thread.start()
            self._record_action(
                "start",
                details={
                    "active_targets": target_names,
                    "reasoner": getattr(self._reasoner, "name", "unknown"),
                },
            )
            return BlueAgentActionResponse(
                success=True,
                message="Blue agent started.",
                state=self._state.model_copy(deep=True),
            )

    def stop(self, reason: str = "Blue agent stopped by operator.") -> BlueAgentActionResponse:
        thread = self._thread
        with self._state_lock:
            self._stop_event.set()
            previous_started_at = self._state.last_started_at
            self._state = BlueAgentState(
                status=BlueAgentStatus.STOPPED,
                active_target_count=0,
                active_target_names=[],
                selected_target=None,
                iteration_count=int(self._graph_state.get("iteration_count", 0)),
                suspicion_score=self._state.suspicion_score,
                predicted_attack_type=self._state.predicted_attack_type,
                confidence=self._state.confidence,
                selected_model_id=self._state.selected_model_id,
                selected_model_label=self._state.selected_model_label,
                last_started_at=previous_started_at,
                last_stopped_at=utc_now(),
                message=reason,
            )
            self._append_log(reason, level="warning")
            response = BlueAgentActionResponse(
                success=True,
                message=reason,
                state=self._state.model_copy(deep=True),
            )
            self._record_action("stop", details={"reason": reason})
            self._broadcast_stream_event(
                self._stream_event(
                    "status_update",
                    {
                        "state": self._state.model_dump(mode="json"),
                        "confidence": self._state.confidence,
                        "detection_label": self._state.predicted_attack_type,
                        "containment_decision": None,
                    },
                    legacy={
                        "type": "status",
                        "state": self._state.model_dump(mode="json"),
                    },
                )
            )
            self._sync_run_state_store()

        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=0.2)
        return response

    def logs(self) -> BlueAgentLogsResponse:
        return BlueAgentLogsResponse(logs=list(self._logs))
