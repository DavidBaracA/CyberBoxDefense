"""Managed bounded Red-agent runtime for local scenario execution."""

from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib import error, parse, request
from uuid import uuid4

from fastapi import HTTPException

from ...models import AttackGroundTruth, Severity, TelemetryEvent, TelemetryKind, TelemetrySource
from ...red_agent_models import (
    AttackRunRecord,
    GroundTruthAttackEvent,
    RedAgentActionResponse,
    RedAgentLogEvent,
    RedAgentLogsResponse,
    RedAgentRunStatus,
    RedAgentStartRequest,
    RedAgentStatus,
)
from ...vulnerable_apps_models import VulnerableAppDetail, VulnerableAppStatus
from .scenarios import build_probe_plan, get_scenario, get_scenario_catalog


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RedAgentManager:
    """Run a bounded Red-agent scenario batch against one local managed target.

    TODO:
    - Add persisted run history and replay support.
    - Add richer per-scenario telemetry mapping for different target families.
    - Add experiment scheduling once multiple runs must be orchestrated.
    """

    def __init__(
        self,
        running_targets_provider: Callable[[], list[VulnerableAppDetail]],
        telemetry_callback: Callable[[TelemetryEvent], TelemetryEvent],
        ground_truth_callback: Callable[[AttackGroundTruth], AttackGroundTruth],
    ) -> None:
        self._running_targets_provider = running_targets_provider
        self._telemetry_callback = telemetry_callback
        self._ground_truth_callback = ground_truth_callback
        self._state = RedAgentStatus()
        self._logs: list[RedAgentLogEvent] = []
        self._ground_truth_events: list[GroundTruthAttackEvent] = []
        self._state_lock = threading.Lock()
        self._stream_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._stream_subscribers: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, object]]]] = {}

    def scenarios(self):
        return get_scenario_catalog()

    def _append_log(self, message: str, level: str = "info") -> None:
        entry = RedAgentLogEvent(level=level, message=message)
        self._logs.append(entry)
        self._logs = self._logs[-400:]
        self._broadcast({"type": "log", "entry": entry.model_dump(mode="json")})

    def _broadcast(self, event: dict[str, object]) -> None:
        with self._stream_lock:
            subscribers = list(self._stream_subscribers.items())
        stale_ids: list[str] = []
        for subscriber_id, (loop, queue) in subscribers:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except RuntimeError:
                stale_ids.append(subscriber_id)
        for subscriber_id in stale_ids:
            self.unregister_stream(subscriber_id)

    def register_stream(self) -> tuple[str, asyncio.Queue[dict[str, object]]]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        subscriber_id = str(uuid4())
        with self._stream_lock:
            self._stream_subscribers[subscriber_id] = (loop, queue)
        queue.put_nowait({"type": "history", "logs": [entry.model_dump(mode="json") for entry in self._logs]})
        queue.put_nowait({"type": "status", "state": self.status().model_dump(mode="json")})
        return subscriber_id, queue

    def unregister_stream(self, subscriber_id: str) -> None:
        with self._stream_lock:
            self._stream_subscribers.pop(subscriber_id, None)

    def _broadcast_status(self) -> None:
        self._broadcast({"type": "status", "state": self._state.model_dump(mode="json")})

    def _running_targets(self) -> list[VulnerableAppDetail]:
        return [target for target in self._running_targets_provider() if target.status == VulnerableAppStatus.RUNNING]

    def _resolve_target(self, app_id: str) -> VulnerableAppDetail:
        target = next((item for item in self._running_targets() if item.app_id == app_id), None)
        if not target:
            raise HTTPException(
                status_code=409,
                detail="Red agent can only target a currently running platform-managed vulnerable app.",
            )
        return target

    def _record_ground_truth(self, run_id: str, target: VulnerableAppDetail, scenario_id: str, phase: str, metadata: dict[str, object]) -> None:
        event = GroundTruthAttackEvent(
            run_id=run_id,
            target_app_id=target.app_id,
            scenario_id=scenario_id,
            phase=phase,
            metadata=metadata,
        )
        self._ground_truth_events.append(event)
        self._ground_truth_events = self._ground_truth_events[-400:]
        self._ground_truth_callback(
            AttackGroundTruth(
                attack_type=scenario_id,
                target=f"{target.name}:{metadata.get('path', target.target_url)}",
                status=phase,
                notes=f"Red-agent {phase} recorded for offline evaluation.",
                metadata={
                    "run_id": run_id,
                    "target_app_id": target.app_id,
                    "scenario_id": scenario_id,
                    **metadata,
                },
            )
        )

    def _emit_observable_telemetry(
        self,
        target: VulnerableAppDetail,
        path: str,
        method: str,
        status_code: int,
        response_size: int,
    ) -> None:
        is_error = status_code >= 400
        self._telemetry_callback(
            TelemetryEvent(
                source=TelemetrySource.CONTAINER_MONITOR,
                kind=TelemetryKind.HTTP_ERROR if is_error else TelemetryKind.ACCESS_LOG,
                severity=Severity.WARNING if (is_error or status_code == 0) else Severity.INFO,
                container_name=target.container_name or target.name,
                service_name=target.name,
                path=path,
                http_status=status_code or None,
                message=(
                    f"Observed {method} traffic to monitored target route with HTTP {status_code}."
                ),
                metadata={
                    "response_size": response_size,
                    "method": method,
                },
            )
        )

    def _perform_probe(self, base_url: str, probe: dict[str, object]) -> tuple[int, int]:
        method = str(probe.get("method", "GET")).upper()
        path = str(probe.get("path", "/"))
        body = probe.get("body")
        url = f"{base_url.rstrip('/')}{path}"
        data = None
        headers = {"User-Agent": "CyberBoxDefense-RedAgent/0.1"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=8.0) as response:
                payload = response.read()
                return int(response.getcode() or 200), len(payload)
        except error.HTTPError as exc:
            payload = exc.read()
            return int(exc.code), len(payload)
        except error.URLError:
            return 0, 0

    def _run_selected_scenarios(self, run_id: str, target: VulnerableAppDetail, scenario_ids: list[str]) -> None:
        self._append_log(f"Selected target URL: {target.target_url}", level="info")
        for scenario_id in scenario_ids:
            if self._stop_event.is_set():
                self._append_log("Red agent stop requested; ending run before next scenario.", level="warning")
                return

            scenario = get_scenario(scenario_id)
            if not scenario:
                self._append_log(f"Skipped unknown scenario {scenario_id}.", level="warning")
                continue

            self._append_log(f"Running scenario: {scenario.display_name}.", level="info")
            plan = build_probe_plan(target.template_id, scenario_id)
            self._record_ground_truth(run_id, target, scenario_id, "started", {"path": target.target_url})
            for index, probe in enumerate(plan, start=1):
                if self._stop_event.is_set():
                    self._append_log("Red agent stop requested during active scenario execution.", level="warning")
                    return
                method = str(probe.get("method", "GET")).upper()
                path = str(probe.get("path", "/"))
                self._append_log(
                    f"Sending probe batch item {index}/{len(plan)} to {path} with method {method}.",
                    level="info",
                )
                status_code, response_size = self._perform_probe(target.target_url, probe)
                self._append_log(
                    f"Received response summary: status={status_code or 'unreachable'}, bytes={response_size}.",
                    level="info" if status_code and status_code < 400 else "warning",
                )
                self._emit_observable_telemetry(target, path, method, status_code, response_size)
                self._state.emitted_events_count += 1
                self._record_ground_truth(
                    run_id,
                    target,
                    scenario_id,
                    "probe_sent",
                    {"path": path, "method": method, "http_status": status_code},
                )

            self._append_log(f"Scenario completed: {scenario.display_name}.", level="info")
            self._record_ground_truth(run_id, target, scenario_id, "completed", {"path": target.target_url})

    def _run_loop(self, run_id: str, target: VulnerableAppDetail, scenario_ids: list[str]) -> None:
        try:
            self._run_selected_scenarios(run_id, target, scenario_ids)
            with self._state_lock:
                if self._stop_event.is_set():
                    self._state.status = RedAgentRunStatus.STOPPED
                    self._state.message = "Red agent run stopped by operator."
                else:
                    self._state.status = RedAgentRunStatus.COMPLETED
                    self._state.message = "Red agent completed the selected bounded scenarios."
                self._state.finished_at = utc_now()
            self._append_log("Attack run finished.", level="info")
            self._broadcast_status()
        except Exception as exc:
            with self._state_lock:
                self._state.status = RedAgentRunStatus.ERROR
                self._state.message = f"Red agent runtime error: {exc}"
                self._state.finished_at = utc_now()
            self._append_log(f"Red agent runtime error: {exc}", level="error")
            self._broadcast_status()
        finally:
            self._thread = None

    def status(self) -> RedAgentStatus:
        return self._state.model_copy(deep=True)

    def start(self, payload: RedAgentStartRequest) -> RedAgentActionResponse:
        running_targets = self._running_targets()
        if not running_targets:
            raise HTTPException(
                status_code=409,
                detail="Red agent cannot start because no vulnerable app is currently running.",
            )

        invalid = [scenario_id for scenario_id in payload.scenario_ids if get_scenario(scenario_id) is None]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Unsupported Red scenario(s): {', '.join(invalid)}")

        target = self._resolve_target(payload.target_app_id)
        with self._state_lock:
            if self._thread and self._thread.is_alive() and self._state.status in {
                RedAgentRunStatus.STARTING,
                RedAgentRunStatus.RUNNING,
            }:
                raise HTTPException(status_code=409, detail="Red agent is already running.")

            run_id = str(uuid4())
            self._stop_event = threading.Event()
            self._logs = []
            self._broadcast({"type": "reset"})
            self._state = RedAgentStatus(
                run_id=run_id,
                target_app_id=target.app_id,
                target_name=target.name,
                target_url=target.target_url,
                selected_scenarios=list(payload.scenario_ids),
                status=RedAgentRunStatus.STARTING,
                started_at=utc_now(),
                message="Red agent is preparing the selected bounded scenario run.",
                emitted_events_count=0,
            )
            self._append_log("Red agent initialization started.", level="info")
            self._append_log(f"Validated managed target: {target.name}.", level="info")
            self._append_log(
                f"Selected scenarios: {', '.join(payload.scenario_ids)}.",
                level="info",
            )
            self._state.status = RedAgentRunStatus.RUNNING
            self._state.message = "Red agent is executing bounded local scenarios."
            self._broadcast_status()
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(run_id, target, list(payload.scenario_ids)),
                name="cyberbox-red-agent",
                daemon=True,
            )
            self._thread.start()
            return RedAgentActionResponse(
                success=True,
                message="Red agent started.",
                state=self._state.model_copy(deep=True),
            )

    def stop(self, reason: str = "Red agent stopped by operator.") -> RedAgentActionResponse:
        thread = self._thread
        with self._state_lock:
            self._stop_event.set()
            if self._state.status in {RedAgentRunStatus.IDLE, RedAgentRunStatus.COMPLETED, RedAgentRunStatus.STOPPED}:
                self._state.message = reason
            else:
                self._state.status = RedAgentRunStatus.STOPPED
                self._state.message = reason
                self._state.finished_at = utc_now()
            self._append_log(reason, level="warning")
            self._broadcast_status()
            response = RedAgentActionResponse(
                success=True,
                message=reason,
                state=self._state.model_copy(deep=True),
            )
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=0.2)
        return response

    def logs(self) -> RedAgentLogsResponse:
        return RedAgentLogsResponse(logs=list(self._logs))
