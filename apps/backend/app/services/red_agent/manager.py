"""Managed bounded Red-agent runtime for local scenario execution."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib import parse
from uuid import uuid4

from fastapi import HTTPException

from ...models import ActionEvent, AttackGroundTruth, Severity, TelemetryEvent, TelemetryKind, TelemetrySource
from ...red_agent_models import (
    AttackExecutionPlan,
    RedReasonerOption,
    AttackTechniquePlan,
    GroundTruthAttackEvent,
    RedAgentActionResponse,
    RedAgentLogEvent,
    RedAgentLogsResponse,
    RedAgentRunStatus,
    RedAgentSessionDetail,
    RedAgentSessionScreenshot,
    RedAgentSessionVulnerability,
    RedAgentStartRequest,
    RedAgentStatus,
)
from ...run_models import Run, RunStatus, RunTerminationReason
from ...services.run_service import RunService
from ...services.run_state_store import RunStateStore
from ...vulnerable_apps_models import VulnerableAppDetail, VulnerableAppStatus
from .planner import AttackPlanner
from .reasoner import (
    build_red_planning_reasoner,
    get_red_planning_model_options,
    resolve_red_planning_model_option,
)
from .scenarios import get_scenario, get_scenario_catalog
from .session_history import RedAgentSessionHistoryStore


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RedAgentManager:
    """Run a bounded Red-agent scenario batch against one local managed target.

    TODO:
    - Add richer per-scenario telemetry mapping for different target families.
    - Add experiment scheduling once multiple runs must be orchestrated.
    """

    def __init__(
        self,
        running_targets_provider: Callable[[], list[VulnerableAppDetail]],
        run_service: RunService,
        telemetry_callback: Callable[[TelemetryEvent], TelemetryEvent],
        ground_truth_callback: Callable[[AttackGroundTruth], AttackGroundTruth],
        action_callback: Optional[Callable[[ActionEvent], ActionEvent]] = None,
        planner: Optional[AttackPlanner] = None,
        run_state_store: Optional[RunStateStore] = None,
        session_history_store: Optional[RedAgentSessionHistoryStore] = None,
    ) -> None:
        self._running_targets_provider = running_targets_provider
        self._run_service = run_service
        self._telemetry_callback = telemetry_callback
        self._ground_truth_callback = ground_truth_callback
        self._action_callback = action_callback
        self._planner = planner or AttackPlanner()
        self._run_state_store = run_state_store
        self._session_history_store = session_history_store
        self._state = RedAgentStatus()
        self._logs: list[RedAgentLogEvent] = []
        self._ground_truth_events: list[GroundTruthAttackEvent] = []
        self._current_session: Optional[RedAgentSessionDetail] = None
        self._state_lock = threading.Lock()
        self._stream_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._stream_subscribers: dict[
            str,
            tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, object]], Optional[str]],
        ] = {}

    def _record_action(
        self,
        action: str,
        target_id: str = "",
        run_id: Optional[str] = None,
        status: str = "recorded",
        details: Optional[dict[str, object]] = None,
    ) -> None:
        if not self._action_callback:
            return
        self._action_callback(
            ActionEvent(
                actor="red_agent",
                action=action,
                target_type="vulnerable_app",
                target_id=target_id,
                run_id=run_id,
                status=status,
                details=details or {},
            )
        )

    def scenarios(self):
        return get_scenario_catalog()

    def model_options(self):
        return [
            RedReasonerOption(
                model_id=option.model_id,
                label=option.label,
                ollama_model=option.ollama_model,
                description=option.description,
            )
            for option in get_red_planning_model_options()
        ]

    def _append_log(self, message: str, level: str = "info") -> None:
        entry = RedAgentLogEvent(level=level, message=message)
        self._logs.append(entry)
        self._logs = self._logs[-400:]
        if self._current_session is not None:
            self._current_session.logs.append(entry)
            self._current_session.logs = self._current_session.logs[-400:]
        self._broadcast(
            self._stream_event(
                "log_entry",
                {"entry": entry.model_dump(mode="json")},
                legacy={"type": "log", "entry": entry.model_dump(mode="json")},
            )
        )

    def _stream_event(
        self,
        event_type: str,
        payload: dict[str, object],
        *,
        legacy: Optional[dict[str, object]] = None,
        run_id: Optional[str] = None,
    ) -> dict[str, object]:
        resolved_run_id = run_id if run_id is not None else self._state.run_id
        event = {
            "event_type": event_type,
            "run_id": resolved_run_id,
            "timestamp": utc_now().isoformat(),
            "payload": payload,
        }
        if legacy:
            event.update(legacy)
        return event

    def _broadcast(self, event: dict[str, object]) -> None:
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

    def register_stream(
        self,
        run_id: Optional[str] = None,
    ) -> tuple[str, asyncio.Queue[dict[str, object]]]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        subscriber_id = str(uuid4())
        with self._stream_lock:
            self._stream_subscribers[subscriber_id] = (loop, queue, run_id)
        if not run_id or not self._state.run_id or run_id == self._state.run_id:
            logs = [entry.model_dump(mode="json") for entry in self._logs]
            queue.put_nowait(
                self._stream_event(
                    "history_snapshot",
                    {"logs": logs},
                    legacy={"type": "history", "logs": logs},
                )
            )
            state = self.status().model_dump(mode="json")
            queue.put_nowait(
                self._stream_event(
                    "status_update",
                    self._status_payload(state),
                    legacy={"type": "status", "state": state},
                    run_id=state.get("run_id"),
                )
            )
        return subscriber_id, queue

    def unregister_stream(self, subscriber_id: str) -> None:
        with self._stream_lock:
            self._stream_subscribers.pop(subscriber_id, None)

    def _broadcast_status(self) -> None:
        self._sync_run_state_store()
        state = self._state.model_dump(mode="json")
        self._broadcast(
            self._stream_event(
                "status_update",
                self._status_payload(state),
                legacy={"type": "status", "state": state},
                run_id=state.get("run_id"),
            )
        )

    def _status_payload(self, state: dict[str, object]) -> dict[str, object]:
        return {
            "state": state,
            "current_technique": state.get("current_technique"),
            "progress": {
                "completed_techniques": state.get("completed_techniques", []),
                "remaining_techniques": state.get("remaining_techniques", []),
                "remaining_time_budget_seconds": state.get("remaining_time_budget_seconds"),
            },
            "evidence_references": [
                {
                    "artifact_path": state.get("latest_artifact_path"),
                    "artifact_url": state.get("latest_artifact_url"),
                }
            ]
            if state.get("latest_artifact_path") or state.get("latest_artifact_url")
            else [],
        }

    def _sync_run_state_store(self) -> None:
        if not self._run_state_store or not self._state.run_id:
            return
        run_id = self._state.run_id
        self._run_state_store.update_red_status(run_id, self._state.model_copy(deep=True))
        self._run_state_store.set_remaining_time(
            run_id,
            self._state.remaining_time_budget_seconds,
        )
        if self._state.latest_artifact_path or self._state.latest_artifact_url:
            self._run_state_store.record_evidence_artifact(
                run_id,
                artifact_path=self._state.latest_artifact_path,
                artifact_url=self._state.latest_artifact_url,
                artifact_type="browser_screenshot",
            )

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

    def _remaining_budget_seconds(self, run: Run) -> int:
        return max(0, int((run.expires_at - utc_now()).total_seconds()))

    def _apply_progress_state(
        self,
        *,
        run: Run,
        current_technique: Optional[str],
        completed_techniques: list[str],
        remaining_techniques: list[str],
    ) -> None:
        self._state.current_technique = current_technique
        self._state.completed_techniques = list(completed_techniques)
        self._state.remaining_techniques = list(remaining_techniques)
        self._state.remaining_time_budget_seconds = self._remaining_budget_seconds(run)
        self._broadcast_status()

    def _stop_reason_from_run(self, run: Run) -> Optional[RunTerminationReason]:
        if self._stop_event.is_set():
            return RunTerminationReason.STOPPED_BY_USER
        latest_run = self._run_service.get_run(run.run_id)
        if latest_run.status == RunStatus.STOPPING:
            return latest_run.termination_reason
        return None

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
                run_id=run_id,
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
        run_id: str,
        target: VulnerableAppDetail,
        path: str,
        method: str,
        status_code: int,
        response_size: int,
    ) -> None:
        is_error = status_code >= 400
        self._telemetry_callback(
            TelemetryEvent(
                run_id=run_id,
                app_id=target.app_id,
                source=TelemetrySource.CONTAINER_MONITOR,
                source_type="red_browser_observable",
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

    def _perform_browser_scenario(
        self,
        run_id: str,
        target: VulnerableAppDetail,
        scenario_id: str,
    ) -> dict[str, object]:
        repo_root = Path(__file__).resolve().parents[5]
        frontend_dir = repo_root / "apps" / "frontend"
        runner_path = frontend_dir / "tests" / "e2e" / "helpers" / "runBrowserScenario.mjs"
        output_dir = frontend_dir / "test-results" / "red-agent"
        env = os.environ.copy()
        env.update(
            {
                "CYBERBOX_TARGET_URL": target.target_url,
                "CYBERBOX_TARGET_TEMPLATE": target.template_id.value,
                "CYBERBOX_SCENARIO_ID": scenario_id,
                "CYBERBOX_RUN_ID": run_id,
                "CYBERBOX_OUTPUT_DIR": str(output_dir),
            }
        )
        completed = subprocess.run(
            ["node", str(runner_path)],
            cwd=str(frontend_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "Unknown Playwright runner failure."
            raise RuntimeError(stderr)

        try:
            return json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            raise RuntimeError("Playwright runner returned invalid JSON.") from exc

    def _artifact_url_for_path(self, artifact_path: str) -> str:
        artifact_name = Path(artifact_path).name
        return f"/artifacts/red-agent/{artifact_name}"

    def _record_session_screenshot(
        self,
        *,
        scenario_id: str,
        scenario_name: str,
        screenshot_path: str,
        artifact_url: str,
        summary: Optional[str],
    ) -> None:
        if self._current_session is None:
            return
        self._current_session.screenshots.append(
            RedAgentSessionScreenshot(
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                filename=Path(screenshot_path).name,
                artifact_path=str(screenshot_path),
                artifact_url=artifact_url,
                summary=summary,
            )
        )

    def _record_session_vulnerability(
        self,
        *,
        scenario_id: str,
        scenario_name: str,
        location: str,
        evidence: str,
    ) -> None:
        if self._current_session is None:
            return
        vulnerability_type = "credential_attack" if scenario_id == "browser_login_bruteforce" else scenario_id
        vulnerability_title = (
            "Login brute-force vulnerability signal"
            if scenario_id == "browser_login_bruteforce"
            else f"{scenario_name} vulnerability signal"
        )
        vulnerability = RedAgentSessionVulnerability(
            scenario_id=scenario_id,
            type=vulnerability_type,
            title=vulnerability_title,
            severity="high",
            location=location,
            evidence=evidence,
        )
        self._current_session.vulnerabilities.append(vulnerability)

    def _finalize_session(self) -> None:
        if self._current_session is None or self._session_history_store is None:
            return
        finalized = self._current_session.model_copy(
            update={
                "ended_at": self._state.finished_at or utc_now(),
                "status": self._state.status,
                "completed_techniques": list(self._state.completed_techniques),
                "summary": self._state.message,
                "metadata": {
                    **self._current_session.metadata,
                    "run_id": self._state.run_id,
                    "emitted_events_count": self._state.emitted_events_count,
                    "latest_artifact_path": self._state.latest_artifact_path,
                    "latest_artifact_url": self._state.latest_artifact_url,
                    "remaining_time_budget_seconds": self._state.remaining_time_budget_seconds,
                },
            }
        )
        self._session_history_store.save_session(finalized)
        self._current_session = None

    def _run_browser_scenario(self, run: Run, target: VulnerableAppDetail, technique: AttackTechniquePlan) -> bool:
        run_id = run.run_id
        scenario_id = technique.technique_id
        scenario = get_scenario(scenario_id)
        self._append_log(f"Running browser scenario: {scenario.display_name}.", level="info")
        self._record_ground_truth(run_id, target, scenario_id, "started", {"path": target.target_url})
        self._record_action(
            "scenario_started",
            target_id=target.app_id,
            run_id=run_id,
            details={"scenario_id": scenario_id, "execution_mode": "browser"},
        )
        result = self._perform_browser_scenario(run_id, target, scenario_id)
        self._append_log(result.get("summary", "Browser scenario completed."), level="info")
        screenshot_path = result.get("screenshot_path")
        if screenshot_path:
            self._append_log(f"Playwright screenshot saved to {screenshot_path}.", level="info")
            self._state.latest_artifact_path = str(screenshot_path)
            self._state.latest_artifact_url = self._artifact_url_for_path(str(screenshot_path))
            self._record_session_screenshot(
                scenario_id=scenario_id,
                scenario_name=scenario.display_name,
                screenshot_path=str(screenshot_path),
                artifact_url=self._state.latest_artifact_url,
                summary=result.get("summary"),
            )
            self._broadcast_status()
        status_code = int(result.get("status_code") or 200)
        response_size = int(result.get("response_size") or 0)
        current_url = str(result.get("current_url") or target.target_url)
        try:
            current_path = parse.urlparse(current_url).path or "/"
        except Exception:
            current_path = "/"
        path = current_path or "/"
        self._emit_observable_telemetry(run_id, target, path, "BROWSER", status_code, response_size)
        self._state.emitted_events_count += 1
        confirmed_vulnerability = bool(result.get("confirmed_vulnerability", False))
        self._record_ground_truth(
            run_id,
            target,
            scenario_id,
            "completed",
            {
                "path": target.target_url,
                "status_code": status_code,
                "response_size": response_size,
                "screenshot_path": screenshot_path,
                "artifact_url": self._state.latest_artifact_url,
                "execution_mode": "browser",
                "confirmed_vulnerability": confirmed_vulnerability,
            },
        )
        self._record_action(
            "scenario_completed",
            target_id=target.app_id,
            run_id=run_id,
            details={
                "scenario_id": scenario_id,
                "execution_mode": "browser",
                "confirmed_vulnerability": confirmed_vulnerability,
            },
        )
        if confirmed_vulnerability:
            self._record_session_vulnerability(
                scenario_id=scenario_id,
                scenario_name=scenario.display_name,
                location=current_url,
                evidence=result.get("summary", "Confirmed vulnerability signal observed by the Red agent."),
            )
            self._append_log(
                f"Confirmed vulnerability signal observed during {scenario.display_name}.",
                level="warning",
            )
        return confirmed_vulnerability

    def _run_planned_techniques(
        self,
        run: Run,
        target: VulnerableAppDetail,
        plan: AttackExecutionPlan,
    ) -> Optional[RunTerminationReason]:
        self._append_log(f"Selected target URL: {target.target_url}", level="info")
        completed: list[str] = []
        techniques = list(plan.techniques)
        if not techniques:
            self._append_log("Attack planner returned no techniques for this run.", level="warning")
            self._apply_progress_state(run=run, current_technique=None, completed_techniques=[], remaining_techniques=[])
            return None

        self._apply_progress_state(
            run=run,
            current_technique=None,
            completed_techniques=completed,
            remaining_techniques=[technique.technique_id for technique in techniques],
        )
        for index, technique in enumerate(techniques):
            stop_reason = self._stop_reason_from_run(run)
            if stop_reason:
                self._append_log(
                    "Red agent stopping before next technique due to run stop or timeout.",
                    level="warning",
                )
                return stop_reason

            remaining_after_current = [
                item.technique_id for item in techniques[index + 1 :]
            ]
            self._apply_progress_state(
                run=run,
                current_technique=technique.technique_name,
                completed_techniques=completed,
                remaining_techniques=remaining_after_current,
            )

            scenario = get_scenario(technique.technique_id)
            if not scenario:
                self._append_log(
                    f"Skipped unknown planned technique {technique.technique_id}.",
                    level="warning",
                )
                continue
            if scenario.execution_mode != "browser":
                self._append_log(
                    f"Skipped non-browser planned technique {technique.technique_id}.",
                    level="warning",
                )
                continue

            confirmed_vulnerability = self._run_browser_scenario(run, target, technique)
            completed.append(technique.technique_id)
            self._apply_progress_state(
                run=run,
                current_technique=None,
                completed_techniques=completed,
                remaining_techniques=remaining_after_current,
            )

            if confirmed_vulnerability and run.config.stop_on_first_confirmed_vulnerability:
                self._append_log(
                    "Run configuration requests stop on first confirmed vulnerability. Ending run early.",
                    level="warning",
                )
                return RunTerminationReason.FIRST_CONFIRMED_VULNERABILITY

            stop_reason = self._stop_reason_from_run(run)
            if stop_reason:
                return stop_reason
        return None

    def _run_loop(self, run: Run, target: VulnerableAppDetail, plan: AttackExecutionPlan) -> None:
        try:
            termination_reason = self._run_planned_techniques(run, target, plan)
            with self._state_lock:
                if termination_reason == RunTerminationReason.COMPLETED_TIMEOUT:
                    self._state.status = RedAgentRunStatus.STOPPED
                    self._state.message = "Red agent stopped because the run time budget expired."
                elif termination_reason == RunTerminationReason.STOPPED_BY_USER:
                    self._state.status = RedAgentRunStatus.STOPPED
                    self._state.message = "Red agent run stopped by operator."
                elif termination_reason == RunTerminationReason.FIRST_CONFIRMED_VULNERABILITY:
                    self._run_service.mark_completed(
                        run.run_id,
                        termination_reason=RunTerminationReason.FIRST_CONFIRMED_VULNERABILITY,
                    )
                    self._state.status = RedAgentRunStatus.COMPLETED
                    self._state.message = (
                        "Red agent stopped after the first confirmed vulnerability as configured."
                    )
                else:
                    self._run_service.mark_completed(
                        run.run_id,
                        termination_reason=RunTerminationReason.COMPLETED_PLAN_FINISHED,
                    )
                    self._state.status = RedAgentRunStatus.COMPLETED
                    self._state.message = "Red agent completed the planned techniques."
                self._state.finished_at = utc_now()
                self._state.remaining_time_budget_seconds = self._remaining_budget_seconds(run)
            self._append_log("Attack run finished.", level="info")
            self._broadcast_status()
        except Exception as exc:
            self._run_service.mark_failed(run.run_id)
            with self._state_lock:
                self._state.status = RedAgentRunStatus.ERROR
                self._state.message = f"Red agent runtime error: {exc}"
                self._state.finished_at = utc_now()
            self._append_log(f"Red agent runtime error: {exc}", level="error")
            self._broadcast_status()
        finally:
            self._finalize_session()
            self._thread = None

    def status(self) -> RedAgentStatus:
        self._sync_run_state_store()
        return self._state.model_copy(deep=True)

    def start(self, payload: RedAgentStartRequest) -> RedAgentActionResponse:
        if not payload.run_id:
            raise HTTPException(
                status_code=400,
                detail="Red agent start now requires run_id so the execution plan can be derived from RunConfig.",
            )

        run = self._run_service.get_run(payload.run_id)
        if run.status not in {RunStatus.PENDING, RunStatus.STARTING, RunStatus.RUNNING, RunStatus.STOPPING}:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Run {run.run_id} is {run.status.value} and cannot be used to start the Red agent."
                ),
            )
        target = self._resolve_target(run.app_id)
        selected_model = resolve_red_planning_model_option(run.config.red_model_id)
        self._planner = AttackPlanner(
            reasoner=build_red_planning_reasoner(run.config.red_model_id)
        )
        plan = self._planner.plan(
            run.config,
            target_name=target.name,
            target_url=target.target_url,
        )
        planned_technique_ids = [technique.technique_id for technique in plan.techniques]
        with self._state_lock:
            if self._thread and self._thread.is_alive() and self._state.status in {
                RedAgentRunStatus.STARTING,
                RedAgentRunStatus.RUNNING,
            }:
                raise HTTPException(status_code=409, detail="Red agent is already running.")

            self._stop_event = threading.Event()
            self._logs = []
            self._broadcast({"type": "reset"})
            self._state = RedAgentStatus(
                run_id=run.run_id,
                target_app_id=target.app_id,
                target_name=target.name,
                target_url=target.target_url,
                selected_scenarios=planned_technique_ids,
                selected_model_id=selected_model.model_id,
                selected_model_label=selected_model.label,
                current_technique=None,
                completed_techniques=[],
                remaining_techniques=planned_technique_ids,
                remaining_time_budget_seconds=self._remaining_budget_seconds(run),
                status=RedAgentRunStatus.STARTING,
                started_at=utc_now(),
                message="Red agent is preparing the planned bounded scenario run.",
                emitted_events_count=0,
                latest_artifact_path=None,
                latest_artifact_url=None,
            )
            self._current_session = RedAgentSessionDetail(
                session_id=run.run_id,
                started_at=self._state.started_at or utc_now(),
                ended_at=None,
                target_app_id=target.app_id,
                target_name=target.name,
                target_url=target.target_url,
                status=RedAgentRunStatus.STARTING,
                summary=self._state.message,
                selected_scenarios=planned_technique_ids,
                selected_model_id=selected_model.model_id,
                selected_model_label=selected_model.label,
                completed_techniques=[],
                logs=[],
                screenshots=[],
                vulnerabilities=[],
                metadata={
                    "planner_name": plan.planner_name,
                    "planner_rationale": plan.planner_rationale,
                },
            )
            self._append_log("Red agent initialization started.", level="info")
            self._append_log(f"Attached to run {run.run_id}.", level="info")
            self._append_log(f"Validated managed target: {target.name}.", level="info")
            self._append_log(
                f"Planning backend selected: {plan.planner_name} via {selected_model.label}.",
                level="info",
            )
            if plan.planner_rationale:
                self._append_log(f"Planning rationale: {plan.planner_rationale}", level="info")
            self._append_log(
                f"Planned techniques: {', '.join(planned_technique_ids) if planned_technique_ids else 'none'}.",
                level="info",
            )
            self._state.status = RedAgentRunStatus.RUNNING
            self._state.message = "Red agent is executing the generated bounded attack plan."
            self._broadcast_status()
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(run, target, plan),
                name="cyberbox-red-agent",
                daemon=True,
            )
            self._thread.start()
            self._record_action(
                "start",
                target_id=target.app_id,
                run_id=run.run_id,
                details={
                    "target_name": target.name,
                    "target_url": target.target_url,
                    "planned_technique_ids": planned_technique_ids,
                },
            )
            return RedAgentActionResponse(
                success=True,
                message="Red agent started.",
                state=self._state.model_copy(deep=True),
            )

    def stop(
        self,
        reason: str = "Red agent stopped by operator.",
        termination_reason: RunTerminationReason = RunTerminationReason.STOPPED_BY_USER,
    ) -> RedAgentActionResponse:
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
        if (
            self._state.run_id
            and self._state.status == RedAgentRunStatus.STOPPED
            and termination_reason == RunTerminationReason.STOPPED_BY_USER
        ):
            try:
                self._run_service.mark_cancelled(
                    self._state.run_id,
                    termination_reason=termination_reason,
                )
            except HTTPException:
                pass
        self._record_action(
            "stop",
            target_id=self._state.target_app_id or "",
            run_id=self._state.run_id,
            details={"reason": reason},
        )
        return response

    def logs(self) -> RedAgentLogsResponse:
        return RedAgentLogsResponse(logs=list(self._logs))

    def list_sessions(self):
        if self._session_history_store is None:
            return []
        return self._session_history_store.list_sessions()

    def get_session(self, session_id: str):
        if self._session_history_store is None:
            raise HTTPException(status_code=404, detail="Red-agent session history is not configured.")
        return self._session_history_store.get_session(session_id)
