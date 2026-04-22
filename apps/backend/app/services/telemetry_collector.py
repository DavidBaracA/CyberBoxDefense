"""Passive telemetry collection for managed vulnerable apps.

The collector tails platform-managed local targets and forwards normalized
telemetry into the existing ingestion pipeline. The implementation stays
modular so the source readers can later be replaced by container agents,
sidecars, Redis streams, or database-backed collectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Callable, Optional

from ..models import Severity, TelemetryEvent, TelemetryKind, TelemetrySource, utc_now
from ..services.template_registry import get_template
from ..vulnerable_apps_models import DeploymentType, VulnerableAppDetail, VulnerableAppStatus


DOCKER_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^\s]+)\s(?P<message>.*)$"
)
ACCESS_LOG_PATTERN = re.compile(
    r'"?(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+'
    r"(?P<path>/\S*)\s+HTTP/[0-9.]+" r'"\s+(?P<status>\d{3})'
)
STATUS_PATTERN = re.compile(r"\b(?:status|code)[=: ]+(?P<status>\d{3})\b", re.IGNORECASE)
PATH_PATTERN = re.compile(r"\b(?:path|uri|route)[=: ]+(?P<path>/\S*)\b", re.IGNORECASE)
ERROR_KEYWORDS = ("error", "exception", "traceback", "fatal", "failed")
WARNING_KEYWORDS = ("warn", "timeout", "slow", "denied")


@dataclass
class CollectorSourceSpec:
    """One concrete passive telemetry source for a managed app."""

    source_type: str
    target: str
    source: TelemetrySource
    reader_kind: str
    container_name: Optional[str] = None


@dataclass
class AppCollectorRuntime:
    """Runtime handles for one managed app collector."""

    app: VulnerableAppDetail
    stop_event: threading.Event
    thread: threading.Thread


class TelemetryLineNormalizer:
    """Normalize raw container or file log lines into TelemetryEvent records."""

    def normalize(
        self,
        *,
        app: VulnerableAppDetail,
        source_spec: CollectorSourceSpec,
        raw_line: str,
        run_id: Optional[str],
    ) -> Optional[TelemetryEvent]:
        line = raw_line.strip()
        if not line:
            return None

        timestamp, message = self._split_timestamp(line)
        access_match = ACCESS_LOG_PATTERN.search(message)
        status = None
        path = None
        kind = TelemetryKind.APP_LOG

        if access_match:
            status = int(access_match.group("status"))
            path = access_match.group("path")
            kind = TelemetryKind.HTTP_ERROR if status >= 400 else TelemetryKind.ACCESS_LOG
        else:
            status_match = STATUS_PATTERN.search(message)
            if status_match:
                status = int(status_match.group("status"))
                kind = TelemetryKind.HTTP_ERROR if status >= 400 else TelemetryKind.ACCESS_LOG
            path_match = PATH_PATTERN.search(message)
            if path_match:
                path = path_match.group("path")
            if source_spec.source_type == "access_log_file":
                kind = TelemetryKind.ACCESS_LOG

        severity = self._infer_severity(message, status)
        if kind == TelemetryKind.APP_LOG and source_spec.source == TelemetrySource.CONTAINER_MONITOR:
            kind = TelemetryKind.CONTAINER_SIGNAL if severity != Severity.INFO else TelemetryKind.APP_LOG

        return TelemetryEvent(
            run_id=run_id,
            app_id=app.app_id,
            timestamp=timestamp,
            source=source_spec.source,
            source_type=source_spec.source_type,
            kind=kind,
            severity=severity,
            container_name=source_spec.container_name or app.container_name,
            service_name=app.name,
            path=path,
            http_status=status,
            message=message,
            metadata={
                "raw_line": message,
                "collector_target": source_spec.target,
                "deployment_type": app.deployment_type.value,
            },
        )

    def _split_timestamp(self, line: str) -> tuple[datetime, str]:
        match = DOCKER_TIMESTAMP_PATTERN.match(line)
        if not match:
            return utc_now(), line

        raw_timestamp = match.group("timestamp")
        try:
            normalized = raw_timestamp.replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            timestamp = utc_now()
        return timestamp, match.group("message")

    def _infer_severity(self, message: str, status: Optional[int]) -> Severity:
        lowered = message.lower()
        if status is not None:
            if status >= 500:
                return Severity.HIGH
            if status >= 400:
                return Severity.WARNING
        if any(keyword in lowered for keyword in ERROR_KEYWORDS):
            return Severity.HIGH
        if any(keyword in lowered for keyword in WARNING_KEYWORDS):
            return Severity.WARNING
        return Severity.INFO


class TelemetryCollector:
    """Passive telemetry collector for deployed local vulnerable apps."""

    def __init__(
        self,
        *,
        deployment_service,
        telemetry_callback: Callable[[TelemetryEvent], TelemetryEvent],
        run_id_provider: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        self._deployment_service = deployment_service
        self._telemetry_callback = telemetry_callback
        self._run_id_provider = run_id_provider
        self._normalizer = TelemetryLineNormalizer()
        self._runtimes: dict[str, AppCollectorRuntime] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        """No-op lifecycle hook kept for future collector backends."""

    def shutdown(self) -> None:
        """Stop all active app collectors."""
        with self._lock:
            app_ids = list(self._runtimes.keys())
        for app_id in app_ids:
            self.stop_for_app(app_id)

    def sync_apps(self, apps: list[VulnerableAppDetail]) -> None:
        """Align passive collectors with the current managed app set."""
        desired_running_ids = {app.app_id for app in apps if app.status == VulnerableAppStatus.RUNNING}
        with self._lock:
            existing_ids = set(self._runtimes.keys())

        for app_id in existing_ids - desired_running_ids:
            self.stop_for_app(app_id)

        for app in apps:
            self.refresh_app(app)

    def refresh_app(self, app: VulnerableAppDetail) -> None:
        """Start or stop one app collector to match the app status."""
        if app.status == VulnerableAppStatus.RUNNING:
            self._start_for_app(app)
        else:
            self.stop_for_app(app.app_id)

    def stop_for_app(self, app_id: str) -> None:
        """Stop collection for one app."""
        runtime: Optional[AppCollectorRuntime] = None
        with self._lock:
            runtime = self._runtimes.pop(app_id, None)
        if not runtime:
            return
        runtime.stop_event.set()
        if runtime.thread.is_alive():
            runtime.thread.join(timeout=1.0)

    def _start_for_app(self, app: VulnerableAppDetail) -> None:
        app_copy = app.model_copy(deep=True)
        with self._lock:
            existing = self._runtimes.get(app.app_id)
            if existing and existing.thread.is_alive():
                same_runtime = (
                    existing.app.runtime_identifier == app.runtime_identifier
                    and existing.app.container_name == app.container_name
                    and existing.app.status == app.status
                )
                if same_runtime:
                    return
                self._runtimes.pop(app.app_id, None)
                existing.stop_event.set()

            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._run_app_collector,
                args=(app_copy, stop_event),
                name=f"cyberbox-telemetry-{app.app_id[:8]}",
                daemon=True,
            )
            self._runtimes[app.app_id] = AppCollectorRuntime(
                app=app_copy,
                stop_event=stop_event,
                thread=thread,
            )
            thread.start()

    def _run_app_collector(self, app: VulnerableAppDetail, stop_event: threading.Event) -> None:
        specs = self._build_source_specs(app)
        workers: list[threading.Thread] = []
        for spec in specs:
            worker = threading.Thread(
                target=self._consume_source,
                args=(app, spec, stop_event),
                name=f"cyberbox-telemetry-source-{app.app_id[:8]}",
                daemon=True,
            )
            workers.append(worker)
            worker.start()

        while not stop_event.wait(0.5):
            if workers and not any(worker.is_alive() for worker in workers):
                break

    def _build_source_specs(self, app: VulnerableAppDetail) -> list[CollectorSourceSpec]:
        specs: list[CollectorSourceSpec] = []
        container_names = self._container_names_for_app(app)
        for container_name in container_names:
            specs.append(
                CollectorSourceSpec(
                    source_type="container_stdout_stderr",
                    target=container_name,
                    source=TelemetrySource.CONTAINER_MONITOR,
                    reader_kind="docker_logs",
                    container_name=container_name,
                )
            )

        template = get_template(app.template_id)
        for path in template.metadata.get("app_log_paths", []):
            specs.append(
                CollectorSourceSpec(
                    source_type="application_log_file",
                    target=str(path),
                    source=TelemetrySource.VULNERABLE_APP,
                    reader_kind="file_tail",
                )
            )
        for path in template.metadata.get("access_log_paths", []):
            specs.append(
                CollectorSourceSpec(
                    source_type="access_log_file",
                    target=str(path),
                    source=TelemetrySource.VULNERABLE_APP,
                    reader_kind="file_tail",
                )
            )
        return specs

    def _container_names_for_app(self, app: VulnerableAppDetail) -> list[str]:
        if app.container_name:
            return [app.container_name]
        if app.deployment_type != DeploymentType.DOCKER_COMPOSE or not app.compose_project_name:
            return []

        result = self._deployment_service._run_docker_command(
            [
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={app.compose_project_name}",
                "--format",
                "{{.Names}}",
            ]
        )
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _consume_source(
        self,
        app: VulnerableAppDetail,
        source_spec: CollectorSourceSpec,
        stop_event: threading.Event,
    ) -> None:
        if source_spec.reader_kind == "docker_logs":
            self._follow_docker_logs(app, source_spec, stop_event)
            return
        if source_spec.reader_kind == "file_tail":
            self._tail_log_file(app, source_spec, stop_event)

    def _follow_docker_logs(
        self,
        app: VulnerableAppDetail,
        source_spec: CollectorSourceSpec,
        stop_event: threading.Event,
    ) -> None:
        while not stop_event.is_set():
            self._deployment_service.ensure_docker_available()
            process = subprocess.Popen(
                [
                    self._deployment_service.docker_binary,
                    "logs",
                    "--timestamps",
                    "-f",
                    source_spec.target,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            try:
                self._read_process_lines(app, source_spec, process, stop_event)
            finally:
                self._terminate_process(process)

            if stop_event.wait(1.0):
                return

    def _read_process_lines(
        self,
        app: VulnerableAppDetail,
        source_spec: CollectorSourceSpec,
        process: subprocess.Popen[str],
        stop_event: threading.Event,
    ) -> None:
        if not process.stdout:
            return
        while not stop_event.is_set():
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    return
                continue
            self._emit_normalized_event(app, source_spec, line)

    def _tail_log_file(
        self,
        app: VulnerableAppDetail,
        source_spec: CollectorSourceSpec,
        stop_event: threading.Event,
    ) -> None:
        path = Path(source_spec.target)
        while not stop_event.is_set():
            if not path.exists():
                if stop_event.wait(2.0):
                    return
                continue
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(0, os.SEEK_END)
                while not stop_event.is_set():
                    line = handle.readline()
                    if line:
                        self._emit_normalized_event(app, source_spec, line)
                        continue
                    if stop_event.wait(0.5):
                        return

    def _emit_normalized_event(
        self,
        app: VulnerableAppDetail,
        source_spec: CollectorSourceSpec,
        raw_line: str,
    ) -> None:
        event = self._normalizer.normalize(
            app=app,
            source_spec=source_spec,
            raw_line=raw_line,
            run_id=self._run_id_provider() if self._run_id_provider else None,
        )
        if event is None:
            return
        self._telemetry_callback(event)

    def _terminate_process(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
