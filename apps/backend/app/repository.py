"""SQLite-backed backend repository.

TODO:
- Add per-run filtering once experiment run isolation becomes first-class.
- Add pagination and archival once event volume grows.
- Add stronger query abstractions if more reporting endpoints are introduced.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Callable, Optional

from .database import Database
from .models import (
    ActionEvent,
    AttackGroundTruth,
    DeploymentTemplateStat,
    DetectionEvent,
    MetricSnapshot,
    ReportSummary,
    TelemetryEvent,
    TelemetryKind,
    Severity,
    VulnerabilityFindingStat,
)
from .runtime_settings import get_runtime_int


DEFAULT_TELEMETRY_MAX_ROWS = 100_000
DEFAULT_TELEMETRY_RETENTION_DAYS = 7
DEFAULT_TELEMETRY_INFO_SAMPLE_RATE = 50
TELEMETRY_RETENTION_INTERVAL = 1_000
NOISY_HEALTH_PATH_PATTERN = re.compile(r"/(?:health|health_check|actuator|metrics)(?:[/\s?]|$)", re.IGNORECASE)
NOISY_INFO_PATTERNS = (
    re.compile(r"\bconnection (?:accepted|ended|closed)\b", re.IGNORECASE),
    re.compile(r"\bclient metadata\b", re.IGNORECASE),
    re.compile(r"\bclosing connection\b", re.IGNORECASE),
    re.compile(r"\bGET\s+\S*(?:health|health_check|actuator|metrics)\b", re.IGNORECASE),
)
SECURITY_SIGNAL_PATTERN = re.compile(
    r"(login|auth|password|credential|token|csrf|unauthorized|forbidden|denied|"
    r"sql|xss|script|traversal|redirect|upload|exception|traceback|fatal|failed)",
    re.IGNORECASE,
)


class InMemoryRepository:
    """Preserve the old class name while persisting to SQLite."""

    def __init__(
        self,
        database: Database,
        current_run_id_provider: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        self._database = database
        self._current_run_id_provider = current_run_id_provider
        self._telemetry_insert_count = 0
        self._telemetry_sample_rate = max(
            1,
            get_runtime_int("TELEMETRY_INFO_SAMPLE_RATE", DEFAULT_TELEMETRY_INFO_SAMPLE_RATE),
        )
        self._telemetry_max_rows = max(
            0,
            get_runtime_int("TELEMETRY_MAX_ROWS", DEFAULT_TELEMETRY_MAX_ROWS),
        )
        self._telemetry_retention_days = max(
            0,
            get_runtime_int("TELEMETRY_RETENTION_DAYS", DEFAULT_TELEMETRY_RETENTION_DAYS),
        )

    def _resolve_run_id(self, run_id: Optional[str]) -> Optional[str]:
        if run_id:
            return run_id
        if self._current_run_id_provider:
            return self._current_run_id_provider()
        return None

    def _telemetry_text(self, event: TelemetryEvent) -> str:
        return " ".join(
            str(part or "")
            for part in (
                event.message,
                event.path,
                event.source_type,
                event.container_name,
                event.service_name,
            )
        )

    def _is_noisy_health_event(self, event: TelemetryEvent) -> bool:
        text = self._telemetry_text(event)
        return bool(NOISY_HEALTH_PATH_PATTERN.search(text))

    def _is_noisy_info_event(self, event: TelemetryEvent) -> bool:
        text = self._telemetry_text(event)
        return any(pattern.search(text) for pattern in NOISY_INFO_PATTERNS)

    def _has_security_signal(self, event: TelemetryEvent) -> bool:
        return bool(SECURITY_SIGNAL_PATTERN.search(self._telemetry_text(event)))

    def _sample_info_event(self, event: TelemetryEvent) -> bool:
        if self._telemetry_sample_rate <= 1:
            return True
        sample_key = "|".join(
            str(part or "")
            for part in (
                event.run_id,
                event.app_id,
                event.source.value,
                event.kind.value,
                event.container_name,
                event.path,
                event.message,
            )
        )
        digest = hashlib.sha256(sample_key.encode("utf-8", errors="ignore")).hexdigest()
        return int(digest[:8], 16) % self._telemetry_sample_rate == 0

    def _should_persist_telemetry_event(self, event: TelemetryEvent) -> bool:
        if event.severity != Severity.INFO:
            return True
        if event.kind == TelemetryKind.HTTP_ERROR:
            return True
        if event.source_type in {"docker_event", "docker_status"}:
            return True
        if self._has_security_signal(event):
            return True
        if self._is_noisy_health_event(event) or self._is_noisy_info_event(event):
            return False
        if event.kind in {TelemetryKind.ACCESS_LOG, TelemetryKind.APP_LOG, TelemetryKind.CONTAINER_SIGNAL}:
            return self._sample_info_event(event)
        return True

    def _apply_telemetry_retention(self, connection) -> None:
        if self._telemetry_retention_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._telemetry_retention_days)
            connection.execute(
                """
                DELETE FROM telemetry_events
                WHERE timestamp < ?
                """,
                (cutoff.isoformat(),),
            )

        if not self._telemetry_max_rows:
            return
        row = connection.execute("SELECT COUNT(*) AS count FROM telemetry_events").fetchone()
        overflow = int(row["count"] or 0) - self._telemetry_max_rows
        if overflow <= 0:
            return
        connection.execute(
            """
            DELETE FROM telemetry_events
            WHERE event_id IN (
                SELECT event_id
                FROM telemetry_events
                ORDER BY timestamp ASC
                LIMIT ?
            )
            """,
            (overflow,),
        )

    def prune_telemetry_events(self) -> None:
        """Apply configured telemetry retention immediately."""
        with self._database.connect() as connection:
            self._apply_telemetry_retention(connection)

    def add_telemetry_event(self, event: TelemetryEvent) -> Optional[TelemetryEvent]:
        event.run_id = self._resolve_run_id(event.run_id)
        if not self._should_persist_telemetry_event(event):
            return None
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO telemetry_events (
                    event_id, run_id, timestamp, source, kind, severity, service_name,
                    container_name, path, http_status, message, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.run_id,
                    event.timestamp.isoformat(),
                    event.source.value,
                    event.kind.value,
                    event.severity.value,
                    event.service_name,
                    event.container_name,
                    event.path,
                    event.http_status,
                    event.message,
                    self._database.to_json(event.model_dump(mode="json")),
                ),
            )
            self._telemetry_insert_count += 1
            if self._telemetry_insert_count % TELEMETRY_RETENTION_INTERVAL == 0:
                self._apply_telemetry_retention(connection)
        return event

    def add_detection_event(self, detection: DetectionEvent) -> DetectionEvent:
        detection.run_id = self._resolve_run_id(detection.run_id)
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO detection_events (
                    detection_id, run_id, timestamp, detector, classification, confidence, summary, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    detection.detection_id,
                    detection.run_id,
                    detection.timestamp.isoformat(),
                    detection.detector,
                    detection.classification,
                    detection.confidence,
                    detection.summary,
                    self._database.to_json(detection.model_dump(mode="json")),
                ),
            )
        return detection

    def add_attack_ground_truth(self, attack: AttackGroundTruth) -> AttackGroundTruth:
        attack.run_id = self._resolve_run_id(attack.run_id)
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO attack_ground_truth (
                    attack_id, run_id, timestamp, attack_type, target, status, notes, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attack.attack_id,
                    attack.run_id,
                    attack.timestamp.isoformat(),
                    attack.attack_type,
                    attack.target,
                    attack.status,
                    attack.notes,
                    self._database.to_json(attack.model_dump(mode="json")),
                ),
            )
        return attack

    def log_action(self, event: ActionEvent) -> ActionEvent:
        event.run_id = self._resolve_run_id(event.run_id)
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO action_events (
                    action_id, timestamp, actor, action_name, target_type, target_id, run_id, status, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.action_id,
                    event.timestamp.isoformat(),
                    event.actor,
                    event.action,
                    event.target_type,
                    event.target_id,
                    event.run_id,
                    event.status,
                    self._database.to_json(event.model_dump(mode="json")),
                ),
            )
        return event

    def list_actions(self, limit: int = 200, run_id: Optional[str] = None) -> list[ActionEvent]:
        with self._database.connect() as connection:
            if run_id:
                rows = connection.execute(
                    """
                    SELECT payload_json
                    FROM action_events
                    WHERE run_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (run_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT payload_json
                    FROM action_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [ActionEvent.model_validate(self._database.from_json(row["payload_json"])) for row in rows]

    def list_detection_events(self, run_id: Optional[str] = None) -> list[DetectionEvent]:
        with self._database.connect() as connection:
            if run_id:
                rows = connection.execute(
                    """
                    SELECT payload_json
                    FROM detection_events
                    WHERE run_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (run_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM detection_events ORDER BY timestamp ASC"
                ).fetchall()
        return [DetectionEvent.model_validate(self._database.from_json(row["payload_json"])) for row in rows]

    def list_telemetry_events(self, run_id: Optional[str] = None) -> list[TelemetryEvent]:
        with self._database.connect() as connection:
            if run_id:
                rows = connection.execute(
                    """
                    SELECT payload_json
                    FROM telemetry_events
                    WHERE run_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (run_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM telemetry_events ORDER BY timestamp ASC"
                ).fetchall()
        return [TelemetryEvent.model_validate(self._database.from_json(row["payload_json"])) for row in rows]

    def list_attack_ground_truth(self, run_id: Optional[str] = None) -> list[AttackGroundTruth]:
        with self._database.connect() as connection:
            if run_id:
                rows = connection.execute(
                    """
                    SELECT payload_json
                    FROM attack_ground_truth
                    WHERE run_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (run_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM attack_ground_truth ORDER BY timestamp ASC"
                ).fetchall()
        return [AttackGroundTruth.model_validate(self._database.from_json(row["payload_json"])) for row in rows]

    def count_telemetry_events(self, run_id: Optional[str] = None) -> int:
        """Return a cheap telemetry row count without hydrating event payloads."""
        with self._database.connect() as connection:
            if run_id:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM telemetry_events WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM telemetry_events"
                ).fetchone()
        return int(row["count"] or 0)

    def count_detection_events(self, run_id: Optional[str] = None) -> int:
        """Return a cheap detection row count without hydrating event payloads."""
        with self._database.connect() as connection:
            if run_id:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM detection_events WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM detection_events"
                ).fetchone()
        return int(row["count"] or 0)

    def count_attack_ground_truth(self, run_id: Optional[str] = None) -> int:
        """Return a cheap ground-truth row count without hydrating event payloads."""
        with self._database.connect() as connection:
            if run_id:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM attack_ground_truth WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM attack_ground_truth"
                ).fetchone()
        return int(row["count"] or 0)

    def compute_metrics(self, run_id: Optional[str] = None) -> MetricSnapshot:
        """Compute first-pass metrics from persisted state."""
        attack_ground_truth = self.list_attack_ground_truth(run_id=run_id)
        detection_events = self.list_detection_events(run_id=run_id)
        matches: list[tuple[AttackGroundTruth, DetectionEvent]] = []
        used_detection_ids: set[str] = set()

        for attack in attack_ground_truth:
            for detection in detection_events:
                if detection.detection_id in used_detection_ids:
                    continue
                if detection.classification != attack.attack_type:
                    continue
                if detection.timestamp < attack.timestamp:
                    continue
                matches.append((attack, detection))
                used_detection_ids.add(detection.detection_id)
                break

        if matches:
            mean_time_to_detection = sum(
                (detection.timestamp - attack.timestamp) / timedelta(seconds=1)
                for attack, detection in matches
            ) / len(matches)
        else:
            mean_time_to_detection = None

        attack_count = len(attack_ground_truth)
        detection_count = len(detection_events)
        match_count = len(matches)
        false_positive_count = detection_count - match_count

        return MetricSnapshot(
            mean_time_to_detection_seconds=mean_time_to_detection,
            detection_accuracy=match_count / attack_count if attack_count else 0.0,
            classification_accuracy=match_count / detection_count if detection_count else 0.0,
            false_positive_rate=false_positive_count / detection_count if detection_count else 0.0,
            telemetry_event_count=self.count_telemetry_events(run_id=run_id),
            detection_count=detection_count,
            attack_ground_truth_count=attack_count,
            red={
                "evaluated_attack_count": attack_count,
                "detected_attack_count": match_count,
                "missed_attack_count": attack_count - match_count,
                "ground_truth_record_count": attack_count,
            },
            blue={
                "detection_count": detection_count,
                "matched_detection_count": match_count,
                "false_positive_count": false_positive_count,
                "false_positive_rate": false_positive_count / detection_count if detection_count else 0.0,
            },
            overall={
                "telemetry_event_count": self.count_telemetry_events(run_id=run_id),
                "mean_time_to_detection_seconds": mean_time_to_detection,
                "detection_accuracy": match_count / attack_count if attack_count else 0.0,
                "classification_accuracy": match_count / detection_count if detection_count else 0.0,
            },
        )

    def get_report_summary(
        self,
        vulnerable_app_count: int,
        running_app_count: int,
        run_id: Optional[str] = None,
    ) -> ReportSummary:
        metrics = self.compute_metrics(run_id=run_id)
        with self._database.connect() as connection:
            if run_id:
                vulnerability_rows = connection.execute(
                    """
                    SELECT classification, COUNT(*) AS count
                    FROM detection_events
                    WHERE run_id = ?
                    GROUP BY classification
                    ORDER BY count DESC, classification ASC
                    LIMIT 10
                    """,
                    (run_id,),
                ).fetchall()
                action_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM action_events WHERE run_id = ?",
                    (run_id,),
                ).fetchone()["count"]
            else:
                vulnerability_rows = connection.execute(
                    """
                    SELECT classification, COUNT(*) AS count
                    FROM detection_events
                    GROUP BY classification
                    ORDER BY count DESC, classification ASC
                    LIMIT 10
                    """
                ).fetchall()
                action_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM action_events"
                ).fetchone()["count"]
            template_rows = connection.execute(
                """
                SELECT template_id, COUNT(*) AS count
                FROM vulnerable_apps
                GROUP BY template_id
                ORDER BY count DESC, template_id ASC
                """
            ).fetchall()

        return ReportSummary(
            total_deployed_apps=vulnerable_app_count,
            running_app_count=running_app_count,
            total_action_count=action_count,
            most_common_vulnerabilities=[
                VulnerabilityFindingStat(classification=row["classification"], count=row["count"])
                for row in vulnerability_rows
            ],
            deployment_templates=[
                DeploymentTemplateStat(template_id=row["template_id"], count=row["count"])
                for row in template_rows
            ],
            mean_time_to_detection_seconds=metrics.mean_time_to_detection_seconds,
        )
