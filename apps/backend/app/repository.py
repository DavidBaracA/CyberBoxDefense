"""SQLite-backed backend repository.

TODO:
- Add per-run filtering once experiment run isolation becomes first-class.
- Add pagination and archival once event volume grows.
- Add stronger query abstractions if more reporting endpoints are introduced.
"""

from __future__ import annotations

from datetime import timedelta
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
    VulnerabilityFindingStat,
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

    def _resolve_run_id(self, run_id: Optional[str]) -> Optional[str]:
        if run_id:
            return run_id
        if self._current_run_id_provider:
            return self._current_run_id_provider()
        return None

    def has_seed_data(self) -> bool:
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM telemetry_events) AS telemetry_count,
                  (SELECT COUNT(*) FROM detection_events) AS detection_count,
                  (SELECT COUNT(*) FROM attack_ground_truth) AS truth_count
                """
            ).fetchone()
        return bool(row["telemetry_count"] or row["detection_count"] or row["truth_count"])

    def add_telemetry_event(self, event: TelemetryEvent) -> TelemetryEvent:
        event.run_id = self._resolve_run_id(event.run_id)
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
            telemetry_event_count=len(self.list_telemetry_events(run_id=run_id)),
            detection_count=detection_count,
            attack_ground_truth_count=attack_count,
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
