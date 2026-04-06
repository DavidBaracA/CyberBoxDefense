"""In-memory runtime state for the first research prototype iteration."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from cyberbox_contracts import (
    AttackExecutionRecord,
    DetectionRecord,
    MetricSnapshot,
    ObservableEvent,
    TelemetryFeed,
)


class RuntimeStore:
    """Store observability, detections, and offline ground truth separately."""

    def __init__(self) -> None:
        self.observable_events: list[ObservableEvent] = []
        self.detections: list[DetectionRecord] = []
        self.attack_ground_truth: list[AttackExecutionRecord] = []
        repo_root = Path(__file__).resolve().parents[3]
        self.observability_log_path = repo_root / "logs" / "observability" / "events.jsonl"
        self.ground_truth_log_path = (
            repo_root / "data" / "evaluation_ground_truth" / "attacks.jsonl"
        )
        self.detection_log_path = repo_root / "logs" / "observability" / "detections.jsonl"

    def _append_jsonl(self, path: Path, payload: dict) -> None:
        """Append JSONL records to the appropriate observability or evaluation store."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")

    def ingest_event(self, event: ObservableEvent) -> ObservableEvent:
        self.observable_events.append(event)
        self.observable_events.sort(key=lambda item: item.timestamp)
        self._append_jsonl(self.observability_log_path, event.model_dump(mode="json"))
        return event

    def record_detection(self, detection: DetectionRecord) -> DetectionRecord:
        self.detections.append(detection)
        self.detections.sort(key=lambda item: item.timestamp)
        self._append_jsonl(self.detection_log_path, detection.model_dump(mode="json"))
        return detection

    def record_attack(self, attack: AttackExecutionRecord) -> AttackExecutionRecord:
        self.attack_ground_truth.append(attack)
        self.attack_ground_truth.sort(key=lambda item: item.timestamp)
        self._append_jsonl(self.ground_truth_log_path, attack.model_dump(mode="json"))
        return attack

    def blue_telemetry_feed(self) -> TelemetryFeed:
        """Return Blue-safe telemetry only, with no attack ground truth."""
        return TelemetryFeed(events=self.observable_events)

    def metric_snapshot(self) -> MetricSnapshot:
        """Compute minimal first-pass metrics from current attack and detection records."""
        attacks = self.attack_ground_truth
        detections = self.detections

        matched_pairs: list[tuple[AttackExecutionRecord, DetectionRecord]] = []
        used_detection_ids: set[str] = set()

        for attack in attacks:
            for detection in detections:
                if detection.detection_id in used_detection_ids:
                    continue
                if detection.predicted_attack_type != attack.attack_type:
                    continue
                if detection.timestamp < attack.timestamp:
                    continue
                matched_pairs.append((attack, detection))
                used_detection_ids.add(detection.detection_id)
                break

        if matched_pairs:
            total = sum(
                (
                    detection.timestamp - attack.timestamp
                ) / timedelta(seconds=1)
                for attack, detection in matched_pairs
            )
            mean_time_to_detection = total / len(matched_pairs)
        else:
            mean_time_to_detection = None

        attack_count = len(attacks)
        detection_count = len(detections)
        match_count = len(matched_pairs)

        detection_accuracy = match_count / attack_count if attack_count else 0.0
        classification_accuracy = match_count / detection_count if detection_count else 0.0
        false_positive_count = detection_count - match_count
        false_positive_rate = false_positive_count / detection_count if detection_count else 0.0

        return MetricSnapshot(
            mean_time_to_detection_seconds=mean_time_to_detection,
            detection_accuracy=round(detection_accuracy, 3),
            classification_accuracy=round(classification_accuracy, 3),
            false_positive_rate=round(false_positive_rate, 3),
            attack_count=attack_count,
            detection_count=detection_count,
            observable_event_count=len(self.observable_events),
        )
