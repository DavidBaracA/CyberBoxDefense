"""Simple in-memory backend repository.

TODO:
- Replace the lists in this repository with a persistent storage layer.
- Add run/scenario identifiers so repeated experiments can be isolated cleanly.
- Expose repository interfaces that can later be wrapped by LangGraph nodes or
  orchestration services without changing API contracts.
"""

from __future__ import annotations

from datetime import timedelta

from .models import AttackGroundTruth, DetectionEvent, MetricSnapshot, TelemetryEvent


class InMemoryRepository:
    """Keep backend state in memory for the first prototype iteration."""

    def __init__(self) -> None:
        self.telemetry_events: list[TelemetryEvent] = []
        self.detection_events: list[DetectionEvent] = []
        self.attack_ground_truth: list[AttackGroundTruth] = []

    def add_telemetry_event(self, event: TelemetryEvent) -> TelemetryEvent:
        self.telemetry_events.append(event)
        self.telemetry_events.sort(key=lambda item: item.timestamp)
        return event

    def add_detection_event(self, detection: DetectionEvent) -> DetectionEvent:
        self.detection_events.append(detection)
        self.detection_events.sort(key=lambda item: item.timestamp)
        return detection

    def add_attack_ground_truth(self, attack: AttackGroundTruth) -> AttackGroundTruth:
        self.attack_ground_truth.append(attack)
        self.attack_ground_truth.sort(key=lambda item: item.timestamp)
        return attack

    def list_detection_events(self) -> list[DetectionEvent]:
        return list(self.detection_events)

    def list_telemetry_events(self) -> list[TelemetryEvent]:
        return list(self.telemetry_events)

    def compute_metrics(self) -> MetricSnapshot:
        """Compute simple first-pass metrics from in-memory state."""
        matches: list[tuple[AttackGroundTruth, DetectionEvent]] = []
        used_detection_ids: set[str] = set()

        for attack in self.attack_ground_truth:
            for detection in self.detection_events:
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

        attack_count = len(self.attack_ground_truth)
        detection_count = len(self.detection_events)
        match_count = len(matches)
        false_positive_count = detection_count - match_count

        return MetricSnapshot(
            mean_time_to_detection_seconds=mean_time_to_detection,
            detection_accuracy=match_count / attack_count if attack_count else 0.0,
            classification_accuracy=match_count / detection_count if detection_count else 0.0,
            false_positive_rate=false_positive_count / detection_count if detection_count else 0.0,
            telemetry_event_count=len(self.telemetry_events),
            detection_count=detection_count,
            attack_ground_truth_count=attack_count,
        )
