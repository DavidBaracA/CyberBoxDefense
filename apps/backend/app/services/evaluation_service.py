"""Offline per-run evaluation for Red outcomes versus Blue detections.

This module intentionally operates after telemetry and detections have already
been persisted so the live Blue runtime remains zero-awareness and never
consumes Red-side ground truth directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from ..models import MetricSnapshot, ReportSummary
from ..repository import InMemoryRepository
from ..run_models import EvaluationMatchRecord, Run, RunSummary


ATTACK_LABEL_ALIASES: dict[str, str] = {
    "sql_injection": "sql_injection",
    "sql_injection_probe": "sql_injection",
    "suspected_sql_injection": "sql_injection",
    "xss": "xss",
    "xss_probe": "xss",
    "suspected_xss": "xss",
    "path_traversal": "path_traversal",
    "path_traversal_probe": "path_traversal",
    "suspected_path_traversal": "path_traversal",
    "brute_force": "brute_force",
    "login_bruteforce": "brute_force",
    "browser_login_bruteforce": "brute_force",
    "suspected_bruteforce": "brute_force",
    "repeated_internal_error_burst": "internal_error_burst",
}
NON_EVALUATED_ATTACK_LABELS = {
    "browser_homepage_smoke",
    "browser_login_navigation",
}


@dataclass(frozen=True)
class EvaluationConfig:
    """Configurable matching policy for offline run evaluation."""

    max_detection_delay_seconds: int = 300
    require_detection_after_attack: bool = True
    eligible_attack_statuses: tuple[str, ...] = ("completed",)
    classification_aliases: dict[str, str] = field(default_factory=lambda: dict(ATTACK_LABEL_ALIASES))
    ignored_attack_labels: set[str] = field(default_factory=lambda: set(NON_EVALUATED_ATTACK_LABELS))

    def describe(self) -> dict[str, object]:
        """Return an inspectable public view of the matching policy."""
        return {
            "max_detection_delay_seconds": self.max_detection_delay_seconds,
            "require_detection_after_attack": self.require_detection_after_attack,
            "eligible_attack_statuses": list(self.eligible_attack_statuses),
            "ignored_attack_labels": sorted(self.ignored_attack_labels),
            "classification_aliases": dict(sorted(self.classification_aliases.items())),
        }


def canonicalize_label(
    label: Optional[str],
    *,
    aliases: dict[str, str],
) -> Optional[str]:
    """Normalize one raw label into a canonical evaluation family."""
    if not label:
        return None
    return aliases.get(label, label)


def is_evaluable_attack(
    attack,
    *,
    config: EvaluationConfig,
) -> bool:
    """Return true when a Red ground-truth record should count as an evaluable outcome."""
    if attack.status not in config.eligible_attack_statuses:
        return False
    raw_label = attack.metadata.get("scenario_id") or attack.attack_type
    if raw_label in config.ignored_attack_labels:
        return False
    return canonicalize_label(raw_label, aliases=config.classification_aliases) is not None


def is_detection_candidate_for_attack(
    attack,
    detection,
    *,
    config: EvaluationConfig,
) -> bool:
    """Return true when a detection is eligible to match an attack outcome."""
    if config.require_detection_after_attack and detection.timestamp < attack.timestamp:
        return False
    if detection.timestamp > attack.timestamp + timedelta(seconds=config.max_detection_delay_seconds):
        return False
    return True


class EvaluationService:
    """Compute offline per-run evaluation from persisted Red and Blue records."""

    def __init__(
        self,
        repository: InMemoryRepository,
        *,
        config: Optional[EvaluationConfig] = None,
    ) -> None:
        self._repository = repository
        self._config = config or EvaluationConfig()

    def metrics_for_run(self, run_id: Optional[str]) -> MetricSnapshot:
        """Return offline evaluation metrics for one run."""
        _, metric_snapshot = self._build_matches_and_metrics(run_id)
        return metric_snapshot

    def run_summary(self, run: Run) -> RunSummary:
        """Return run-scoped summary including offline evaluation metrics."""
        matches, metrics = self._build_matches_and_metrics(run.run_id)
        truth_records = self._repository.list_attack_ground_truth(run_id=run.run_id)
        return RunSummary(
            run_id=run.run_id,
            app_id=run.app_id,
            status=run.status,
            termination_reason=run.termination_reason,
            started_at=run.started_at,
            expires_at=run.expires_at,
            telemetry_event_count=len(self._repository.list_telemetry_events(run_id=run.run_id)),
            detection_count=metrics.detection_count,
            attack_ground_truth_count=len(truth_records),
            mean_time_to_detection_seconds=metrics.mean_time_to_detection_seconds,
            detection_accuracy=metrics.detection_accuracy,
            classification_accuracy=metrics.classification_accuracy,
            false_positive_rate=metrics.false_positive_rate,
            evaluated_attack_count=sum(1 for match in matches if match.canonical_attack_label),
            matched_attack_count=sum(1 for match in matches if match.detected),
            evaluation_policy=self._config.describe(),
        )

    def report_summary(
        self,
        *,
        run_id: str,
        vulnerable_app_count: int,
        running_app_count: int,
    ) -> ReportSummary:
        """Return high-level report summary with offline evaluation metrics."""
        metrics = self.metrics_for_run(run_id)
        vulnerability_rows = self._repository.get_report_summary(
            vulnerable_app_count=vulnerable_app_count,
            running_app_count=running_app_count,
            run_id=run_id,
        )
        matches, _ = self._build_matches_and_metrics(run_id)
        vulnerability_rows.detection_accuracy = metrics.detection_accuracy
        vulnerability_rows.classification_accuracy = metrics.classification_accuracy
        vulnerability_rows.false_positive_rate = metrics.false_positive_rate
        vulnerability_rows.evaluated_attack_count = sum(
            1 for match in matches if match.canonical_attack_label
        )
        vulnerability_rows.matched_attack_count = sum(1 for match in matches if match.detected)
        vulnerability_rows.evaluation_policy = self._config.describe()
        return vulnerability_rows

    def _build_matches_and_metrics(
        self,
        run_id: Optional[str],
    ) -> tuple[list[EvaluationMatchRecord], MetricSnapshot]:
        truth_records = self._repository.list_attack_ground_truth(run_id=run_id)
        detections = self._repository.list_detection_events(run_id=run_id)

        evaluable_attacks = [attack for attack in truth_records if is_evaluable_attack(attack, config=self._config)]
        unused_detection_ids: set[str] = set(detection.detection_id for detection in detections)
        matches: list[EvaluationMatchRecord] = []
        correct_classification_count = 0
        detected_attack_count = 0
        matched_detection_ids: set[str] = set()
        time_to_detection_samples: list[float] = []

        for attack in evaluable_attacks:
            raw_attack_label = attack.metadata.get("scenario_id") or attack.attack_type
            canonical_attack_label = canonicalize_label(
                raw_attack_label,
                aliases=self._config.classification_aliases,
            ) or raw_attack_label

            candidate = next(
                (
                    detection
                    for detection in detections
                    if detection.detection_id in unused_detection_ids
                    and is_detection_candidate_for_attack(attack, detection, config=self._config)
                ),
                None,
            )
            if candidate is None:
                matches.append(
                    EvaluationMatchRecord(
                        attack_id=attack.attack_id,
                        attack_label=raw_attack_label,
                        canonical_attack_label=canonical_attack_label,
                        attack_timestamp=attack.timestamp,
                        detected=False,
                        correctly_classified=False,
                        notes="No Blue detection fell within the configured matching window.",
                    )
                )
                continue

            unused_detection_ids.remove(candidate.detection_id)
            matched_detection_ids.add(candidate.detection_id)
            canonical_detection_label = canonicalize_label(
                candidate.classification,
                aliases=self._config.classification_aliases,
            ) or candidate.classification
            detected_attack_count += 1
            correctly_classified = canonical_detection_label == canonical_attack_label
            if correctly_classified:
                correct_classification_count += 1
            delta_seconds = (candidate.timestamp - attack.timestamp) / timedelta(seconds=1)
            time_to_detection_samples.append(delta_seconds)
            matches.append(
                EvaluationMatchRecord(
                    attack_id=attack.attack_id,
                    attack_label=raw_attack_label,
                    canonical_attack_label=canonical_attack_label,
                    attack_timestamp=attack.timestamp,
                    detection_id=candidate.detection_id,
                    detection_label=candidate.classification,
                    canonical_detection_label=canonical_detection_label,
                    detection_timestamp=candidate.timestamp,
                    detected=True,
                    correctly_classified=correctly_classified,
                    time_to_detection_seconds=delta_seconds,
                    notes=(
                        "Matched by earliest detection within the configured time window."
                    ),
                )
            )

        detection_count = len(detections)
        false_positive_count = detection_count - len(matched_detection_ids)
        mean_time_to_detection = (
            sum(time_to_detection_samples) / len(time_to_detection_samples)
            if time_to_detection_samples
            else None
        )
        metrics = MetricSnapshot(
            mean_time_to_detection_seconds=mean_time_to_detection,
            detection_accuracy=(
                detected_attack_count / len(evaluable_attacks) if evaluable_attacks else 0.0
            ),
            classification_accuracy=(
                correct_classification_count / detected_attack_count if detected_attack_count else 0.0
            ),
            false_positive_rate=(
                false_positive_count / detection_count if detection_count else 0.0
            ),
            telemetry_event_count=len(self._repository.list_telemetry_events(run_id=run_id)),
            detection_count=detection_count,
            attack_ground_truth_count=len(evaluable_attacks),
        )
        return matches, metrics
