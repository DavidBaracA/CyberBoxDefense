"""Hybrid page analyzer for bounded Red-agent scenario routing.

This module combines Playwright DOM extraction, screenshot evidence, and an
optional vision-capable local model to recommend generic vulnerability
scenarios against platform-managed local targets only.

TODO:
- Add bounded multi-page crawling once a single-page analyzer is stable.
- Improve structured DOM extraction coverage for richer form semantics.
- Benchmark local vision models and calibrate confidence thresholds.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Iterable, Optional

from ...red_agent_models import (
    AttackScenario,
    PageAnalysisEvidence,
    PageElementSignal,
    RedAgentPageAnalysis,
    ScenarioRecommendation,
)
from ...vulnerable_apps_models import VulnerableAppDetail
from .scenarios import get_scenario_catalog
from .vision_reasoner import build_page_understanding_reasoner


class PageAnalyzer:
    """Analyze one managed local target page for generic scenario applicability."""

    def __init__(
        self,
        page_screenshot_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._vision_reasoner = build_page_understanding_reasoner()
        self._page_screenshot_callback = page_screenshot_callback

    def analyze_target(
        self,
        *,
        target: VulnerableAppDetail,
        run_id: str,
    ) -> RedAgentPageAnalysis:
        raw = self._run_playwright_analyzer(target=target, run_id=run_id)
        scenario_catalog = get_scenario_catalog()
        heuristic_elements = self._build_elements(raw.get("candidate_elements", []))
        scenario_recommendations = self._build_recommendations(
            raw.get("recommended_scenarios", []),
            scenario_catalog,
            source="dom_heuristic",
        )

        page_type = str(raw.get("page_type") or "unknown")
        analyzer_name = "dom_heuristic"
        rationale_parts = [str(raw.get("summary") or "DOM and accessibility heuristics collected page context.")]
        confidence = 0.45
        vision_summary: dict[str, object] = {}

        screenshot_path = str(raw.get("screenshot_path") or "")
        if not screenshot_path:
            raise RuntimeError("Page analysis did not produce a screenshot for LLM scenario applicability.")
        screenshot_url = self._artifact_url_for_path(screenshot_path)
        if self._page_screenshot_callback:
            self._page_screenshot_callback(screenshot_path, screenshot_url)

        try:
            vision_decision = self._vision_reasoner.analyze_page(
                payload=self._build_vision_payload(raw, target, scenario_catalog, screenshot_path)
            )
            vision_summary = {
                "page_type": vision_decision.page_type,
                "confidence": vision_decision.confidence,
                "rationale": vision_decision.rationale,
                "recommended_scenarios": vision_decision.recommended_scenarios,
                "raw_response": vision_decision.raw_response,
            }
            page_type = vision_decision.page_type or page_type
            confidence = max(confidence, vision_decision.confidence)
            analyzer_name = self._vision_reasoner.name
            rationale_parts.append(vision_decision.rationale)
            heuristic_elements = self._merge_elements(heuristic_elements, vision_decision.candidate_elements)
            vision_recommendations = self._build_recommendations(
                vision_decision.recommended_scenarios,
                scenario_catalog,
                source=self._vision_reasoner.name,
            )
            scenario_recommendations = self._merge_recommendations(
                scenario_recommendations,
                vision_recommendations,
            )
        except Exception as exc:
            raise RuntimeError(
                f"LLM screenshot analysis failed; refusing to choose applicable Red scenarios without it: {exc}"
            ) from exc

        dom_summary = raw.get("dom_summary", {})
        heuristic_summary = raw.get("heuristic_summary", {})
        interaction_surfaces = list(raw.get("candidate_interaction_surfaces", []))
        return RedAgentPageAnalysis(
            page_url=str(raw.get("page_url") or target.target_url),
            page_type=page_type,
            confidence=max(0.0, min(1.0, confidence)),
            analyzer_name=analyzer_name,
            rationale=" ".join(part for part in rationale_parts if part).strip(),
            candidate_elements=heuristic_elements,
            candidate_interaction_surfaces=interaction_surfaces,
            recommended_scenarios=scenario_recommendations,
            evidence=PageAnalysisEvidence(
                screenshot_path=screenshot_path or None,
                screenshot_url=screenshot_url,
                page_title=str(raw.get("page_title") or ""),
                visible_text_excerpt=str(raw.get("visible_text_excerpt") or ""),
                dom_summary=dom_summary if isinstance(dom_summary, dict) else {},
                heuristic_summary=heuristic_summary if isinstance(heuristic_summary, dict) else {},
                vision_summary=vision_summary,
            ),
        )

    def _run_playwright_analyzer(
        self,
        *,
        target: VulnerableAppDetail,
        run_id: str,
    ) -> dict[str, object]:
        repo_root = Path(__file__).resolve().parents[5]
        frontend_dir = repo_root / "apps" / "frontend"
        runner_path = frontend_dir / "tests" / "e2e" / "helpers" / "analyzeManagedPage.mjs"
        output_dir = frontend_dir / "test-results" / "red-agent"
        env = os.environ.copy()
        env.update(
            {
                "CYBERBOX_TARGET_URL": target.target_url,
                "CYBERBOX_TARGET_TEMPLATE": target.template_id.value,
                "CYBERBOX_RUN_ID": run_id,
                "CYBERBOX_OUTPUT_DIR": str(output_dir),
                "CYBERBOX_TARGET_APP_ID": target.app_id,
                "CYBERBOX_TARGET_NAME": target.name,
            }
        )
        completed = subprocess.run(
            ["node", str(runner_path)],
            cwd=str(frontend_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "Unknown Playwright analyzer failure."
            raise RuntimeError(stderr)
        try:
            return json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            raise RuntimeError("Playwright analyzer returned invalid JSON.") from exc

    def _build_vision_payload(
        self,
        raw: dict[str, object],
        target: VulnerableAppDetail,
        scenarios: Iterable[AttackScenario],
        screenshot_path: str,
    ):
        from .vision_reasoner import VisionPageInput

        return VisionPageInput(
            target_name=target.name,
            page_url=str(raw.get("page_url") or target.target_url),
            page_title=str(raw.get("page_title") or ""),
            visible_text_excerpt=str(raw.get("visible_text_excerpt") or ""),
            dom_summary=dict(raw.get("dom_summary", {}) or {}),
            scenario_ids=[scenario.scenario_id for scenario in scenarios],
            screenshot_path=screenshot_path,
        )

    def _build_elements(self, rows: list[object]) -> list[PageElementSignal]:
        elements: list[PageElementSignal] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            elements.append(
                PageElementSignal(
                    element_kind=str(row.get("element_kind") or "unknown"),
                    text=self._as_optional_text(row.get("text")),
                    locator_hint=self._as_optional_text(row.get("locator_hint")),
                    input_type=self._as_optional_text(row.get("input_type")),
                    action=self._as_optional_text(row.get("action")),
                    href=self._as_optional_text(row.get("href")),
                    confidence=self._bounded_float(row.get("confidence"), 0.5),
                    signals=self._as_string_list(row.get("signals")),
                )
            )
        return elements

    def _build_recommendations(
        self,
        rows: list[object],
        scenarios: Iterable[AttackScenario],
        *,
        source: str,
    ) -> list[ScenarioRecommendation]:
        allowed_ids = {scenario.scenario_id for scenario in scenarios}
        recommendations: list[ScenarioRecommendation] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            scenario_id = str(row.get("scenario_id") or "").strip()
            if not scenario_id or scenario_id not in allowed_ids:
                continue
            recommendations.append(
                ScenarioRecommendation(
                    scenario_id=scenario_id,
                    confidence=self._bounded_float(row.get("confidence"), 0.5),
                    rationale=str(row.get("rationale") or "Scenario matched by bounded page analysis."),
                    source=str(row.get("source") or source),
                    supporting_signals=self._as_string_list(row.get("supporting_signals")),
                    candidate_element_ids=self._as_string_list(row.get("candidate_element_ids")),
                    bounded_action_summary=self._as_optional_text(row.get("bounded_action_summary")),
                    target_page_url=self._as_optional_text(row.get("target_page_url")),
                    pre_action_selector=self._as_optional_text(row.get("pre_action_selector")),
                    target_selector=self._as_optional_text(row.get("target_selector")),
                    target_parameter=self._as_optional_text(row.get("target_parameter")),
                )
            )
        return recommendations

    def _merge_elements(
        self,
        existing: list[PageElementSignal],
        inferred_rows: list[dict[str, object]],
    ) -> list[PageElementSignal]:
        merged = list(existing)
        for row in inferred_rows:
            if not isinstance(row, dict):
                continue
            candidate = PageElementSignal(
                element_kind=str(row.get("element_kind") or "unknown"),
                text=self._as_optional_text(row.get("text")),
                locator_hint=self._as_optional_text(row.get("locator_hint")),
                confidence=self._bounded_float(row.get("confidence"), 0.4),
                signals=self._as_string_list(row.get("signals")),
            )
            duplicate = next(
                (
                    item
                    for item in merged
                    if item.element_kind == candidate.element_kind
                    and item.locator_hint == candidate.locator_hint
                    and item.text == candidate.text
                ),
                None,
            )
            if duplicate is None:
                merged.append(candidate)
                continue
            duplicate.confidence = max(duplicate.confidence, candidate.confidence)
            duplicate.signals = sorted(set(duplicate.signals + candidate.signals))
        return merged

    def _merge_recommendations(
        self,
        existing: list[ScenarioRecommendation],
        inferred: list[ScenarioRecommendation],
    ) -> list[ScenarioRecommendation]:
        merged = {item.scenario_id: item for item in existing}
        for item in inferred:
            previous = merged.get(item.scenario_id)
            if previous is None:
                merged[item.scenario_id] = item
                continue
            previous.confidence = max(previous.confidence, item.confidence)
            previous.supporting_signals = sorted(set(previous.supporting_signals + item.supporting_signals))
            previous.candidate_element_ids = sorted(set(previous.candidate_element_ids + item.candidate_element_ids))
            if item.source != previous.source:
                previous.source = f"{previous.source}+{item.source}"
            if item.rationale and item.rationale not in previous.rationale:
                previous.rationale = f"{previous.rationale} {item.rationale}".strip()
            if not previous.bounded_action_summary and item.bounded_action_summary:
                previous.bounded_action_summary = item.bounded_action_summary
            if not previous.target_page_url and item.target_page_url:
                previous.target_page_url = item.target_page_url
            if not previous.pre_action_selector and item.pre_action_selector:
                previous.pre_action_selector = item.pre_action_selector
            if not previous.target_selector and item.target_selector:
                previous.target_selector = item.target_selector
            if not previous.target_parameter and item.target_parameter:
                previous.target_parameter = item.target_parameter
        return sorted(merged.values(), key=lambda item: (-item.confidence, item.scenario_id))

    def _artifact_url_for_path(self, artifact_path: str) -> str:
        artifact_name = Path(artifact_path).name
        return f"/artifacts/red-agent/{artifact_name}"

    def _as_string_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]

    def _as_optional_text(self, value: object) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _bounded_float(self, value: object, default: float) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = default
        return max(0.0, min(1.0, numeric))
