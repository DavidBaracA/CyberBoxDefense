"""Deterministic attack planning for the bounded Red agent.

The planner converts a `RunConfig` into an ordered list of safe predefined
techniques. It does not execute anything yet.

TODO:
- Make planning template-aware once scenarios differ significantly by target.
- Add richer cost estimates from empirical run timings.
- Allow run-time re-planning when Blue containment changes the target surface.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...red_agent_models import AttackExecutionPlan, AttackScenario, AttackTechniquePlan
from ...run_models import AttackDepth, RunConfig
from .reasoner import (
    RedPlanningInput,
    RedPlanningReasoner,
    build_red_planning_reasoner,
)
from .scenarios import get_scenario_catalog


@dataclass(frozen=True)
class TechniqueProfile:
    """Internal deterministic planning metadata for one scenario."""

    base_priority: int
    estimated_cost: int
    estimated_difficulty: str
    high_signal: bool = False
    deep_only: bool = False
    multi_step: bool = False


TECHNIQUE_PROFILES: dict[str, TechniqueProfile] = {
    "browser_homepage_smoke": TechniqueProfile(
        base_priority=10,
        estimated_cost=1,
        estimated_difficulty="low",
        high_signal=True,
    ),
    "browser_login_navigation": TechniqueProfile(
        base_priority=20,
        estimated_cost=2,
        estimated_difficulty="low",
        high_signal=True,
        multi_step=True,
    ),
    "browser_login_bruteforce": TechniqueProfile(
        base_priority=30,
        estimated_cost=4,
        estimated_difficulty="medium",
        high_signal=True,
        multi_step=True,
        deep_only=True,
    ),
}


class AttackPlanner:
    """Generate a deterministic Red-agent execution plan from a run config."""

    def __init__(
        self,
        scenarios: list[AttackScenario] | None = None,
        reasoner: RedPlanningReasoner | None = None,
    ) -> None:
        self._scenarios = scenarios or get_scenario_catalog()
        self._reasoner = reasoner or build_red_planning_reasoner()

    def plan(
        self,
        config: RunConfig,
        *,
        target_name: str = "unknown-target",
        target_url: str = "",
    ) -> AttackExecutionPlan:
        """Return an ordered technique plan based on time budget and depth."""
        candidate_scenarios = self._select_candidates(config)
        scored = []
        for scenario in candidate_scenarios:
            profile = TECHNIQUE_PROFILES.get(
                scenario.scenario_id,
                TechniqueProfile(
                    base_priority=100,
                    estimated_cost=3,
                    estimated_difficulty="medium",
                ),
            )
            score = self._score_scenario(profile, config)
            scored.append((score, scenario, profile))

        ordered = sorted(
            scored,
            key=lambda item: (
                item[0],
                item[2].estimated_cost,
                item[1].display_name.lower(),
                item[1].scenario_id,
            ),
        )

        ordered_candidates = [scenario for _, scenario, _ in ordered]
        planning_decision = self._reasoner.choose_order(
            RedPlanningInput(
                target_name=target_name,
                target_url=target_url,
                attack_depth=config.attack_depth.value,
                duration_seconds=config.duration_seconds,
                try_all_available=config.try_all_available,
                stop_on_first_confirmed_vulnerability=config.stop_on_first_confirmed_vulnerability,
                candidate_scenarios=ordered_candidates,
            )
        )
        ordered_map = {scenario.scenario_id: scenario for scenario in ordered_candidates}
        ordered_profiles = {scenario.scenario_id: profile for _, scenario, profile in ordered}
        final_scenarios = [
            ordered_map[scenario_id]
            for scenario_id in planning_decision.ordered_scenario_ids
            if scenario_id in ordered_map
        ]

        techniques = [
            AttackTechniquePlan(
                technique_id=scenario.scenario_id,
                technique_name=scenario.display_name,
                estimated_cost=ordered_profiles[scenario.scenario_id].estimated_cost,
                estimated_difficulty=ordered_profiles[scenario.scenario_id].estimated_difficulty,
                priority_order=index,
            )
            for index, scenario in enumerate(final_scenarios, start=1)
        ]
        return AttackExecutionPlan(
            techniques=techniques,
            planner_name=getattr(self._reasoner, "name", "heuristic"),
            planner_rationale=planning_decision.rationale,
        )

    def _select_candidates(self, config: RunConfig) -> list[AttackScenario]:
        enabled_scenarios = [scenario for scenario in self._scenarios if scenario.enabled]
        if config.try_all_available:
            return self._filter_by_depth(enabled_scenarios, config.attack_depth)

        requested = set(config.enabled_attack_types)
        matched = [
            scenario for scenario in enabled_scenarios if scenario.scenario_id in requested
        ]
        return self._filter_by_depth(matched, config.attack_depth)

    def _filter_by_depth(
        self,
        scenarios: list[AttackScenario],
        attack_depth: AttackDepth,
    ) -> list[AttackScenario]:
        if attack_depth == AttackDepth.DEEP:
            return scenarios

        filtered: list[AttackScenario] = []
        for scenario in scenarios:
            profile = TECHNIQUE_PROFILES.get(scenario.scenario_id)
            if not profile:
                filtered.append(scenario)
                continue
            if attack_depth == AttackDepth.QUICK and profile.deep_only:
                continue
            filtered.append(scenario)
        return filtered

    def _score_scenario(self, profile: TechniqueProfile, config: RunConfig) -> int:
        """Lower score means earlier execution in the plan."""
        score = profile.base_priority

        if config.duration_seconds <= 180:
            score -= 12 if profile.high_signal else 0
            score += profile.estimated_cost * 8
            score += 25 if profile.deep_only else 0
            score += 6 if profile.multi_step else 0
        elif config.duration_seconds <= 600:
            score -= 8 if profile.high_signal else 0
            score += profile.estimated_cost * 5
            score += 10 if profile.deep_only else 0
        else:
            score -= 4 if profile.high_signal else 0
            score += profile.estimated_cost * 2
            score -= 10 if profile.deep_only else 0
            score -= 4 if profile.multi_step else 0

        if config.attack_depth == AttackDepth.QUICK:
            score += 20 if profile.deep_only else 0
            score += 4 if profile.multi_step else 0
        elif config.attack_depth == AttackDepth.BALANCED:
            score += 6 if profile.deep_only else 0
        elif config.attack_depth == AttackDepth.DEEP:
            score -= 12 if profile.deep_only else 0
            score -= 5 if profile.multi_step else 0

        return score
