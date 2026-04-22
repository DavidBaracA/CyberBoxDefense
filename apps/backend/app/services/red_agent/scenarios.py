"""Curated Red-agent scenario catalog.

These scenarios are bounded, local-only simulations. They do not permit free
form commands or arbitrary remote targeting.

TODO:
- Add richer per-template scenario mappings as the target catalog expands.
- Add replay fixtures for deterministic evaluation runs.
"""

from __future__ import annotations

from typing import Optional

from ...red_agent_models import AttackScenario


SCENARIO_CATALOG = [
    AttackScenario(
        scenario_id="browser_homepage_smoke",
        display_name="Browser Homepage Smoke",
        description="Open the managed target homepage in Playwright and capture a screenshot.",
        execution_mode="browser",
        notes="Safe bounded browser validation against the managed local target only.",
    ),
    AttackScenario(
        scenario_id="browser_login_navigation",
        display_name="Browser Login Navigation",
        description="Open the target in Playwright and navigate to a login or account view where safely available.",
        execution_mode="browser",
    ),
    AttackScenario(
        scenario_id="browser_login_bruteforce",
        display_name="Browser Login Brute-Force",
        description="Attempt a small bounded set of browser-based login submissions if a login page is available.",
        execution_mode="browser",
        notes="Uses only a tiny predefined credential list against the selected managed local target.",
    ),
]


def get_scenario_catalog() -> list[AttackScenario]:
    return list(SCENARIO_CATALOG)


def get_scenario(scenario_id: str) -> Optional[AttackScenario]:
    return next((scenario for scenario in SCENARIO_CATALOG if scenario.scenario_id == scenario_id), None)
