"""Curated generic Red-agent scenario catalog.

These scenarios are bounded, local-only simulations. They do not permit free
form commands or arbitrary remote targeting. The catalog is intentionally
generic so target routing can be driven by page understanding rather than
hardcoded app names.

TODO:
- Add richer per-scenario action templates once bounded execution expands.
- Add replay fixtures for deterministic evaluation runs.
"""

from __future__ import annotations

from typing import Optional

from ...red_agent_models import AttackScenario


SCENARIO_CATALOG = [
    AttackScenario(
        scenario_id="brute_force_login",
        display_name="Brute-Force Login",
        description="Identify a likely login surface and run a small allowlisted login-attempt sequence.",
        vulnerability_class="authentication",
        prerequisites=["password_input", "login_form_or_submit"],
        candidate_page_signals=["login_page", "account_access", "authentication"],
        candidate_element_signals=["password_field", "username_field", "submit_button"],
        bounded_action_template="Navigate to a candidate login page, verify the form, submit only predefined lab credentials, and capture bounded evidence.",
        success_indicators=["login_form_detected", "candidate_navigation_reached", "post_login_navigation"],
        evidence_requirements=["screenshot", "login_form_fields", "page_url", "attempt_count"],
        safety_limits=[
            "Managed local targets only",
            "Only predefined lab credentials",
            "No arbitrary credentials or payload generation",
        ],
        execution_mode="browser",
        notes="Uses page understanding to locate authentication surfaces without target-specific hardcoding.",
    ),
    AttackScenario(
        scenario_id="sql_injection_probe",
        display_name="SQL Injection Probe",
        description="Identify likely query or search inputs where a later bounded SQLi probe could apply.",
        vulnerability_class="input_validation",
        prerequisites=["query_input_or_form"],
        candidate_page_signals=["search_page", "query_form", "filter_form"],
        candidate_element_signals=["search_field", "text_input", "submit_button"],
        bounded_action_template="Locate query-like forms and record evidence for a future bounded SQL injection probe.",
        success_indicators=["query_surface_detected"],
        evidence_requirements=["screenshot", "candidate_input", "page_url"],
        safety_limits=[
            "Managed local targets only",
            "No unrestricted payload generation",
            "Current MVP focuses on scenario routing and evidence capture",
        ],
        execution_mode="browser",
        notes="Page understanding should surface search, filter, and query workflows generically.",
    ),
    AttackScenario(
        scenario_id="reflected_xss_probe",
        display_name="Reflected XSS Probe",
        description="Identify likely reflected-input surfaces such as search boxes, contact forms, or echo-style inputs.",
        vulnerability_class="input_validation",
        prerequisites=["reflective_input_surface"],
        candidate_page_signals=["search_page", "form_page", "message_input"],
        candidate_element_signals=["text_input", "textarea", "submit_button"],
        bounded_action_template="Locate reflective input surfaces and capture evidence for future bounded reflected-XSS testing.",
        success_indicators=["text_input_detected", "form_submit_detected"],
        evidence_requirements=["screenshot", "candidate_input", "page_url"],
        safety_limits=[
            "Managed local targets only",
            "No unrestricted payload generation",
            "Current MVP focuses on planner applicability only",
        ],
        execution_mode="browser",
        notes="Shared heuristics often overlap with SQLi-style search and form discovery.",
    ),
    AttackScenario(
        scenario_id="file_upload_probe",
        display_name="File Upload Probe",
        description="Identify upload forms or file selectors suitable for future bounded upload testing.",
        vulnerability_class="file_handling",
        prerequisites=["file_input_or_upload_widget"],
        candidate_page_signals=["upload_page", "profile_page", "attachment_form"],
        candidate_element_signals=["file_input", "upload_button", "multipart_form"],
        bounded_action_template="Locate upload controls and capture evidence for future bounded upload validation.",
        success_indicators=["file_input_detected"],
        evidence_requirements=["screenshot", "candidate_file_input", "page_url"],
        safety_limits=[
            "Managed local targets only",
            "No file delivery beyond harmless demo fixtures in future iterations",
            "Current MVP focuses on planner applicability only",
        ],
        execution_mode="browser",
        notes="Designed for generic upload widgets rather than app-specific routes.",
    ),
    AttackScenario(
        scenario_id="open_redirect_probe",
        display_name="Open Redirect Probe",
        description="Identify redirect-like parameters, return URLs, or outbound navigation surfaces for future bounded redirect checks.",
        vulnerability_class="navigation_flow",
        prerequisites=["redirect_signal_or_navigation_parameter"],
        candidate_page_signals=["login_page", "navigation_page", "return_flow"],
        candidate_element_signals=["redirect_link", "return_url_param", "continue_button"],
        bounded_action_template="Locate likely redirect surfaces and capture evidence for future bounded redirect validation.",
        success_indicators=["redirect_signal_detected"],
        evidence_requirements=["screenshot", "link_targets", "page_url"],
        safety_limits=[
            "Managed local targets only",
            "No arbitrary external destinations",
            "Current MVP focuses on planner applicability only",
        ],
        execution_mode="browser",
        notes="Looks for return parameters and suspiciously redirect-oriented navigation hints.",
    ),
]


def get_scenario_catalog() -> list[AttackScenario]:
    return list(SCENARIO_CATALOG)


def get_scenario(scenario_id: str) -> Optional[AttackScenario]:
    return next((scenario for scenario in SCENARIO_CATALOG if scenario.scenario_id == scenario_id), None)
