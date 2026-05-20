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
        description="Run bounded SQL injection validation against likely query inputs and common local search routes.",
        vulnerability_class="input_validation",
        prerequisites=["query_input_or_form"],
        candidate_page_signals=["search_page", "query_form", "filter_form"],
        candidate_element_signals=["search_field", "text_input", "submit_button"],
        bounded_action_template="Locate query-like forms or common search routes, submit only predefined SQLi test values, and capture bounded evidence.",
        success_indicators=["query_surface_detected", "sql_error_signal", "http_5xx_after_payload"],
        evidence_requirements=["screenshot", "candidate_input_or_route", "page_url", "status_code_comparison"],
        safety_limits=[
            "Managed local targets only",
            "Only predefined SQLi test values",
            "No unrestricted payload generation",
        ],
        execution_mode="browser",
        notes="Page understanding should surface search, filter, and query workflows generically.",
    ),
    AttackScenario(
        scenario_id="reflected_xss_probe",
        display_name="Reflected XSS Probe",
        description="Run bounded reflected-XSS validation against likely reflected inputs and common local search routes.",
        vulnerability_class="input_validation",
        prerequisites=["reflective_input_surface"],
        candidate_page_signals=["search_page", "form_page", "message_input"],
        candidate_element_signals=["text_input", "textarea", "submit_button"],
        bounded_action_template="Locate reflective input surfaces, submit only predefined XSS canary values, and capture bounded evidence.",
        success_indicators=["xss_dialog_signal", "xss_dom_marker_signal", "candidate_input_detected"],
        evidence_requirements=["screenshot", "candidate_input_or_route", "page_url", "execution_or_dom_marker"],
        safety_limits=[
            "Managed local targets only",
            "Only predefined XSS canary values",
            "No unrestricted payload generation",
        ],
        execution_mode="browser",
        notes="Can click a planner-suggested search reveal control before probing hidden query inputs.",
    ),
    AttackScenario(
        scenario_id="file_upload_probe",
        display_name="File Upload Probe",
        description="Identify upload forms and submit harmless multipart files to validate upload filtering behavior.",
        vulnerability_class="file_handling",
        prerequisites=["file_input_or_upload_widget"],
        candidate_page_signals=["upload_page", "profile_page", "attachment_form"],
        candidate_element_signals=["file_input", "upload_button", "multipart_form"],
        bounded_action_template="Locate upload controls, submit tiny harmless test files, and capture validation or retrieval evidence without executing uploads.",
        success_indicators=["file_input_detected", "dangerous_extension_accepted", "mime_mismatch_accepted", "uploaded_file_publicly_retrievable"],
        evidence_requirements=["screenshot", "candidate_file_input", "page_url", "tested_filename", "http_status", "upload_url_if_returned"],
        safety_limits=[
            "Managed local targets only",
            "Only tiny harmless probe files",
            "No web shells, reverse shells, malware, or uploaded-content execution",
        ],
        execution_mode="browser",
        notes="Designed for generic upload widgets rather than app-specific routes.",
    ),
    AttackScenario(
        scenario_id="open_redirect_probe",
        display_name="Open Redirect Probe",
        description="Validate redirect-like parameters with harmless external test destinations without following redirects.",
        vulnerability_class="navigation_flow",
        prerequisites=["redirect_signal_or_navigation_parameter"],
        candidate_page_signals=["login_page", "navigation_page", "return_flow"],
        candidate_element_signals=["redirect_link", "return_url_param", "continue_button"],
        bounded_action_template="Locate likely redirect surfaces, send bounded redirect-parameter probes, and inspect Location headers or conservative client-side redirect signals.",
        success_indicators=["redirect_signal_detected", "external_location_header", "client_side_external_redirect"],
        evidence_requirements=["screenshot", "tested_url", "target_parameter", "http_status", "location_header"],
        safety_limits=[
            "Managed local targets only",
            "Redirects are not followed automatically",
            "Only documentation/test external destinations are used",
        ],
        execution_mode="browser",
        notes="Looks for return parameters and suspiciously redirect-oriented navigation hints.",
    ),
]


def get_scenario_catalog() -> list[AttackScenario]:
    return list(SCENARIO_CATALOG)


def get_scenario(scenario_id: str) -> Optional[AttackScenario]:
    return next((scenario for scenario in SCENARIO_CATALOG if scenario.scenario_id == scenario_id), None)
