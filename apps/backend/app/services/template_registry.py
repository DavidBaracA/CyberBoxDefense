"""Template registry for predefined vulnerable targets.

TODO:
- Add WebGoat and NodeGoat as additional curated templates.
- Consider moving this catalog to a small config file if template count grows.
"""

from __future__ import annotations

from ..vulnerable_apps_models import DeploymentType, SupportedTemplate, VulnerableAppTemplate


TEMPLATE_REGISTRY: dict[SupportedTemplate, VulnerableAppTemplate] = {
    SupportedTemplate.JUICE_SHOP: VulnerableAppTemplate(
        template_id=SupportedTemplate.JUICE_SHOP,
        display_name="OWASP Juice Shop",
        description="Modern intentionally vulnerable web application covering a broad range of web flaws.",
        deployment_type=DeploymentType.DOCKER_RUN,
        default_port=3000,
        container_ports=[3000],
        image_name="bkimminich/juice-shop",
        enabled_for_ui=True,
        status_notes="Single-container baseline target for web attack and detection demos.",
    ),
    SupportedTemplate.DVWA: VulnerableAppTemplate(
        template_id=SupportedTemplate.DVWA,
        display_name="DVWA",
        description="Classic Damn Vulnerable Web Application for simpler web exploitation scenarios.",
        deployment_type=DeploymentType.DOCKER_RUN,
        default_port=8080,
        container_ports=[80],
        image_name="kaakaww/dvwa-docker:latest",
        enabled_for_ui=True,
        status_notes="Single-container classic target intended for direct Docker run usage.",
        caveat="Default DVWA credentials are typically admin / password after setup.",
    ),
    SupportedTemplate.CRAPI: VulnerableAppTemplate(
        template_id=SupportedTemplate.CRAPI,
        display_name="OWASP crAPI",
        description="API-focused intentionally vulnerable target built around a microservice architecture.",
        deployment_type=DeploymentType.DOCKER_COMPOSE,
        default_port=8888,
        container_ports=[8888, 8025],
        enabled_for_ui=True,
        status_notes="Multi-container target. Primary UI is exposed on the chosen port, and MailHog is exposed on the next port.",
        caveat="crAPI is heavier than Juice Shop or DVWA and may take longer to start.",
        metadata={"mailhog_offset": 1},
    ),
}


def list_enabled_templates() -> list[VulnerableAppTemplate]:
    """Return templates that should be shown in the operator UI."""
    return [template for template in TEMPLATE_REGISTRY.values() if template.enabled_for_ui]


def get_template(template_id: SupportedTemplate) -> VulnerableAppTemplate:
    """Return metadata for a single predefined template."""
    return TEMPLATE_REGISTRY[template_id]
