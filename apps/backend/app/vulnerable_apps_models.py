"""Pydantic models for predefined vulnerable app management and template catalog.

TODO:
- Persist deployments so vulnerable app state survives backend restarts.
- Add richer health information and container inspection data.
- Expand template support to additional predefined targets like WebGoat or NodeGoat.
- Add orchestration hooks when multiple targets and experiment scenarios are managed together.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class SupportedTemplate(str, Enum):
    JUICE_SHOP = "juice_shop"
    DVWA = "dvwa"
    CRAPI = "crapi"


class DeploymentType(str, Enum):
    DOCKER_RUN = "docker_run"
    DOCKER_COMPOSE = "docker_compose"


class VulnerableAppStatus(str, Enum):
    DEPLOYING = "deploying"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    REMOVED = "removed"


class VulnerableAppDeployRequest(BaseModel):
    """Request for deploying a predefined vulnerable app template."""

    template_id: SupportedTemplate
    name: str = Field(min_length=1, max_length=100)
    port: int = Field(ge=1, le=65535)

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("name must not be empty")
        return cleaned


class VulnerableAppTemplate(BaseModel):
    """Backend-controlled metadata for a deployable vulnerable app template."""

    template_id: SupportedTemplate
    display_name: str
    description: str
    deployment_type: DeploymentType
    default_port: int
    container_ports: list[int] = Field(default_factory=list)
    image_name: Optional[str] = None
    enabled_for_ui: bool = True
    status_notes: Optional[str] = None
    caveat: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerableAppSummary(BaseModel):
    """Operator-facing summary for a deployed vulnerable app."""

    app_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    template_id: SupportedTemplate
    template_display_name: str
    deployment_type: DeploymentType
    status: VulnerableAppStatus
    port: int
    host_ports: dict[str, int] = Field(default_factory=dict)
    runtime_identifier: str
    container_name: Optional[str] = None
    target_url: str
    created_at: datetime = Field(default_factory=utc_now)
    status_notes: Optional[str] = None


class VulnerableAppDetail(VulnerableAppSummary):
    """Detailed view for a deployed vulnerable app."""

    image_name: Optional[str] = None
    container_id: Optional[str] = None
    compose_project_name: Optional[str] = None
    last_error: Optional[str] = None


class VulnerableAppActionResponse(BaseModel):
    """Response for lifecycle actions such as deploy, stop, restart, or remove."""

    success: bool
    action: str
    message: str
    app: Optional[VulnerableAppDetail] = None
