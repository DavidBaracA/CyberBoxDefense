"""API router for predefined vulnerable app lifecycle management."""

from __future__ import annotations

from typing import Callable, Optional

from fastapi import APIRouter, HTTPException

from ..models import ActionEvent
from ..repositories.app_repository import VulnerableAppRepository
from ..services.deployment_service import DeploymentService
from ..vulnerable_apps_models import (
    VulnerableAppActionResponse,
    VulnerableAppDeployRequest,
    VulnerableAppDetail,
    VulnerableAppSummary,
    VulnerableAppTemplate,
)


def create_apps_router(
    repository: VulnerableAppRepository,
    deployment_service: DeploymentService,
    action_logger: Optional[Callable[[ActionEvent], ActionEvent]] = None,
    telemetry_collector=None,
) -> APIRouter:
    """Create the vulnerable app lifecycle router.

    TODO:
    - Add auth and role checks before exposing operator actions beyond localhost.
    - Add support for additional predefined templates without allowing arbitrary images.
    """

    router = APIRouter(prefix="/apps", tags=["vulnerable-apps"])

    def log_action(action: str, app: VulnerableAppDetail) -> None:
        if not action_logger:
            return
        action_logger(
            ActionEvent(
                actor="operator",
                action=action,
                target_type="vulnerable_app",
                target_id=app.app_id,
                details={
                    "name": app.name,
                    "template_id": app.template_id.value,
                    "port": app.port,
                    "runtime_identifier": app.runtime_identifier,
                    "target_url": app.target_url,
                },
            )
        )

    def get_app_or_404(app_id: str) -> VulnerableAppDetail:
        app = repository.get(app_id)
        if not app:
            raise HTTPException(status_code=404, detail=f"App {app_id} was not found.")
        return app

    @router.post("/deploy", response_model=VulnerableAppActionResponse)
    def deploy_app(request: VulnerableAppDeployRequest) -> VulnerableAppActionResponse:
        if repository.find_by_port(request.port):
            raise HTTPException(
                status_code=409,
                detail=f"Port {request.port} is already assigned to a managed vulnerable app.",
            )

        app = deployment_service.deploy(request)
        repository.add(app)
        if telemetry_collector:
            telemetry_collector.refresh_app(app)
        log_action("deploy", app)
        return VulnerableAppActionResponse(
            success=True,
            action="deploy",
            message=f"Deployed {request.template_id.value} as {app.name}.",
            app=app,
        )

    @router.get("/templates", response_model=list[VulnerableAppTemplate])
    def list_templates() -> list[VulnerableAppTemplate]:
        return deployment_service.get_template_catalog()

    @router.get("", response_model=list[VulnerableAppSummary])
    def list_apps() -> list[VulnerableAppSummary]:
        apps = [deployment_service.inspect_status(app) for app in repository.list_all()]
        for app in apps:
            repository.update(app)
            if telemetry_collector:
                telemetry_collector.refresh_app(app)
        return apps

    @router.get("/{app_id}", response_model=VulnerableAppDetail)
    def get_app(app_id: str) -> VulnerableAppDetail:
        app = deployment_service.inspect_status(get_app_or_404(app_id))
        repository.update(app)
        if telemetry_collector:
            telemetry_collector.refresh_app(app)
        return app

    @router.post("/{app_id}/stop", response_model=VulnerableAppActionResponse)
    def stop_app(app_id: str) -> VulnerableAppActionResponse:
        app = get_app_or_404(app_id)
        app = deployment_service.stop(app)
        repository.update(app)
        if telemetry_collector:
            telemetry_collector.refresh_app(app)
        log_action("stop", app)
        return VulnerableAppActionResponse(
            success=True,
            action="stop",
            message=f"Stopped {app.name}.",
            app=app,
        )

    @router.post("/{app_id}/restart", response_model=VulnerableAppActionResponse)
    def restart_app(app_id: str) -> VulnerableAppActionResponse:
        app = get_app_or_404(app_id)
        app = deployment_service.restart(app)
        repository.update(app)
        if telemetry_collector:
            telemetry_collector.refresh_app(app)
        log_action("restart", app)
        return VulnerableAppActionResponse(
            success=True,
            action="restart",
            message=f"Restarted {app.name}.",
            app=app,
        )

    @router.delete("/{app_id}", response_model=VulnerableAppActionResponse)
    def remove_app(app_id: str) -> VulnerableAppActionResponse:
        app = get_app_or_404(app_id)
        removed = deployment_service.remove(app)
        repository.remove(app_id)
        if telemetry_collector:
            telemetry_collector.stop_for_app(app_id)
        log_action("remove", removed)
        return VulnerableAppActionResponse(
            success=True,
            action="remove",
            message=f"Removed {removed.name}.",
            app=removed,
        )

    return router
