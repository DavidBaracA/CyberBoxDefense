"""Docker-backed deployment service for predefined vulnerable apps.

TODO:
- Persist deployment state and reconcile it with Docker on backend restart.
- Add compose/network policy integration for richer cyber-range isolation.
- Add container health probing before marking deployments as healthy.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import json
from pathlib import Path
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException

from .template_registry import get_template, list_enabled_templates
from ..vulnerable_apps_models import (
    DeploymentType,
    SupportedTemplate,
    VulnerableAppDeployRequest,
    VulnerableAppDetail,
    VulnerableAppStatus,
    VulnerableAppTemplate,
)


class TemplateHandler:
    """Base handler for a predefined vulnerable app template."""

    def __init__(self, service: "DeploymentService", template: VulnerableAppTemplate) -> None:
        self.service = service
        self.template = template

    def deploy(self, request: VulnerableAppDeployRequest) -> VulnerableAppDetail:
        raise NotImplementedError

    def inspect_status(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        raise NotImplementedError

    def stop(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        raise NotImplementedError

    def restart(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        raise NotImplementedError

    def remove(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        raise NotImplementedError


class SingleContainerTemplateHandler(TemplateHandler):
    """Handler for simple single-container templates."""

    def deploy(self, request: VulnerableAppDeployRequest) -> VulnerableAppDetail:
        self.service.ensure_port_available(request.port)

        app_id = str(uuid4())
        container_name = self.service.build_container_name(request, app_id)
        internal_port = self.template.container_ports[0]

        result = self.service._run_docker_command(
            [
                "run",
                "-d",
                "--name",
                container_name,
                "-p",
                f"{request.port}:{internal_port}",
                self.template.image_name,
            ]
        )

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(
                status_code=502,
                detail=f"Failed to deploy {request.template_id.value}: {detail}",
            )

        container_id = result.stdout.strip() or None
        return VulnerableAppDetail(
            app_id=app_id,
            name=request.name,
            template_id=request.template_id,
            template_display_name=self.template.display_name,
            deployment_type=self.template.deployment_type,
            status=VulnerableAppStatus.RUNNING,
            port=request.port,
            host_ports={"primary": request.port},
            runtime_identifier=container_name,
            container_name=container_name,
            target_url=f"http://localhost:{request.port}",
            image_name=self.template.image_name,
            container_id=container_id,
            status_notes=self.template.status_notes,
        )

    def inspect_status(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        result = self.service._run_docker_command(
            ["inspect", "-f", "{{.State.Status}}", app.container_name]
        )

        if result.returncode != 0:
            app.status = VulnerableAppStatus.ERROR
            app.last_error = result.stderr.strip() or "Container no longer available."
            return app

        state = result.stdout.strip().lower()
        if state == "running":
            app.status = VulnerableAppStatus.RUNNING
            app.last_error = None
        elif state == "exited":
            app.status = VulnerableAppStatus.STOPPED
            app.last_error = None
        else:
            app.status = VulnerableAppStatus.ERROR
            app.last_error = "Unexpected Docker state: %s" % (state or "unknown")
        return app

    def stop(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        result = self.service._run_docker_command(["stop", app.container_name])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to stop app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.STOPPED
        app.last_error = None
        return app

    def restart(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        result = self.service._run_docker_command(["restart", app.container_name])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to restart app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.RUNNING
        app.last_error = None
        return app

    def remove(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        result = self.service._run_docker_command(["rm", "-f", app.container_name])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to remove app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.REMOVED
        app.last_error = None
        return app


class CrAPITemplateHandler(TemplateHandler):
    """Handler scaffold for the multi-container crAPI target."""

    def _compose_file_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "template_assets" / "crapi" / "docker-compose.yml"

    def _env_file_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "template_assets" / "crapi" / ".env"

    def _ensure_compose_ready(self) -> Path:
        compose_file = self._compose_file_path()
        env_file = self._env_file_path()
        if not compose_file.exists():
            raise HTTPException(
                status_code=501,
                detail=(
                    "crAPI support is scaffolded, but local compose assets are not bundled yet. "
                    "Add the official crAPI docker-compose files under apps/backend/app/template_assets/crapi "
                    "to enable deployment."
                ),
            )
        if not env_file.exists():
            raise HTTPException(
                status_code=501,
                detail="crAPI compose assets are incomplete: missing .env in template_assets/crapi.",
            )

        result = self.service._run_docker_command(["compose", "version"])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "docker compose is unavailable."
            raise HTTPException(
                status_code=503,
                detail=f"crAPI requires docker compose support from the local Docker runtime: {detail}",
            )

        return compose_file

    def _mailhog_port(self, primary_port: int) -> int:
        candidate = primary_port + 1
        if candidate > 65535:
            raise HTTPException(
                status_code=400,
                detail="crAPI requires an additional MailHog port, but no valid companion port is available.",
            )
        return candidate

    def deploy(self, request: VulnerableAppDeployRequest) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        mailhog_port = self._mailhog_port(request.port)
        self.service.ensure_port_available(request.port)
        self.service.ensure_port_available(mailhog_port)

        app_id = str(uuid4())
        project_name = self.service.build_compose_project_name(request, app_id)
        env = os.environ.copy()
        env["LISTEN_IP"] = "127.0.0.1"
        env["CRAPI_PORT"] = str(request.port)
        env["CRAPI_MAILHOG_PORT"] = str(mailhog_port)

        result = self.service._run_docker_command(
            [
                "compose",
                "-p",
                project_name,
                "-f",
                str(compose_file),
                "--compatibility",
                "up",
                "-d",
            ],
            env=env,
            cwd=str(compose_file.parent),
        )

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown docker compose error."
            raise HTTPException(status_code=502, detail=f"Failed to deploy crapi: {detail}")

        return VulnerableAppDetail(
            app_id=app_id,
            name=request.name,
            template_id=request.template_id,
            template_display_name=self.template.display_name,
            deployment_type=self.template.deployment_type,
            status=VulnerableAppStatus.RUNNING,
            port=request.port,
            host_ports={"primary": request.port, "mailhog": mailhog_port},
            runtime_identifier=project_name,
            target_url=f"http://localhost:{request.port}",
            compose_project_name=project_name,
            status_notes=self.template.status_notes,
        )

    def inspect_status(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        compose_file = self._compose_file_path()
        if not compose_file.exists():
            app.status = VulnerableAppStatus.ERROR
            app.last_error = "crAPI compose assets are missing."
            return app

        result = self.service._run_docker_command(
            [
                "compose",
                "-p",
                app.runtime_identifier,
                "-f",
                str(compose_file),
                "ps",
                "--format",
                "json",
            ],
            cwd=str(compose_file.parent),
        )
        if result.returncode != 0:
            app.status = VulnerableAppStatus.ERROR
            app.last_error = result.stderr.strip() or result.stdout.strip() or "Unable to inspect compose project."
            return app

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        states: list[str] = []
        for line in lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            state = str(payload.get("State", "")).lower()
            if state:
                states.append(state)

        if any(state == "running" for state in states):
            app.status = VulnerableAppStatus.RUNNING
            app.last_error = None
        elif lines:
            app.status = VulnerableAppStatus.STOPPED
            app.last_error = None
        else:
            app.status = VulnerableAppStatus.STOPPED
            app.last_error = None
        return app

    def stop(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        result = self.service._run_docker_command(
            ["compose", "-p", app.runtime_identifier, "-f", str(compose_file), "stop"],
            cwd=str(compose_file.parent),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown docker compose error."
            raise HTTPException(status_code=502, detail=f"Failed to stop app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.STOPPED
        app.last_error = None
        return app

    def restart(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        result = self.service._run_docker_command(
            ["compose", "-p", app.runtime_identifier, "-f", str(compose_file), "restart"],
            cwd=str(compose_file.parent),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown docker compose error."
            raise HTTPException(status_code=502, detail=f"Failed to restart app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.RUNNING
        app.last_error = None
        return app

    def remove(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        result = self.service._run_docker_command(
            ["compose", "-p", app.runtime_identifier, "-f", str(compose_file), "down", "-v"],
            cwd=str(compose_file.parent),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown docker compose error."
            raise HTTPException(status_code=502, detail=f"Failed to remove app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.REMOVED
        app.last_error = None
        return app


class DeploymentService:
    """Manage lifecycle operations for predefined local Docker targets."""

    def __init__(self) -> None:
        self.docker_binary = self._resolve_docker_binary()

    def _resolve_docker_binary(self) -> Optional[str]:
        """Resolve the Docker CLI path dynamically for local macOS setups."""
        candidates = [
            shutil.which("docker"),
            "/usr/local/bin/docker",
            "/opt/homebrew/bin/docker",
            "/Applications/Docker.app/Contents/Resources/bin/docker",
            os.path.expanduser("~/.docker/bin/docker"),
        ]

        for candidate in candidates:
            if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def ensure_docker_available(self) -> None:
        """Raise a user-friendly error if Docker is unavailable."""
        self.docker_binary = self._resolve_docker_binary()
        if not self.docker_binary:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Docker CLI is not available. Make sure Docker Desktop is installed, "
                    "running, and visible in your shell PATH, then retry."
                ),
            )

    def _run_docker_command(
        self,
        args: list[str],
        env: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> subprocess.CompletedProcess[str]:
        self.ensure_docker_available()
        result = subprocess.run(
            [self.docker_binary, *args],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            cwd=cwd,
        )
        return result

    def ensure_port_available(self, port: int) -> None:
        """Fail fast if the requested localhost port is already in use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                raise HTTPException(
                    status_code=409,
                    detail=f"Port {port} is already in use. Choose a different port.",
                )

    def _safe_slug(self, name: str) -> str:
        cleaned = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return cleaned or "target"

    def build_container_name(self, request: VulnerableAppDeployRequest, app_id: str) -> str:
        """Generate a deterministic local container name for the app."""
        return f"cyberbox-{request.template_id.value}-{self._safe_slug(request.name)}-{app_id[:8]}"

    def build_compose_project_name(self, request: VulnerableAppDeployRequest, app_id: str) -> str:
        """Generate a deterministic compose project name."""
        return f"cyberbox-{request.template_id.value}-{self._safe_slug(request.name)}-{app_id[:8]}"

    def get_template_catalog(self) -> list[VulnerableAppTemplate]:
        """Return the backend-controlled template catalog for the operator UI."""
        return list_enabled_templates()

    def _get_handler(self, template_id: SupportedTemplate) -> TemplateHandler:
        template = get_template(template_id)
        if template.deployment_type == DeploymentType.DOCKER_RUN:
            return SingleContainerTemplateHandler(self, template)
        if template.template_id == SupportedTemplate.CRAPI:
            return CrAPITemplateHandler(self, template)
        raise HTTPException(status_code=500, detail=f"No deployment handler configured for {template_id.value}.")

    def deploy(self, request: VulnerableAppDeployRequest) -> VulnerableAppDetail:
        """Deploy the selected predefined vulnerable app template."""
        return self._get_handler(request.template_id).deploy(request)

    def inspect_status(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        """Refresh app status from the underlying runtime."""
        return self._get_handler(app.template_id).inspect_status(app)

    def stop(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        """Stop a deployed vulnerable app."""
        return self._get_handler(app.template_id).stop(app)

    def restart(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        """Restart a deployed vulnerable app."""
        return self._get_handler(app.template_id).restart(app)

    def remove(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        """Remove a deployed vulnerable app."""
        return self._get_handler(app.template_id).remove(app)
