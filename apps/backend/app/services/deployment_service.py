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
import textwrap
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

    def _internal_port_for_request(self, request: VulnerableAppDeployRequest) -> int:
        if request.template_id == SupportedTemplate.CUSTOM:
            image_name = self._image_name_for_request(request)
            return request.container_port or self.service.detect_container_port(image_name)
        return self.template.container_ports[0]

    def _image_name_for_request(self, request: VulnerableAppDeployRequest) -> str:
        image_name = request.custom_image_name if request.template_id == SupportedTemplate.CUSTOM else self.template.image_name
        if not image_name:
            raise HTTPException(status_code=400, detail="Docker image name is required.")
        return image_name

    def deploy(self, request: VulnerableAppDeployRequest) -> VulnerableAppDetail:
        self.service.ensure_port_available(request.port)

        app_id = str(uuid4())
        container_name = self.service.build_container_name(request, app_id)
        proxy_container_name = self.service.build_proxy_container_name(request, app_id)
        internal_port = self._internal_port_for_request(request)
        image_name = self._image_name_for_request(request)

        self.service.validate_image_name(image_name)
        self.service.ensure_managed_network()

        result = self.service._run_docker_command(
            [
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                self.service.managed_network_name,
                image_name,
            ]
        )

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(
                status_code=502,
                detail=f"Failed to deploy {request.template_id.value}: {detail}",
            )

        container_id = result.stdout.strip() or None
        target_path = request.target_path if request.template_id == SupportedTemplate.CUSTOM else None
        proxy_config_path = self.service.write_nginx_proxy_config(
            app_id=app_id,
            upstream_container_name=container_name,
            upstream_container_port=internal_port,
        )
        try:
            self.service.run_nginx_proxy(
                proxy_container_name=proxy_container_name,
                host_port=request.port,
                config_path=proxy_config_path,
            )
        except Exception:
            self.service._run_docker_command(["rm", "-f", container_name])
            raise
        return VulnerableAppDetail(
            app_id=app_id,
            name=request.name,
            template_id=request.template_id,
            template_display_name=self.template.display_name,
            deployment_type=self.template.deployment_type,
            status=VulnerableAppStatus.RUNNING,
            port=request.port,
            container_port=internal_port,
            host_ports={"primary": request.port},
            runtime_identifier=container_name,
            container_name=container_name,
            proxy_container_name=proxy_container_name,
            proxy_image_name=self.service.nginx_proxy_image,
            proxy_config_path=str(proxy_config_path),
            upstream_container_name=container_name,
            upstream_container_port=internal_port,
            target_url=f"http://localhost:{request.port}{target_path or ''}",
            image_name=image_name,
            container_id=container_id,
            status_notes=self.template.status_notes,
        )

    def _run_new_container(self, app: VulnerableAppDetail) -> Optional[str]:
        internal_port = app.container_port or self.template.container_ports[0]
        image_name = app.image_name or self.template.image_name
        if not image_name:
            raise HTTPException(status_code=400, detail=f"App {app.app_id} does not have a Docker image name.")
        self.service.ensure_managed_network()
        result = self.service._run_docker_command(
            [
                "run",
                "-d",
                "--name",
                app.container_name,
                "--network",
                self.service.managed_network_name,
                image_name,
            ]
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to start app {app.app_id}: {detail}")
        return result.stdout.strip() or None

    def _ensure_proxy(self, app: VulnerableAppDetail) -> None:
        if not app.proxy_container_name:
            app.proxy_container_name = self.service.build_proxy_container_name_for_app(app)
        upstream_name = app.upstream_container_name or app.container_name
        upstream_port = app.upstream_container_port or app.container_port or self.template.container_ports[0]
        if not upstream_name:
            raise HTTPException(status_code=400, detail=f"App {app.app_id} does not have an upstream container name.")
        proxy_config_path = self.service.write_nginx_proxy_config(
            app_id=app.app_id,
            upstream_container_name=upstream_name,
            upstream_container_port=upstream_port,
        )
        app.proxy_config_path = str(proxy_config_path)
        app.proxy_image_name = self.service.nginx_proxy_image
        app.upstream_container_name = upstream_name
        app.upstream_container_port = upstream_port
        self.service.run_nginx_proxy(
            proxy_container_name=app.proxy_container_name,
            host_port=app.port,
            config_path=proxy_config_path,
        )

    def inspect_status(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        result = self.service._run_docker_command(
            ["inspect", "-f", "{{json .State}}", app.container_name]
        )

        if result.returncode != 0:
            app.status = VulnerableAppStatus.ERROR
            app.last_error = result.stderr.strip() or "Container no longer available."
            return app

        try:
            state_payload = json.loads(result.stdout.strip() or "{}")
        except json.JSONDecodeError:
            state_payload = {}

        state = str(state_payload.get("Status") or "").lower()
        exit_code = int(state_payload.get("ExitCode") or 0)
        if state == "running":
            app.status = VulnerableAppStatus.RUNNING
            app.last_error = None
        elif state == "exited" and exit_code == 0:
            app.status = VulnerableAppStatus.STOPPED
            app.last_error = None
        elif state == "exited":
            app.status = VulnerableAppStatus.ERROR
            app.last_error = self.service._container_error_summary(app.container_name, exit_code)
        else:
            app.status = VulnerableAppStatus.ERROR
            app.last_error = "Unexpected Docker state: %s" % (state or "unknown")

        if app.status == VulnerableAppStatus.RUNNING and app.proxy_container_name:
            proxy_result = self.service._run_docker_command(
                ["inspect", "-f", "{{json .State}}", app.proxy_container_name]
            )
            if proxy_result.returncode != 0:
                app.status = VulnerableAppStatus.ERROR
                app.last_error = proxy_result.stderr.strip() or "Proxy container no longer available."
                return app
            try:
                proxy_state_payload = json.loads(proxy_result.stdout.strip() or "{}")
            except json.JSONDecodeError:
                proxy_state_payload = {}
            proxy_state = str(proxy_state_payload.get("Status") or "").lower()
            proxy_exit_code = int(proxy_state_payload.get("ExitCode") or 0)
            if proxy_state != "running":
                app.status = VulnerableAppStatus.ERROR
                app.last_error = self.service._container_error_summary(app.proxy_container_name, proxy_exit_code)
        return app

    def stop(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        if app.proxy_container_name:
            self.service._run_docker_command(["stop", app.proxy_container_name])
        result = self.service._run_docker_command(["stop", app.container_name])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to stop app {app.app_id}: {detail}")
        app.status = VulnerableAppStatus.STOPPED
        app.last_error = None
        return app

    def restart(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        if app.proxy_container_name:
            self.service._run_docker_command(["rm", "-f", app.proxy_container_name])
        result = self.service._run_docker_command(["rm", "-f", app.container_name])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to recreate app {app.app_id}: {detail}")
        app.container_id = self._run_new_container(app)
        self._ensure_proxy(app)
        app.status = VulnerableAppStatus.RUNNING
        app.last_error = None
        return self.inspect_status(app)

    def remove(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        if app.proxy_container_name:
            self.service._run_docker_command(["rm", "-f", app.proxy_container_name])
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
        start_port = primary_port + 1
        if start_port > 65535:
            raise HTTPException(
                status_code=400,
                detail="crAPI requires an additional MailHog port, but no valid companion port is available.",
            )
        return self.service.find_available_port(start_port, excluded_ports={primary_port})

    def _compose_network_name(self, project_name: str) -> str:
        return f"{project_name}_default"

    def _ensure_proxy(self, app: VulnerableAppDetail) -> None:
        project_name = app.compose_project_name or app.runtime_identifier
        if not project_name:
            raise HTTPException(status_code=400, detail=f"App {app.app_id} does not have a compose project name.")
        if not app.proxy_container_name:
            app.proxy_container_name = self.service.build_proxy_container_name_for_app(app)
        proxy_config_path = self.service.write_nginx_proxy_config(
            app_id=app.app_id,
            upstream_container_name=app.upstream_container_name or "crapi-web",
            upstream_container_port=app.upstream_container_port or 80,
        )
        app.proxy_config_path = str(proxy_config_path)
        app.proxy_image_name = self.service.nginx_proxy_image
        app.upstream_container_name = app.upstream_container_name or "crapi-web"
        app.upstream_container_port = app.upstream_container_port or 80
        self.service.run_nginx_proxy(
            proxy_container_name=app.proxy_container_name,
            host_port=app.port,
            config_path=proxy_config_path,
            network_name=self._compose_network_name(project_name),
        )

    def deploy(self, request: VulnerableAppDeployRequest) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        mailhog_port = self._mailhog_port(request.port)
        self.service.ensure_port_available(request.port)
        self.service.ensure_port_available(mailhog_port)

        app_id = str(uuid4())
        project_name = self.service.build_compose_project_name(request, app_id)
        proxy_container_name = self.service.build_proxy_container_name(request, app_id)
        env = os.environ.copy()
        env["LISTEN_IP"] = "127.0.0.1"
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

        proxy_config_path = self.service.write_nginx_proxy_config(
            app_id=app_id,
            upstream_container_name="crapi-web",
            upstream_container_port=80,
        )
        try:
            self.service.run_nginx_proxy(
                proxy_container_name=proxy_container_name,
                host_port=request.port,
                config_path=proxy_config_path,
                network_name=self._compose_network_name(project_name),
            )
        except Exception:
            self.service._run_docker_command(
                ["compose", "-p", project_name, "-f", str(compose_file), "down", "-v"],
                cwd=str(compose_file.parent),
            )
            raise

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
            proxy_container_name=proxy_container_name,
            proxy_image_name=self.service.nginx_proxy_image,
            proxy_config_path=str(proxy_config_path),
            upstream_container_name="crapi-web",
            upstream_container_port=80,
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

        if app.status == VulnerableAppStatus.RUNNING and app.proxy_container_name:
            proxy_result = self.service._run_docker_command(
                ["inspect", "-f", "{{json .State}}", app.proxy_container_name]
            )
            if proxy_result.returncode != 0:
                app.status = VulnerableAppStatus.ERROR
                app.last_error = proxy_result.stderr.strip() or "Proxy container no longer available."
                return app
            try:
                proxy_state_payload = json.loads(proxy_result.stdout.strip() or "{}")
            except json.JSONDecodeError:
                proxy_state_payload = {}
            proxy_state = str(proxy_state_payload.get("Status") or "").lower()
            proxy_exit_code = int(proxy_state_payload.get("ExitCode") or 0)
            if proxy_state != "running":
                app.status = VulnerableAppStatus.ERROR
                app.last_error = self.service._container_error_summary(app.proxy_container_name, proxy_exit_code)
        return app

    def stop(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        if app.proxy_container_name:
            self.service._run_docker_command(["stop", app.proxy_container_name])
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
        if app.proxy_container_name:
            self.service._run_docker_command(["rm", "-f", app.proxy_container_name])
        result = self.service._run_docker_command(
            ["compose", "-p", app.runtime_identifier, "-f", str(compose_file), "restart"],
            cwd=str(compose_file.parent),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown docker compose error."
            raise HTTPException(status_code=502, detail=f"Failed to restart app {app.app_id}: {detail}")
        self._ensure_proxy(app)
        app.status = VulnerableAppStatus.RUNNING
        app.last_error = None
        return app

    def remove(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        compose_file = self._ensure_compose_ready()
        if app.proxy_container_name:
            self.service._run_docker_command(["rm", "-f", app.proxy_container_name])
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
        self.managed_network_name = "cyberbox-managed"
        self.nginx_proxy_image = "nginx:1.27-alpine"
        self.proxy_config_dir = Path(__file__).resolve().parents[4] / "data" / "nginx-proxies"

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

    def _container_error_summary(self, container_name: Optional[str], exit_code: int) -> str:
        if not container_name:
            return f"Container exited with code {exit_code}."
        result = self._run_docker_command(["logs", "--tail", "20", container_name])
        log_tail = (result.stderr.strip() or result.stdout.strip()).splitlines()
        latest_lines = [line.strip() for line in log_tail if line.strip()][-4:]
        if latest_lines:
            return f"Container exited with code {exit_code}. Recent logs: {' | '.join(latest_lines)}"
        return f"Container exited with code {exit_code}."

    def ensure_managed_network(self) -> None:
        result = self._run_docker_command(["network", "inspect", self.managed_network_name])
        if result.returncode == 0:
            return
        create_result = self._run_docker_command(["network", "create", self.managed_network_name])
        if create_result.returncode != 0:
            detail = create_result.stderr.strip() or create_result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to create Docker network {self.managed_network_name}: {detail}")

    def write_nginx_proxy_config(
        self,
        *,
        app_id: str,
        upstream_container_name: str,
        upstream_container_port: int,
    ) -> Path:
        self.proxy_config_dir.mkdir(parents=True, exist_ok=True)
        config_path = self.proxy_config_dir / f"{app_id}.conf"
        config = textwrap.dedent(
            f"""
            log_format cyberbox '$remote_addr - - [$time_local] "$request" $status $body_bytes_sent '
                                '"$http_referer" "$http_user_agent" request_time=$request_time '
                                'upstream_time=$upstream_response_time';

            server {{
                listen 80;
                access_log /dev/stdout cyberbox;
                error_log /dev/stderr warn;

                location / {{
                    proxy_pass http://{upstream_container_name}:{upstream_container_port};
                    proxy_http_version 1.1;
                    proxy_set_header Host $http_host;
                    proxy_set_header X-Forwarded-Host $http_host;
                    proxy_set_header X-Forwarded-Port $server_port;
                    proxy_set_header X-Forwarded-Proto $scheme;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection "upgrade";
                }}
            }}
            """
        ).strip()
        config_path.write_text(f"{config}\n", encoding="utf-8")
        return config_path

    def run_nginx_proxy(
        self,
        *,
        proxy_container_name: str,
        host_port: int,
        config_path: Path,
        network_name: Optional[str] = None,
    ) -> Optional[str]:
        if network_name is None:
            self.ensure_managed_network()
            network_name = self.managed_network_name
        result = self._run_docker_command(
            [
                "run",
                "-d",
                "--name",
                proxy_container_name,
                "--network",
                network_name,
                "-p",
                f"{host_port}:80",
                "-v",
                f"{config_path}:/etc/nginx/conf.d/default.conf:ro",
                self.nginx_proxy_image,
            ]
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown Docker error."
            raise HTTPException(status_code=502, detail=f"Failed to start nginx proxy: {detail}")
        return result.stdout.strip() or None

    def ensure_port_available(self, port: int) -> None:
        """Fail fast if the requested localhost port is already in use."""
        if not self.is_port_available(port):
            raise HTTPException(
                status_code=409,
                detail=f"Port {port} is already in use. Choose a different port.",
            )

    def is_port_available(self, port: int) -> bool:
        """Return whether the localhost port is currently free to bind."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex(("127.0.0.1", port)) != 0

    def find_available_port(self, start_port: int, excluded_ports: Optional[set[int]] = None) -> int:
        """Find the first free localhost port at or above the requested start."""
        excluded_ports = excluded_ports or set()
        for candidate in range(start_port, 65536):
            if candidate in excluded_ports:
                continue
            if self.is_port_available(candidate):
                return candidate
        raise HTTPException(
            status_code=409,
            detail=f"No available port was found at or above {start_port}. Choose a different port.",
        )

    def _safe_slug(self, name: str) -> str:
        cleaned = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return cleaned or "target"

    def validate_image_name(self, image_name: str) -> None:
        """Reject shell-like or malformed image references before passing them to Docker."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}", image_name):
            raise HTTPException(
                status_code=400,
                detail="Docker image must be a valid image reference such as my-app:latest.",
            )

    def detect_container_port(self, image_name: str) -> int:
        """Infer the primary container port from image metadata."""
        self.validate_image_name(image_name)
        payload = self._inspect_image_exposed_ports(image_name)
        if payload is None:
            pull_result = self._run_docker_command(["pull", image_name])
            if pull_result.returncode != 0:
                detail = pull_result.stderr.strip() or pull_result.stdout.strip() or "Docker could not pull the image."
                raise HTTPException(status_code=502, detail=f"Could not inspect or pull {image_name}: {detail}")
            payload = self._inspect_image_exposed_ports(image_name)

        ports = self._parse_exposed_ports(payload)
        if not ports:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Docker image {image_name} does not declare an exposed port. "
                    "Enter the container port from the image documentation."
                ),
            )

        preferred_ports = [80, 8080, 3000, 5000, 8000, 8081, 9090]
        for preferred_port in preferred_ports:
            if preferred_port in ports:
                return preferred_port
        if len(ports) == 1:
            return ports[0]
        raise HTTPException(
            status_code=400,
            detail=(
                f"Docker image {image_name} exposes multiple ports: {', '.join(str(port) for port in ports)}. "
                "Choose the app's container port."
            ),
        )

    def _inspect_image_exposed_ports(self, image_name: str) -> Optional[str]:
        result = self._run_docker_command(
            ["image", "inspect", image_name, "--format", "{{json .Config.ExposedPorts}}"]
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()

    def _parse_exposed_ports(self, payload: Optional[str]) -> list[int]:
        if not payload or payload == "null":
            return []
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, dict):
            return []
        ports: list[int] = []
        for raw_port in parsed:
            port_text = str(raw_port).split("/", 1)[0]
            try:
                port = int(port_text)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.append(port)
        return sorted(set(ports))

    def build_container_name(self, request: VulnerableAppDeployRequest, app_id: str) -> str:
        """Generate a deterministic local container name for the app."""
        return f"cyberbox-{request.template_id.value}-{self._safe_slug(request.name)}-{app_id[:8]}"

    def build_proxy_container_name(self, request: VulnerableAppDeployRequest, app_id: str) -> str:
        """Generate a deterministic local proxy container name for the app."""
        return f"cyberbox-proxy-{request.template_id.value}-{self._safe_slug(request.name)}-{app_id[:8]}"

    def build_proxy_container_name_for_app(self, app: VulnerableAppDetail) -> str:
        """Generate a proxy container name for legacy app records missing proxy metadata."""
        return f"cyberbox-proxy-{app.template_id.value}-{self._safe_slug(app.name)}-{app.app_id[:8]}"

    def build_compose_project_name(self, request: VulnerableAppDeployRequest, app_id: str) -> str:
        """Generate a deterministic compose project name."""
        return f"cyberbox-{request.template_id.value}-{self._safe_slug(request.name)}-{app_id[:8]}"

    def get_template_catalog(self) -> list[VulnerableAppTemplate]:
        """Return the backend-controlled template catalog for the operator UI."""
        return list_enabled_templates()

    def _get_handler(self, template_id: SupportedTemplate) -> TemplateHandler:
        if template_id == SupportedTemplate.CUSTOM:
            template = VulnerableAppTemplate(
                template_id=SupportedTemplate.CUSTOM,
                display_name="Custom Docker Image",
                description="Operator-provided single-container Docker target.",
                deployment_type=DeploymentType.DOCKER_RUN,
                default_port=8080,
                container_ports=[8080],
                enabled_for_ui=False,
                status_notes="Custom Docker image managed by CyberBoxDefense.",
            )
            return SingleContainerTemplateHandler(self, template)
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
