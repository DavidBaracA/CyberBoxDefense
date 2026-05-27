from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from fastapi import HTTPException

from apps.backend.app.services.deployment_service import (
    CrAPITemplateHandler,
    DeploymentService,
    SingleContainerTemplateHandler,
)
from apps.backend.app.services.template_registry import get_template
from apps.backend.app.vulnerable_apps_models import SupportedTemplate, VulnerableAppDeployRequest


class FakeDeploymentService(DeploymentService):
    def __init__(self, proxy_config_dir: Path) -> None:
        super().__init__()
        self.proxy_config_dir = proxy_config_dir
        self.commands: list[list[str]] = []
        self.command_envs = []

    def ensure_port_available(self, port: int) -> None:
        return None

    def detect_container_port(self, image_name: str) -> int:
        return 8080

    def _run_docker_command(self, args, env=None, cwd=None):
        self.commands.append(list(args))
        self.command_envs.append(env)
        if args[:2] == ["network", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="missing")
        if args[:2] == ["network", "create"]:
            return SimpleNamespace(returncode=0, stdout="network-id\n", stderr="")
        if args and args[0] == "run":
            return SimpleNamespace(returncode=0, stdout=f"{args[args.index('--name') + 1]}-id\n", stderr="")
        if args[:2] == ["inspect", "-f"]:
            return SimpleNamespace(returncode=0, stdout='{"Status":"running","ExitCode":0}\n', stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class DeploymentServicePortTests(unittest.TestCase):
    def test_crapi_mailhog_port_skips_occupied_companion_port(self) -> None:
        service = DeploymentService()
        service.is_port_available = lambda port: port != 8889
        handler = CrAPITemplateHandler(service, get_template(SupportedTemplate.CRAPI))

        selected_port = handler._mailhog_port(8888)

        self.assertEqual(selected_port, 8890)

    def test_crapi_mailhog_port_requires_valid_companion_range(self) -> None:
        service = DeploymentService()
        handler = CrAPITemplateHandler(service, get_template(SupportedTemplate.CRAPI))

        with self.assertRaises(HTTPException) as context:
            handler._mailhog_port(65535)

        self.assertEqual(context.exception.status_code, 400)

    def test_single_container_deploy_routes_public_port_through_nginx_proxy(self) -> None:
        with TemporaryDirectory() as temp_dir:
            service = FakeDeploymentService(Path(temp_dir))
            handler = SingleContainerTemplateHandler(service, get_template(SupportedTemplate.JUICE_SHOP))

            app = handler.deploy(
                VulnerableAppDeployRequest(
                    template_id=SupportedTemplate.JUICE_SHOP,
                    name="Target A",
                    port=3000,
                )
            )

            app_run = next(command for command in service.commands if command[:2] == ["run", "-d"] and "bkimminich/juice-shop" in command)
            proxy_run = next(command for command in service.commands if command[:2] == ["run", "-d"] and service.nginx_proxy_image in command)

            self.assertIn("--network", app_run)
            self.assertIn(service.managed_network_name, app_run)
            self.assertNotIn("-p", app_run)
            self.assertIn("-p", proxy_run)
            self.assertIn("3000:80", proxy_run)
            self.assertEqual(app.target_url, "http://localhost:3000")
            self.assertEqual(app.upstream_container_name, app.container_name)
            self.assertEqual(app.upstream_container_port, 3000)
            self.assertTrue(app.proxy_container_name.startswith("cyberbox-proxy-juice_shop-target-a-"))

    def test_nginx_proxy_config_logs_access_to_stdout_and_forwards_to_upstream(self) -> None:
        with TemporaryDirectory() as temp_dir:
            service = FakeDeploymentService(Path(temp_dir))

            config_path = service.write_nginx_proxy_config(
                app_id="app-1",
                upstream_container_name="app-container",
                upstream_container_port=8080,
            )

            config = config_path.read_text(encoding="utf-8")
            self.assertIn("access_log /dev/stdout cyberbox;", config)
            self.assertIn("error_log /dev/stderr warn;", config)
            self.assertIn("proxy_pass http://app-container:8080;", config)
            self.assertIn("proxy_set_header Host $http_host;", config)
            self.assertIn("proxy_set_header X-Forwarded-Host $http_host;", config)
            self.assertIn("proxy_set_header X-Forwarded-Port $server_port;", config)
            self.assertIn("proxy_set_header X-Forwarded-For", config)

    def test_crapi_deploy_routes_primary_port_through_nginx_proxy(self) -> None:
        with TemporaryDirectory() as temp_dir:
            service = FakeDeploymentService(Path(temp_dir))
            handler = CrAPITemplateHandler(service, get_template(SupportedTemplate.CRAPI))

            app = handler.deploy(
                VulnerableAppDeployRequest(
                    template_id=SupportedTemplate.CRAPI,
                    name="API Target",
                    port=8888,
                )
            )

            proxy_run = next(command for command in service.commands if command[:2] == ["run", "-d"] and service.nginx_proxy_image in command)
            compose_env = next(env for command, env in zip(service.commands, service.command_envs) if command[:1] == ["compose"] and "up" in command)

            self.assertIn("8888:80", proxy_run)
            self.assertIn(f"{app.compose_project_name}_default", proxy_run)
            self.assertEqual(app.target_url, "http://localhost:8888")
            self.assertEqual(app.upstream_container_name, "crapi-web")
            self.assertEqual(app.upstream_container_port, 80)
            self.assertNotIn("CRAPI_PORT", compose_env)


if __name__ == "__main__":
    unittest.main()
