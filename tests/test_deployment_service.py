from __future__ import annotations

import unittest

from fastapi import HTTPException

from apps.backend.app.services.deployment_service import CrAPITemplateHandler, DeploymentService
from apps.backend.app.services.template_registry import get_template
from apps.backend.app.vulnerable_apps_models import SupportedTemplate


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


if __name__ == "__main__":
    unittest.main()
