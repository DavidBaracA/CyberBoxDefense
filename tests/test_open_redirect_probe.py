from __future__ import annotations

import unittest

from apps.backend.app.services.red_agent.probes.models import HttpResponse
from apps.backend.app.services.red_agent.probes.open_redirect_probe import (
    OpenRedirectProbe,
    OpenRedirectProbeConfig,
    detect_client_side_redirect,
    is_external_redirect,
    normalize_redirect_location,
)


class FakeClient:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.requests = []

    async def request(self, method, url, **kwargs):  # noqa: ANN001
        self.requests.append((method, url, kwargs))
        return self.response


class OpenRedirectProbeTests(unittest.IsolatedAsyncioTestCase):
    def test_external_redirect_detection_normalizes_hosts(self) -> None:
        target = "http://localhost:3000/login"
        self.assertTrue(is_external_redirect(target, "https://example.com/"))
        self.assertTrue(is_external_redirect(target, "//example.com/path"))
        self.assertFalse(is_external_redirect(target, "/dashboard"))
        self.assertFalse(is_external_redirect(target, "http://localhost:3000/dashboard"))
        self.assertEqual(normalize_redirect_location(target, "/dashboard"), "http://localhost:3000/dashboard")

    def test_client_side_redirect_detection_is_conservative(self) -> None:
        target = "http://localhost:3000/"
        self.assertEqual(
            detect_client_side_redirect(target, '<meta http-equiv="refresh" content="0;url=https://example.com/">'),
            "https://example.com/",
        )
        self.assertIsNone(detect_client_side_redirect(target, 'window.location = "/safe";'))

    async def test_probe_finding_for_location_header(self) -> None:
        client = FakeClient(
            HttpResponse(
                status_code=302,
                url="http://localhost:3000/redirect",
                headers={"Location": "https://example.com/"},
                text="",
            )
        )
        probe = OpenRedirectProbe(
            OpenRedirectProbeConfig(paths=("/redirect",), parameters=("url",), payloads=("https://example.com/",)),
            client=client,
        )

        result = await probe.run("http://localhost:3000/")

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.probe_name, "open_redirect_probe")
        self.assertEqual(finding.cwe, "CWE-601")
        self.assertEqual(finding.severity, "medium")
        self.assertFalse(client.requests[0][2]["follow_redirects"])


if __name__ == "__main__":
    unittest.main()
