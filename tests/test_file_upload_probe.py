from __future__ import annotations

import unittest

from apps.backend.app.services.red_agent.probes.file_upload_probe import (
    MARKER,
    MultipartCase,
    UploadForm,
    build_multipart_cases,
    classify_upload_case,
    discover_upload_forms,
    extract_uploaded_url,
)
from apps.backend.app.services.red_agent.probes.models import HttpResponse
from apps.backend.app.services.red_agent.probes.registry import list_probes


class FileUploadProbeTests(unittest.TestCase):
    def test_discover_upload_forms_only_returns_post_file_inputs(self) -> None:
        html = """
        <form method="GET" action="/ignored"><input type="file" name="bad"></form>
        <form method="POST" action="/upload"><input type="file" name="avatar"></form>
        """

        forms = discover_upload_forms(html, "http://localhost:3000/profile", max_forms=5)

        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].action_url, "http://localhost:3000/upload")
        self.assertEqual(forms[0].file_field, "avatar")

    def test_extract_uploaded_url_from_json_and_html(self) -> None:
        self.assertEqual(
            extract_uploaded_url('{"file_url": "/uploads/probe_test.php"}', "http://localhost:3000/upload"),
            "http://localhost:3000/uploads/probe_test.php",
        )
        self.assertEqual(
            extract_uploaded_url('<a href="/uploads/probe_test.jpg.php">file</a>', "http://localhost:3000/upload"),
            "http://localhost:3000/uploads/probe_test.jpg.php",
        )

    def test_dangerous_extension_publicly_retrievable_is_high(self) -> None:
        form = UploadForm("http://localhost:3000/upload", "POST", "file")
        case = MultipartCase("dangerous_extension", "probe_test.php", "text/plain", MARKER.encode("ascii"))
        response = HttpResponse(
            status_code=201,
            url=form.action_url,
            headers={"Location": "/uploads/probe_test.php"},
            text="created",
        )
        retrieval = HttpResponse(
            status_code=200,
            url="http://localhost:3000/uploads/probe_test.php",
            headers={"Content-Type": "text/plain"},
            text=MARKER,
        )

        finding = classify_upload_case("http://localhost:3000/", form, case, response, retrieval)

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.cwe, "CWE-434")
        self.assertTrue(finding.evidence["publicly_retrievable"])

    def test_benign_allowed_case_is_not_a_finding(self) -> None:
        form = UploadForm("http://localhost:3000/upload", "POST", "file")
        case = next(item for item in build_multipart_cases() if item.case_id == "allowed_benign")
        response = HttpResponse(status_code=201, url=form.action_url, text="ok")

        self.assertIsNone(classify_upload_case("http://localhost:3000/", form, case, response))

    def test_registry_lists_new_probes(self) -> None:
        self.assertIn("file_upload_probe", list_probes())
        self.assertIn("open_redirect_probe", list_probes())


if __name__ == "__main__":
    unittest.main()
