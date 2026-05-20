"""Safe file-upload validation probe for controlled cyber-range targets.

The probe submits only tiny harmless multipart files, never uploads executable
payloads, and never attempts to execute uploaded content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from .http_client import UrllibAsyncHttpClient
from .models import AsyncHttpClient, HttpResponse, ProbeFinding, ProbeResult, RawHttpMetadata


PROBE_NAME = "file_upload_probe"
MARKER = "PROBE_ONLY_DO_NOT_EXECUTE"
DANGEROUS_EXTENSIONS = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx")
REMEDIATION = (
    "Allow-list extensions, verify file signatures rather than trusting Content-Type, "
    "rename files server-side, store uploads outside the web root, serve downloads "
    "with safe Content-Disposition, enforce size limits, and scan files where appropriate."
)


@dataclass(frozen=True)
class UploadProbeConfig:
    upload_paths: tuple[str, ...] = ("/upload", "/profile/avatar", "/files")
    max_forms: int = 5
    timeout: float = 5.0


@dataclass(frozen=True)
class UploadForm:
    action_url: str
    method: str
    file_field: str


@dataclass(frozen=True)
class MultipartCase:
    case_id: str
    filename: str
    content_type: str
    content: bytes
    expected_allowed: bool = False


class _UploadFormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.forms: list[dict[str, object]] = []
        self._current: Optional[dict[str, object]] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current = {
                "action": attributes.get("action") or self.page_url,
                "method": (attributes.get("method") or "GET").upper(),
                "file_fields": [],
            }
            return
        if tag.lower() == "input" and self._current is not None:
            input_type = (attributes.get("type") or "text").lower()
            if input_type == "file":
                fields = self._current["file_fields"]
                assert isinstance(fields, list)
                fields.append(attributes.get("name") or "file")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def discover_upload_forms(html: str, page_url: str, max_forms: int = 5) -> list[UploadForm]:
    """Extract POST multipart candidates with file inputs from one HTML page."""
    parser = _UploadFormParser(page_url)
    parser.feed(html or "")
    forms: list[UploadForm] = []
    for form in parser.forms:
        method = str(form.get("method") or "GET").upper()
        file_fields = list(form.get("file_fields") or [])
        if method != "POST" or not file_fields:
            continue
        forms.append(
            UploadForm(
                action_url=urljoin(page_url, str(form.get("action") or page_url)),
                method=method,
                file_field=str(file_fields[0]),
            )
        )
        if len(forms) >= max_forms:
            break
    return forms


def build_multipart_cases() -> list[MultipartCase]:
    """Return tiny harmless files for validation testing."""
    tiny_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    )
    return [
        MultipartCase("allowed_benign", "probe_test.txt", "text/plain", b"cyberbox benign upload probe\n", True),
        MultipartCase("dangerous_extension", "probe_test.php", "text/plain", MARKER.encode("ascii")),
        MultipartCase("mime_mismatch", "probe_test.jpg", "text/plain", b"not really a jpeg\n"),
        MultipartCase("double_extension", "probe_test.jpg.php", "image/jpeg", MARKER.encode("ascii")),
        MultipartCase("filename_edge", "probe test.txt", "text/plain", b"filename sanitization probe\n"),
        MultipartCase("path_like_filename", "../probe_test.txt", "text/plain", b"path-like filename probe\n"),
        MultipartCase("allowed_png", "probe_test.png", "image/png", tiny_png, True),
    ]


def encode_multipart(field_name: str, case: MultipartCase) -> tuple[bytes, str]:
    boundary = f"----CyberBoxProbe{uuid4().hex}"
    safe_filename = case.filename.replace('"', "")
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{safe_filename}"\r\n'
        f"Content-Type: {case.content_type}\r\n\r\n"
    ).encode("utf-8") + case.content + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, f"multipart/form-data; boundary={boundary}"


def extract_uploaded_url(response_text: str, base_url: str, location: Optional[str] = None) -> Optional[str]:
    """Extract a likely uploaded-file URL from Location, JSON, or simple HTML."""
    if location:
        return urljoin(base_url, location)
    text = response_text or ""
    try:
        parsed = json.loads(text)
        for key in ("url", "fileUrl", "file_url", "location", "path"):
            value = parsed.get(key) if isinstance(parsed, dict) else None
            if isinstance(value, str) and value:
                return urljoin(base_url, value)
    except json.JSONDecodeError:
        pass
    match = re.search(r'href=["\']([^"\']+(?:probe_test|probe%20test)[^"\']*)["\']', text, re.IGNORECASE)
    if match:
        return urljoin(base_url, match.group(1))
    match = re.search(r'(?:https?://[^\s"\']+|/[^\s"\']*)(?:probe_test|probe%20test)[^\s"\']*', text, re.IGNORECASE)
    if match:
        return urljoin(base_url, match.group(0))
    return None


def _raw_metadata(method: str, url: str, response: HttpResponse) -> RawHttpMetadata:
    return RawHttpMetadata(
        method=method,
        url=url,
        status_code=response.status_code,
        headers=dict(response.headers),
        redirect_location=response.headers.get("Location") or response.headers.get("location"),
        response_size=response.response_size,
    )


def _looks_accepted(response: HttpResponse) -> bool:
    if response.status_code in {400, 403, 409, 413, 415, 422}:
        return False
    validation_text = response.text.lower()
    return not any(token in validation_text for token in ("invalid file", "not allowed", "unsupported", "forbidden"))


def classify_upload_case(
    target_url: str,
    form: UploadForm,
    case: MultipartCase,
    response: HttpResponse,
    retrieval: Optional[HttpResponse] = None,
) -> Optional[ProbeFinding]:
    """Classify one harmless upload attempt into a structured finding."""
    accepted = _looks_accepted(response)
    uploaded_url = extract_uploaded_url(response.text, form.action_url, response.headers.get("Location"))
    publicly_retrievable = bool(retrieval and retrieval.status_code == 200 and MARKER in retrieval.text)
    filename_lower = case.filename.lower()
    dangerous_extension = filename_lower.endswith(DANGEROUS_EXTENSIONS)
    double_extension = any(filename_lower.endswith(f".jpg{ext}") or filename_lower.endswith(f".png{ext}") for ext in DANGEROUS_EXTENSIONS)
    mime_mismatch = case.case_id == "mime_mismatch"
    weak_filename = "/" in case.filename or "\\" in case.filename or case.filename in response.text

    if not accepted and not publicly_retrievable:
        return None

    severity = "low"
    confidence = 0.66
    description = "The upload endpoint accepted weak file-upload validation input."
    if dangerous_extension or double_extension:
        severity = "high" if publicly_retrievable else "medium"
        confidence = 0.9 if publicly_retrievable else 0.78
        description = "The upload endpoint accepted a script-like or double-extension filename."
    elif mime_mismatch:
        severity = "medium"
        confidence = 0.72
        description = "The upload endpoint accepted a file whose extension and declared Content-Type did not match."
    elif weak_filename:
        severity = "low"
        confidence = 0.68
        description = "The upload endpoint reflected or accepted a weak filename sanitization edge case."
    elif case.expected_allowed:
        return None

    raw_http = [_raw_metadata("POST", form.action_url, response)]
    if retrieval:
        raw_http.append(_raw_metadata("GET", retrieval.url, retrieval))

    return ProbeFinding(
        probe_name=PROBE_NAME,
        target_url=target_url,
        severity=severity,
        confidence=confidence,
        category="file_handling",
        cwe="CWE-434",
        description=description,
        evidence={
            "tested_filename": case.filename,
            "declared_content_type": case.content_type,
            "http_status": response.status_code,
            "redirect_location": response.headers.get("Location") or response.headers.get("location"),
            "returned_upload_url": uploaded_url,
            "validation_message": response.text[:300],
            "publicly_retrievable": publicly_retrievable,
        },
        remediation=REMEDIATION,
        raw_http=raw_http,
    )


class FileUploadProbe:
    """Bounded upload-validation probe using tiny harmless multipart files."""

    name = PROBE_NAME

    def __init__(
        self,
        config: Optional[UploadProbeConfig] = None,
        client: Optional[AsyncHttpClient] = None,
    ) -> None:
        self.config = config or UploadProbeConfig()
        self.client = client or UrllibAsyncHttpClient()

    async def run(self, target_url: str) -> ProbeResult:
        result = ProbeResult(probe_name=self.name, target_url=target_url)
        forms = await self._discover_forms(target_url, result)
        if not forms:
            result.evidence.append({"message": "No POST file-upload forms found.", "target_url": target_url})
            return result

        for form in forms[: self.config.max_forms]:
            for case in build_multipart_cases():
                body, content_type = encode_multipart(form.file_field, case)
                try:
                    response = await self.client.request(
                        "POST",
                        form.action_url,
                        headers={"Content-Type": content_type},
                        body=body,
                        timeout=self.config.timeout,
                        follow_redirects=False,
                    )
                except Exception as exc:  # pragma: no cover - transport-specific
                    result.errors.append(f"{form.action_url}: {exc}")
                    continue

                uploaded_url = extract_uploaded_url(
                    response.text,
                    form.action_url,
                    response.headers.get("Location") or response.headers.get("location"),
                )
                retrieval = None
                if uploaded_url and self._is_same_origin(target_url, uploaded_url):
                    retrieval = await self.client.request(
                        "GET",
                        uploaded_url,
                        timeout=self.config.timeout,
                        follow_redirects=False,
                    )

                finding = classify_upload_case(target_url, form, case, response, retrieval)
                result.evidence.append(
                    {
                        "form_action": form.action_url,
                        "file_field": form.file_field,
                        "tested_filename": case.filename,
                        "status_code": response.status_code,
                        "returned_upload_url": uploaded_url,
                    }
                )
                if finding:
                    result.findings.append(finding)
        return result

    async def _discover_forms(self, target_url: str, result: ProbeResult) -> list[UploadForm]:
        pages = [target_url, *[urljoin(target_url, path) for path in self.config.upload_paths]]
        forms: list[UploadForm] = []
        seen: set[tuple[str, str]] = set()
        for page_url in pages:
            try:
                response = await self.client.request(
                    "GET",
                    page_url,
                    timeout=self.config.timeout,
                    follow_redirects=False,
                )
            except Exception as exc:  # pragma: no cover - transport-specific
                result.errors.append(f"{page_url}: {exc}")
                continue
            for form in discover_upload_forms(response.text, page_url, self.config.max_forms):
                key = (form.action_url, form.file_field)
                if key not in seen:
                    seen.add(key)
                    forms.append(form)
                if len(forms) >= self.config.max_forms:
                    return forms
        return forms

    def _is_same_origin(self, target_url: str, uploaded_url: str) -> bool:
        target = urlparse(target_url)
        uploaded = urlparse(uploaded_url)
        return target.scheme == uploaded.scheme and target.netloc == uploaded.netloc
