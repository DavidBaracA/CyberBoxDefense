"""Central registry for safe Red-agent probe modules."""

from __future__ import annotations

from typing import Callable

from .file_upload_probe import FileUploadProbe
from .open_redirect_probe import OpenRedirectProbe


PROBE_REGISTRY: dict[str, Callable[[], object]] = {
    FileUploadProbe.name: FileUploadProbe,
    OpenRedirectProbe.name: OpenRedirectProbe,
}


def list_probes() -> list[str]:
    """Return registered safe probe names."""
    return sorted(PROBE_REGISTRY)


def get_probe(name: str) -> object:
    """Instantiate a registered probe by name."""
    return PROBE_REGISTRY[name]()
