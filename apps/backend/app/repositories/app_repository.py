"""In-memory repository for vulnerable app deployments.

TODO:
- Replace in-memory storage with durable persistence for repeated experiment runs.
- Add ownership/run identifiers when multiple operators or experiments share one backend.
- Add optimistic locking or event sourcing if lifecycle actions become concurrent.
"""

from __future__ import annotations

from typing import Optional

from ..vulnerable_apps_models import VulnerableAppDetail, VulnerableAppStatus


class VulnerableAppRepository:
    """Store deployed vulnerable apps in memory for the MVP."""

    def __init__(self) -> None:
        self._apps: dict[str, VulnerableAppDetail] = {}

    def add(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        self._apps[app.app_id] = app
        return app

    def list_all(self) -> list[VulnerableAppDetail]:
        return sorted(self._apps.values(), key=lambda item: item.created_at)

    def get(self, app_id: str) -> Optional[VulnerableAppDetail]:
        return self._apps.get(app_id)

    def find_by_port(self, port: int) -> Optional[VulnerableAppDetail]:
        return next((app for app in self._apps.values() if app.port == port), None)

    def update(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        self._apps[app.app_id] = app
        return app

    def mark_status(
        self, app_id: str, status: VulnerableAppStatus, last_error: Optional[str] = None
    ) -> Optional[VulnerableAppDetail]:
        app = self._apps.get(app_id)
        if not app:
            return None
        app.status = status
        app.last_error = last_error
        self._apps[app_id] = app
        return app

    def remove(self, app_id: str) -> Optional[VulnerableAppDetail]:
        return self._apps.pop(app_id, None)
