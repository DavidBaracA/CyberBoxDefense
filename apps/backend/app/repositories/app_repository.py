"""SQLite-backed repository for vulnerable app deployments.

TODO:
- Add experiment/run identifiers when multiple scenarios share one backend.
- Add optimistic locking if lifecycle actions become concurrent.
- Add soft-delete/archive support if removed apps should remain queryable forever.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..database import Database
from ..vulnerable_apps_models import VulnerableAppDetail, VulnerableAppStatus


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VulnerableAppRepository:
    """Persist deployed vulnerable apps in SQLite for repeatable experiments."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def _upsert(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO vulnerable_apps (
                    app_id, name, template_id, status, port, created_at, updated_at,
                    runtime_identifier, target_url, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app.app_id,
                    app.name,
                    app.template_id.value,
                    app.status.value,
                    app.port,
                    app.created_at.isoformat(),
                    utc_now().isoformat(),
                    app.runtime_identifier,
                    app.target_url,
                    self._database.to_json(app.model_dump(mode="json")),
                ),
            )
        return app

    def _row_to_app(self, payload_json: str) -> VulnerableAppDetail:
        return VulnerableAppDetail.model_validate(self._database.from_json(payload_json))

    def add(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        return self._upsert(app)

    def list_all(self) -> list[VulnerableAppDetail]:
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM vulnerable_apps
                ORDER BY created_at ASC
                """
            ).fetchall()
        return [self._row_to_app(row["payload_json"]) for row in rows]

    def get(self, app_id: str) -> Optional[VulnerableAppDetail]:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM vulnerable_apps WHERE app_id = ?",
                (app_id,),
            ).fetchone()
        return self._row_to_app(row["payload_json"]) if row else None

    def find_by_port(self, port: int) -> Optional[VulnerableAppDetail]:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM vulnerable_apps WHERE port = ?",
                (port,),
            ).fetchone()
        return self._row_to_app(row["payload_json"]) if row else None

    def update(self, app: VulnerableAppDetail) -> VulnerableAppDetail:
        return self._upsert(app)

    def mark_status(
        self, app_id: str, status: VulnerableAppStatus, last_error: Optional[str] = None
    ) -> Optional[VulnerableAppDetail]:
        app = self.get(app_id)
        if not app:
            return None
        app.status = status
        app.last_error = last_error
        return self._upsert(app)

    def remove(self, app_id: str) -> Optional[VulnerableAppDetail]:
        app = self.get(app_id)
        if not app:
            return None
        with self._database.connect() as connection:
            connection.execute("DELETE FROM vulnerable_apps WHERE app_id = ?", (app_id,))
        return app
