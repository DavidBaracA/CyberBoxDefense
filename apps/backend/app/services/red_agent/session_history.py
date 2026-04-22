"""File-backed history for completed Red-agent operator review sessions.

TODO:
- Replace the JSON file with a proper relational store if session volume grows.
- Add filtering and pagination once the operator review list gets longer.
- Add export/report generation for thesis-demo evidence packages.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from fastapi import HTTPException
from pydantic import TypeAdapter

from ...red_agent_models import RedAgentSessionDetail, RedAgentSessionSummary


class RedAgentSessionHistoryStore:
    """Persist completed Red-agent sessions for operator review."""

    def __init__(self, storage_path: Path) -> None:
        self._storage_path = storage_path
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._adapter = TypeAdapter(list[RedAgentSessionDetail])

    def _read_all_unlocked(self) -> list[RedAgentSessionDetail]:
        if not self._storage_path.exists():
            return []
        payload = json.loads(self._storage_path.read_text(encoding="utf-8"))
        return self._adapter.validate_python(payload)

    def _write_all_unlocked(self, sessions: list[RedAgentSessionDetail]) -> None:
        serialized = [session.model_dump(mode="json") for session in sessions]
        self._storage_path.write_text(
            json.dumps(serialized, indent=2),
            encoding="utf-8",
        )

    def save_session(self, session: RedAgentSessionDetail) -> RedAgentSessionDetail:
        with self._lock:
            sessions = self._read_all_unlocked()
            sessions = [item for item in sessions if item.session_id != session.session_id]
            sessions.append(session)
            sessions.sort(key=lambda item: item.started_at, reverse=True)
            self._write_all_unlocked(sessions)
        return session

    def list_sessions(self) -> list[RedAgentSessionSummary]:
        with self._lock:
            sessions = self._read_all_unlocked()
        sessions.sort(key=lambda item: item.started_at, reverse=True)
        latest_session_id = sessions[0].session_id if sessions else None
        return [
            RedAgentSessionSummary(
                session_id=session.session_id,
                started_at=session.started_at,
                ended_at=session.ended_at,
                target_app_id=session.target_app_id,
                target_name=session.target_name,
                target_url=session.target_url,
                status=session.status,
                vulnerability_count=len(session.vulnerabilities),
                screenshot_count=len(session.screenshots),
                is_latest=session.session_id == latest_session_id,
                summary=session.summary,
            )
            for session in sessions
        ]

    def get_session(self, session_id: str) -> RedAgentSessionDetail:
        with self._lock:
            sessions = self._read_all_unlocked()
        sessions.sort(key=lambda item: item.started_at, reverse=True)
        latest_session_id = sessions[0].session_id if sessions else None
        for session in sessions:
            if session.session_id == session_id:
                return session.model_copy(update={"is_latest": session.session_id == latest_session_id})
        raise HTTPException(status_code=404, detail=f"Red-agent session {session_id} was not found.")
