"""Lightweight SQLite persistence layer for CyberBoxDefense.

The database keeps the first production-like persistence step intentionally
small and explicit. It is suitable for local thesis experiments and demos.

TODO:
- Add Alembic or a small migration framework if the schema starts evolving often.
- Add experiment/run tables once scenarios need stronger isolation.
- Consider WAL tuning and connection pooling if write volume increases.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class Database:
    """Thread-safe SQLite helper with eager schema initialization."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        schema = """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS telemetry_events (
            event_id TEXT PRIMARY KEY,
            run_id TEXT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL,
            service_name TEXT,
            container_name TEXT,
            path TEXT,
            http_status INTEGER,
            message TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detection_events (
            detection_id TEXT PRIMARY KEY,
            run_id TEXT,
            timestamp TEXT NOT NULL,
            detector TEXT NOT NULL,
            classification TEXT NOT NULL,
            confidence REAL NOT NULL,
            summary TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attack_ground_truth (
            attack_id TEXT PRIMARY KEY,
            run_id TEXT,
            timestamp TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            notes TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vulnerable_apps (
            app_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            template_id TEXT NOT NULL,
            status TEXT NOT NULL,
            port INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            runtime_identifier TEXT NOT NULL,
            target_url TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS action_events (
            action_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action_name TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            run_id TEXT,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON detection_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ground_truth_timestamp ON attack_ground_truth(timestamp);
        CREATE INDEX IF NOT EXISTS idx_apps_status ON vulnerable_apps(status);
        CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON action_events(timestamp);
        """

        with self._lock:
            with self.connect() as connection:
                connection.executescript(schema)
                self._ensure_column(connection, "telemetry_events", "run_id", "TEXT")
                self._ensure_column(connection, "detection_events", "run_id", "TEXT")
                self._ensure_column(connection, "attack_ground_truth", "run_id", "TEXT")
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_telemetry_run_id ON telemetry_events(run_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_run_id ON detection_events(run_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ground_truth_run_id ON attack_ground_truth(run_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_actions_run_id ON action_events(run_id)"
                )

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection,
        table_name: str,
        column_name: str,
        column_definition: str,
    ) -> None:
        existing_columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
            )

    @staticmethod
    def to_json(payload: dict) -> str:
        return json.dumps(payload, sort_keys=True)

    @staticmethod
    def from_json(payload: str) -> dict:
        return json.loads(payload)
