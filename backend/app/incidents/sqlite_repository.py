"""SQLite-backed implementation of the incident store contract."""

import json
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any, Iterator
from uuid import uuid4

from app.incidents.service import (
    IncidentConflictError,
    IncidentNotFoundError,
)
from app.incidents.types import (
    IncidentAuditEvent,
    IncidentRecord,
    InvestigationNote,
)


class SQLiteIncidentStore:
    """Persist incident records, notes, and audit events in SQLite."""

    def __init__(self, database_path: str | Path) -> None:
        self._is_memory_database = str(database_path) == ":memory:"
        self._database_path = (
            f"file:incident_store_{uuid4().hex}?mode=memory&cache=shared"
            if self._is_memory_database
            else str(database_path)
        )
        self._write_lock = RLock() if self._is_memory_database else nullcontext()
        self._closed = False
        self._keeper_connection: sqlite3.Connection | None = None
        if self._is_memory_database:
            self._keeper_connection = self._connect(keeper=True)
        else:
            Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self._initialize_schema()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        """Close the repository and release its in-memory database."""
        if self._closed:
            return
        self._closed = True
        if self._keeper_connection is not None:
            self._keeper_connection.close()
            self._keeper_connection = None

    def create_incident(
        self, incident: IncidentRecord, event: IncidentAuditEvent
    ) -> None:
        self._validate_incident_event(incident, event)
        if type(incident["revision"]) is not int or incident["revision"] != 0:
            raise IncidentConflictError("New incidents must start at revision zero.")

        incident_json = _serialize(incident)
        event_json = _serialize(event)
        with self._write_lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO incidents (incident_id, revision, record_json)
                    VALUES (?, ?, ?)
                    """,
                    (
                        incident["incident_id"],
                        incident["revision"],
                        incident_json,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO incident_audit_events
                        (event_id, incident_id, occurred_at, event_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        event["event_id"],
                        event["incident_id"],
                        _serialize_timestamp(event["occurred_at"]),
                        event_json,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as error:
                connection.rollback()
                _raise_integrity_error(error)
            except Exception:
                connection.rollback()
                raise

    def update_incident(
        self,
        incident: IncidentRecord,
        expected_revision: int,
        event: IncidentAuditEvent,
        note: InvestigationNote | None = None,
    ) -> None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise IncidentConflictError("Incident update is stale.")
        self._validate_incident_event(incident, event)
        if note is not None:
            _validate_note(note, incident["incident_id"])

        incident_json = _serialize(incident)
        event_json = _serialize(event)
        note_json = _serialize(note) if note is not None else None
        with self._write_lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT revision FROM incidents WHERE incident_id = ?",
                    (incident["incident_id"],),
                ).fetchone()
                if row is None:
                    raise IncidentNotFoundError("Incident does not exist.")
                if row["revision"] != expected_revision:
                    raise IncidentConflictError("Incident update is stale.")
                if (
                    type(incident["revision"]) is not int
                    or incident["revision"] != expected_revision + 1
                ):
                    raise IncidentConflictError(
                        "Updated incident revision must increment exactly once."
                    )

                cursor = connection.execute(
                    """
                    UPDATE incidents
                    SET revision = ?, record_json = ?
                    WHERE incident_id = ? AND revision = ?
                    """,
                    (
                        incident["revision"],
                        incident_json,
                        incident["incident_id"],
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise IncidentConflictError("Incident update is stale.")

                connection.execute(
                    """
                    INSERT INTO incident_audit_events
                        (event_id, incident_id, occurred_at, event_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        event["event_id"],
                        event["incident_id"],
                        _serialize_timestamp(event["occurred_at"]),
                        event_json,
                    ),
                )
                if note is not None and note_json is not None:
                    connection.execute(
                        """
                        INSERT INTO investigation_notes
                            (note_id, incident_id, created_at, note_json)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            note["note_id"],
                            note["incident_id"],
                            _serialize_timestamp(note["created_at"]),
                            note_json,
                        ),
                    )
                connection.commit()
            except sqlite3.IntegrityError as error:
                connection.rollback()
                _raise_integrity_error(error)
            except Exception:
                connection.rollback()
                raise

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT record_json FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        return _deserialize(row["record_json"], IncidentRecord)

    def get_notes(self, incident_id: str) -> list[InvestigationNote]:
        with self._connection() as connection:
            self._require_incident(connection, incident_id)
            rows = connection.execute(
                """
                SELECT note_json FROM investigation_notes
                WHERE incident_id = ?
                ORDER BY created_at, rowid
                """,
                (incident_id,),
            ).fetchall()
        return [
            _deserialize(row["note_json"], InvestigationNote) for row in rows
        ]

    def get_audit_events(self, incident_id: str) -> list[IncidentAuditEvent]:
        with self._connection() as connection:
            self._require_incident(connection, incident_id)
            rows = connection.execute(
                """
                SELECT event_json FROM incident_audit_events
                WHERE incident_id = ?
                ORDER BY occurred_at, rowid
                """,
                (incident_id,),
            ).fetchall()
        return [
            _deserialize(row["event_json"], IncidentAuditEvent) for row in rows
        ]

    def _connect(self, *, keeper: bool = False) -> sqlite3.Connection:
        if self._closed:
            raise RuntimeError("SQLiteIncidentStore is closed.")
        connection = sqlite3.connect(
            self._database_path,
            timeout=30.0,
            isolation_level=None,
            uri=self._is_memory_database,
            check_same_thread=not keeper,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize_schema(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    record_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS investigation_notes (
                    note_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    note_json TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
                );

                CREATE TABLE IF NOT EXISTS incident_audit_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
                );

                CREATE INDEX IF NOT EXISTS idx_investigation_notes_chronology
                    ON investigation_notes (incident_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_incident_audit_chronology
                    ON incident_audit_events (incident_id, occurred_at);
                """
            )

    @staticmethod
    def _require_incident(
        connection: sqlite3.Connection, incident_id: str
    ) -> None:
        row = connection.execute(
            "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise IncidentNotFoundError("Incident does not exist.")

    @staticmethod
    def _validate_incident_event(
        incident: IncidentRecord, event: IncidentAuditEvent
    ) -> None:
        if event["incident_id"] != incident["incident_id"]:
            raise ValueError("Audit event incident_id does not match the incident.")
        if not isinstance(incident["incident_id"], str) or not incident["incident_id"]:
            raise ValueError("incident_id must be a non-empty string.")
        if not isinstance(event["event_id"], str) or not event["event_id"]:
            raise ValueError("event_id must be a non-empty string.")
        if event["new_status"] != incident["status"]:
            raise ValueError("Audit event status does not match the incident.")
        _serialize_timestamp(incident["created_at"])
        _serialize_timestamp(incident["updated_at"])
        _serialize_timestamp(event["occurred_at"])


def _validate_note(note: InvestigationNote, incident_id: str) -> None:
    if note["incident_id"] != incident_id:
        raise ValueError("Note incident_id does not match the incident.")
    if not isinstance(note["note_id"], str) or not note["note_id"]:
        raise ValueError("note_id must be a non-empty string.")
    _serialize_timestamp(note["created_at"])


def _serialize_timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("Persisted timestamps must be timezone-aware UTC datetimes.")
    return value.isoformat()


def _serialize(value: object) -> str:
    return json.dumps(
        value,
        default=_json_default,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _json_default(value: object) -> dict[str, str]:
    if isinstance(value, datetime):
        return {"__incident_datetime__": _serialize_timestamp(value)}
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable.")


def _datetime_object_hook(value: dict[str, Any]) -> object:
    if set(value) == {"__incident_datetime__"}:
        timestamp = value["__incident_datetime__"]
        if not isinstance(timestamp, str):
            raise ValueError("Malformed persisted datetime.")
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError("Persisted timestamp is not timezone-aware UTC.")
        return parsed
    return value


def _deserialize(value: str, expected_type: type[Any]) -> Any:
    decoded = json.loads(value, object_hook=_datetime_object_hook)
    if not isinstance(decoded, dict):
        raise ValueError("Persisted incident data must decode to an object.")
    return expected_type(decoded)


def _raise_integrity_error(error: sqlite3.IntegrityError) -> None:
    message = str(error).lower()
    if "unique constraint failed" in message or "primary key" in message:
        raise IncidentConflictError("A persisted incident, note, or event ID already exists.") from error
    raise error
