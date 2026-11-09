import copy
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from app.cognition.explanation import generate_explanations
from app.cognition.reconciliation import reconcile_evidence
from app.cognition.risk_assessment import assess_risk
from app.cognition.types import (
    ConsolidatedAssessment,
    ModelEvidence,
    RuleEvidence,
)
from app.detection.rule_engine import FeatureCheck, RuleResult
from app.incidents.policy import determine_assessment_handling
from app.incidents.service import (
    IncidentConflictError,
    IncidentNotFoundError,
    IncidentService,
)
from app.incidents.sqlite_repository import SQLiteIncidentStore
from app.incidents.types import (
    IncidentAuditEvent,
    IncidentCreationInput,
    IncidentRecord,
    InvestigationNote,
)


_BASE_TIME = datetime(2026, 11, 5, tzinfo=timezone.utc)


def make_assessment() -> ConsolidatedAssessment:
    model: ModelEvidence = {
        "status": "available",
        "predicted_class": 1,
        "predicted_label": "attack",
        "class_0_probability": 0.2,
        "class_1_probability": 0.8,
        "model_name": "test-model",
        "model_version": "1.0",
        "error_code": None,
    }
    check = cast(
        FeatureCheck,
        {
            "name": "num_failed_logins",
            "observed_value": 1,
            "operator": ">=",
            "threshold": 1,
            "condition_met": True,
        },
    )
    rule = cast(
        RuleResult,
        {
            "rule_id": "RBD-AUTH-001",
            "triggered": True,
            "severity": "high",
            "description": "Failed login evidence",
            "features_examined": [check],
            "reason": "One or more failed login attempts were recorded.",
        },
    )
    rules: RuleEvidence = {
        "status": "available",
        "results": [rule],
        "triggered_rule_ids": ["RBD-AUTH-001"],
        "error_code": None,
    }
    reconciliation = reconcile_evidence(model, rules)
    risk = assess_risk(model, rules)
    return {
        "model": model,
        "rules": rules,
        "reconciliation": reconciliation,
        "risk": risk,
        "explanations": generate_explanations(
            model, rules, reconciliation, risk
        ),
    }


class SequenceIds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> str:
        self.value += 1
        return f"id-{self.value}"


class SequenceClock:
    def __init__(self) -> None:
        self.value = _BASE_TIME

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(seconds=1)
        return result


class SQLiteIncidentRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.directory.name) / "incidents.sqlite3"
        self.store = SQLiteIncidentStore(self.database_path)
        self.service = IncidentService(
            store=self.store,
            id_generator=SequenceIds(),
            utc_clock=SequenceClock(),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def create_incident(self) -> IncidentRecord:
        assessment = make_assessment()
        decision = determine_assessment_handling(assessment)
        return self.service.create_incident(
            cast(
                IncidentCreationInput,
                {"assessment": assessment, "decision": decision},
            ),
            actor_id="analyst-1",
        )

    def transition(
        self,
        incident: IncidentRecord,
        *,
        new_status: str = "open",
        resolution_outcome: str | None = None,
    ) -> IncidentRecord:
        return self.service.transition_status(
            incident["incident_id"],
            {
                "new_status": new_status,
                "actor_id": "analyst-1",
                "resolution_outcome": resolution_outcome,
            },  # type: ignore[arg-type]
        )

    def raw_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def test_creation_survives_repository_reconstruction(self) -> None:
        incident = self.create_incident()
        restarted_store = SQLiteIncidentStore(self.database_path)

        self.assertEqual(
            restarted_store.get_incident(incident["incident_id"]), incident
        )

    def test_assessment_snapshot_and_recommendations_round_trip(self) -> None:
        incident = self.create_incident()
        retrieved = SQLiteIncidentStore(self.database_path).get_incident(
            incident["incident_id"]
        )

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["assessment_snapshot"], incident["assessment_snapshot"])
        self.assertEqual(retrieved["recommendations"], incident["recommendations"])
        self.assertEqual(
            retrieved["assessment_snapshot"]["rules"]["results"][0]["features_examined"][0][
                "observed_value"
            ],
            1,
        )

    def test_notes_and_audit_events_survive_restart_with_utc_datetimes(self) -> None:
        incident = self.create_incident()
        self.transition(incident)
        note = self.service.add_investigation_note(
            incident["incident_id"],
            {"content": "Reviewed evidence.", "actor_id": "analyst-1"},
        )
        restarted_store = SQLiteIncidentStore(self.database_path)

        notes = restarted_store.get_notes(incident["incident_id"])
        events = restarted_store.get_audit_events(incident["incident_id"])

        self.assertEqual(notes, [note])
        self.assertEqual(
            [event["event_type"] for event in events],
            ["incident_created", "status_transitioned", "investigation_note_added"],
        )
        self.assertTrue(
            all(item["created_at"].utcoffset() == timedelta(0) for item in notes)
        )
        self.assertTrue(
            all(event["occurred_at"].utcoffset() == timedelta(0) for event in events)
        )

    def test_failed_creation_rolls_back_incident_when_event_insert_fails(self) -> None:
        connection = self.raw_connection()
        connection.execute(
            """
            CREATE TRIGGER reject_creation_event
            BEFORE INSERT ON incident_audit_events
            BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaises(sqlite3.IntegrityError):
            self.create_incident()

        connection = self.raw_connection()
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM incident_audit_events").fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_failed_update_rolls_back_incident_and_event(self) -> None:
        incident = self.create_incident()
        connection = self.raw_connection()
        connection.execute(
            """
            CREATE TRIGGER reject_update_event
            BEFORE INSERT ON incident_audit_events
            WHEN NEW.event_id != 'id-2'
            BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaises(sqlite3.IntegrityError):
            self.transition(incident)

        self.assertEqual(
            self.store.get_incident(incident["incident_id"]), incident
        )
        self.assertEqual(len(self.store.get_audit_events(incident["incident_id"])), 1)

    def test_failed_note_insert_rolls_back_incident_and_audit(self) -> None:
        incident = self.create_incident()
        self.transition(incident)
        current = self.store.get_incident(incident["incident_id"])
        connection = self.raw_connection()
        connection.execute(
            """
            CREATE TRIGGER reject_note
            BEFORE INSERT ON investigation_notes
            BEGIN SELECT RAISE(ABORT, 'forced note failure'); END
            """
        )
        connection.commit()
        connection.close()
        before_events = self.store.get_audit_events(incident["incident_id"])

        with self.assertRaises(sqlite3.IntegrityError):
            self.service.add_investigation_note(
                incident["incident_id"],
                {"content": "This will fail.", "actor_id": "analyst"},
            )

        self.assertEqual(self.store.get_incident(incident["incident_id"]), current)
        self.assertEqual(self.store.get_audit_events(incident["incident_id"]), before_events)
        self.assertEqual(self.store.get_notes(incident["incident_id"]), [])

    def test_failed_audit_insert_during_note_rolls_back_update_and_note(self) -> None:
        incident = self.create_incident()
        self.transition(incident)
        current = self.store.get_incident(incident["incident_id"])
        connection = self.raw_connection()
        connection.execute(
            """
            CREATE TRIGGER reject_note_audit
            BEFORE INSERT ON incident_audit_events
            WHEN NEW.event_id = 'id-5'
            BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END
            """
        )
        connection.commit()
        connection.close()
        before_events = self.store.get_audit_events(incident["incident_id"])

        with self.assertRaises(sqlite3.IntegrityError):
            self.service.add_investigation_note(
                incident["incident_id"],
                {"content": "Note should roll back.", "actor_id": "analyst"},
            )

        self.assertEqual(self.store.get_incident(incident["incident_id"]), current)
        self.assertEqual(self.store.get_audit_events(incident["incident_id"]), before_events)
        self.assertEqual(self.store.get_notes(incident["incident_id"]), [])

    def test_revision_zero_and_successful_update_increment_exactly_once(self) -> None:
        incident = self.create_incident()
        updated = self.transition(incident)

        self.assertEqual(incident["revision"], 0)
        self.assertEqual(updated["revision"], 1)
        self.assertEqual(self.store.get_incident(incident["incident_id"])["revision"], 1)

    def test_stale_and_invalid_revision_updates_are_rejected(self) -> None:
        incident = self.create_incident()
        updated = copy.deepcopy(incident)
        updated["status"] = "open"
        updated["revision"] = 1
        event: IncidentAuditEvent = {
            "event_id": "stale-event",
            "incident_id": incident["incident_id"],
            "event_type": "status_transitioned",
            "actor_id": "analyst",
            "previous_status": "new",
            "new_status": "open",
            "occurred_at": incident["updated_at"] + timedelta(seconds=1),
            "details": {},
        }

        with self.assertRaisesRegex(IncidentConflictError, "stale"):
            self.store.update_incident(updated, 1, event)
        updated["revision"] = 2
        with self.assertRaisesRegex(IncidentConflictError, "increment exactly once"):
            self.store.update_incident(updated, 0, event)
        self.assertEqual(self.store.get_incident(incident["incident_id"]), incident)
        self.assertEqual(len(self.store.get_audit_events(incident["incident_id"])), 1)

    def test_concurrent_updates_from_same_revision_only_commit_once(self) -> None:
        incident = self.create_incident()
        incident_id = incident["incident_id"]
        barrier = threading.Barrier(2)
        repositories = [
            SQLiteIncidentStore(self.database_path),
            SQLiteIncidentStore(self.database_path),
        ]
        successes: list[None] = []
        failures: list[Exception] = []

        def update(repository: SQLiteIncidentStore, event_id: str) -> None:
            updated = copy.deepcopy(incident)
            updated["status"] = "open"
            updated["revision"] = 1
            event: IncidentAuditEvent = {
                "event_id": event_id,
                "incident_id": incident_id,
                "event_type": "status_transitioned",
                "actor_id": "analyst",
                "previous_status": "new",
                "new_status": "open",
                "occurred_at": _BASE_TIME + timedelta(seconds=1),
                "details": {},
            }
            try:
                with repository._connection() as connection:
                    row = connection.execute(
                        "SELECT revision FROM incidents WHERE incident_id = ?",
                        (incident_id,),
                    ).fetchone()
                    self.assertEqual(row["revision"], 0)
                barrier.wait(timeout=5)
                repository.update_incident(updated, 0, event)
                successes.append(None)
            except Exception as error:
                failures.append(error)

        threads = [
            threading.Thread(
                target=update, args=(repositories[0], "concurrent-event-a")
            ),
            threading.Thread(
                target=update, args=(repositories[1], "concurrent-event-b")
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], IncidentConflictError)
        current = self.store.get_incident(incident_id)
        self.assertEqual(current["revision"], 1)
        self.assertEqual(current["status"], "open")
        self.assertEqual(len(self.store.get_audit_events(incident_id)), 2)

    def test_duplicate_incident_audit_and_note_ids_are_rejected(self) -> None:
        incident = self.create_incident()
        with self.assertRaises(IncidentConflictError):
            self.store.create_incident(incident, self.store.get_audit_events(incident["incident_id"])[0])

        another = copy.deepcopy(incident)
        another["incident_id"] = "another"
        creation_event = copy.deepcopy(self.store.get_audit_events(incident["incident_id"])[0])
        creation_event["incident_id"] = "another"
        with self.assertRaises(IncidentConflictError):
            self.store.create_incident(another, creation_event)

        self.transition(incident)
        note = {
            "note_id": "unique-note",
            "incident_id": incident["incident_id"],
            "content": "first",
            "actor_id": "analyst",
            "created_at": _BASE_TIME + timedelta(seconds=3),
        }
        event: IncidentAuditEvent = {
            "event_id": "note-event-a",
            "incident_id": incident["incident_id"],
            "event_type": "investigation_note_added",
            "actor_id": "analyst",
            "previous_status": "open",
            "new_status": "open",
            "occurred_at": note["created_at"],
            "details": {"note_id": note["note_id"]},
        }
        current = self.store.get_incident(incident["incident_id"])
        updated = copy.deepcopy(current)
        updated["revision"] += 1
        updated["updated_at"] = note["created_at"]
        self.store.update_incident(updated, current["revision"], event, note)

        duplicate_note = copy.deepcopy(note)
        duplicate_note["content"] = "duplicate"
        duplicate_event = copy.deepcopy(event)
        duplicate_event["event_id"] = "note-event-b"
        duplicate_event["occurred_at"] += timedelta(seconds=1)
        duplicate_note["created_at"] = duplicate_event["occurred_at"]
        newer = self.store.get_incident(incident["incident_id"])
        next_update = copy.deepcopy(newer)
        next_update["revision"] += 1
        next_update["updated_at"] = duplicate_note["created_at"]
        with self.assertRaises(IncidentConflictError):
            self.store.update_incident(
                next_update,
                newer["revision"],
                duplicate_event,
                duplicate_note,
            )
        self.assertEqual(len(self.store.get_notes(incident["incident_id"])), 1)
        self.assertEqual(len(self.store.get_audit_events(incident["incident_id"])), 3)

    def test_unknown_incident_retrieval_matches_in_memory_behavior(self) -> None:
        self.assertIsNone(self.store.get_incident("unknown"))
        with self.assertRaises(IncidentNotFoundError):
            self.store.get_notes("unknown")
        with self.assertRaises(IncidentNotFoundError):
            self.store.get_audit_events("unknown")

    def test_returned_objects_cannot_mutate_persisted_state(self) -> None:
        incident = self.create_incident()
        retrieved = self.store.get_incident(incident["incident_id"])
        retrieved["triggered_rule_ids"].clear()
        retrieved["assessment_snapshot"]["rules"]["triggered_rule_ids"].clear()
        retrieved["recommendations"].clear()

        persisted = self.store.get_incident(incident["incident_id"])
        self.assertEqual(persisted["triggered_rule_ids"], ["RBD-AUTH-001"])
        self.assertEqual(
            persisted["assessment_snapshot"]["rules"]["triggered_rule_ids"],
            ["RBD-AUTH-001"],
        )
        self.assertTrue(persisted["recommendations"])

    def test_notes_and_audit_events_are_returned_chronologically(self) -> None:
        incident = self.create_incident()
        self.transition(incident)
        first = self.service.add_investigation_note(
            incident["incident_id"],
            {"content": "first", "actor_id": "analyst"},
        )
        second = self.service.add_investigation_note(
            incident["incident_id"],
            {"content": "second", "actor_id": "analyst"},
        )

        self.assertEqual(
            self.store.get_notes(incident["incident_id"]), [first, second]
        )
        events = self.store.get_audit_events(incident["incident_id"])
        self.assertEqual(
            [event["occurred_at"] for event in events],
            sorted(event["occurred_at"] for event in events),
        )

    def test_foreign_keys_are_enabled_on_repository_connections(self) -> None:
        with self.store._connection() as connection:
            enabled = connection.execute("PRAGMA foreign_keys").fetchone()[0]
        self.assertEqual(enabled, 1)


class SQLiteInMemoryIncidentRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SQLiteIncidentStore(":memory:")
        self.service = IncidentService(
            store=self.store,
            id_generator=SequenceIds(),
            utc_clock=SequenceClock(),
        )

    def tearDown(self) -> None:
        self.store.close()

    def create_incident(self) -> IncidentRecord:
        assessment = make_assessment()
        decision = determine_assessment_handling(assessment)
        return self.service.create_incident(
            cast(
                IncidentCreationInput,
                {"assessment": assessment, "decision": decision},
            ),
            actor_id="analyst-1",
        )

    def test_schema_is_available_on_separate_connections(self) -> None:
        for _ in range(2):
            connection = self.store._connect()
            try:
                tables = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertTrue(
                    {
                        "incidents",
                        "investigation_notes",
                        "incident_audit_events",
                    }.issubset(tables)
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
                )
            finally:
                connection.close()

    def test_incident_update_note_and_audit_work_across_operations(self) -> None:
        incident = self.create_incident()
        self.assertEqual(
            self.store.get_incident(incident["incident_id"]), incident
        )
        updated = self.service.transition_status(
            incident["incident_id"],
            {
                "new_status": "open",
                "actor_id": "analyst-1",
                "resolution_outcome": None,
            },
        )
        note = self.service.add_investigation_note(
            incident["incident_id"],
            {"content": "Reviewed evidence.", "actor_id": "analyst-1"},
        )

        self.assertEqual(
            self.store.get_incident(incident["incident_id"]), updated | {
                "revision": updated["revision"] + 1,
                "updated_at": note["created_at"],
            }
        )
        self.assertEqual(self.store.get_notes(incident["incident_id"]), [note])
        self.assertEqual(
            [
                event["event_type"]
                for event in self.store.get_audit_events(incident["incident_id"])
            ],
            [
                "incident_created",
                "status_transitioned",
                "investigation_note_added",
            ],
        )

    def test_independent_memory_stores_do_not_share_data(self) -> None:
        incident = self.create_incident()
        other_store = SQLiteIncidentStore(":memory:")
        try:
            self.assertIsNone(other_store.get_incident(incident["incident_id"]))
            with self.assertRaises(IncidentNotFoundError):
                other_store.get_notes(incident["incident_id"])
        finally:
            other_store.close()

    def test_close_releases_keeper_and_is_idempotent(self) -> None:
        self.assertIsNotNone(self.store._keeper_connection)

        self.store.close()
        self.store.close()

        self.assertIsNone(self.store._keeper_connection)
        with self.assertRaisesRegex(RuntimeError, "is closed"):
            self.store.get_incident("any")

    def test_concurrent_updates_from_same_memory_revision_only_commit_once(self) -> None:
        incident = self.create_incident()
        incident_id = incident["incident_id"]
        read_barrier = threading.Barrier(2)
        successes: list[None] = []
        failures: list[Exception] = []

        def update(event_id: str) -> None:
            updated = copy.deepcopy(incident)
            updated["status"] = "open"
            updated["revision"] = 1
            event: IncidentAuditEvent = {
                "event_id": event_id,
                "incident_id": incident_id,
                "event_type": "status_transitioned",
                "actor_id": "analyst",
                "previous_status": "new",
                "new_status": "open",
                "occurred_at": _BASE_TIME + timedelta(seconds=1),
                "details": {},
            }
            try:
                with self.store._connection() as connection:
                    row = connection.execute(
                        "SELECT revision FROM incidents WHERE incident_id = ?",
                        (incident_id,),
                    ).fetchone()
                    self.assertEqual(row["revision"], 0)
                read_barrier.wait(timeout=5)
                self.store.update_incident(updated, 0, event)
                successes.append(None)
            except Exception as error:
                failures.append(error)

        threads = [
            threading.Thread(target=update, args=("memory-event-a",)),
            threading.Thread(target=update, args=("memory-event-b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIs(type(failures[0]), IncidentConflictError)
        current = self.store.get_incident(incident_id)
        self.assertEqual(current["revision"], incident["revision"] + 1)
        self.assertEqual(len(self.store.get_audit_events(incident_id)), 2)


if __name__ == "__main__":
    unittest.main()
