"""Framework-independent incident lifecycle and audit service."""

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Protocol
from uuid import uuid4

from app.cognition.types import ConsolidatedAssessment
from app.incidents.policy import (
    IncidentPolicyInputError,
    determine_assessment_handling,
)
from app.incidents.recommendations import (
    RecommendationInputError,
    generate_recommendations,
)
from app.incidents.types import (
    AssessmentHandlingDecision,
    IncidentAuditEvent,
    IncidentAuditEventType,
    IncidentCreationInput,
    IncidentRecord,
    IncidentStatus,
    InvestigationNote,
    InvestigationNoteInput,
    ResponseRecommendation,
    StatusTransitionInput,
)

_VALID_TRANSITIONS: dict[IncidentStatus, IncidentStatus] = {
    "new": "open",
    "open": "under_investigation",
    "under_investigation": "resolved",
    "resolved": "closed",
}


class IncidentServiceError(ValueError):
    """Base error for invalid incident service operations."""


class IncidentNotFoundError(IncidentServiceError):
    """Raised when an operation references an unknown incident."""


class IncidentConflictError(IncidentServiceError):
    """Raised when an incident ID already exists or an operation conflicts."""


class IncidentStore(Protocol):
    """Atomic storage boundary for incident state, notes, and audit events."""

    def create_incident(
        self, incident: IncidentRecord, event: IncidentAuditEvent
    ) -> None:
        """Atomically store a new incident and its creation event."""

    def update_incident(
        self,
        incident: IncidentRecord,
        expected_revision: int,
        event: IncidentAuditEvent,
        note: InvestigationNote | None = None,
    ) -> None:
        """Atomically compare-and-update incident state and append its records."""

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Return a defensive copy of an incident, if it exists."""

    def get_notes(self, incident_id: str) -> list[InvestigationNote]:
        """Return defensive copies of notes for an incident."""

    def get_audit_events(self, incident_id: str) -> list[IncidentAuditEvent]:
        """Return defensive copies of the append-only audit history."""


class InMemoryIncidentStore:
    """Thread-safe in-memory store implementing the atomic incident boundary."""

    def __init__(self) -> None:
        self._incidents: dict[str, IncidentRecord] = {}
        self._notes: dict[str, list[InvestigationNote]] = {}
        self._events: dict[str, list[IncidentAuditEvent]] = {}
        self._lock = RLock()

    def create_incident(
        self, incident: IncidentRecord, event: IncidentAuditEvent
    ) -> None:
        with self._lock:
            incident_id = incident["incident_id"]
            if type(incident["revision"]) is not int or incident["revision"] != 0:
                raise IncidentConflictError(
                    "New incidents must start at revision zero."
                )
            if incident_id in self._incidents:
                raise IncidentConflictError("Incident ID already exists.")
            if any(
                existing_event["event_id"] == event["event_id"]
                for event_list in self._events.values()
                for existing_event in event_list
            ):
                raise IncidentConflictError("Audit event ID already exists.")
            incident_copy = deepcopy(incident)
            event_copy = deepcopy(event)
            self._incidents[incident_id] = incident_copy
            self._notes[incident_id] = []
            self._events[incident_id] = [event_copy]

    def update_incident(
        self,
        incident: IncidentRecord,
        expected_revision: int,
        event: IncidentAuditEvent,
        note: InvestigationNote | None = None,
    ) -> None:
        with self._lock:
            incident_id = incident["incident_id"]
            if incident_id not in self._incidents:
                raise IncidentNotFoundError("Incident does not exist.")
            if (
                type(expected_revision) is not int
                or expected_revision < 0
                or type(self._incidents[incident_id]["revision"]) is not int
                or self._incidents[incident_id]["revision"] != expected_revision
            ):
                raise IncidentConflictError("Incident update is stale.")
            if (
                type(incident["revision"]) is not int
                or incident["revision"] != expected_revision + 1
            ):
                raise IncidentConflictError(
                    "Updated incident revision must increment exactly once."
                )
            if any(
                existing_event["event_id"] == event["event_id"]
                for event_list in self._events.values()
                for existing_event in event_list
            ):
                raise IncidentConflictError("Audit event ID already exists.")
            if note is not None and any(
                existing_note["note_id"] == note["note_id"]
                for note_list in self._notes.values()
                for existing_note in note_list
            ):
                raise IncidentConflictError("Investigation note ID already exists.")
            incident_copy = deepcopy(incident)
            event_copy = deepcopy(event)
            notes_copy = list(self._notes[incident_id])
            events_copy = list(self._events[incident_id])
            if note is not None:
                notes_copy.append(deepcopy(note))
            events_copy.append(event_copy)
            self._incidents[incident_id] = incident_copy
            self._notes[incident_id] = notes_copy
            self._events[incident_id] = events_copy

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        with self._lock:
            incident = self._incidents.get(incident_id)
            return deepcopy(incident) if incident is not None else None

    def get_notes(self, incident_id: str) -> list[InvestigationNote]:
        with self._lock:
            if incident_id not in self._incidents:
                raise IncidentNotFoundError("Incident does not exist.")
            return deepcopy(self._notes[incident_id])

    def get_audit_events(self, incident_id: str) -> list[IncidentAuditEvent]:
        with self._lock:
            if incident_id not in self._incidents:
                raise IncidentNotFoundError("Incident does not exist.")
            return deepcopy(self._events[incident_id])


def _validate_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IncidentServiceError(f"{field} must be a non-empty string.")
    return value


def _validate_utc_timestamp(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise IncidentServiceError("Clock must return a timezone-aware UTC datetime.")
    return value


class IncidentService:
    """Manage incident records, lifecycle transitions, notes, and audit events."""

    def __init__(
        self,
        store: IncidentStore | None = None,
        id_generator: Callable[[], str] | None = None,
        utc_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store if store is not None else InMemoryIncidentStore()
        self._id_generator = id_generator if id_generator is not None else lambda: str(uuid4())
        self._utc_clock = (
            utc_clock
            if utc_clock is not None
            else lambda: datetime.now(timezone.utc)
        )

    def create_incident(
        self,
        creation: IncidentCreationInput,
        actor_id: str | None = None,
    ) -> IncidentRecord:
        """Create an eligible incident or assessment-review record."""
        if not isinstance(creation, Mapping) or set(creation) != {
            "assessment",
            "decision",
        }:
            raise IncidentServiceError("Incident creation input is malformed.")
        if actor_id is not None:
            actor_id = _validate_identifier(actor_id, "actor_id")

        assessment = creation["assessment"]
        decision = creation["decision"]
        try:
            expected_decision = determine_assessment_handling(assessment)
            recommendations = generate_recommendations(assessment, decision)
        except (
            IncidentPolicyInputError,
            RecommendationInputError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise IncidentServiceError(
                "Assessment or handling decision is invalid."
            ) from error
        if dict(decision) != expected_decision:
            raise IncidentServiceError(
                "Handling decision contradicts the supplied assessment."
            )
        if decision["outcome"] not in ("security_incident", "assessment_review"):
            raise IncidentServiceError(
                "Assessment is not eligible for incident or review creation."
            )
        if decision["category"] is None or decision["severity"] is None:
            raise IncidentServiceError(
                "Eligible handling decision requires category and severity."
            )
        if decision["initial_status"] != "new":
            raise IncidentServiceError(
                "Eligible handling decision must start at status 'new'."
            )

        incident_id = _validate_identifier(
            self._id_generator(), "generated incident ID"
        )
        event_id = _validate_identifier(
            self._id_generator(), "generated audit event ID"
        )
        if event_id == incident_id:
            raise IncidentServiceError("Generated IDs must be unique.")
        timestamp = _validate_utc_timestamp(self._utc_clock())
        assessment_snapshot = deepcopy(assessment)
        incident: IncidentRecord = {
            "incident_id": incident_id,
            "revision": 0,
            "category": decision["category"],
            "severity": decision["severity"],
            "status": "new",
            "original_handling_outcome": decision["outcome"],
            "original_risk_level": assessment_snapshot["risk"]["level"],
            "reconciliation": assessment_snapshot["reconciliation"],
            "triggered_rule_ids": list(
                assessment_snapshot["rules"]["triggered_rule_ids"]
            ),
            "recommendations": deepcopy(recommendations),
            "assessment_snapshot": assessment_snapshot,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        event: IncidentAuditEvent = {
            "event_id": event_id,
            "incident_id": incident_id,
            "event_type": "incident_created",
            "actor_id": actor_id,
            "previous_status": None,
            "new_status": "new",
            "occurred_at": timestamp,
            "details": {
                "handling_outcome": decision["outcome"],
                "risk_level": assessment_snapshot["risk"]["level"],
                "reconciliation": assessment_snapshot["reconciliation"],
                "triggered_rule_ids": list(
                    assessment_snapshot["rules"]["triggered_rule_ids"]
                ),
            },
        }
        self._store.create_incident(incident, event)
        return deepcopy(incident)

    def transition_status(
        self,
        incident_id: str,
        transition: StatusTransitionInput,
    ) -> IncidentRecord:
        """Perform the next permitted lifecycle transition."""
        incident_id = _validate_identifier(incident_id, "incident_id")
        if not isinstance(transition, Mapping) or set(transition) != {
            "new_status",
            "actor_id",
            "resolution_outcome",
        }:
            raise IncidentServiceError("Status transition input is malformed.")
        actor_id = _validate_identifier(transition["actor_id"], "actor_id")
        new_status = transition["new_status"]
        if new_status not in (
            "new",
            "open",
            "under_investigation",
            "resolved",
            "closed",
        ):
            raise IncidentServiceError("Invalid incident status.")
        resolution_outcome = transition["resolution_outcome"]
        if new_status == "resolved":
            resolution_outcome = _validate_identifier(
                resolution_outcome, "resolution_outcome"
            )
        elif resolution_outcome is not None:
            raise IncidentServiceError(
                "resolution_outcome is only valid when resolving an incident."
            )

        incident = self._get_existing_incident(incident_id)
        expected_status = _VALID_TRANSITIONS.get(incident["status"])
        if expected_status is None:
            raise IncidentServiceError("Closed incidents cannot be reopened.")
        if new_status != expected_status:
            raise IncidentServiceError(
                f"Invalid status transition from {incident['status']} to {new_status}."
            )
        timestamp = _validate_utc_timestamp(self._utc_clock())
        if timestamp < incident["updated_at"]:
            raise IncidentServiceError(
                "Operation timestamp cannot precede the incident's last update."
            )

        updated = deepcopy(incident)
        previous_status = updated["status"]
        updated["status"] = new_status
        expected_revision = updated["revision"]
        updated["revision"] = expected_revision + 1
        updated["updated_at"] = timestamp
        event_id = _validate_identifier(
            self._id_generator(), "generated audit event ID"
        )
        event_type: IncidentAuditEventType = (
            "incident_resolved"
            if new_status == "resolved"
            else "incident_closed"
            if new_status == "closed"
            else "status_transitioned"
        )
        event: IncidentAuditEvent = {
            "event_id": event_id,
            "incident_id": incident_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "previous_status": previous_status,
            "new_status": new_status,
            "occurred_at": timestamp,
            "details": {
                "resolution_outcome": (
                    resolution_outcome
                    if isinstance(resolution_outcome, str)
                    else None
                )
            },
        }
        self._store.update_incident(updated, expected_revision, event)
        return deepcopy(updated)

    def add_investigation_note(
        self,
        incident_id: str,
        note_input: InvestigationNoteInput,
    ) -> InvestigationNote:
        """Append a non-empty, attributed investigation note."""
        incident_id = _validate_identifier(incident_id, "incident_id")
        if not isinstance(note_input, Mapping) or set(note_input) != {
            "content",
            "actor_id",
        }:
            raise IncidentServiceError("Investigation note input is malformed.")
        content = _validate_identifier(note_input["content"], "content")
        actor_id = _validate_identifier(note_input["actor_id"], "actor_id")
        incident = self._get_existing_incident(incident_id)
        if incident["status"] == "closed":
            raise IncidentServiceError("Cannot add a note to a closed incident.")
        timestamp = _validate_utc_timestamp(self._utc_clock())
        if timestamp < incident["updated_at"]:
            raise IncidentServiceError(
                "Operation timestamp cannot precede the incident's last update."
            )
        note_id = _validate_identifier(
            self._id_generator(), "generated note ID"
        )
        event_id = _validate_identifier(
            self._id_generator(), "generated audit event ID"
        )
        if event_id == note_id:
            raise IncidentServiceError("Generated IDs must be unique.")
        note: InvestigationNote = {
            "note_id": note_id,
            "incident_id": incident_id,
            "content": content,
            "actor_id": actor_id,
            "created_at": timestamp,
        }
        event: IncidentAuditEvent = {
            "event_id": event_id,
            "incident_id": incident_id,
            "event_type": "investigation_note_added",
            "actor_id": actor_id,
            "previous_status": incident["status"],
            "new_status": incident["status"],
            "occurred_at": timestamp,
            "details": {"note_id": note_id},
        }
        updated = deepcopy(incident)
        expected_revision = updated["revision"]
        updated["revision"] = expected_revision + 1
        updated["updated_at"] = timestamp
        self._store.update_incident(updated, expected_revision, event, note)
        return deepcopy(note)

    def get_incident(self, incident_id: str) -> IncidentRecord:
        return self._get_existing_incident(incident_id)

    def list_investigation_notes(
        self, incident_id: str
    ) -> list[InvestigationNote]:
        incident_id = _validate_identifier(incident_id, "incident_id")
        return self._store.get_notes(incident_id)

    def list_audit_events(self, incident_id: str) -> list[IncidentAuditEvent]:
        incident_id = _validate_identifier(incident_id, "incident_id")
        return self._store.get_audit_events(incident_id)

    def _get_existing_incident(self, incident_id: str) -> IncidentRecord:
        incident = self._store.get_incident(incident_id)
        if incident is None:
            raise IncidentNotFoundError("Incident does not exist.")
        return incident
