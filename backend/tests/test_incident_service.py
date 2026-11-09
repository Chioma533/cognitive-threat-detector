import copy
import threading
import unittest
from datetime import datetime, timedelta, timezone
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
    InMemoryIncidentStore,
    IncidentService,
    IncidentServiceError,
)
from app.incidents.types import (
    IncidentAuditEvent,
    IncidentCreationInput,
    IncidentRecord,
    InvestigationNote,
)


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 1,
    probability: float | None = 0.8,
) -> ModelEvidence:
    if status == "unavailable":
        return {
            "status": "unavailable",
            "predicted_class": None,
            "predicted_label": None,
            "class_0_probability": None,
            "class_1_probability": None,
            "model_name": None,
            "model_version": None,
            "error_code": "MODEL_UNAVAILABLE",
        }
    return cast(
        ModelEvidence,
        {
            "status": "available",
            "predicted_class": predicted_class,
            "predicted_label": "normal" if predicted_class == 0 else "attack",
            "class_0_probability": None if probability is None else 1 - probability,
            "class_1_probability": probability,
            "model_name": "test-model",
            "model_version": "1.0",
            "error_code": None,
        },
    )


def make_rule() -> RuleResult:
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
    return cast(
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


def make_rules() -> RuleEvidence:
    return {
        "status": "available",
        "results": [make_rule()],
        "triggered_rule_ids": ["RBD-AUTH-001"],
        "error_code": None,
    }


def make_assessment(
    *,
    model: ModelEvidence | None = None,
    rules: RuleEvidence | None = None,
) -> ConsolidatedAssessment:
    actual_model = model or make_model()
    actual_rules = rules or make_rules()
    reconciliation = reconcile_evidence(actual_model, actual_rules)
    risk = assess_risk(actual_model, actual_rules)
    return {
        "model": actual_model,
        "rules": actual_rules,
        "reconciliation": reconciliation,
        "risk": risk,
        "explanations": generate_explanations(
            actual_model, actual_rules, reconciliation, risk
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
        self.value = datetime(2026, 11, 4, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(seconds=1)
        return result


class SynchronizedReadStore(InMemoryIncidentStore):
    def __init__(self) -> None:
        super().__init__()
        self.read_barrier = threading.Barrier(2)
        self.synchronize_reads = False

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        incident = super().get_incident(incident_id)
        if self.synchronize_reads and incident is not None:
            self.read_barrier.wait(timeout=5)
        return incident


def make_service(
    *,
    ids: SequenceIds | None = None,
    clock: SequenceClock | None = None,
) -> IncidentService:
    return IncidentService(
        id_generator=ids or SequenceIds(),
        utc_clock=clock or SequenceClock(),
    )


def create_high_incident(service: IncidentService) -> dict[str, object]:
    assessment = make_assessment()
    decision = determine_assessment_handling(assessment)
    return service.create_incident(
        cast(IncidentCreationInput, {"assessment": assessment, "decision": decision}),
        actor_id="analyst-1",
    )


class IncidentServiceTests(unittest.TestCase):
    def test_successful_incident_creation_preserves_assessment_and_audits(self) -> None:
        service = make_service()
        assessment = make_assessment()
        original_assessment = copy.deepcopy(assessment)
        decision = determine_assessment_handling(assessment)

        incident = service.create_incident(
            cast(IncidentCreationInput, {"assessment": assessment, "decision": decision}),
            actor_id="analyst-1",
        )
        events = service.list_audit_events(incident["incident_id"])

        self.assertEqual(incident["incident_id"], "id-1")
        self.assertEqual(incident["category"], "security_incident")
        self.assertEqual(incident["severity"], "high")
        self.assertEqual(incident["status"], "new")
        self.assertEqual(incident["revision"], 0)
        self.assertEqual(incident["original_handling_outcome"], "security_incident")
        self.assertEqual(incident["original_risk_level"], "high")
        self.assertEqual(incident["reconciliation"], assessment["reconciliation"])
        self.assertEqual(incident["triggered_rule_ids"], ["RBD-AUTH-001"])
        self.assertEqual(incident["assessment_snapshot"], original_assessment)
        self.assertEqual(incident["created_at"], incident["updated_at"])
        self.assertEqual(assessment, original_assessment)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "incident_created")
        self.assertEqual(events[0]["actor_id"], "analyst-1")
        self.assertEqual(events[0]["previous_status"], None)
        self.assertEqual(events[0]["new_status"], "new")

    def test_assessment_review_can_be_created_with_existing_recommendations(self) -> None:
        service = make_service()
        assessment = make_assessment(
            model=make_model(predicted_class=1, probability=0.55),
            rules={
                "status": "available",
                "results": [],
                "triggered_rule_ids": [],
                "error_code": None,
            },
        )
        decision = determine_assessment_handling(assessment)

        incident = service.create_incident(
            cast(IncidentCreationInput, {"assessment": assessment, "decision": decision})
        )

        self.assertEqual(incident["category"], "assessment_review")
        self.assertEqual(incident["original_handling_outcome"], "assessment_review")
        self.assertTrue(incident["recommendations"])

    def test_no_action_and_processing_failure_are_not_incident_eligible(self) -> None:
        low_assessment = make_assessment(
            model=make_model(predicted_class=0, probability=0.1),
            rules={
                "status": "available",
                "results": [],
                "triggered_rule_ids": [],
                "error_code": None,
            },
        )
        processing_failure = make_assessment(
            model=make_model(status="unavailable"),
            rules={
                "status": "unavailable",
                "results": [],
                "triggered_rule_ids": [],
                "error_code": "RULE_EVALUATION_ERROR",
            },
        )

        for assessment in (low_assessment, processing_failure):
            decision = determine_assessment_handling(assessment)
            with self.subTest(outcome=decision["outcome"]):
                service = make_service()
                with self.assertRaises(IncidentServiceError):
                    service.create_incident(
                        cast(
                            IncidentCreationInput,
                            {"assessment": assessment, "decision": decision},
                        )
                    )

    def test_valid_transitions_and_audit_event_types(self) -> None:
        service = make_service()
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])

        opened = service.transition_status(
            incident_id,
            {
                "new_status": "open",
                "actor_id": "analyst-1",
                "resolution_outcome": None,
            },
        )
        investigating = service.transition_status(
            incident_id,
            {
                "new_status": "under_investigation",
                "actor_id": "analyst-2",
                "resolution_outcome": None,
            },
        )
        resolved = service.transition_status(
            incident_id,
            {
                "new_status": "resolved",
                "actor_id": "analyst-2",
                "resolution_outcome": "investigation_complete",
            },
        )
        closed = service.transition_status(
            incident_id,
            {
                "new_status": "closed",
                "actor_id": "analyst-1",
                "resolution_outcome": None,
            },
        )
        events = service.list_audit_events(incident_id)

        self.assertEqual(opened["status"], "open")
        self.assertEqual(investigating["status"], "under_investigation")
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(
            [
                incident["revision"],
                opened["revision"],
                investigating["revision"],
                resolved["revision"],
                closed["revision"],
            ],
            [0, 1, 2, 3, 4],
        )
        self.assertEqual(
            [event["event_type"] for event in events],
            [
                "incident_created",
                "status_transitioned",
                "status_transitioned",
                "incident_resolved",
                "incident_closed",
            ],
        )
        self.assertEqual(
            [(event["previous_status"], event["new_status"]) for event in events[1:]],
            [
                ("new", "open"),
                ("open", "under_investigation"),
                ("under_investigation", "resolved"),
                ("resolved", "closed"),
            ],
        )
        self.assertEqual(
            events[3]["details"]["resolution_outcome"],
            "investigation_complete",
        )

    def test_invalid_skipped_backward_and_closed_reopen_transitions_are_rejected(self) -> None:
        service = make_service()
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        before = service.get_incident(incident_id)

        for new_status in ("under_investigation", "closed", "new"):
            with self.subTest(new_status=new_status):
                with self.assertRaises(IncidentServiceError):
                    service.transition_status(
                        incident_id,
                        {
                            "new_status": new_status,
                            "actor_id": "analyst",
                            "resolution_outcome": None,
                        },
                    )
        self.assertEqual(service.get_incident(incident_id), before)
        self.assertEqual(len(service.list_audit_events(incident_id)), 1)

        service.transition_status(
            incident_id,
            {"new_status": "open", "actor_id": "analyst", "resolution_outcome": None},
        )
        service.transition_status(
            incident_id,
            {
                "new_status": "under_investigation",
                "actor_id": "analyst",
                "resolution_outcome": None,
            },
        )
        service.transition_status(
            incident_id,
            {
                "new_status": "resolved",
                "actor_id": "analyst",
                "resolution_outcome": "done",
            },
        )
        service.transition_status(
            incident_id,
            {"new_status": "closed", "actor_id": "analyst", "resolution_outcome": None},
        )
        with self.assertRaisesRegex(IncidentServiceError, "cannot be reopened"):
            service.transition_status(
                incident_id,
                {"new_status": "open", "actor_id": "analyst", "resolution_outcome": None},
            )

    def test_resolution_requires_nonempty_outcome(self) -> None:
        service = make_service()
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        for new_status, outcome in (("resolved", None), ("resolved", "  ")):
            with self.subTest(outcome=outcome):
                with self.assertRaises(IncidentServiceError):
                    service.transition_status(
                        incident_id,
                        {
                            "new_status": new_status,
                            "actor_id": "analyst",
                            "resolution_outcome": outcome,
                        },
                    )
        self.assertEqual(service.get_incident(incident_id)["status"], "new")

    def test_investigation_note_and_audit_are_created_together(self) -> None:
        service = make_service()
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        service.transition_status(
            incident_id,
            {"new_status": "open", "actor_id": "analyst", "resolution_outcome": None},
        )

        note = service.add_investigation_note(
            incident_id,
            {"content": "Reviewed rule evidence.", "actor_id": "analyst"},
        )
        notes = service.list_investigation_notes(incident_id)
        events = service.list_audit_events(incident_id)

        self.assertEqual(note["note_id"], "id-4")
        self.assertEqual(note["actor_id"], "analyst")
        self.assertEqual(notes, [note])
        self.assertEqual(events[-1]["event_type"], "investigation_note_added")
        self.assertEqual(events[-1]["details"], {"note_id": note["note_id"]})
        self.assertEqual(note["created_at"], events[-1]["occurred_at"])
        self.assertEqual(service.get_incident(incident_id)["revision"], 2)

    def test_note_validation_and_unknown_incident_leave_state_unchanged(self) -> None:
        service = make_service()
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        original = service.get_incident(incident_id)
        for content, actor in (("", "analyst"), ("  ", "analyst"), ("note", "")):
            with self.subTest(content=content, actor=actor):
                with self.assertRaises(IncidentServiceError):
                    service.add_investigation_note(
                        incident_id, {"content": content, "actor_id": actor}
                    )
        with self.assertRaises(IncidentNotFoundError):
            service.add_investigation_note(
                "missing", {"content": "note", "actor_id": "analyst"}
            )
        self.assertEqual(service.get_incident(incident_id), original)
        self.assertEqual(service.list_investigation_notes(incident_id), [])
        self.assertEqual(len(service.list_audit_events(incident_id)), 1)

    def test_input_snapshots_and_returned_records_cannot_mutate_stored_state(self) -> None:
        service = make_service()
        assessment = make_assessment()
        decision = determine_assessment_handling(assessment)
        creation = cast(
            IncidentCreationInput,
            {"assessment": assessment, "decision": decision},
        )
        original = copy.deepcopy(creation)
        incident = service.create_incident(creation)
        incident["triggered_rule_ids"].clear()
        incident["assessment_snapshot"]["rules"]["triggered_rule_ids"].clear()

        stored = service.get_incident("id-1")
        self.assertEqual(creation, original)
        self.assertEqual(stored["triggered_rule_ids"], ["RBD-AUTH-001"])
        self.assertEqual(
            stored["assessment_snapshot"]["rules"]["triggered_rule_ids"],
            ["RBD-AUTH-001"],
        )

    def test_audit_order_and_timestamps_are_utc_and_non_decreasing(self) -> None:
        service = make_service()
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        service.transition_status(
            incident_id,
            {"new_status": "open", "actor_id": "analyst", "resolution_outcome": None},
        )
        service.add_investigation_note(
            incident_id,
            {"content": "Review complete.", "actor_id": "analyst"},
        )
        events = service.list_audit_events(incident_id)

        timestamps = [event["occurred_at"] for event in events]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertTrue(all(timestamp.utcoffset() == timedelta(0) for timestamp in timestamps))
        self.assertEqual(
            service.get_incident(incident_id)["updated_at"], timestamps[-1]
        )

    def test_invalid_clock_or_backwards_time_does_not_partially_update(self) -> None:
        values = iter(
            [
                datetime(2026, 11, 4, tzinfo=timezone.utc),
                datetime(2026, 11, 3, tzinfo=timezone.utc),
            ]
        )
        service = IncidentService(
            id_generator=SequenceIds(),
            utc_clock=lambda: next(values),
        )
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        with self.assertRaisesRegex(IncidentServiceError, "cannot precede"):
            service.transition_status(
                incident_id,
                {"new_status": "open", "actor_id": "analyst", "resolution_outcome": None},
            )
        self.assertEqual(service.get_incident(incident_id), incident)
        self.assertEqual(len(service.list_audit_events(incident_id)), 1)

    def test_duplicate_generated_ids_do_not_partially_create_incident(self) -> None:
        service = IncidentService(
            id_generator=lambda: "same-id",
            utc_clock=SequenceClock(),
        )
        assessment = make_assessment()
        decision = determine_assessment_handling(assessment)
        with self.assertRaisesRegex(IncidentServiceError, "unique"):
            service.create_incident(
                cast(
                    IncidentCreationInput,
                    {"assessment": assessment, "decision": decision},
                )
            )
        with self.assertRaises(IncidentNotFoundError):
            service.get_incident("same-id")

    def test_stale_store_update_is_rejected_without_writing_audit_or_note(self) -> None:
        store = InMemoryIncidentStore()
        service = make_service()
        service._store = store
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        stale_update = copy.deepcopy(incident)
        stale_update["status"] = "open"
        stale_update["revision"] = 2
        stale_event: IncidentAuditEvent = {
            "event_id": "stale-event",
            "incident_id": incident_id,
            "event_type": "status_transitioned",
            "actor_id": "analyst",
            "previous_status": "new",
            "new_status": "open",
            "occurred_at": incident["updated_at"] + timedelta(seconds=1),
            "details": {},
        }
        stale_note: InvestigationNote = {
            "note_id": "stale-note",
            "incident_id": incident_id,
            "content": "stale",
            "actor_id": "analyst",
            "created_at": stale_event["occurred_at"],
        }

        with self.assertRaisesRegex(IncidentConflictError, "stale"):
            store.update_incident(
                stale_update, 1, stale_event, stale_note
            )

        self.assertEqual(store.get_incident(incident_id), incident)
        self.assertEqual(store.get_notes(incident_id), [])
        self.assertEqual(len(store.get_audit_events(incident_id)), 1)

    def test_store_rejects_non_single_revision_increment(self) -> None:
        store = InMemoryIncidentStore()
        service = make_service()
        service._store = store
        incident = create_high_incident(service)
        invalid_update = copy.deepcopy(incident)
        invalid_update["revision"] = 3
        event: IncidentAuditEvent = {
            "event_id": "bad-revision-event",
            "incident_id": incident["incident_id"],
            "event_type": "status_transitioned",
            "actor_id": "analyst",
            "previous_status": "new",
            "new_status": "open",
            "occurred_at": incident["updated_at"],
            "details": {},
        }

        with self.assertRaisesRegex(IncidentConflictError, "increment exactly once"):
            store.update_incident(invalid_update, 0, event)
        self.assertEqual(store.get_incident(incident["incident_id"]), incident)
        self.assertEqual(len(store.get_audit_events(incident["incident_id"])), 1)

    def test_concurrent_same_revision_transitions_allow_only_one_commit(self) -> None:
        store = SynchronizedReadStore()
        service = IncidentService(
            store=store,
            id_generator=SequenceIds(),
            utc_clock=SequenceClock(),
        )
        incident = create_high_incident(service)
        incident_id = str(incident["incident_id"])
        store.synchronize_reads = True
        successes: list[dict[str, object]] = []
        failures: list[Exception] = []

        def transition() -> None:
            try:
                successes.append(
                    service.transition_status(
                        incident_id,
                        {
                            "new_status": "open",
                            "actor_id": "analyst",
                            "resolution_outcome": None,
                        },
                    )
                )
            except Exception as error:
                failures.append(error)

        threads = [threading.Thread(target=transition) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        store.synchronize_reads = False
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], IncidentConflictError)
        current = service.get_incident(incident_id)
        self.assertEqual(current["status"], "open")
        self.assertEqual(current["revision"], 1)
        self.assertEqual(len(service.list_audit_events(incident_id)), 2)
        self.assertEqual(service.list_investigation_notes(incident_id), [])

    def test_audit_id_conflict_does_not_partially_apply_transition(self) -> None:
        generated_ids = iter(["incident-id", "creation-event", "creation-event"])
        clock = SequenceClock()
        service = IncidentService(
            id_generator=lambda: next(generated_ids),
            utc_clock=clock,
        )
        incident = create_high_incident(service)

        with self.assertRaises(IncidentConflictError):
            service.transition_status(
                str(incident["incident_id"]),
                {
                    "new_status": "open",
                    "actor_id": "analyst",
                    "resolution_outcome": None,
                },
            )

        self.assertEqual(service.get_incident("incident-id"), incident)
        self.assertEqual(len(service.list_audit_events("incident-id")), 1)

    def test_non_utc_or_naive_clock_is_rejected_without_creation(self) -> None:
        assessment = make_assessment()
        decision = determine_assessment_handling(assessment)
        service = IncidentService(
            id_generator=SequenceIds(),
            utc_clock=lambda: datetime(2026, 11, 4),
        )

        with self.assertRaisesRegex(IncidentServiceError, "UTC datetime"):
            service.create_incident(
                cast(
                    IncidentCreationInput,
                    {"assessment": assessment, "decision": decision},
                )
            )
        with self.assertRaises(IncidentNotFoundError):
            service.get_incident("id-1")


if __name__ == "__main__":
    unittest.main()
