"""Typed contracts for assessment triage and incident handling."""

from datetime import datetime
from typing import Literal, TypedDict

from app.cognition.types import (
    ConsolidatedAssessment,
    EvidenceStatus,
    ReconciliationResult,
    RiskLevel,
)

IncidentCategory = Literal["security_incident", "assessment_review"]
IncidentSeverity = Literal["low", "medium", "high", "indeterminate"]
IncidentStatus = Literal[
    "new",
    "open",
    "under_investigation",
    "resolved",
    "closed",
]
AssessmentTriageOutcome = Literal[
    "security_incident",
    "assessment_review",
    "no_action",
    "processing_failure",
]
RecommendationReviewStatus = Literal["pending"]


class AssessmentHandlingDecision(TypedDict):
    """Deterministic triage decision derived from a consolidated assessment."""

    outcome: AssessmentTriageOutcome
    create_security_incident: bool
    create_assessment_review: bool
    requires_operational_review: bool
    category: IncidentCategory | None
    severity: IncidentSeverity | None
    initial_status: IncidentStatus | None
    reason: str
    risk_level: RiskLevel
    reconciliation: ReconciliationResult
    model_status: EvidenceStatus
    rule_status: EvidenceStatus
    triggered_rule_ids: list[str]


class ResponseRecommendation(TypedDict):
    """Human-reviewed, evidence-linked response proposal."""

    action_key: str
    description: str
    rationale: str
    evidence_references: list[str]
    review_status: RecommendationReviewStatus


IncidentAuditEventType = Literal[
    "incident_created",
    "status_transitioned",
    "incident_resolved",
    "incident_closed",
    "investigation_note_added",
]


class IncidentCreationInput(TypedDict):
    """Validated assessment and handling decision supplied for incident creation."""

    assessment: ConsolidatedAssessment
    decision: AssessmentHandlingDecision


class StatusTransitionInput(TypedDict):
    """Requested lifecycle transition and its audit context."""

    new_status: IncidentStatus
    actor_id: str
    resolution_outcome: str | None


class InvestigationNoteInput(TypedDict):
    """Investigation note content and attributed actor."""

    content: str
    actor_id: str


class InvestigationNote(TypedDict):
    """Immutable investigation note recorded against an incident."""

    note_id: str
    incident_id: str
    content: str
    actor_id: str
    created_at: datetime


class IncidentAuditEvent(TypedDict):
    """Append-only audit entry for a successful incident operation."""

    event_id: str
    incident_id: str
    event_type: IncidentAuditEventType
    actor_id: str | None
    previous_status: IncidentStatus | None
    new_status: IncidentStatus
    occurred_at: datetime
    details: dict[str, str | list[str] | None]


class IncidentRecord(TypedDict):
    """Incident plus immutable assessment evidence snapshot and lifecycle state."""

    incident_id: str
    revision: int
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    original_handling_outcome: AssessmentTriageOutcome
    original_risk_level: RiskLevel
    reconciliation: ReconciliationResult
    triggered_rule_ids: list[str]
    recommendations: list[ResponseRecommendation]
    assessment_snapshot: ConsolidatedAssessment
    created_at: datetime
    updated_at: datetime
