"""Typed data contracts for per-record cognitive assessments."""

from typing import Literal, TypedDict

from app.detection.rule_engine import RuleResult

EvidenceStatus = Literal["available", "unavailable"]
ModelEvidenceStatus = EvidenceStatus
RuleEvidenceStatus = EvidenceStatus
ReconciliationResult = Literal[
    "agreement_attack",
    "agreement_no_attack_signal",
    "ml_only",
    "rules_only",
    "incomplete",
]
RiskStatus = Literal["complete", "incomplete"]
RiskLevel = Literal["low", "medium", "high", "indeterminate"]
PredictedClass = Literal[0, 1]
PredictedLabel = Literal["normal", "attack"]


class ModelEvidence(TypedDict):
    """Model output and source availability for one record."""

    status: EvidenceStatus
    predicted_class: PredictedClass | None
    predicted_label: PredictedLabel | None
    class_0_probability: float | None
    class_1_probability: float | None
    model_name: str | None
    model_version: str | None
    error_code: str | None


class RuleEvidence(TypedDict):
    """Existing rule-engine output and source availability for one record."""

    status: EvidenceStatus
    results: list[RuleResult]
    triggered_rule_ids: list[str]
    error_code: str | None


class RiskAssessment(TypedDict):
    """Risk outputs, kept distinct from model probability and source evidence."""

    status: RiskStatus
    model_attack_probability: float | None
    model_score: float | None
    rule_score: float | None
    combined_score: float | None
    level: RiskLevel
    policy_version: str | None


class ConsolidatedAssessment(TypedDict):
    """Container for the eventual per-record evidence reconciliation result."""

    model: ModelEvidence
    rules: RuleEvidence
    reconciliation: ReconciliationResult
    risk: RiskAssessment
    explanations: list[str]
