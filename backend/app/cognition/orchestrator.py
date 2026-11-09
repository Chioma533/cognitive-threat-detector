"""Coordinate per-record model, rule, and cognitive assessment components."""

from collections.abc import Callable, Mapping
from typing import Protocol

from app.cognition.explanation import generate_explanations
from app.cognition.reconciliation import reconcile_evidence
from app.cognition.risk_assessment import assess_risk
from app.cognition.types import (
    ConsolidatedAssessment,
    ModelEvidence,
    RuleEvidence,
)
from app.detection.input_validation import (
    FeatureRecordValidationError,
    validate_feature_record,
)
from app.detection.model_service import (
    INFERENCE_ERROR,
    MODEL_UNAVAILABLE,
    ModelInferenceService,
)
from app.detection.rule_engine import (
    RuleResult,
    evaluate_rules,
)


class AssessmentInputValidationError(FeatureRecordValidationError):
    """Raised when an assessment record fails canonical feature validation."""


class ModelPredictor(Protocol):
    def predict(self, record: Mapping[str, object]) -> ModelEvidence:
        """Return model evidence for one validated record."""


RuleEvaluator = Callable[[Mapping[str, object]], list[RuleResult]]


def _unavailable_model(error_code: str) -> ModelEvidence:
    return {
        "status": "unavailable",
        "predicted_class": None,
        "predicted_label": None,
        "class_0_probability": None,
        "class_1_probability": None,
        "model_name": None,
        "model_version": None,
        "error_code": error_code,
    }


def _unavailable_rules() -> RuleEvidence:
    return {
        "status": "unavailable",
        "results": [],
        "triggered_rule_ids": [],
        "error_code": "RULE_EVALUATION_ERROR",
    }


class AssessmentOrchestrator:
    """Produce a consolidated cognitive assessment for one feature record."""

    def __init__(
        self,
        model_service: ModelPredictor | None = None,
        rule_evaluator: RuleEvaluator = evaluate_rules,
    ) -> None:
        self._rule_evaluator = rule_evaluator
        if model_service is not None:
            self._model_service: ModelPredictor | None = model_service
        else:
            try:
                self._model_service = ModelInferenceService()
            except Exception:
                self._model_service = None

    def assess(
        self, record: Mapping[str, object]
    ) -> ConsolidatedAssessment:
        """Validate and assess one record without mutating the caller's mapping."""
        if not isinstance(record, Mapping):
            raise AssessmentInputValidationError(
                "Record must be a mapping of feature names to values."
            )
        snapshot = dict(record)
        validate_feature_record(
            snapshot, error_type=AssessmentInputValidationError
        )

        model = self._run_model(snapshot)
        rules = self._run_rules(snapshot)
        reconciliation = reconcile_evidence(model, rules)
        risk = assess_risk(model, rules)
        explanations = generate_explanations(
            model, rules, reconciliation, risk
        )
        return {
            "model": model,
            "rules": rules,
            "reconciliation": reconciliation,
            "risk": risk,
            "explanations": explanations,
        }

    def _run_model(self, record: Mapping[str, object]) -> ModelEvidence:
        if self._model_service is None:
            return _unavailable_model(MODEL_UNAVAILABLE)
        try:
            return self._model_service.predict(record)
        except Exception:
            return _unavailable_model(INFERENCE_ERROR)

    def _run_rules(self, record: Mapping[str, object]) -> RuleEvidence:
        try:
            results = self._rule_evaluator(record)
            return {
                "status": "available",
                "results": results,
                "triggered_rule_ids": [
                    result["rule_id"] for result in results if result["triggered"]
                ],
                "error_code": None,
            }
        except Exception:
            return _unavailable_rules()
