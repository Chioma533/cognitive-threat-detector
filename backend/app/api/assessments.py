"""Assessment-only API endpoint."""

from collections.abc import Mapping
from typing import Protocol

from flask import Blueprint, current_app, jsonify, request
from werkzeug.exceptions import BadRequest, UnsupportedMediaType

from app.cognition.types import ConsolidatedAssessment
from app.detection.input_validation import FeatureRecordValidationError
from app.incidents.policy import determine_assessment_handling
from app.incidents.recommendations import generate_recommendations
from app.incidents.types import AssessmentHandlingDecision, ResponseRecommendation
from ml.schema import FEATURE_NAMES

assessments_blueprint = Blueprint("assessments", __name__)

_MODEL_FIELDS = (
    "status",
    "predicted_class",
    "predicted_label",
    "class_0_probability",
    "class_1_probability",
    "model_name",
    "model_version",
    "error_code",
)
_RULE_FIELDS = ("status", "results", "triggered_rule_ids", "error_code")
_RISK_FIELDS = (
    "status",
    "model_attack_probability",
    "model_score",
    "rule_score",
    "combined_score",
    "level",
    "policy_version",
)
_DECISION_FIELDS = (
    "outcome",
    "create_security_incident",
    "create_assessment_review",
    "requires_operational_review",
    "category",
    "severity",
    "initial_status",
    "reason",
    "risk_level",
    "reconciliation",
    "model_status",
    "rule_status",
    "triggered_rule_ids",
)
_RECOMMENDATION_FIELDS = (
    "action_key",
    "description",
    "rationale",
    "evidence_references",
    "review_status",
)


class AssessmentRunner(Protocol):
    def assess(self, record: Mapping[str, object]) -> ConsolidatedAssessment:
        """Return the consolidated assessment for one feature record."""


def _error_response(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def _serialize_assessment(
    assessment: ConsolidatedAssessment,
) -> dict[str, object]:
    return {
        "model": {field: assessment["model"][field] for field in _MODEL_FIELDS},
        "rules": {field: assessment["rules"][field] for field in _RULE_FIELDS},
        "reconciliation": assessment["reconciliation"],
        "risk": {field: assessment["risk"][field] for field in _RISK_FIELDS},
        "explanations": list(assessment["explanations"]),
    }


def _serialize_decision(
    decision: AssessmentHandlingDecision,
) -> dict[str, object]:
    return {field: decision[field] for field in _DECISION_FIELDS}


def _serialize_recommendation(
    recommendation: ResponseRecommendation,
) -> dict[str, object]:
    return {
        field: recommendation[field] for field in _RECOMMENDATION_FIELDS
    }


@assessments_blueprint.post("/api/v1/assessments")
def assess_record():
    try:
        record = request.get_json()
    except (BadRequest, UnsupportedMediaType):
        return _error_response(
            "INVALID_JSON", "Request body must contain valid JSON.", 400
        )

    if not isinstance(record, dict):
        return _error_response(
            "INVALID_REQUEST", "Request body must be a feature object.", 400
        )
    expected_fields = set(FEATURE_NAMES)
    supplied_fields = set(record)
    if supplied_fields != expected_fields:
        return _error_response(
            "INVALID_REQUEST",
            "Request must contain exactly the canonical feature fields.",
            400,
        )

    orchestrator: AssessmentRunner = current_app.extensions[
        "assessment_orchestrator"
    ]
    try:
        assessment = orchestrator.assess(record)
        decision = determine_assessment_handling(assessment)
        recommendations = generate_recommendations(assessment, decision)
        response = {
            "assessment": _serialize_assessment(assessment),
            "handling_decision": _serialize_decision(decision),
            "recommendations": [
                _serialize_recommendation(item) for item in recommendations
            ],
        }
    except FeatureRecordValidationError as error:
        return _error_response("INVALID_FEATURES", str(error), 400)
    except Exception:
        current_app.logger.exception("Assessment request processing failed.")
        return _error_response(
            "ASSESSMENT_PROCESSING_ERROR",
            "Assessment could not be processed.",
            500,
        )

    return jsonify(response), 200
