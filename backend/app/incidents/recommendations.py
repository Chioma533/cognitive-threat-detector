"""Deterministic, evidence-based response recommendation generation."""

from collections.abc import Mapping

from app.cognition.types import ConsolidatedAssessment
from app.incidents.policy import (
    IncidentPolicyInputError,
    determine_assessment_handling,
)
from app.incidents.types import (
    AssessmentHandlingDecision,
    ResponseRecommendation,
)


class RecommendationInputError(ValueError):
    """Raised when an assessment or handling decision is invalid."""


_DECISION_FIELDS = {
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
}


def _validate_decision(
    assessment: ConsolidatedAssessment,
    decision: AssessmentHandlingDecision,
) -> None:
    if not isinstance(decision, Mapping) or set(decision) != _DECISION_FIELDS:
        raise RecommendationInputError("Handling decision contract is malformed.")
    for field in (
        "create_security_incident",
        "create_assessment_review",
        "requires_operational_review",
    ):
        if type(decision.get(field)) is not bool:
            raise RecommendationInputError(
                f"Handling decision field {field} must be a boolean."
            )
    if not isinstance(decision.get("triggered_rule_ids"), list) or any(
        not isinstance(rule_id, str)
        for rule_id in decision["triggered_rule_ids"]
    ):
        raise RecommendationInputError(
            "Handling decision triggered_rule_ids must be a list of strings."
        )
    if not isinstance(decision.get("reason"), str):
        raise RecommendationInputError("Handling decision reason must be a string.")

    try:
        expected = determine_assessment_handling(assessment)
    except (IncidentPolicyInputError, KeyError, TypeError, ValueError) as error:
        raise RecommendationInputError(
            "Assessment is malformed or internally inconsistent."
        ) from error
    if dict(decision) != expected:
        raise RecommendationInputError(
            "Handling decision contradicts the supplied assessment."
        )


def _recommendation(
    action_key: str,
    description: str,
    rationale: str,
    evidence_references: list[str],
) -> ResponseRecommendation:
    return {
        "action_key": action_key,
        "description": description,
        "rationale": rationale,
        "evidence_references": evidence_references,
        "review_status": "pending",
    }


def generate_recommendations(
    assessment: ConsolidatedAssessment,
    decision: AssessmentHandlingDecision,
) -> list[ResponseRecommendation]:
    """Generate deterministic recommendations for human review only."""
    _validate_decision(assessment, decision)

    model = assessment["model"]
    rules = assessment["rules"]
    risk = assessment["risk"]
    recommendations: list[ResponseRecommendation] = []

    if decision["outcome"] == "processing_failure":
        references = ["model.status", "rules.status", "reconciliation"]
        if model["error_code"] is not None:
            references.append("model.error_code")
        if rules["error_code"] is not None:
            references.append("rules.error_code")
        recommendations.append(
            _recommendation(
                "investigate_assessment_processing_failure",
                "Investigate the assessment-processing failure.",
                (
                    "Both evidence sources were unavailable. Review their "
                    "availability and any supplied stable error codes; this is "
                    "not a security incident determination."
                ),
                references,
            )
        )
        return recommendations

    if decision["outcome"] == "security_incident":
        recommendations.append(
            _recommendation(
                "prioritised_analyst_investigation",
                "Prioritise analyst investigation of this high-risk assessment.",
                (
                    f"The complete assessment has {risk['level']} heuristic "
                    "risk under the recorded policy."
                ),
                [
                    "risk.level",
                    "risk.policy_version",
                    "reconciliation",
                ],
            )
        )
    elif decision["outcome"] == "assessment_review":
        action_key = (
            "review_incomplete_assessment"
            if risk["status"] == "incomplete"
            else "review_medium_risk_assessment"
        )
        rationale = (
            "Evidence is incomplete; review the available findings and resolve "
            "the unavailable source before drawing a complete conclusion."
            if risk["status"] == "incomplete"
            else "The complete assessment has medium heuristic risk and requires review."
        )
        recommendations.append(
            _recommendation(
                action_key,
                "Review the assessment evidence.",
                rationale,
                [
                    "risk.level",
                    "risk.policy_version",
                    "reconciliation",
                ],
            )
        )

    if risk["status"] == "incomplete":
        unavailable_references: list[str] = []
        if model["status"] == "unavailable":
            unavailable_references.append("model.status")
            if model["error_code"] is not None:
                unavailable_references.append("model.error_code")
        if rules["status"] == "unavailable":
            unavailable_references.append("rules.status")
            if rules["error_code"] is not None:
                unavailable_references.append("rules.error_code")
        recommendations.append(
            _recommendation(
                "investigate_unavailable_evidence_source",
                "Investigate the unavailable evidence source.",
                (
                    "At least one detection source was unavailable. Review the "
                    "source status and any supplied stable error code; do not "
                    "treat unavailable evidence as a negative finding."
                ),
                unavailable_references + ["reconciliation"],
            )
        )

    if assessment["reconciliation"] == "ml_only":
        recommendations.append(
            _recommendation(
                "review_ml_only_attack_signal",
                "Examine the ML prediction and attack probability.",
                (
                    "ML indicated an attack while no configured rule triggered; "
                    "the probability is evidence, not certainty."
                ),
                [
                    "model.predicted_class",
                    "model.class_1_probability",
                    "reconciliation",
                ],
            )
        )

    if rules["status"] == "available" and rules["triggered_rule_ids"]:
        recommendations.append(
            _recommendation(
                "inspect_triggered_rule_evidence",
                "Inspect the triggered rules and their observed feature checks.",
                "Review the supplied rule findings; a triggered rule is not proof of malicious activity.",
                ["rules.triggered_rule_ids", "rules.results"],
            )
        )

    return recommendations
