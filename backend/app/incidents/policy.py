"""Pure assessment validation and incident-triage policy."""

from collections.abc import Mapping

from app.cognition.explanation import ExplanationInputError, generate_explanations
from app.cognition.reconciliation import (
    EvidenceReconciliationError,
    reconcile_evidence,
)
from app.cognition.types import ConsolidatedAssessment
from app.incidents.types import AssessmentHandlingDecision

_ASSESSMENT_FIELDS = {
    "model",
    "rules",
    "reconciliation",
    "risk",
    "explanations",
}
_MODEL_FIELDS = {
    "status",
    "predicted_class",
    "predicted_label",
    "class_0_probability",
    "class_1_probability",
    "model_name",
    "model_version",
    "error_code",
}
_RULE_FIELDS = {"status", "results", "triggered_rule_ids", "error_code"}
_RISK_FIELDS = {
    "status",
    "model_attack_probability",
    "model_score",
    "rule_score",
    "combined_score",
    "level",
    "policy_version",
}


class IncidentPolicyInputError(ValueError):
    """Raised when an assessment is malformed or internally inconsistent."""


def _require_contract_fields(
    value: object, fields: set[str], contract_name: str
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise IncidentPolicyInputError(
            f"Assessment contains an invalid {contract_name} contract."
        )
    return value


def _validate_assessment(
    assessment: ConsolidatedAssessment,
) -> tuple[str, str, str, list[str], bool]:
    assessment_data = _require_contract_fields(
        assessment, _ASSESSMENT_FIELDS, "consolidated assessment"
    )
    model = _require_contract_fields(
        assessment_data["model"], _MODEL_FIELDS, "model evidence"
    )
    rules = _require_contract_fields(
        assessment_data["rules"], _RULE_FIELDS, "rule evidence"
    )
    risk = _require_contract_fields(
        assessment_data["risk"], _RISK_FIELDS, "risk assessment"
    )
    explanations = assessment_data["explanations"]
    if not isinstance(explanations, list) or any(
        not isinstance(item, str) for item in explanations
    ):
        raise IncidentPolicyInputError(
            "Assessment explanations must be a list of strings."
        )

    try:
        expected_reconciliation = reconcile_evidence(model, rules)  # type: ignore[arg-type]
        if assessment_data["reconciliation"] != expected_reconciliation:
            raise IncidentPolicyInputError(
                "Assessment reconciliation contradicts its evidence."
            )
        expected_explanations = generate_explanations(
            model,  # type: ignore[arg-type]
            rules,  # type: ignore[arg-type]
            expected_reconciliation,
            risk,  # type: ignore[arg-type]
        )
        if explanations != expected_explanations:
            raise IncidentPolicyInputError(
                "Assessment explanations contradict its evidence."
            )
    except IncidentPolicyInputError:
        raise
    except (ExplanationInputError, EvidenceReconciliationError, KeyError, TypeError, ValueError) as error:
        raise IncidentPolicyInputError(
            "Assessment evidence or risk fields are malformed or inconsistent."
        ) from error

    model_status = model["status"]
    rule_status = rules["status"]
    risk_status = risk["status"]
    risk_level = risk["level"]
    triggered_ids = rules["triggered_rule_ids"]
    if (
        not isinstance(model_status, str)
        or not isinstance(rule_status, str)
        or not isinstance(risk_status, str)
        or not isinstance(risk_level, str)
        or not isinstance(triggered_ids, list)
    ):
        raise IncidentPolicyInputError("Assessment contains malformed triage fields.")

    attack_signal = (
        model_status == "available" and model.get("predicted_class") == 1
    ) or (rule_status == "available" and bool(triggered_ids))
    return model_status, rule_status, risk_status, triggered_ids, attack_signal


def determine_assessment_handling(
    assessment: ConsolidatedAssessment,
) -> AssessmentHandlingDecision:
    """Validate an assessment and return its deterministic triage decision."""
    model_status, rule_status, risk_status, triggered_ids, attack_signal = (
        _validate_assessment(assessment)
    )
    risk_level = assessment["risk"]["level"]
    reconciliation = assessment["reconciliation"]

    common = {
        "risk_level": risk_level,
        "reconciliation": reconciliation,
        "model_status": model_status,
        "rule_status": rule_status,
        "triggered_rule_ids": list(triggered_ids),
    }

    if model_status == "unavailable" and rule_status == "unavailable":
        return {
            "outcome": "processing_failure",
            "create_security_incident": False,
            "create_assessment_review": False,
            "requires_operational_review": True,
            "category": None,
            "severity": "indeterminate",
            "initial_status": None,
            "reason": (
                "Both evidence sources were unavailable; operational review is "
                "required and no security incident is inferred."
            ),
            **common,
        }

    if risk_status == "incomplete":
        return {
            "outcome": "assessment_review",
            "create_security_incident": False,
            "create_assessment_review": True,
            "requires_operational_review": False,
            "category": "assessment_review",
            "severity": risk_level,
            "initial_status": "new",
            "reason": (
                "Evidence is incomplete; assessment review is required. "
                + (
                    "Available evidence indicates an attack signal."
                    if attack_signal
                    else "No attack signal is present in the available evidence, "
                    "but the unavailable source prevents a complete assessment."
                )
            ),
            **common,
        }

    if risk_level == "high":
        return {
            "outcome": "security_incident",
            "create_security_incident": True,
            "create_assessment_review": False,
            "requires_operational_review": False,
            "category": "security_incident",
            "severity": "high",
            "initial_status": "new",
            "reason": "Complete assessment has high heuristic risk.",
            **common,
        }
    if risk_level == "medium":
        return {
            "outcome": "assessment_review",
            "create_security_incident": False,
            "create_assessment_review": True,
            "requires_operational_review": False,
            "category": "assessment_review",
            "severity": "medium",
            "initial_status": "new",
            "reason": "Complete assessment has medium heuristic risk.",
            **common,
        }
    return {
        "outcome": "no_action",
        "create_security_incident": False,
        "create_assessment_review": False,
        "requires_operational_review": False,
        "category": None,
        "severity": "low",
        "initial_status": None,
        "reason": (
            "Complete assessment has low heuristic risk; no incident or review "
            "item is required by the current triage policy."
        ),
        **common,
    }
