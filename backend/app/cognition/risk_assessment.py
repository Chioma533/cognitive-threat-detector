"""Deterministic heuristic risk assessment from model and rule evidence."""

import math
from collections.abc import Mapping
from numbers import Real

from app.cognition.types import ModelEvidence, RiskAssessment, RuleEvidence

POLICY_VERSION = "phase6-candidate-1"

_RULE_SCORES = {"low": 20.0, "medium": 55.0, "high": 85.0}
_RULE_RESULT_FIELDS = {
    "rule_id",
    "triggered",
    "severity",
    "description",
    "features_examined",
    "reason",
}
_FEATURE_CHECK_FIELDS = {
    "name",
    "observed_value",
    "operator",
    "threshold",
    "condition_met",
}


class RiskAssessmentInputError(ValueError):
    """Raised when evidence required for risk assessment is invalid."""


def _validate_status(evidence: Mapping[str, object], source: str) -> str:
    if not isinstance(evidence, Mapping):
        raise RiskAssessmentInputError(f"Invalid {source} evidence.")
    status = evidence.get("status")
    if status not in ("available", "unavailable"):
        raise RiskAssessmentInputError(f"Invalid {source} evidence status.")
    return status


def _model_score(model: Mapping[str, object]) -> tuple[float, float]:
    probability = model.get("class_1_probability")
    if isinstance(probability, bool) or not isinstance(probability, Real):
        raise RiskAssessmentInputError(
            "Available model evidence must contain a class-1 probability between 0 and 1."
        )
    try:
        normalized_probability = float(probability)
    except (OverflowError, TypeError, ValueError) as error:
        raise RiskAssessmentInputError(
            "Available model evidence must contain a class-1 probability between 0 and 1."
        ) from error
    if (
        not math.isfinite(normalized_probability)
        or not 0 <= normalized_probability <= 1
    ):
        raise RiskAssessmentInputError(
            "Available model evidence must contain a class-1 probability between 0 and 1."
        )

    predicted_class = model.get("predicted_class")
    predicted_label = model.get("predicted_label")
    if type(predicted_class) is not int or predicted_class not in (0, 1):
        raise RiskAssessmentInputError(
            "Available model evidence must contain predicted_class 0 or 1."
        )
    expected_label = "normal" if predicted_class == 0 else "attack"
    if predicted_label != expected_label:
        raise RiskAssessmentInputError(
            "Available model evidence has an inconsistent predicted_label."
        )

    score = 100.0 * normalized_probability
    return normalized_probability, score


def _validate_unavailable_model(model: Mapping[str, object]) -> None:
    prediction_fields = (
        "predicted_class",
        "predicted_label",
        "class_0_probability",
        "class_1_probability",
    )
    if any(model.get(field) is not None for field in prediction_fields):
        raise RiskAssessmentInputError(
            "Unavailable model evidence must not contain prediction values or probabilities."
        )


def _validate_feature_checks(value: object) -> None:
    if not isinstance(value, list):
        raise RiskAssessmentInputError(
            "Rule features_examined must be a list."
        )
    for check in value:
        if not isinstance(check, Mapping) or not _FEATURE_CHECK_FIELDS.issubset(check):
            raise RiskAssessmentInputError(
                "Rule features_examined contains a malformed feature check."
            )
        if not isinstance(check["name"], str) or not check["name"]:
            raise RiskAssessmentInputError(
                "Rule features_examined contains an invalid feature name."
            )
        if not isinstance(check["operator"], str) or check["operator"] not in {
            "==",
            ">",
            ">=",
        }:
            raise RiskAssessmentInputError(
                "Rule features_examined contains an invalid operator."
            )
        threshold = check["threshold"]
        if isinstance(threshold, bool) or not isinstance(threshold, Real):
            raise RiskAssessmentInputError(
                "Rule features_examined contains an invalid threshold."
            )
        try:
            finite_threshold = math.isfinite(float(threshold))
        except (OverflowError, TypeError, ValueError):
            finite_threshold = False
        if not finite_threshold:
            raise RiskAssessmentInputError(
                "Rule features_examined contains an invalid threshold."
            )
        if type(check["condition_met"]) is not bool:
            raise RiskAssessmentInputError(
                "Rule features_examined contains an invalid condition result."
            )


def _rule_results(rules: Mapping[str, object]) -> tuple[list[object], list[object]]:
    results = rules.get("results")
    triggered_rule_ids = rules.get("triggered_rule_ids")
    if not isinstance(results, list) or not isinstance(triggered_rule_ids, list):
        raise RiskAssessmentInputError(
            "Rule evidence must contain result and triggered-ID lists."
        )
    return results, triggered_rule_ids


def _rule_score(rules: Mapping[str, object]) -> float:
    results, triggered_rule_ids = _rule_results(rules)

    observed_triggered_ids: list[str] = []
    observed_rule_ids: list[str] = []
    highest_score = 0.0
    for result in results:
        if not isinstance(result, Mapping):
            raise RiskAssessmentInputError(
                "Available rule evidence contains an invalid rule result."
            )
        if not _RULE_RESULT_FIELDS.issubset(result):
            raise RiskAssessmentInputError(
                "Available rule evidence contains an incomplete rule result."
            )
        rule_id = result.get("rule_id")
        triggered = result.get("triggered")
        severity = result.get("severity")
        description = result.get("description")
        reason = result.get("reason")
        if not isinstance(rule_id, str) or not rule_id:
            raise RiskAssessmentInputError(
                "Available rule evidence contains an invalid rule ID."
            )
        if rule_id in observed_rule_ids:
            raise RiskAssessmentInputError("Rule result IDs must be unique.")
        observed_rule_ids.append(rule_id)
        if type(triggered) is not bool:
            raise RiskAssessmentInputError(
                "Available rule evidence contains an invalid trigger value."
            )
        if not isinstance(severity, str) or severity not in _RULE_SCORES:
            raise RiskAssessmentInputError(
                "Available rule evidence contains an invalid severity."
            )
        if not isinstance(description, str) or not isinstance(reason, str):
            raise RiskAssessmentInputError(
                "Rule descriptions and reasons must be strings."
            )
        _validate_feature_checks(result["features_examined"])
        if triggered:
            observed_triggered_ids.append(rule_id)
            highest_score = max(highest_score, _RULE_SCORES[severity])

    if any(not isinstance(rule_id, str) for rule_id in triggered_rule_ids):
        raise RiskAssessmentInputError("Triggered rule IDs must be strings.")
    if len(set(triggered_rule_ids)) != len(triggered_rule_ids):
        raise RiskAssessmentInputError("Triggered rule IDs must be unique.")
    if triggered_rule_ids != observed_triggered_ids:
        raise RiskAssessmentInputError(
            "Triggered rule IDs do not match the rule results."
        )
    return highest_score


def _validate_unavailable_rules(rules: Mapping[str, object]) -> None:
    results, triggered_rule_ids = _rule_results(rules)
    if results or triggered_rule_ids:
        raise RiskAssessmentInputError(
            "Unavailable rule evidence must not contain rule findings or triggered IDs."
        )


def assess_risk(
    model: ModelEvidence, rules: RuleEvidence
) -> RiskAssessment:
    """Calculate a deterministic heuristic risk assessment from source evidence."""
    model_status = _validate_status(model, "model")
    rules_status = _validate_status(rules, "rule")

    model_probability: float | None = None
    model_score: float | None = None
    rule_score: float | None = None

    if model_status == "available":
        model_probability, model_score = _model_score(model)
    else:
        _validate_unavailable_model(model)
    if rules_status == "available":
        rule_score = _rule_score(rules)
    else:
        _validate_unavailable_rules(rules)

    if model_status == "unavailable" or rules_status == "unavailable":
        return {
            "status": "incomplete",
            "model_attack_probability": model_probability,
            "model_score": model_score,
            "rule_score": rule_score,
            "combined_score": None,
            "level": "indeterminate",
            "policy_version": POLICY_VERSION,
        }

    if model_score is None or rule_score is None:
        raise RiskAssessmentInputError(
            "Available evidence did not produce the required scores."
        )

    combined_score = max(model_score, rule_score)
    if combined_score < 30:
        level = "low"
    elif combined_score < 70:
        level = "medium"
    else:
        level = "high"

    return {
        "status": "complete",
        "model_attack_probability": model_probability,
        "model_score": model_score,
        "rule_score": rule_score,
        "combined_score": combined_score,
        "level": level,
        "policy_version": POLICY_VERSION,
    }
