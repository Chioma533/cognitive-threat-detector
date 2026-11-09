"""Deterministic explanations derived from supplied assessment evidence."""

import math
import re
from collections.abc import Mapping
from numbers import Real

from app.cognition.types import (
    ModelEvidence,
    ReconciliationResult,
    RiskAssessment,
    RuleEvidence,
)

_RECONCILIATION_RESULTS = {
    "agreement_attack",
    "agreement_no_attack_signal",
    "ml_only",
    "rules_only",
    "incomplete",
}
_ERROR_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_RISK_LEVELS = {"low", "medium", "high", "indeterminate"}
_RISK_STATUSES = {"complete", "incomplete"}
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


class ExplanationInputError(ValueError):
    """Raised when supplied assessment evidence is malformed or inconsistent."""


def _require_mapping(value: object, source: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ExplanationInputError(f"{source} evidence must be a mapping.")
    return value


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ExplanationInputError(f"{field} must be a finite number.")
    try:
        numeric_value = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise ExplanationInputError(f"{field} must be a finite number.") from error
    if not math.isfinite(numeric_value):
        raise ExplanationInputError(f"{field} must be a finite number.")
    return numeric_value


def _validate_model(model: Mapping[str, object]) -> tuple[str, int | None, float | None]:
    status = model.get("status")
    if not isinstance(status, str) or status not in ("available", "unavailable"):
        raise ExplanationInputError("Invalid model evidence status.")
    error_code = model.get("error_code")
    if error_code is not None and (
        not isinstance(error_code, str)
        or _ERROR_CODE_PATTERN.fullmatch(error_code) is None
    ):
        raise ExplanationInputError("Model error_code must be a stable code or None.")
    if status == "available" and error_code is not None:
        raise ExplanationInputError("Available model evidence must not have an error_code.")
    for field in ("model_name", "model_version"):
        if model.get(field) is not None and not isinstance(model[field], str):
            raise ExplanationInputError(f"{field} must be a string or None.")

    prediction_fields = (
        "predicted_class",
        "predicted_label",
        "class_0_probability",
        "class_1_probability",
    )
    if status == "unavailable":
        if any(model.get(field) is not None for field in prediction_fields):
            raise ExplanationInputError(
                "Unavailable model evidence contains prediction values."
            )
        return status, None, None

    predicted_class = model.get("predicted_class")
    if type(predicted_class) is not int or predicted_class not in (0, 1):
        raise ExplanationInputError(
            "Available model evidence must contain predicted_class 0 or 1."
        )
    expected_label = "normal" if predicted_class == 0 else "attack"
    if model.get("predicted_label") != expected_label:
        raise ExplanationInputError("Model prediction label is inconsistent.")

    probabilities = []
    for field in ("class_0_probability", "class_1_probability"):
        probability = _finite_number(model.get(field), field)
        if not 0 <= probability <= 1:
            raise ExplanationInputError(f"{field} must be between 0 and 1.")
        probabilities.append(probability)
    if not math.isclose(sum(probabilities), 1.0, rel_tol=0.0, abs_tol=1e-6):
        raise ExplanationInputError("Model probabilities must sum approximately to 1.")
    return status, predicted_class, probabilities[1]


def _validate_feature_checks(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        raise ExplanationInputError("Rule features_examined must be a list.")
    checks: list[Mapping[str, object]] = []
    for check in value:
        if not isinstance(check, Mapping) or not _FEATURE_CHECK_FIELDS.issubset(check):
            raise ExplanationInputError("Malformed rule feature check.")
        name = check.get("name")
        operator = check.get("operator")
        if not isinstance(name, str) or not name:
            raise ExplanationInputError("Rule feature check has an invalid name.")
        if operator not in ("==", ">", ">="):
            raise ExplanationInputError("Rule feature check has an invalid operator.")
        observed = _finite_number(check.get("observed_value"), "observed_value")
        threshold = _finite_number(check.get("threshold"), "threshold")
        condition_met = check.get("condition_met")
        if type(condition_met) is not bool:
            raise ExplanationInputError("Rule feature check has an invalid condition.")
        expected = (
            observed == threshold
            if operator == "=="
            else observed > threshold
            if operator == ">"
            else observed >= threshold
        )
        if condition_met != expected:
            raise ExplanationInputError(
                "Rule feature check condition contradicts its values."
            )
        checks.append(check)
    return checks


def _validate_rules(
    rules: Mapping[str, object],
) -> tuple[str, list[Mapping[str, object]], list[Mapping[str, object]]]:
    status = rules.get("status")
    if not isinstance(status, str) or status not in ("available", "unavailable"):
        raise ExplanationInputError("Invalid rule evidence status.")
    error_code = rules.get("error_code")
    if error_code is not None and (
        not isinstance(error_code, str)
        or _ERROR_CODE_PATTERN.fullmatch(error_code) is None
    ):
        raise ExplanationInputError("Rule error_code must be a stable code or None.")
    if status == "available" and error_code is not None:
        raise ExplanationInputError("Available rule evidence must not have an error_code.")
    results = rules.get("results")
    triggered_ids = rules.get("triggered_rule_ids")
    if not isinstance(results, list) or not isinstance(triggered_ids, list):
        raise ExplanationInputError("Rule evidence lists are malformed.")
    if any(not isinstance(rule_id, str) for rule_id in triggered_ids):
        raise ExplanationInputError("Triggered rule IDs must be strings.")
    if len(set(triggered_ids)) != len(triggered_ids):
        raise ExplanationInputError("Triggered rule IDs must be unique.")

    if status == "unavailable":
        if results or triggered_ids:
            raise ExplanationInputError(
                "Unavailable rule evidence contains rule findings."
            )
        return status, [], []

    parsed_results: list[Mapping[str, object]] = []
    result_ids: list[str] = []
    observed_triggered_ids: list[str] = []
    for result in results:
        if not isinstance(result, Mapping) or not _RULE_RESULT_FIELDS.issubset(result):
            raise ExplanationInputError("Malformed rule result.")
        rule_id = result.get("rule_id")
        triggered = result.get("triggered")
        severity = result.get("severity")
        if not isinstance(rule_id, str) or not rule_id:
            raise ExplanationInputError("Rule result has an invalid ID.")
        if rule_id in result_ids:
            raise ExplanationInputError("Rule result IDs must be unique.")
        result_ids.append(rule_id)
        if type(triggered) is not bool:
            raise ExplanationInputError("Rule result has an invalid trigger value.")
        if not isinstance(severity, str) or severity not in _RULE_SCORES:
            raise ExplanationInputError("Rule result has an invalid severity.")
        if not isinstance(result.get("description"), str) or not isinstance(
            result.get("reason"), str
        ):
            raise ExplanationInputError("Rule descriptions and reasons must be strings.")
        checks = _validate_feature_checks(result.get("features_examined"))
        if triggered and not checks:
            raise ExplanationInputError(
                "A triggered rule result must include feature checks."
            )
        if triggered:
            observed_triggered_ids.append(rule_id)
            parsed_results.append(result)

    if triggered_ids != observed_triggered_ids:
        raise ExplanationInputError(
            "Triggered rule IDs do not match the rule results."
        )
    return status, parsed_results, results


def _validate_risk(
    risk: Mapping[str, object],
    model_status: str,
    model_probability: float | None,
    rules_status: str,
    triggered_results: list[Mapping[str, object]],
) -> None:
    status = risk.get("status")
    level = risk.get("level")
    if not isinstance(status, str) or status not in _RISK_STATUSES:
        raise ExplanationInputError("Invalid risk status.")
    if not isinstance(level, str) or level not in _RISK_LEVELS:
        raise ExplanationInputError("Invalid risk level.")
    policy_version = risk.get("policy_version")
    if not isinstance(policy_version, str) or not policy_version:
        raise ExplanationInputError("Risk policy_version must be a non-empty string.")

    model_score: float | None = None
    if model_status == "available":
        if model_probability is None:
            raise ExplanationInputError("Available model probability is missing.")
        model_score = model_probability * 100
    rule_score: float | None = None
    if rules_status == "available":
        rule_score = max(
            (_RULE_SCORES[result["severity"]] for result in triggered_results),
            default=0.0,
        )

    expected_incomplete = model_status == "unavailable" or rules_status == "unavailable"
    if expected_incomplete:
        if status != "incomplete" or level != "indeterminate":
            raise ExplanationInputError(
                "Unavailable evidence requires incomplete, indeterminate risk."
            )
        if risk.get("combined_score") is not None:
            raise ExplanationInputError(
                "Incomplete risk must not contain a combined score."
            )
    else:
        if status != "complete":
            raise ExplanationInputError(
                "Available evidence requires a complete risk assessment."
            )
        combined = max(model_score or 0.0, rule_score or 0.0)
        expected_level = "low" if combined < 30 else "medium" if combined < 70 else "high"
        if level != expected_level:
            raise ExplanationInputError("Risk level contradicts the supplied evidence.")
        supplied_combined = _finite_number(risk.get("combined_score"), "combined_score")
        if not math.isclose(supplied_combined, combined, rel_tol=0.0, abs_tol=1e-6):
            raise ExplanationInputError("Combined risk score contradicts the evidence.")

    for field, expected in (
        ("model_attack_probability", model_probability),
        ("model_score", model_score),
        ("rule_score", rule_score),
    ):
        value = risk.get(field)
        if expected is None:
            if value is not None:
                raise ExplanationInputError(
                    f"{field} must be unavailable when its evidence source is unavailable."
                )
        else:
            numeric_value = _finite_number(value, field)
            if not math.isclose(numeric_value, expected, rel_tol=0.0, abs_tol=1e-6):
                raise ExplanationInputError(f"{field} contradicts the supplied evidence.")


def _format_value(value: object) -> str:
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def generate_explanations(
    model: ModelEvidence,
    rules: RuleEvidence,
    reconciliation: ReconciliationResult,
    risk: RiskAssessment,
) -> list[str]:
    """Generate evidence-grounded explanations in stable source order."""
    model_data = _require_mapping(model, "Model")
    rules_data = _require_mapping(rules, "Rule")
    risk_data = _require_mapping(risk, "Risk")

    model_status, predicted_class, model_probability = _validate_model(model_data)
    rules_status, triggered_results, _ = _validate_rules(rules_data)
    if (
        not isinstance(reconciliation, str)
        or reconciliation not in _RECONCILIATION_RESULTS
    ):
        raise ExplanationInputError("Invalid reconciliation result.")
    if (
        reconciliation == "incomplete"
    ) != (model_status == "unavailable" or rules_status == "unavailable"):
        raise ExplanationInputError(
            "Reconciliation result contradicts evidence availability."
        )
    if model_status == "available" and rules_status == "available":
        has_triggered_rules = bool(triggered_results)
        expected_reconciliation = (
            "agreement_attack"
            if predicted_class == 1 and has_triggered_rules
            else "ml_only"
            if predicted_class == 1
            else "rules_only"
            if has_triggered_rules
            else "agreement_no_attack_signal"
        )
        if reconciliation != expected_reconciliation:
            raise ExplanationInputError(
                "Reconciliation result contradicts the evidence."
            )
    _validate_risk(
        risk_data,
        model_status,
        model_probability,
        rules_status,
        triggered_results,
    )

    explanations: list[str] = []
    if model_status == "available":
        predicted_label = "normal" if predicted_class == 0 else "attack"
        probability_text = f"{model_probability * 100:.2f}%"
        model_name = model_data.get("model_name")
        model_version = model_data.get("model_version")
        metadata = (
            f" ({model_name} version {model_version})"
            if model_name and model_version
            else f" ({model_name})"
            if model_name
            else f" (version {model_version})"
            if model_version
            else ""
        )
        explanations.append(
            f"ML predicted {predicted_label} (class {predicted_class}); "
            f"class-1 attack probability: {probability_text}{metadata}. "
            "This probability is not certainty."
        )
    else:
        error_code = model_data.get("error_code")
        suffix = f" Error code: {error_code}." if isinstance(error_code, str) else ""
        explanations.append(f"ML assessment could not be completed.{suffix}")

    if rules_status == "unavailable":
        error_code = rules_data.get("error_code")
        suffix = f" Error code: {error_code}." if isinstance(error_code, str) else ""
        explanations.append(f"Rule-based assessment could not be completed.{suffix}")
    elif not triggered_results:
        explanations.append("No configured rule was triggered for this record.")
    else:
        for result in triggered_results:
            checks = result["features_examined"]
            check_descriptions = [
                f"{check['name']} observed {_format_value(check['observed_value'])} "
                f"{check['operator']} {_format_value(check['threshold'])}: "
                f"{'met' if check['condition_met'] else 'not met'}"
                for check in checks
            ]
            check_summary = (
                "; ".join(check_descriptions)
                if check_descriptions
                else "no feature checks were supplied"
            )
            explanations.append(
                f"Rule {result['rule_id']} triggered: {result['description']} "
                f"Checks: {check_summary}. {result['reason']}"
            )

    reconciliation_text = {
        "agreement_attack": "ML and rule-based detection both indicated an attack.",
        "agreement_no_attack_signal": (
            "Neither source indicated an attack signal for this record; "
            "this does not confirm that the record is benign."
        ),
        "ml_only": "ML indicated an attack, but no configured rule triggered.",
        "rules_only": (
            "One or more rules triggered, but ML classified the record as normal."
        ),
        "incomplete": (
            "At least one evidence source was unavailable, so a complete "
            "comparison could not be made."
        ),
    }
    explanations.append(reconciliation_text[reconciliation])

    risk_status = risk_data["status"]
    risk_level = risk_data["level"]
    if risk_status == "incomplete":
        risk_text = (
            "Overall risk classification could not be established because "
            "evidence was incomplete; risk is indeterminate."
        )
        for field, label in (
            ("model_score", "ML score"),
            ("rule_score", "rule score"),
        ):
            score = risk_data[field]
            if score is not None:
                risk_text += f" Available {label}: {_format_value(score)}."
    else:
        risk_text = f"Overall heuristic risk level: {risk_level}."
        for field, label in (
            ("model_score", "ML score"),
            ("rule_score", "rule score"),
            ("combined_score", "combined score"),
        ):
            score = risk_data[field]
            if score is not None:
                risk_text += f" {label}: {_format_value(score)}."
    risk_text += (
        f" Policy version: {risk_data['policy_version']}. "
        "Scores are heuristic triage indices, not calibrated probabilities."
    )
    explanations.append(risk_text)
    return explanations
