"""Deterministic reconciliation of model and rule evidence."""

from collections.abc import Mapping

from app.cognition.types import (
    ModelEvidence,
    ReconciliationResult,
    RuleEvidence,
)


class EvidenceReconciliationError(ValueError):
    """Raised when available evidence is invalid or internally inconsistent."""


def reconcile_evidence(
    model: ModelEvidence, rules: RuleEvidence
) -> ReconciliationResult:
    """Compare available model and rule signals for one record."""
    model_status = model.get("status")
    rules_status = rules.get("status")
    if model_status not in ("available", "unavailable"):
        raise EvidenceReconciliationError("Invalid model evidence status.")
    if rules_status not in ("available", "unavailable"):
        raise EvidenceReconciliationError("Invalid rule evidence status.")

    if model_status == "unavailable" or rules_status == "unavailable":
        return "incomplete"

    predicted_class = model.get("predicted_class")
    predicted_label = model.get("predicted_label")
    if type(predicted_class) is not int or predicted_class not in (0, 1):
        raise EvidenceReconciliationError(
            "Available model evidence must contain predicted_class 0 or 1."
        )
    expected_label = "normal" if predicted_class == 0 else "attack"
    if predicted_label != expected_label:
        raise EvidenceReconciliationError(
            "Available model evidence has an inconsistent predicted_label."
        )

    results = rules.get("results")
    triggered_rule_ids = rules.get("triggered_rule_ids")
    if not isinstance(results, list) or not isinstance(triggered_rule_ids, list):
        raise EvidenceReconciliationError(
            "Available rule evidence must contain results and triggered_rule_ids lists."
        )

    result_triggered_ids: list[str] = []
    for result in results:
        if not isinstance(result, Mapping):
            raise EvidenceReconciliationError(
                "Available rule evidence contains an invalid rule result."
            )
        rule_id = result.get("rule_id")
        triggered = result.get("triggered")
        if not isinstance(rule_id, str) or type(triggered) is not bool:
            raise EvidenceReconciliationError(
                "Available rule evidence contains an invalid rule result."
            )
        if triggered:
            result_triggered_ids.append(rule_id)

    if any(not isinstance(rule_id, str) for rule_id in triggered_rule_ids):
        raise EvidenceReconciliationError(
            "Triggered rule IDs must be strings."
        )
    if triggered_rule_ids != result_triggered_ids:
        raise EvidenceReconciliationError(
            "Triggered rule IDs do not match the rule results."
        )

    rules_triggered = bool(result_triggered_ids)
    if predicted_class == 1:
        return "agreement_attack" if rules_triggered else "ml_only"
    return "rules_only" if rules_triggered else "agreement_no_attack_signal"
