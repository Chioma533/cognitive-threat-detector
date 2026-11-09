import copy
import unittest
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
from app.incidents.policy import (
    IncidentPolicyInputError,
    determine_assessment_handling,
)


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 1,
    probability: float | None = 0.8,
) -> ModelEvidence:
    if status == "unavailable":
        predicted_class = None
        predicted_label = None
        probability = None
        class_0_probability = None
        error_code = "MODEL_UNAVAILABLE"
    else:
        predicted_label = "normal" if predicted_class == 0 else "attack"
        class_0_probability = None if probability is None else 1 - probability
        error_code = None
    return cast(
        ModelEvidence,
        {
            "status": status,
            "predicted_class": predicted_class,
            "predicted_label": predicted_label,
            "class_0_probability": class_0_probability,
            "class_1_probability": probability,
            "model_name": "test-model" if status == "available" else None,
            "model_version": "test-version" if status == "available" else None,
            "error_code": error_code,
        },
    )


def make_rule(*, severity: str = "high", triggered: bool = True) -> RuleResult:
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
            "triggered": triggered,
            "severity": severity,
            "description": "Failed login evidence",
            "features_examined": [check],
            "reason": "One or more failed login attempts were recorded.",
        },
    )


def make_rules(
    *,
    status: str = "available",
    results: list[RuleResult] | None = None,
) -> RuleEvidence:
    if status == "unavailable":
        return {
            "status": status,
            "results": [],
            "triggered_rule_ids": [],
            "error_code": "RULES_UNAVAILABLE",
        }
    actual_results = [] if results is None else results
    return {
        "status": status,
        "results": actual_results,
        "triggered_rule_ids": [
            result["rule_id"] for result in actual_results if result["triggered"]
        ],
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
    explanations = generate_explanations(
        actual_model, actual_rules, reconciliation, risk
    )
    return {
        "model": actual_model,
        "rules": actual_rules,
        "reconciliation": reconciliation,
        "risk": risk,
        "explanations": explanations,
    }


class IncidentPolicyTests(unittest.TestCase):
    def test_complete_high_risk_qualifies_for_security_incident(self) -> None:
        assessment = make_assessment(
            model=make_model(predicted_class=1, probability=0.8),
            rules=make_rules(),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "security_incident")
        self.assertTrue(decision["create_security_incident"])
        self.assertFalse(decision["create_assessment_review"])
        self.assertEqual(decision["category"], "security_incident")
        self.assertEqual(decision["severity"], "high")
        self.assertEqual(decision["initial_status"], "new")
        self.assertEqual(decision["risk_level"], "high")
        self.assertEqual(decision["reconciliation"], "ml_only")

    def test_complete_medium_risk_qualifies_for_assessment_review(self) -> None:
        assessment = make_assessment(
            model=make_model(predicted_class=1, probability=0.55),
            rules=make_rules(),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "assessment_review")
        self.assertFalse(decision["create_security_incident"])
        self.assertTrue(decision["create_assessment_review"])
        self.assertEqual(decision["severity"], "medium")

    def test_complete_low_risk_requires_no_incident_or_review(self) -> None:
        assessment = make_assessment(
            model=make_model(predicted_class=0, probability=0.1),
            rules=make_rules(),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "no_action")
        self.assertFalse(decision["create_security_incident"])
        self.assertFalse(decision["create_assessment_review"])
        self.assertFalse(decision["requires_operational_review"])
        self.assertEqual(decision["severity"], "low")

    def test_incomplete_assessment_with_ml_attack_signal_requires_review(self) -> None:
        assessment = make_assessment(
            model=make_model(predicted_class=1, probability=0.8),
            rules=make_rules(status="unavailable"),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "assessment_review")
        self.assertTrue(decision["create_assessment_review"])
        self.assertFalse(decision["create_security_incident"])
        self.assertEqual(decision["risk_level"], "indeterminate")
        self.assertIn("attack signal", decision["reason"])

    def test_incomplete_assessment_with_triggered_rule_requires_review(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(results=[make_rule(severity="high")]),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "assessment_review")
        self.assertTrue(decision["create_assessment_review"])
        self.assertFalse(decision["create_security_incident"])
        self.assertEqual(decision["triggered_rule_ids"], ["RBD-AUTH-001"])

    def test_incomplete_without_available_signal_still_requires_review(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "assessment_review")
        self.assertTrue(decision["create_assessment_review"])
        self.assertFalse(decision["create_security_incident"])
        self.assertIn("prevents a complete assessment", decision["reason"])

    def test_both_sources_unavailable_require_operational_review(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(status="unavailable"),
        )

        decision = determine_assessment_handling(assessment)

        self.assertEqual(decision["outcome"], "processing_failure")
        self.assertTrue(decision["requires_operational_review"])
        self.assertFalse(decision["create_security_incident"])
        self.assertFalse(decision["create_assessment_review"])
        self.assertEqual(decision["severity"], "indeterminate")
        self.assertEqual(decision["reconciliation"], "incomplete")

    def test_malformed_and_contradictory_assessments_are_rejected(self) -> None:
        valid = make_assessment()
        missing_field = copy.deepcopy(valid)
        del missing_field["explanations"]

        contradictory_reconciliation = copy.deepcopy(valid)
        contradictory_reconciliation["reconciliation"] = "rules_only"

        contradictory_risk = copy.deepcopy(valid)
        contradictory_risk["risk"]["level"] = "low"

        malformed_explanation = copy.deepcopy(valid)
        malformed_explanation["explanations"] = [42]  # type: ignore[list-item]

        for assessment in (
            missing_field,
            contradictory_reconciliation,
            contradictory_risk,
            malformed_explanation,
        ):
            with self.subTest(assessment=assessment):
                with self.assertRaises(IncidentPolicyInputError):
                    determine_assessment_handling(assessment)

    def test_decision_is_deterministic_and_does_not_mutate_assessment(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(results=[make_rule(severity="medium")]),
        )
        original = copy.deepcopy(assessment)

        first = determine_assessment_handling(assessment)
        second = determine_assessment_handling(assessment)

        self.assertEqual(first, second)
        self.assertEqual(assessment, original)
        self.assertEqual(
            set(first),
            {
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
            },
        )


if __name__ == "__main__":
    unittest.main()
