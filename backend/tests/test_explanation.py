import copy
import unittest
from typing import cast

from app.cognition.explanation import (
    ExplanationInputError,
    generate_explanations,
)
from app.cognition.types import (
    ModelEvidence,
    ReconciliationResult,
    RiskAssessment,
    RuleEvidence,
)
from app.detection.rule_engine import FeatureCheck, RuleResult


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 1,
    predicted_label: str | None = "attack",
    class_1_probability: float | None = 0.8,
    model_name: str | None = "sample-model",
    model_version: str | None = "1.0",
) -> ModelEvidence:
    return cast(
        ModelEvidence,
        {
            "status": status,
            "predicted_class": predicted_class,
            "predicted_label": predicted_label,
            "class_0_probability": (
                None if class_1_probability is None else 1 - class_1_probability
            ),
            "class_1_probability": class_1_probability,
            "model_name": model_name,
            "model_version": model_version,
            "error_code": None if status == "available" else "MODEL_UNAVAILABLE",
        },
    )


def make_check(
    *,
    name: str = "count",
    observed_value: int = 256,
    operator: str = ">=",
    threshold: int = 256,
    condition_met: bool = True,
) -> FeatureCheck:
    return cast(
        FeatureCheck,
        {
            "name": name,
            "observed_value": observed_value,
            "operator": operator,
            "threshold": threshold,
            "condition_met": condition_met,
        },
    )


def make_rule(
    rule_id: str,
    *,
    triggered: bool,
    severity: str = "high",
    checks: list[FeatureCheck] | None = None,
    description: str | None = None,
    reason: str | None = None,
) -> RuleResult:
    return {
        "rule_id": rule_id,
        "triggered": triggered,
        "severity": cast(str, severity),
        "description": description or f"{rule_id} description",
        "features_examined": checks if checks is not None else [make_check()],
        "reason": reason or f"{rule_id} reason",
    }


def make_rules(
    *,
    status: str = "available",
    triggered_rules: list[RuleResult] | None = None,
) -> RuleEvidence:
    results = triggered_rules if triggered_rules is not None else []
    return cast(
        RuleEvidence,
        {
            "status": status,
            "results": results,
            "triggered_rule_ids": [
                result["rule_id"] for result in results if result["triggered"]
            ],
            "error_code": None if status == "available" else "RULES_UNAVAILABLE",
        },
    )


def make_risk(
    *,
    status: str = "complete",
    level: str = "high",
    model_probability: float | None = 0.8,
    model_score: float | None = 80.0,
    rule_score: float | None = 85.0,
    combined_score: float | None = 85.0,
) -> RiskAssessment:
    return cast(
        RiskAssessment,
        {
            "status": status,
            "model_attack_probability": model_probability,
            "model_score": model_score,
            "rule_score": rule_score,
            "combined_score": combined_score,
            "level": level,
            "policy_version": "phase6-candidate-1",
        },
    )


def generate(
    model: ModelEvidence,
    rules: RuleEvidence,
    reconciliation: str,
    risk: RiskAssessment,
) -> list[str]:
    return generate_explanations(
        model,
        rules,
        cast(ReconciliationResult, reconciliation),
        risk,
    )


class ExplanationTests(unittest.TestCase):
    def test_available_ml_explanation_formats_probability_and_metadata(self) -> None:
        explanations = generate(
            make_model(),
            make_rules(),
            "ml_only",
            make_risk(rule_score=0, combined_score=80),
        )

        self.assertIn("ML predicted attack (class 1)", explanations[0])
        self.assertIn("80.00%", explanations[0])
        self.assertIn("sample-model version 1.0", explanations[0])
        self.assertIn("not certainty", explanations[0])

    def test_available_ml_evidence_rejects_error_code(self) -> None:
        model = make_model()
        model["error_code"] = "MODEL_ERROR"

        with self.assertRaisesRegex(ExplanationInputError, "must not have an error_code"):
            generate(model, make_rules(), "ml_only", make_risk(rule_score=0, combined_score=80))

    def test_unavailable_ml_evidence_includes_stable_error_code(self) -> None:
        explanations = generate(
            make_model(
                status="unavailable",
                predicted_class=None,
                predicted_label=None,
                class_1_probability=None,
            ),
            make_rules(),
            "incomplete",
            make_risk(
                status="incomplete",
                level="indeterminate",
                model_probability=None,
                model_score=None,
                rule_score=0,
                combined_score=None,
            ),
        )

        self.assertIn("ML assessment could not be completed", explanations[0])
        self.assertIn("MODEL_UNAVAILABLE", explanations[0])

    def test_unavailable_evidence_accepts_valid_error_codes(self) -> None:
        model = make_model(
            status="unavailable",
            predicted_class=None,
            predicted_label=None,
            class_1_probability=None,
        )
        rules = make_rules(status="unavailable")
        risk = make_risk(
            status="incomplete",
            level="indeterminate",
            model_probability=None,
            model_score=None,
            rule_score=None,
            combined_score=None,
        )

        explanations = generate(model, rules, "incomplete", risk)

        self.assertIn("MODEL_UNAVAILABLE", explanations[0])
        self.assertIn("RULES_UNAVAILABLE", explanations[1])

    def test_multiple_triggered_rules_include_ids_descriptions_and_checks(self) -> None:
        rules = make_rules(
            triggered_rules=[
                make_rule(
                    "RBD-SYN-005",
                    triggered=True,
                    checks=[
                        make_check(
                            name="serror_rate",
                            observed_value=1,
                            operator="==",
                            threshold=1,
                        ),
                        make_check(
                            name="srv_serror_rate",
                            observed_value=0,
                            operator="==",
                            threshold=1,
                            condition_met=False,
                        ),
                    ],
                    description="SYN pattern",
                ),
                make_rule(
                    "RBD-SCAN-006",
                    triggered=True,
                    severity="medium",
                    checks=[
                        make_check(
                            name="diff_srv_rate",
                            observed_value=1,
                            threshold=1,
                        )
                    ],
                ),
            ]
        )
        risk = make_risk(rule_score=85, combined_score=85)

        explanations = generate(
            make_model(),
            rules,
            "agreement_attack",
            risk,
        )
        rule_explanations = explanations[1:3]

        self.assertEqual(len(rule_explanations), 2)
        self.assertIn("RBD-SYN-005", rule_explanations[0])
        self.assertIn("SYN pattern", rule_explanations[0])
        self.assertIn("serror_rate observed 1 == 1: met", rule_explanations[0])
        self.assertIn("srv_serror_rate observed 0 == 1: not met", rule_explanations[0])
        self.assertIn("RBD-SCAN-006", rule_explanations[1])

    def test_no_triggered_rules_are_reported(self) -> None:
        explanations = generate(
            make_model(predicted_class=0, predicted_label="normal", class_1_probability=0.1),
            make_rules(
                triggered_rules=[
                    make_rule("RBD-TEST-001", triggered=False)
                ]
            ),
            "agreement_no_attack_signal",
            make_risk(level="low", model_probability=0.1, model_score=10, rule_score=0, combined_score=10),
        )

        self.assertIn("No configured rule was triggered", explanations[1])
        self.assertIn("does not confirm", explanations[2])

    def test_unavailable_rule_evidence_is_explained(self) -> None:
        explanations = generate(
            make_model(status="unavailable", predicted_class=None, predicted_label=None, class_1_probability=None),
            make_rules(status="unavailable"),
            "incomplete",
            make_risk(
                status="incomplete",
                level="indeterminate",
                model_probability=None,
                model_score=None,
                rule_score=None,
                combined_score=None,
            ),
        )

        self.assertIn("Rule-based assessment could not be completed", explanations[1])
        self.assertIn("RULES_UNAVAILABLE", explanations[1])

    def test_available_rule_evidence_rejects_error_code(self) -> None:
        rules = make_rules()
        rules["error_code"] = "RULE_ERROR"

        with self.assertRaisesRegex(ExplanationInputError, "must not have an error_code"):
            generate(make_model(), rules, "ml_only", make_risk(rule_score=0, combined_score=80))

    def test_all_reconciliation_outcomes_are_explained(self) -> None:
        cases = (
            (
                make_model(),
                make_rules(triggered_rules=[make_rule("RBD-A", triggered=True)]),
                "agreement_attack",
                make_risk(),
                "both indicated an attack",
            ),
            (
                make_model(predicted_class=0, predicted_label="normal", class_1_probability=0.1),
                make_rules(),
                "agreement_no_attack_signal",
                make_risk(level="low", model_probability=0.1, model_score=10, rule_score=0, combined_score=10),
                "does not confirm",
            ),
            (
                make_model(),
                make_rules(),
                "ml_only",
                make_risk(rule_score=0, combined_score=80),
                "no configured rule triggered",
            ),
            (
                make_model(predicted_class=0, predicted_label="normal", class_1_probability=0.1),
                make_rules(triggered_rules=[make_rule("RBD-A", triggered=True)]),
                "rules_only",
                make_risk(level="high", model_probability=0.1, model_score=10, rule_score=85, combined_score=85),
                "ML classified the record as normal",
            ),
            (
                make_model(status="unavailable", predicted_class=None, predicted_label=None, class_1_probability=None),
                make_rules(),
                "incomplete",
                make_risk(status="incomplete", level="indeterminate", model_probability=None, model_score=None, rule_score=0, combined_score=None),
                "complete comparison could not be made",
            ),
        )
        for model, rules, result, risk, expected_text in cases:
            with self.subTest(reconciliation=result):
                explanations = generate(model, rules, result, risk)
                self.assertIn(expected_text, explanations[2])

    def test_complete_risk_explanation_includes_scores_and_policy(self) -> None:
        explanations = generate(
            make_model(),
            make_rules(triggered_rules=[make_rule("RBD-A", triggered=True)]),
            "agreement_attack",
            make_risk(),
        )

        risk_text = explanations[-1]
        self.assertIn("heuristic risk level: high", risk_text)
        self.assertIn("ML score: 80", risk_text)
        self.assertIn("rule score: 85", risk_text)
        self.assertIn("combined score: 85", risk_text)
        self.assertIn("phase6-candidate-1", risk_text)
        self.assertIn("not calibrated probabilities", risk_text)

    def test_incomplete_risk_preserves_only_available_source_score(self) -> None:
        explanations = generate(
            make_model(status="unavailable", predicted_class=None, predicted_label=None, class_1_probability=None),
            make_rules(triggered_rules=[make_rule("RBD-A", triggered=True)]),
            "incomplete",
            make_risk(
                status="incomplete",
                level="indeterminate",
                model_probability=None,
                model_score=None,
                rule_score=85,
                combined_score=None,
            ),
        )

        risk_text = explanations[-1]
        self.assertIn("classification could not be established", risk_text)
        self.assertIn("Available rule score: 85", risk_text)
        self.assertNotIn("ML score", risk_text)
        self.assertNotIn("combined score", risk_text)

    def test_incomplete_risk_with_both_sources_unavailable(self) -> None:
        explanations = generate(
            make_model(status="unavailable", predicted_class=None, predicted_label=None, class_1_probability=None),
            make_rules(status="unavailable"),
            "incomplete",
            make_risk(
                status="incomplete",
                level="indeterminate",
                model_probability=None,
                model_score=None,
                rule_score=None,
                combined_score=None,
            ),
        )

        risk_text = explanations[-1]
        self.assertIn("indeterminate", risk_text)
        self.assertNotIn("Available ML score", risk_text)
        self.assertNotIn("Available rule score", risk_text)

    def test_explanation_order_is_ml_rules_reconciliation_risk(self) -> None:
        explanations = generate(
            make_model(),
            make_rules(triggered_rules=[make_rule("RBD-A", triggered=True)]),
            "agreement_attack",
            make_risk(),
        )

        self.assertTrue(explanations[0].startswith("ML predicted"))
        self.assertTrue(explanations[1].startswith("Rule RBD-A"))
        self.assertTrue(explanations[2].startswith("ML and rule-based"))
        self.assertTrue(explanations[3].startswith("Overall heuristic"))

    def test_invalid_reconciliation_is_rejected(self) -> None:
        with self.assertRaisesRegex(ExplanationInputError, "Invalid reconciliation"):
            generate(make_model(), make_rules(), "other", make_risk())

    def test_invalid_risk_status_and_level_are_rejected(self) -> None:
        for field, value in (("status", "unknown"), ("level", "critical")):
            risk = make_risk()
            risk[field] = value  # type: ignore[literal-required]
            with self.subTest(field=field):
                with self.assertRaises(ExplanationInputError):
                    generate(make_model(), make_rules(), "ml_only", risk)

    def test_unavailable_ml_evidence_validates_model_metadata_types(self) -> None:
        for field in ("model_name", "model_version"):
            model = make_model(
                status="unavailable",
                predicted_class=None,
                predicted_label=None,
                class_1_probability=None,
            )
            model[field] = 123  # type: ignore[literal-required]
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ExplanationInputError, f"{field} must be a string or None"
                ):
                    generate(
                        model,
                        make_rules(status="unavailable"),
                        "incomplete",
                        make_risk(
                            status="incomplete",
                            level="indeterminate",
                            model_probability=None,
                            model_score=None,
                            rule_score=None,
                            combined_score=None,
                        ),
                    )

    def test_contradictory_risk_fields_are_rejected(self) -> None:
        risk = make_risk(combined_score=None)
        with self.assertRaisesRegex(ExplanationInputError, "combined_score"):
            generate(make_model(), make_rules(), "ml_only", risk)

        incomplete_risk = make_risk(
            status="incomplete",
            level="indeterminate",
            combined_score=85,
        )
        with self.assertRaisesRegex(ExplanationInputError, "requires a complete"):
            generate(make_model(), make_rules(), "ml_only", incomplete_risk)

    def test_malformed_rule_result_and_feature_checks_are_rejected(self) -> None:
        malformed_result = cast(RuleResult, {"rule_id": "RBD-X", "triggered": True})
        rules = make_rules(triggered_rules=[malformed_result])
        with self.assertRaisesRegex(ExplanationInputError, "Malformed rule result"):
            generate(make_model(), rules, "agreement_attack", make_risk())

        bad_check = cast(FeatureCheck, {"name": "count"})
        rules = make_rules(
            triggered_rules=[
                make_rule("RBD-X", triggered=True, checks=[bad_check])
            ]
        )
        with self.assertRaisesRegex(ExplanationInputError, "Malformed rule feature check"):
            generate(make_model(), rules, "agreement_attack", make_risk())

    def test_identical_inputs_are_deterministic_and_unmodified(self) -> None:
        model = make_model()
        rules = make_rules(
            triggered_rules=[make_rule("RBD-A", triggered=True)]
        )
        risk = make_risk()
        originals = copy.deepcopy((model, rules, risk))

        first = generate(model, rules, "agreement_attack", risk)
        second = generate(model, rules, "agreement_attack", risk)

        self.assertEqual(first, second)
        self.assertEqual((model, rules, risk), originals)


if __name__ == "__main__":
    unittest.main()
