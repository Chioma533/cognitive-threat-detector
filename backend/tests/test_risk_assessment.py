import unittest
from typing import cast

from app.cognition.risk_assessment import (
    POLICY_VERSION,
    RiskAssessmentInputError,
    assess_risk,
)
from app.cognition.types import ModelEvidence, RuleEvidence
from app.detection.rule_engine import RuleResult


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 0,
    predicted_label: str | None = "normal",
    class_1_probability: object = 0.1,
) -> ModelEvidence:
    return cast(
        ModelEvidence,
        {
            "status": status,
            "predicted_class": predicted_class,
            "predicted_label": predicted_label,
            "class_0_probability": None,
            "class_1_probability": class_1_probability,
            "model_name": None,
            "model_version": None,
            "error_code": None if status == "available" else "MODEL_UNAVAILABLE",
        },
    )


def make_rule_result(
    rule_id: str = "RBD-TEST-001",
    *,
    triggered: bool = False,
    severity: object = "low",
) -> RuleResult:
    return cast(
        RuleResult,
        {
            "rule_id": rule_id,
            "triggered": triggered,
            "severity": severity,
            "description": "Test rule",
            "features_examined": [],
            "reason": "Test result",
        },
    )


def make_rules(
    *,
    status: str = "available",
    results: list[RuleResult] | None = None,
    triggered_rule_ids: list[str] | None = None,
) -> RuleEvidence:
    default_results = (
        [] if status == "unavailable" else [make_rule_result()]
    )
    selected_results = results if results is not None else default_results
    ids = (
        triggered_rule_ids
        if triggered_rule_ids is not None
        else [
            result["rule_id"]
            for result in selected_results
            if result["triggered"]
        ]
    )
    return cast(
        RuleEvidence,
        {
            "status": status,
            "results": selected_results,
            "triggered_rule_ids": ids,
            "error_code": None if status == "available" else "RULES_UNAVAILABLE",
        },
    )


class RiskAssessmentTests(unittest.TestCase):
    def test_model_score_uses_class_one_probability_not_predicted_class(self) -> None:
        result = assess_risk(
            make_model(
                predicted_class=0,
                predicted_label="normal",
                class_1_probability=0.42,
            ),
            make_rules(),
        )

        self.assertEqual(result["model_score"], 42.0)
        self.assertEqual(result["model_attack_probability"], 0.42)
        self.assertEqual(result["level"], "medium")

    def test_rule_score_for_each_severity(self) -> None:
        for severity, expected_score in (
            ("low", 20.0),
            ("medium", 55.0),
            ("high", 85.0),
        ):
            rules = make_rules(
                results=[
                    make_rule_result(
                        "RBD-TEST-001", triggered=True, severity=severity
                    )
                ]
            )
            with self.subTest(severity=severity):
                result = assess_risk(make_model(), rules)
                self.assertEqual(result["rule_score"], expected_score)

    def test_no_triggered_rules_have_zero_rule_score(self) -> None:
        result = assess_risk(make_model(), make_rules())
        self.assertEqual(result["rule_score"], 0.0)

    def test_multiple_rules_use_highest_severity_not_sum(self) -> None:
        results = [
            make_rule_result("RBD-TEST-001", triggered=True, severity="low"),
            make_rule_result("RBD-TEST-002", triggered=True, severity="medium"),
            make_rule_result("RBD-TEST-003", triggered=True, severity="high"),
        ]
        result = assess_risk(
            make_model(),
            make_rules(
                results=results,
                triggered_rule_ids=[
                    "RBD-TEST-001",
                    "RBD-TEST-002",
                    "RBD-TEST-003",
                ],
            ),
        )
        self.assertEqual(result["rule_score"], 85.0)

    def test_combined_score_uses_maximum_source_score(self) -> None:
        lower_rule_risk = assess_risk(
            make_model(class_1_probability=0.4),
            make_rules(
                results=[
                    make_rule_result(triggered=True, severity="low")
                ]
            ),
        )
        higher_rule_risk = assess_risk(
            make_model(class_1_probability=0.1),
            make_rules(
                results=[
                    make_rule_result(triggered=True, severity="high")
                ]
            ),
        )

        self.assertEqual(lower_rule_risk["combined_score"], 40.0)
        self.assertEqual(higher_rule_risk["combined_score"], 85.0)

    def test_risk_band_boundaries(self) -> None:
        cases = (
            (0.2999, "low"),
            (0.3, "medium"),
            (0.6999, "medium"),
            (0.7, "high"),
        )
        for probability, expected_level in cases:
            with self.subTest(probability=probability):
                result = assess_risk(
                    make_model(class_1_probability=probability),
                    make_rules(),
                )
                self.assertEqual(result["level"], expected_level)

    def test_policy_version_is_set(self) -> None:
        self.assertEqual(
            assess_risk(make_model(), make_rules())["policy_version"],
            POLICY_VERSION,
        )
        self.assertEqual(POLICY_VERSION, "phase6-candidate-1")

    def test_model_unavailable_preserves_rule_score(self) -> None:
        rules = make_rules(
            results=[make_rule_result(triggered=True, severity="medium")]
        )
        result = assess_risk(
            make_model(
                status="unavailable",
                predicted_class=None,
                predicted_label=None,
                class_1_probability=None,
            ),
            rules,
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["model_attack_probability"])
        self.assertIsNone(result["model_score"])
        self.assertEqual(result["rule_score"], 55.0)
        self.assertIsNone(result["combined_score"])
        self.assertEqual(result["level"], "indeterminate")

    def test_rules_unavailable_preserves_model_score(self) -> None:
        result = assess_risk(
            make_model(class_1_probability=0.64),
            make_rules(status="unavailable"),
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["model_attack_probability"], 0.64)
        self.assertEqual(result["model_score"], 64.0)
        self.assertIsNone(result["rule_score"])
        self.assertIsNone(result["combined_score"])
        self.assertEqual(result["level"], "indeterminate")

    def test_both_sources_unavailable_produce_indeterminate_risk(self) -> None:
        result = assess_risk(
            make_model(
                status="unavailable",
                predicted_class=None,
                predicted_label=None,
                class_1_probability=None,
            ),
            make_rules(status="unavailable"),
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["model_score"])
        self.assertIsNone(result["rule_score"])
        self.assertIsNone(result["combined_score"])
        self.assertEqual(result["level"], "indeterminate")

    def test_unavailable_model_rejects_prediction_and_probability_values(self) -> None:
        for field, value in (
            ("predicted_class", 0),
            ("predicted_label", "normal"),
            ("class_0_probability", 0.9),
            ("class_1_probability", 0.1),
        ):
            model = make_model(
                status="unavailable",
                predicted_class=None,
                predicted_label=None,
                class_1_probability=None,
            )
            model[field] = value  # type: ignore[literal-required]
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    RiskAssessmentInputError, "Unavailable model evidence"
                ):
                    assess_risk(model, make_rules())

    def test_unavailable_rules_reject_rule_results_or_triggered_ids(self) -> None:
        contradictory_evidence = (
            make_rules(
                status="unavailable",
                results=[make_rule_result()],
            ),
            make_rules(
                status="unavailable",
                triggered_rule_ids=["RBD-TEST-001"],
            ),
        )
        for rules in contradictory_evidence:
            with self.subTest(rules=rules):
                with self.assertRaisesRegex(
                    RiskAssessmentInputError, "Unavailable rule evidence"
                ):
                    assess_risk(
                        make_model(),
                        rules,
                    )

    def test_invalid_probabilities_are_rejected(self) -> None:
        for probability in (-0.01, 1.01, float("nan"), float("inf"), True, "0.5"):
            with self.subTest(probability=probability):
                with self.assertRaises(RiskAssessmentInputError):
                    assess_risk(
                        make_model(class_1_probability=probability),
                        make_rules(),
                    )

    def test_invalid_severities_are_rejected(self) -> None:
        for severity in ("critical", None, 1):
            with self.subTest(severity=severity):
                rules = make_rules(
                    results=[
                        make_rule_result(
                            triggered=True, severity=severity
                        )
                    ]
                )
                with self.assertRaises(RiskAssessmentInputError):
                    assess_risk(make_model(), rules)

    def test_triggered_rule_ids_must_match_results(self) -> None:
        rules = make_rules(
            results=[
                make_rule_result("RBD-TEST-001", triggered=True)
            ],
            triggered_rule_ids=["RBD-OTHER-001"],
        )
        with self.assertRaisesRegex(RiskAssessmentInputError, "do not match"):
            assess_risk(make_model(), rules)

    def test_duplicate_rule_result_ids_are_rejected(self) -> None:
        result = make_rule_result("RBD-DUPLICATE")
        rules = make_rules(results=[result, result.copy()])

        with self.assertRaisesRegex(RiskAssessmentInputError, "Rule result IDs"):
            assess_risk(make_model(), rules)

    def test_duplicate_triggered_ids_are_rejected(self) -> None:
        results = [
            make_rule_result("RBD-TEST-001", triggered=True),
            make_rule_result("RBD-TEST-002", triggered=False),
        ]
        rules = make_rules(
            results=results,
            triggered_rule_ids=["RBD-TEST-001", "RBD-TEST-001"],
        )

        with self.assertRaisesRegex(RiskAssessmentInputError, "Triggered rule IDs"):
            assess_risk(make_model(), rules)

    def test_missing_rule_result_fields_are_rejected(self) -> None:
        for field in ("features_examined", "reason"):
            result = make_rule_result()
            del result[field]  # type: ignore[misc]
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    RiskAssessmentInputError, "incomplete rule result"
                ):
                    assess_risk(make_model(), make_rules(results=[result]))

    def test_invalid_features_examined_structure_is_rejected(self) -> None:
        for checks in (
            "not-a-list",
            [{}],
            [
                {
                    "name": "count",
                    "observed_value": 1,
                    "operator": ">=",
                    "threshold": 1,
                }
            ],
        ):
            result = make_rule_result()
            result["features_examined"] = checks  # type: ignore[typeddict-item]
            with self.subTest(checks=checks):
                with self.assertRaisesRegex(
                    RiskAssessmentInputError, "features_examined"
                ):
                    assess_risk(make_model(), make_rules(results=[result]))

    def test_invalid_reason_type_is_rejected(self) -> None:
        result = make_rule_result()
        result["reason"] = 42  # type: ignore[typeddict-item]

        with self.assertRaisesRegex(RiskAssessmentInputError, "reasons must be strings"):
            assess_risk(make_model(), make_rules(results=[result]))

    def test_invalid_evidence_statuses_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            RiskAssessmentInputError, "Invalid model evidence status"
        ):
            assess_risk(make_model(status="unknown"), make_rules())
        with self.assertRaisesRegex(
            RiskAssessmentInputError, "Invalid rule evidence status"
        ):
            assess_risk(make_model(), make_rules(status="unknown"))

    def test_model_class_and_label_must_be_consistent(self) -> None:
        with self.assertRaisesRegex(
            RiskAssessmentInputError, "inconsistent predicted_label"
        ):
            assess_risk(
                make_model(
                    predicted_class=1,
                    predicted_label="normal",
                ),
                make_rules(),
            )


if __name__ == "__main__":
    unittest.main()
