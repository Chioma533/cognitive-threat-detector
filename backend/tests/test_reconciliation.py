import unittest
from typing import cast

from app.cognition.reconciliation import (
    EvidenceReconciliationError,
    reconcile_evidence,
)
from app.cognition.types import ModelEvidence, RuleEvidence
from app.detection.rule_engine import RuleResult


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 0,
    predicted_label: str | None = "normal",
) -> ModelEvidence:
    return cast(
        ModelEvidence,
        {
            "status": status,
            "predicted_class": predicted_class,
            "predicted_label": predicted_label,
            "class_0_probability": None,
            "class_1_probability": None,
            "model_name": None,
            "model_version": None,
            "error_code": None if status == "available" else "MODEL_UNAVAILABLE",
        },
    )


def make_rule_result(rule_id: str, triggered: bool) -> RuleResult:
    return {
        "rule_id": rule_id,
        "triggered": triggered,
        "severity": "low",
        "description": "Test rule",
        "features_examined": [],
        "reason": "Test result",
    }


def make_rules(
    *,
    status: str = "available",
    triggered_ids: tuple[str, ...] = (),
) -> RuleEvidence:
    result_ids = ("RBD-TEST-001", "RBD-TEST-002")
    results = [
        make_rule_result(rule_id, rule_id in triggered_ids)
        for rule_id in result_ids
    ]
    return cast(
        RuleEvidence,
        {
            "status": status,
            "results": results,
            "triggered_rule_ids": list(triggered_ids),
            "error_code": None if status == "available" else "RULES_UNAVAILABLE",
        },
    )


class EvidenceReconciliationTests(unittest.TestCase):
    def test_agreement_attack(self) -> None:
        self.assertEqual(
            reconcile_evidence(
                make_model(predicted_class=1, predicted_label="attack"),
                make_rules(triggered_ids=("RBD-TEST-001",)),
            ),
            "agreement_attack",
        )

    def test_agreement_no_attack_signal(self) -> None:
        self.assertEqual(
            reconcile_evidence(make_model(), make_rules()),
            "agreement_no_attack_signal",
        )

    def test_ml_only(self) -> None:
        self.assertEqual(
            reconcile_evidence(
                make_model(predicted_class=1, predicted_label="attack"),
                make_rules(),
            ),
            "ml_only",
        )

    def test_rules_only(self) -> None:
        self.assertEqual(
            reconcile_evidence(
                make_model(),
                make_rules(triggered_ids=("RBD-TEST-001",)),
            ),
            "rules_only",
        )

    def test_incomplete_when_both_sources_are_unavailable(self) -> None:
        self.assertEqual(
            reconcile_evidence(
                make_model(status="unavailable", predicted_class=None, predicted_label=None),
                make_rules(status="unavailable"),
            ),
            "incomplete",
        )

    def test_incomplete_when_model_is_unavailable(self) -> None:
        self.assertEqual(
            reconcile_evidence(
                make_model(status="unavailable", predicted_class=None, predicted_label=None),
                make_rules(triggered_ids=("RBD-TEST-001",)),
            ),
            "incomplete",
        )

    def test_incomplete_when_rules_are_unavailable(self) -> None:
        self.assertEqual(
            reconcile_evidence(make_model(), make_rules(status="unavailable")),
            "incomplete",
        )

    def test_multiple_triggered_rules_produce_one_positive_rule_signal(self) -> None:
        self.assertEqual(
            reconcile_evidence(
                make_model(predicted_class=1, predicted_label="attack"),
                make_rules(
                    triggered_ids=("RBD-TEST-001", "RBD-TEST-002")
                ),
            ),
            "agreement_attack",
        )

    def test_rule_summary_must_match_rule_results(self) -> None:
        inconsistent_rules = make_rules()
        inconsistent_rules["triggered_rule_ids"] = ["RBD-TEST-001"]

        with self.assertRaisesRegex(
            EvidenceReconciliationError, "do not match"
        ):
            reconcile_evidence(make_model(), inconsistent_rules)

    def test_available_model_prediction_and_label_must_agree(self) -> None:
        with self.assertRaisesRegex(
            EvidenceReconciliationError, "inconsistent predicted_label"
        ):
            reconcile_evidence(
                make_model(predicted_class=1, predicted_label="normal"),
                make_rules(),
            )

    def test_invalid_source_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            EvidenceReconciliationError, "Invalid model evidence status"
        ):
            reconcile_evidence(make_model(status="unknown"), make_rules())


if __name__ == "__main__":
    unittest.main()
