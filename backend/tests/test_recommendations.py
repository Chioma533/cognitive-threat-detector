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
from app.incidents.policy import determine_assessment_handling
from app.incidents.recommendations import (
    RecommendationInputError,
    generate_recommendations,
)
from app.incidents.types import (
    AssessmentHandlingDecision,
    ResponseRecommendation,
)


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 1,
    probability: float | None = 0.8,
) -> ModelEvidence:
    if status == "unavailable":
        return {
            "status": "unavailable",
            "predicted_class": None,
            "predicted_label": None,
            "class_0_probability": None,
            "class_1_probability": None,
            "model_name": None,
            "model_version": None,
            "error_code": "INFERENCE_ERROR",
        }
    return {
        "status": "available",
        "predicted_class": predicted_class,  # type: ignore[typeddict-item]
        "predicted_label": "normal" if predicted_class == 0 else "attack",  # type: ignore[comparison-overlap]
        "class_0_probability": None if probability is None else 1 - probability,
        "class_1_probability": probability,
        "model_name": "test-model",
        "model_version": "1.0",
        "error_code": None,
    }


def make_rule(
    rule_id: str = "RBD-AUTH-001",
    *,
    severity: str = "high",
    triggered: bool = True,
) -> RuleResult:
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
            "rule_id": rule_id,
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
            "status": "unavailable",
            "results": [],
            "triggered_rule_ids": [],
            "error_code": "RULE_EVALUATION_ERROR",
        }
    actual_results = [] if results is None else results
    return {
        "status": "available",
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
    return {
        "model": actual_model,
        "rules": actual_rules,
        "reconciliation": reconciliation,
        "risk": risk,
        "explanations": generate_explanations(
            actual_model, actual_rules, reconciliation, risk
        ),
    }


def recommend(
    assessment: ConsolidatedAssessment,
) -> list[ResponseRecommendation]:
    decision = determine_assessment_handling(assessment)
    return generate_recommendations(assessment, decision)


def resolve_reference(
    assessment: ConsolidatedAssessment, reference: str
) -> object:
    value: object = assessment
    for part in reference.split("."):
        if not isinstance(value, dict) or part not in value:
            raise AssertionError(f"Invalid evidence reference: {reference}")
        value = value[part]
    return value


class RecommendationTests(unittest.TestCase):
    def test_high_risk_incident_recommends_prioritised_investigation(self) -> None:
        assessment = make_assessment(model=make_model(probability=0.8))

        recommendations = recommend(assessment)

        investigation = next(
            item
            for item in recommendations
            if item["action_key"] == "prioritised_analyst_investigation"
        )
        self.assertIn("risk.level", investigation["evidence_references"])
        self.assertIn("risk.policy_version", investigation["evidence_references"])

    def test_medium_risk_assessment_recommends_evidence_review(self) -> None:
        assessment = make_assessment(
            model=make_model(probability=0.55),
            rules=make_rules(),
        )

        recommendations = recommend(assessment)

        self.assertEqual(
            recommendations[0]["action_key"], "review_medium_risk_assessment"
        )
        self.assertIn("reconciliation", recommendations[0]["evidence_references"])

    def test_ml_only_signal_recommends_prediction_review(self) -> None:
        assessment = make_assessment(
            model=make_model(probability=0.8), rules=make_rules()
        )

        recommendations = recommend(assessment)

        ml_review = next(
            item
            for item in recommendations
            if item["action_key"] == "review_ml_only_attack_signal"
        )
        self.assertEqual(
            ml_review["evidence_references"],
            [
                "model.predicted_class",
                "model.class_1_probability",
                "reconciliation",
            ],
        )

    def test_triggered_rules_recommend_inspection_of_findings(self) -> None:
        assessment = make_assessment(
            model=make_model(probability=0.55),
            rules=make_rules(results=[make_rule(severity="low")]),
        )

        recommendations = recommend(assessment)

        rule_review = next(
            item
            for item in recommendations
            if item["action_key"] == "inspect_triggered_rule_evidence"
        )
        self.assertEqual(
            rule_review["evidence_references"],
            ["rules.triggered_rule_ids", "rules.results"],
        )
        self.assertIn("not proof", rule_review["rationale"])

    def test_incomplete_assessment_recommends_review_and_source_investigation(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(),
        )

        recommendations = recommend(assessment)
        by_key = {item["action_key"]: item for item in recommendations}

        self.assertIn("review_incomplete_assessment", by_key)
        source_review = by_key["investigate_unavailable_evidence_source"]
        self.assertIn("model.status", source_review["evidence_references"])
        self.assertIn("model.error_code", source_review["evidence_references"])
        self.assertNotIn("rules.error_code", source_review["evidence_references"])
        self.assertNotIn("model.class_1_probability", source_review["evidence_references"])

    def test_incomplete_rules_unavailable_preserves_rule_error_code(self) -> None:
        assessment = make_assessment(
            model=make_model(probability=0.55),
            rules=make_rules(status="unavailable"),
        )

        recommendations = recommend(assessment)
        source_review = next(
            item
            for item in recommendations
            if item["action_key"] == "investigate_unavailable_evidence_source"
        )

        self.assertIn("rules.status", source_review["evidence_references"])
        self.assertIn("rules.error_code", source_review["evidence_references"])
        self.assertNotIn("rules.results", source_review["evidence_references"])

    def test_both_sources_unavailable_recommends_processing_investigation(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(status="unavailable"),
        )

        recommendations = recommend(assessment)

        self.assertEqual(
            [item["action_key"] for item in recommendations],
            ["investigate_assessment_processing_failure"],
        )
        self.assertNotIn(
            "prioritised_analyst_investigation",
            [item["action_key"] for item in recommendations],
        )
        self.assertIn("model.error_code", recommendations[0]["evidence_references"])
        self.assertIn("rules.error_code", recommendations[0]["evidence_references"])

    def test_low_risk_no_signal_produces_no_recommendations(self) -> None:
        assessment = make_assessment(
            model=make_model(predicted_class=0, probability=0.1),
            rules=make_rules(),
        )

        self.assertEqual(recommend(assessment), [])

    def test_all_references_resolve_and_unavailable_values_are_excluded(self) -> None:
        assessment = make_assessment(
            model=make_model(status="unavailable"),
            rules=make_rules(results=[make_rule(severity="low")]),
        )

        for item in recommend(assessment):
            for reference in item["evidence_references"]:
                value = resolve_reference(assessment, reference)
                self.assertIsNotNone(value)
            self.assertNotIn(
                "model.class_1_probability", item["evidence_references"]
            )
            self.assertNotIn("model.predicted_class", item["evidence_references"])

    def test_recommendations_have_stable_keys_and_pending_status(self) -> None:
        assessment = make_assessment(
            model=make_model(probability=0.55),
            rules=make_rules(results=[make_rule(severity="low")]),
        )

        recommendations = recommend(assessment)

        keys = [item["action_key"] for item in recommendations]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(
            keys,
            [
                "review_medium_risk_assessment",
                "inspect_triggered_rule_evidence",
            ],
        )
        self.assertTrue(
            all(item["review_status"] == "pending" for item in recommendations)
        )

    def test_invalid_or_contradictory_decision_and_assessment_are_rejected(self) -> None:
        assessment = make_assessment()
        decision = determine_assessment_handling(assessment)
        contradictory_decision = copy.deepcopy(decision)
        contradictory_decision["outcome"] = "no_action"

        with self.assertRaises(RecommendationInputError):
            generate_recommendations(assessment, contradictory_decision)

        malformed_decision = copy.deepcopy(decision)
        malformed_decision["create_security_incident"] = 1  # type: ignore[assignment]
        with self.assertRaises(RecommendationInputError):
            generate_recommendations(assessment, malformed_decision)

        contradictory_assessment = copy.deepcopy(assessment)
        contradictory_assessment["reconciliation"] = "rules_only"
        with self.assertRaises(RecommendationInputError):
            generate_recommendations(contradictory_assessment, decision)

    def test_output_is_deterministic_and_inputs_are_not_mutated(self) -> None:
        assessment = make_assessment(
            model=make_model(probability=0.55),
            rules=make_rules(results=[make_rule(severity="low")]),
        )
        decision = determine_assessment_handling(assessment)
        originals = copy.deepcopy((assessment, decision))

        first = generate_recommendations(assessment, decision)
        second = generate_recommendations(assessment, decision)

        self.assertEqual(first, second)
        self.assertEqual((assessment, decision), originals)


if __name__ == "__main__":
    unittest.main()
