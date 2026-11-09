import copy
import unittest
from collections.abc import Mapping
from typing import cast
from unittest.mock import patch

from app.cognition.orchestrator import (
    AssessmentInputValidationError,
    AssessmentOrchestrator,
)
from app.cognition.types import ModelEvidence
from app.detection.input_validation import FeatureRecordValidationError
from app.detection.model_service import (
    INFERENCE_ERROR,
    MODEL_UNAVAILABLE,
    ModelInferenceService,
    ModelInputValidationError,
)
from app.detection.rule_engine import (
    RuleInputValidationError,
    RuleResult,
    evaluate_rules,
)
from ml.schema import CATEGORICAL_FEATURES, FEATURE_NAMES


def make_record() -> dict[str, object]:
    return {
        name: "unseen-value" if name in CATEGORICAL_FEATURES else 0
        for name in FEATURE_NAMES
    }


def make_model(
    *,
    status: str = "available",
    probability: float | None = 0.8,
    error_code: str | None = None,
) -> ModelEvidence:
    if status == "unavailable":
        probability = None
        predicted_class = None
        predicted_label = None
        class_0_probability = None
        error_code = error_code or MODEL_UNAVAILABLE
    else:
        predicted_class = 1
        predicted_label = "attack"
        class_0_probability = None if probability is None else 1 - probability
    return cast(
        ModelEvidence,
        {
            "status": status,
            "predicted_class": predicted_class,
            "predicted_label": predicted_label,
            "class_0_probability": class_0_probability,
            "class_1_probability": probability,
            "model_name": None,
            "model_version": None,
            "error_code": error_code,
        },
    )


def triggered_rule() -> RuleResult:
    return {
        "rule_id": "RBD-AUTH-001",
        "triggered": True,
        "severity": "low",
        "description": "Failed login evidence",
        "features_examined": [
            {
                "name": "num_failed_logins",
                "observed_value": 1,
                "operator": ">=",
                "threshold": 1,
                "condition_met": True,
            }
        ],
        "reason": "One failed login attempt was recorded.",
    }


class FakeModelService:
    def __init__(
        self,
        evidence: ModelEvidence | None = None,
        error: Exception | None = None,
    ) -> None:
        self.evidence = evidence or make_model()
        self.error = error
        self.calls: list[Mapping[str, object]] = []

    def predict(self, record: Mapping[str, object]) -> ModelEvidence:
        self.calls.append(record)
        if self.error is not None:
            raise self.error
        return self.evidence


class AssessmentOrchestratorTests(unittest.TestCase):
    def test_successful_assessment_has_exact_contract_fields_and_calls_once(self) -> None:
        model = FakeModelService()
        rule_calls: list[Mapping[str, object]] = []

        def rules(record: Mapping[str, object]) -> list[RuleResult]:
            rule_calls.append(record)
            return []

        orchestrator = AssessmentOrchestrator(model, rules)
        assessment = orchestrator.assess(make_record())

        self.assertEqual(
            set(assessment),
            {"model", "rules", "reconciliation", "risk", "explanations"},
        )
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(len(rule_calls), 1)
        self.assertEqual(assessment["reconciliation"], "ml_only")
        self.assertEqual(assessment["risk"]["status"], "complete")

    def test_input_is_immutable_and_both_detectors_receive_same_snapshot(self) -> None:
        record = make_record()
        original = copy.deepcopy(record)
        model = FakeModelService()
        rule_calls: list[Mapping[str, object]] = []
        orchestrator = AssessmentOrchestrator(
            model,
            lambda snapshot: rule_calls.append(snapshot) or [],
        )

        orchestrator.assess(record)

        self.assertEqual(record, original)
        self.assertIs(model.calls[0], rule_calls[0])
        self.assertIsNot(model.calls[0], record)

    def test_invalid_input_is_rejected_before_either_detector_runs(self) -> None:
        model = FakeModelService()
        rule_calls: list[Mapping[str, object]] = []
        orchestrator = AssessmentOrchestrator(
            model, lambda record: rule_calls.append(record) or []
        )
        record = make_record()
        del record["duration"]

        with self.assertRaises(AssessmentInputValidationError):
            orchestrator.assess(record)

        self.assertEqual(model.calls, [])
        self.assertEqual(rule_calls, [])

    def test_valid_unseen_categories_are_accepted(self) -> None:
        record = make_record()
        record.update(
            {
                "protocol_type": "future-protocol",
                "service": "future-service",
                "flag": "FUTURE",
            }
        )
        model = FakeModelService()
        received: list[Mapping[str, object]] = []
        AssessmentOrchestrator(
            model, lambda snapshot: received.append(snapshot) or []
        ).assess(record)

        self.assertEqual(len(model.calls), 1)
        self.assertEqual(model.calls[0]["service"], "future-service")
        self.assertEqual(received[0]["flag"], "FUTURE")

    def test_unavailable_model_evidence_from_service_is_preserved(self) -> None:
        unavailable = make_model(
            status="unavailable", error_code="INCOMPATIBLE_MODEL_ARTIFACT"
        )
        assessment = AssessmentOrchestrator(
            FakeModelService(evidence=unavailable), lambda record: []
        ).assess(make_record())

        self.assertIs(assessment["model"], unavailable)
        self.assertEqual(assessment["model"]["error_code"], "INCOMPATIBLE_MODEL_ARTIFACT")
        self.assertEqual(assessment["reconciliation"], "incomplete")
        self.assertEqual(assessment["risk"]["level"], "indeterminate")

    def test_unexpected_model_failure_does_not_prevent_rule_assessment(self) -> None:
        assessment = AssessmentOrchestrator(
            FakeModelService(error=RuntimeError("private model detail")),
            lambda record: [triggered_rule()],
        ).assess(make_record())

        self.assertEqual(assessment["model"]["error_code"], INFERENCE_ERROR)
        self.assertEqual(assessment["rules"]["status"], "available")
        self.assertEqual(assessment["rules"]["triggered_rule_ids"], ["RBD-AUTH-001"])
        self.assertNotIn("private model detail", str(assessment))
        self.assertEqual(assessment["reconciliation"], "incomplete")
        self.assertEqual(assessment["risk"]["rule_score"], 20.0)
        self.assertIsNone(assessment["risk"]["combined_score"])

    def test_unexpected_rule_failure_does_not_prevent_model_assessment(self) -> None:
        def fail_rules(record: Mapping[str, object]) -> list[RuleResult]:
            raise RuntimeError("private rule detail")

        assessment = AssessmentOrchestrator(
            FakeModelService(), fail_rules
        ).assess(make_record())

        self.assertEqual(assessment["model"]["status"], "available")
        self.assertEqual(assessment["rules"]["status"], "unavailable")
        self.assertEqual(assessment["rules"]["error_code"], "RULE_EVALUATION_ERROR")
        self.assertEqual(assessment["rules"]["results"], [])
        self.assertEqual(assessment["rules"]["triggered_rule_ids"], [])
        self.assertNotIn("private rule detail", str(assessment))
        self.assertEqual(assessment["reconciliation"], "incomplete")
        self.assertEqual(assessment["risk"]["model_score"], 80.0)
        self.assertIsNone(assessment["risk"]["combined_score"])

    def test_both_sources_failing_produces_indeterminate_assessment(self) -> None:
        def fail_rules(record: Mapping[str, object]) -> list[RuleResult]:
            raise RuntimeError("private detail")

        assessment = AssessmentOrchestrator(
            FakeModelService(error=RuntimeError("private detail")),
            fail_rules,
        ).assess(make_record())

        self.assertEqual(assessment["model"]["status"], "unavailable")
        self.assertEqual(assessment["rules"]["status"], "unavailable")
        self.assertEqual(assessment["reconciliation"], "incomplete")
        self.assertEqual(assessment["risk"]["status"], "incomplete")
        self.assertEqual(assessment["risk"]["level"], "indeterminate")
        self.assertIsNone(assessment["risk"]["combined_score"])

    def test_model_initialization_failure_does_not_prevent_rule_evaluation(self) -> None:
        rule_calls: list[Mapping[str, object]] = []
        with patch(
            "app.cognition.orchestrator.ModelInferenceService",
            side_effect=RuntimeError("private initialization detail"),
        ):
            orchestrator = AssessmentOrchestrator(
                rule_evaluator=lambda record: rule_calls.append(record) or []
            )

        assessment = orchestrator.assess(make_record())

        self.assertEqual(len(rule_calls), 1)
        self.assertEqual(assessment["model"]["status"], "unavailable")
        self.assertEqual(assessment["model"]["error_code"], MODEL_UNAVAILABLE)
        self.assertEqual(assessment["rules"]["status"], "available")
        self.assertEqual(assessment["reconciliation"], "incomplete")
        self.assertEqual(assessment["risk"]["level"], "indeterminate")

    def test_identical_inputs_produce_deterministic_assessments(self) -> None:
        orchestrator = AssessmentOrchestrator(
            FakeModelService(), lambda record: [triggered_rule()]
        )

        first = orchestrator.assess(make_record())
        second = orchestrator.assess(make_record())

        self.assertEqual(first, second)

    def test_existing_detection_validation_exceptions_remain_compatible(self) -> None:
        invalid = make_record()
        invalid["duration"] = True
        with self.assertRaises(RuleInputValidationError):
            evaluate_rules(invalid)
        with patch(
            "app.detection.model_service.load_model_artifact",
            side_effect=OSError("missing artifact"),
        ):
            service = ModelInferenceService()
        with self.assertRaises(ModelInputValidationError):
            service.predict(invalid)

        self.assertTrue(issubclass(ModelInputValidationError, FeatureRecordValidationError))
        self.assertTrue(issubclass(RuleInputValidationError, FeatureRecordValidationError))


if __name__ == "__main__":
    unittest.main()
