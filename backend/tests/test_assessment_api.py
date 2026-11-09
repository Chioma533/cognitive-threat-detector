import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from unittest.mock import patch

from app import create_app
from app.cognition.orchestrator import AssessmentOrchestrator
from app.cognition.types import ConsolidatedAssessment, ModelEvidence
from app.detection.rule_engine import RuleResult, evaluate_rules
from ml.schema import FEATURE_NAMES


def make_record() -> dict[str, object]:
    return {
        name: (
            "tcp" if name == "protocol_type" else
            "http" if name == "service" else
            "SF" if name == "flag" else
            0
        )
        for name in FEATURE_NAMES
    }


def make_model(
    *,
    status: str = "available",
    predicted_class: int | None = 1,
    probability: float | None = 0.85,
    error_code: str | None = None,
) -> ModelEvidence:
    if status == "unavailable":
        return cast(
            ModelEvidence,
            {
                "status": "unavailable",
                "predicted_class": None,
                "predicted_label": None,
                "class_0_probability": None,
                "class_1_probability": None,
                "model_name": None,
                "model_version": None,
                "error_code": error_code or "MODEL_UNAVAILABLE",
            },
        )
    assert predicted_class is not None
    assert probability is not None
    return {
        "status": "available",
        "predicted_class": predicted_class,
        "predicted_label": "attack" if predicted_class else "normal",
        "class_0_probability": 1 - probability,
        "class_1_probability": probability,
        "model_name": "test-model",
        "model_version": "test-version",
        "error_code": None,
    }


class FakeModelService:
    def __init__(self, evidence: ModelEvidence) -> None:
        self.evidence = evidence

    def predict(self, record: Mapping[str, object]) -> ModelEvidence:
        return self.evidence


class FakeOrchestrator:
    def __init__(
        self,
        assessment: ConsolidatedAssessment | None = None,
        error: Exception | None = None,
    ) -> None:
        self.assessment = assessment
        self.error = error
        self.calls: list[dict[str, object]] = []

    def assess(self, record: Mapping[str, object]) -> ConsolidatedAssessment:
        self.calls.append(dict(record))
        if self.error is not None:
            raise self.error
        if self.assessment is None:
            raise AssertionError("Fake assessment was not configured.")
        return self.assessment


def fail_rules(record: object) -> list[RuleResult]:
    raise RuntimeError("private rule error")


def make_orchestrator(
    *,
    model: ModelEvidence | None = None,
    rule_evaluator=None,
) -> AssessmentOrchestrator:
    return AssessmentOrchestrator(
        model_service=FakeModelService(model or make_model()),
        rule_evaluator=rule_evaluator
        if rule_evaluator is not None
        else evaluate_rules,
    )


class AssessmentEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(
            {
                "TESTING": True,
                "ASSESSMENT_ORCHESTRATOR": make_orchestrator(),
            }
        )
        self.client = self.app.test_client()

    def post_record(self, record: dict[str, object] | None = None):
        return self.client.post(
            "/api/v1/assessments",
            json=make_record() if record is None else record,
        )

    def test_health_endpoint_still_returns_api_status(self) -> None:
        response = self.client.get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_valid_record_returns_documented_assessment_contract(self) -> None:
        response = self.post_record()
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(payload),
            {"assessment", "handling_decision", "recommendations"},
        )
        self.assertEqual(
            set(payload["assessment"]),
            {"model", "rules", "reconciliation", "risk", "explanations"},
        )
        self.assertEqual(
            set(payload["handling_decision"]),
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
        self.assertEqual(payload["handling_decision"]["outcome"], "security_incident")
        self.assertTrue(payload["recommendations"])
        self.assertTrue(
            all(item["review_status"] == "pending" for item in payload["recommendations"])
        )
        self.assertNotIn("incident_id", payload)

    def test_response_preserves_evidence_and_handling_typed_dict_fields(self) -> None:
        payload = self.post_record().get_json()

        self.assertEqual(
            set(payload["assessment"]["model"]),
            {
                "status",
                "predicted_class",
                "predicted_label",
                "class_0_probability",
                "class_1_probability",
                "model_name",
                "model_version",
                "error_code",
            },
        )
        self.assertEqual(
            set(payload["assessment"]["rules"]),
            {"status", "results", "triggered_rule_ids", "error_code"},
        )
        self.assertEqual(
            set(payload["assessment"]["risk"]),
            {
                "status",
                "model_attack_probability",
                "model_score",
                "rule_score",
                "combined_score",
                "level",
                "policy_version",
            },
        )
        self.assertEqual(
            set(payload["recommendations"][0]),
            {
                "action_key",
                "description",
                "rationale",
                "evidence_references",
                "review_status",
            },
        )

    def test_missing_fields_return_400(self) -> None:
        record = make_record()
        del record["duration"]

        response = self.post_record(record)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_REQUEST")

    def test_unexpected_fields_return_400(self) -> None:
        record = make_record()
        record["attack"] = 1

        response = self.post_record(record)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_REQUEST")

    def test_malformed_json_returns_400(self) -> None:
        response = self.client.post(
            "/api/v1/assessments",
            data="{",
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_JSON")

    def test_non_object_json_returns_400(self) -> None:
        response = self.client.post("/api/v1/assessments", json=["not", "an object"])

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_REQUEST")

    def test_invalid_feature_values_return_400(self) -> None:
        record = make_record()
        record["duration"] = "not-numeric"

        response = self.post_record(record)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_FEATURES")

    def test_unavailable_model_evidence_is_preserved(self) -> None:
        orchestrator = make_orchestrator(
            model=make_model(
                status="unavailable",
                predicted_class=None,
                probability=None,
                error_code="MODEL_UNAVAILABLE",
            )
        )
        response = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client().post("/api/v1/assessments", json=make_record())

        self.assertEqual(response.status_code, 200)
        model = response.get_json()["assessment"]["model"]
        self.assertEqual(model["status"], "unavailable")
        self.assertEqual(model["error_code"], "MODEL_UNAVAILABLE")

    def test_unavailable_rule_evidence_is_preserved(self) -> None:
        orchestrator = make_orchestrator(rule_evaluator=fail_rules)
        response = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client().post("/api/v1/assessments", json=make_record())

        self.assertEqual(response.status_code, 200)
        rules = response.get_json()["assessment"]["rules"]
        self.assertEqual(rules["status"], "unavailable")
        self.assertEqual(rules["error_code"], "RULE_EVALUATION_ERROR")

    def test_processing_failure_is_not_reported_as_an_incident(self) -> None:
        orchestrator = make_orchestrator(
            model=make_model(
                status="unavailable",
                predicted_class=None,
                probability=None,
                error_code="MODEL_UNAVAILABLE",
            ),
            rule_evaluator=fail_rules,
        )
        response = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client().post("/api/v1/assessments", json=make_record())
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            payload["handling_decision"]["outcome"], "processing_failure"
        )
        self.assertFalse(
            payload["handling_decision"]["create_security_incident"]
        )
        self.assertNotIn("incident", payload)
        self.assertTrue(payload["recommendations"])

    def test_no_action_and_assessment_review_outcomes_are_preserved(self) -> None:
        cases = (
            (make_model(predicted_class=0, probability=0.1), "no_action"),
            (make_model(predicted_class=1, probability=0.55), "assessment_review"),
        )
        for model, expected_outcome in cases:
            with self.subTest(outcome=expected_outcome):
                orchestrator = make_orchestrator(model=model)
                response = create_app(
                    {
                        "TESTING": True,
                        "ASSESSMENT_ORCHESTRATOR": orchestrator,
                    }
                ).test_client().post(
                    "/api/v1/assessments", json=make_record()
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.get_json()["handling_decision"]["outcome"],
                    expected_outcome,
                )

    def test_unexpected_internal_error_is_sanitized(self) -> None:
        orchestrator = FakeOrchestrator(error=RuntimeError("private failure detail"))
        response = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client().post("/api/v1/assessments", json=make_record())

        self.assertEqual(response.status_code, 500)
        self.assertNotIn("private failure detail", response.get_data(as_text=True))
        self.assertEqual(
            response.get_json()["error"]["code"], "ASSESSMENT_PROCESSING_ERROR"
        )

    def test_injected_fake_orchestrator_is_used(self) -> None:
        assessment = make_orchestrator().assess(make_record())
        orchestrator = FakeOrchestrator(assessment=assessment)
        response = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client().post("/api/v1/assessments", json=make_record())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(orchestrator.calls, [make_record()])

    def test_default_orchestrator_is_constructed_once_per_app(self) -> None:
        assessment = make_orchestrator().assess(make_record())
        fake = FakeOrchestrator(assessment=assessment)
        with patch("app.AssessmentOrchestrator", return_value=fake) as constructor:
            app = create_app({"TESTING": True})
            client = app.test_client()
            client.post("/api/v1/assessments", json=make_record())
            client.post("/api/v1/assessments", json=make_record())

        constructor.assert_called_once_with()
        self.assertEqual(len(fake.calls), 2)

    def test_repeated_assessments_do_not_create_persistence_files(self) -> None:
        assessment = make_orchestrator().assess(make_record())
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "incidents.sqlite3"
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": str(database_path),
                    "ASSESSMENT_ORCHESTRATOR": FakeOrchestrator(
                        assessment=assessment
                    ),
                }
            )
            client = app.test_client()
            for _ in range(3):
                self.assertEqual(
                    client.post(
                        "/api/v1/assessments", json=make_record()
                    ).status_code,
                    200,
                )

            self.assertFalse(database_path.exists())


if __name__ == "__main__":
    unittest.main()
