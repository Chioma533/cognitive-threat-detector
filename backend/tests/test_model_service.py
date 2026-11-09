import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

from app.detection.model_service import (
    INCOMPATIBLE_MODEL_ARTIFACT,
    INFERENCE_ERROR,
    INVALID_INFERENCE_OUTPUT,
    MODEL_UNAVAILABLE,
    ModelInferenceService,
    ModelInputValidationError,
)
from ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ml.train import MODEL_NAME, MODEL_VERSION


def make_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        name: (
            "tcp" if name == "protocol_type" else
            "http" if name == "service" else
            "SF" if name == "flag" else
            0
        )
        for name in FEATURE_NAMES
    }
    record.update(overrides)
    return record


class FakePipeline:
    def __init__(
        self,
        prediction: object = (0,),
        probabilities: object = ((0.8, 0.2),),
        classes: object = (0, 1),
    ) -> None:
        self.prediction = prediction
        self.probabilities = probabilities
        self.named_steps = {"classifier": SimpleNamespace(classes_=classes)}
        self.predict_rows: list[object] = []
        self.probability_rows: list[object] = []

    def predict(self, rows: object) -> np.ndarray:
        self.predict_rows.append(rows)
        return np.asarray(self.prediction)

    def predict_proba(self, rows: object) -> np.ndarray:
        self.probability_rows.append(rows)
        return np.asarray(self.probabilities)


def make_artifact(pipeline: FakePipeline) -> dict[str, object]:
    return {
        "pipeline": pipeline,
        "metadata": {
            "model_name": MODEL_NAME,
            "model_version": MODEL_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
        },
    }


class ModelInferenceServiceTests(unittest.TestCase):
    def service_with(self, pipeline: FakePipeline) -> ModelInferenceService:
        with patch(
            "app.detection.model_service.load_model_artifact",
            return_value=make_artifact(pipeline),
        ):
            return ModelInferenceService()

    def test_successful_class_zero_prediction_and_metadata(self) -> None:
        pipeline = FakePipeline(prediction=(0,), probabilities=((0.8, 0.2),))
        service = self.service_with(pipeline)

        evidence = service.predict(make_record())

        self.assertEqual(evidence["status"], "available")
        self.assertEqual(evidence["predicted_class"], 0)
        self.assertEqual(evidence["predicted_label"], "normal")
        self.assertEqual(evidence["class_0_probability"], 0.8)
        self.assertEqual(evidence["class_1_probability"], 0.2)
        self.assertEqual(evidence["model_name"], MODEL_NAME)
        self.assertEqual(evidence["model_version"], MODEL_VERSION)
        self.assertIsNone(evidence["error_code"])

    def test_successful_class_one_prediction(self) -> None:
        pipeline = FakePipeline(prediction=(1,), probabilities=((0.1, 0.9),))
        evidence = self.service_with(pipeline).predict(make_record())

        self.assertEqual(evidence["predicted_class"], 1)
        self.assertEqual(evidence["predicted_label"], "attack")
        self.assertEqual(evidence["class_1_probability"], 0.9)

    def test_probability_columns_are_mapped_by_classifier_classes(self) -> None:
        pipeline = FakePipeline(
            prediction=(0,),
            probabilities=((0.75, 0.25),),
            classes=(1, 0),
        )
        evidence = self.service_with(pipeline).predict(make_record())

        self.assertEqual(evidence["predicted_class"], 0)
        self.assertEqual(evidence["class_0_probability"], 0.25)
        self.assertEqual(evidence["class_1_probability"], 0.75)

    def test_predict_class_remains_authoritative_over_probabilities(self) -> None:
        pipeline = FakePipeline(prediction=(0,), probabilities=((0.1, 0.9),))
        evidence = self.service_with(pipeline).predict(make_record())

        self.assertEqual(evidence["predicted_class"], 0)
        self.assertEqual(evidence["predicted_label"], "normal")

    def test_named_features_are_passed_in_canonical_order(self) -> None:
        record = dict(reversed(list(make_record().items())))
        pipeline = FakePipeline()
        evidence = self.service_with(pipeline).predict(record)

        expected_row = [[record[name] for name in FEATURE_NAMES]]
        self.assertEqual(pipeline.predict_rows, [expected_row])
        self.assertEqual(pipeline.probability_rows, [expected_row])
        self.assertEqual(evidence["status"], "available")

    def test_matching_schema_version_is_accepted(self) -> None:
        service = self.service_with(FakePipeline())

        self.assertEqual(service.predict(make_record())["status"], "available")

    def test_missing_or_incompatible_schema_version_is_rejected(self) -> None:
        for schema_version in (None, "unsupported-version"):
            artifact = make_artifact(FakePipeline())
            metadata = dict(artifact["metadata"])
            if schema_version is None:
                del metadata["feature_schema_version"]
            else:
                metadata["feature_schema_version"] = schema_version
            artifact["metadata"] = metadata

            with self.subTest(schema_version=schema_version):
                with patch(
                    "app.detection.model_service.load_model_artifact",
                    return_value=artifact,
                ):
                    evidence = ModelInferenceService().predict(make_record())

                self.assertEqual(evidence["status"], "unavailable")
                self.assertEqual(
                    evidence["error_code"], INCOMPATIBLE_MODEL_ARTIFACT
                )

    def test_missing_classifier_step_is_rejected(self) -> None:
        pipeline = FakePipeline()
        pipeline.named_steps = {}
        service = self.service_with(pipeline)

        evidence = service.predict(make_record())

        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["error_code"], INCOMPATIBLE_MODEL_ARTIFACT)

    def test_missing_prediction_methods_are_rejected(self) -> None:
        for method_name in ("predict", "predict_proba"):
            pipeline = FakePipeline()
            setattr(pipeline, method_name, None)
            with self.subTest(method=method_name):
                service = self.service_with(pipeline)
                evidence = service.predict(make_record())

                self.assertEqual(evidence["status"], "unavailable")
                self.assertEqual(
                    evidence["error_code"], INCOMPATIBLE_MODEL_ARTIFACT
                )

    def test_missing_and_invalid_input_are_rejected(self) -> None:
        service = self.service_with(FakePipeline())
        missing_record = make_record()
        del missing_record["duration"]

        with self.assertRaisesRegex(ModelInputValidationError, "duration"):
            service.predict(missing_record)
        for invalid_record in (
            make_record(protocol_type=42),
            make_record(duration=-1),
            make_record(count=1.5),
            make_record(serror_rate=float("nan")),
        ):
            with self.subTest(invalid_record=invalid_record):
                with self.assertRaises(ModelInputValidationError):
                    service.predict(invalid_record)

    def test_non_mapping_input_is_rejected(self) -> None:
        service = self.service_with(FakePipeline())
        with self.assertRaises(ModelInputValidationError):
            service.predict([])  # type: ignore[arg-type]

    def test_missing_artifact_returns_unavailable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing.joblib"
            service = ModelInferenceService(missing_path)

        evidence = service.predict(make_record())

        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["error_code"], MODEL_UNAVAILABLE)
        self.assertIsNone(evidence["predicted_class"])
        self.assertIsNone(evidence["class_1_probability"])

    def test_malformed_prediction_shape_returns_unavailable_evidence(self) -> None:
        service = self.service_with(FakePipeline(prediction=(0, 1)))

        evidence = service.predict(make_record())

        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["error_code"], INVALID_INFERENCE_OUTPUT)

    def test_malformed_probability_shape_returns_unavailable_evidence(self) -> None:
        service = self.service_with(
            FakePipeline(probabilities=((0.5,),))
        )

        evidence = service.predict(make_record())

        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["error_code"], INVALID_INFERENCE_OUTPUT)

    def test_unexpected_inference_exception_has_distinct_error_code(self) -> None:
        pipeline = FakePipeline()

        def fail_prediction(rows: object) -> np.ndarray:
            raise RuntimeError(f"failure for {len(rows)} rows")
        pipeline.predict = fail_prediction  # type: ignore[method-assign]
        evidence = self.service_with(pipeline).predict(make_record())

        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["error_code"], INFERENCE_ERROR)
        self.assertNotIn("failure for", str(evidence))

    def test_missing_expected_class_returns_unavailable_evidence(self) -> None:
        service = self.service_with(
            FakePipeline(probabilities=((1.0,),), classes=(0,))
        )

        evidence = service.predict(make_record())

        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["error_code"], INCOMPATIBLE_MODEL_ARTIFACT)

    def test_invalid_probabilities_return_unavailable_evidence(self) -> None:
        invalid_probabilities = (
            ((float("nan"), 0.0),),
            ((float("inf"), 0.0),),
            ((-0.1, 1.1),),
            ((0.2, 0.2),),
        )
        for probabilities in invalid_probabilities:
            with self.subTest(probabilities=probabilities):
                service = self.service_with(
                    FakePipeline(probabilities=probabilities)
                )

                evidence = service.predict(make_record())

                self.assertEqual(evidence["status"], "unavailable")
                self.assertEqual(evidence["error_code"], INVALID_INFERENCE_OUTPUT)

    def test_model_is_loaded_once_for_multiple_predictions(self) -> None:
        pipeline = FakePipeline()
        artifact = make_artifact(pipeline)
        with patch(
            "app.detection.model_service.load_model_artifact",
            return_value=artifact,
        ) as load_artifact:
            service = ModelInferenceService()
            service.predict(make_record())
            service.predict(make_record())

        load_artifact.assert_called_once()

    def test_input_record_is_not_mutated(self) -> None:
        record = make_record(service="unseen-service")
        original = copy.deepcopy(record)
        self.service_with(FakePipeline()).predict(record)

        self.assertEqual(record, original)


if __name__ == "__main__":
    unittest.main()
