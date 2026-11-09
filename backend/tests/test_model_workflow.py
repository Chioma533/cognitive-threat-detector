import tempfile
import unittest
from pathlib import Path

from ml.dataset import load_dataset
from ml.evaluate import evaluate_model
from ml.schema import CATEGORICAL_FEATURES, FEATURE_NAMES
from ml.train import (
    MODEL_NAME,
    create_model_artifact,
    load_model_artifact,
)
from tests.test_dataset import make_record


def write_dataset(path: Path, records: list[str]) -> None:
    path.write_text("\n".join(records), encoding="utf-8")


class ModelWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)
        self.artifact_path = self.directory / "nested" / "model.joblib"

        self.normal_record = make_record(
            categorical=("tcp", "http", "SF"),
            label="normal",
            difficulty="1",
            numeric_value="0",
        )
        self.attack_record = make_record(
            categorical=("udp", "private", "S0"),
            label="neptune",
            difficulty="2",
            numeric_value="10",
        )
        training_path = self.directory / "training.txt"
        write_dataset(
            training_path,
            [self.normal_record] * 4 + [self.attack_record] * 4,
        )
        self.training_data = load_dataset(training_path)

    def _create_artifact(self) -> None:
        create_model_artifact(self.training_data, self.artifact_path)

    def test_artifact_creation_and_loading(self) -> None:
        artifact = create_model_artifact(self.training_data, self.artifact_path)
        loaded = load_model_artifact(self.artifact_path)

        self.assertTrue(self.artifact_path.is_file())
        self.assertEqual(loaded["training_attack_labels"], {"neptune"})
        self.assertEqual(loaded["metadata"]["model_name"], MODEL_NAME)
        self.assertEqual(loaded["metadata"]["training_sample_count"], 8)
        self.assertIn("training_timestamp_utc", loaded["metadata"])
        self.assertEqual(
            artifact["pipeline"].named_steps["classifier"].random_state,
            42,
        )
        self.assertEqual(
            artifact["pipeline"].named_steps["preprocessing"]
            .named_transformers_["categorical"]
            .categories_[0].tolist(),
            ["tcp", "udp"],
        )

    def test_pipeline_predicts_from_features_without_label_or_difficulty(self) -> None:
        self._create_artifact()
        artifact = load_model_artifact(self.artifact_path)
        predictions = artifact["pipeline"].predict(
            (self.training_data.features[0], self.training_data.features[4])
        )

        self.assertEqual(predictions.tolist(), [0, 1])
        self.assertEqual(len(self.training_data.features[0]), len(FEATURE_NAMES))

    def test_evaluation_metrics_and_unseen_attack_breakdown(self) -> None:
        self._create_artifact()
        test_path = self.directory / "test.txt"
        write_dataset(
            test_path,
            [
                self.normal_record,
                self.attack_record,
                make_record(
                    categorical=("udp", "private", "S0"),
                    label="new_attack",
                    difficulty="3",
                    numeric_value="10",
                ),
                make_record(
                    categorical=("tcp", "http", "SF"),
                    label="new_attack",
                    difficulty="3",
                    numeric_value="0",
                ),
            ],
        )

        result = evaluate_model(load_dataset(test_path), self.artifact_path)

        self.assertEqual(result["total_samples"], 4)
        self.assertEqual(result["actual_class_counts"], {"normal": 1, "attack": 3})
        self.assertEqual(result["prediction_counts"], {"normal": 2, "attack": 2})
        self.assertEqual(result["true_positives"], 2)
        self.assertEqual(result["true_negatives"], 1)
        self.assertEqual(result["false_positives"], 0)
        self.assertEqual(result["false_negatives"], 1)
        self.assertEqual(result["metrics"]["accuracy"], 0.75)
        self.assertEqual(result["metrics"]["precision"], 1.0)
        self.assertEqual(result["metrics"]["recall"], 2 / 3)
        self.assertEqual(result["metrics"]["f1_score"], 0.8)
        self.assertEqual(result["confusion_matrix"]["matrix"], [[1, 0], [1, 2]])
        self.assertEqual(
            result["unseen_attack_evaluation"]["attack_labels"],
            [
                {
                    "label": "new_attack",
                    "sample_count": 2,
                    "predicted_as_attack": 1,
                    "predicted_as_normal": 1,
                    "detection_recall": 0.5,
                }
            ],
        )
        self.assertEqual(
            result["unseen_attack_evaluation"]["aggregate_detection_recall"],
            0.5,
        )
        self.assertIn("macro avg", result["classification_report"])


if __name__ == "__main__":
    unittest.main()
