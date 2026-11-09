import tempfile
import unittest
from pathlib import Path

from ml.dataset import load_dataset
from ml.preprocessing import fit_preprocessor
from ml.schema import CATEGORICAL_FEATURES, FEATURE_NAMES
from tests.test_dataset import make_record


class PreprocessingTests(unittest.TestCase):
    def _load_records(self, records: list[str]):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        path = Path(temporary_directory.name) / "sample.txt"
        path.write_text("\n".join(records), encoding="utf-8")
        return load_dataset(path)

    def test_encodes_categoricals_and_passes_numeric_features(self) -> None:
        training = self._load_records(
            [
                make_record(categorical=("tcp", "http", "SF"), numeric_value="1"),
                make_record(categorical=("udp", "domain", "S0"), numeric_value="2"),
            ]
        )

        preprocessor = fit_preprocessor(training)
        transformed = preprocessor.transform(training.features)
        feature_names = preprocessor.get_feature_names_out()

        self.assertEqual(transformed.shape[0], 2)
        self.assertIn("categorical__x2_http", feature_names)
        self.assertIn("categorical__x3_SF", feature_names)
        self.assertEqual(transformed.shape[1], len(feature_names))
        self.assertEqual(len(training.features[0]), len(FEATURE_NAMES))
        self.assertFalse(any("attack_label" in name for name in feature_names))
        self.assertFalse(any("difficulty" in name for name in feature_names))

    def test_unseen_categories_are_ignored_and_dimensions_remain_consistent(self) -> None:
        training = self._load_records(
            [make_record(categorical=("tcp", "http", "SF"))]
        )
        test = self._load_records(
            [make_record(categorical=("new_protocol", "new_service", "new_flag"))]
        )

        preprocessor = fit_preprocessor(training)
        fitted_categories = tuple(
            tuple(categories)
            for categories in preprocessor.named_transformers_["categorical"].categories_
        )
        training_matrix = preprocessor.transform(training.features)
        test_matrix = preprocessor.transform(test.features)

        self.assertEqual(training_matrix.shape[1], test_matrix.shape[1])
        self.assertEqual(fitted_categories, tuple(
            tuple(categories)
            for categories in preprocessor.named_transformers_["categorical"].categories_
        ))
        self.assertEqual(len(CATEGORICAL_FEATURES), 3)


if __name__ == "__main__":
    unittest.main()