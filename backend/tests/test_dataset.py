import tempfile
import unittest
from pathlib import Path

from ml.dataset import (
    DatasetValidationError,
    TEST_DATA_PATH,
    TRAIN_DATA_PATH,
    load_dataset,
)
from ml.schema import (
    CATEGORICAL_FEATURES,
    COLUMN_NAMES,
    FEATURE_NAMES,
    NUMERIC_FEATURES,
)


def make_record(
    *,
    categorical: tuple[str, str, str] = ("tcp", "http", "SF"),
    label: str = "normal",
    difficulty: str = "1",
    numeric_value: str = "0",
) -> str:
    values = []
    categorical_values = dict(zip(CATEGORICAL_FEATURES, categorical))
    for feature_name in FEATURE_NAMES:
        values.append(
            categorical_values.get(feature_name, numeric_value)
        )
    values.extend((label, difficulty))
    return ",".join(values)


class DatasetSchemaTests(unittest.TestCase):
    def test_schema_has_canonical_order_and_43_columns(self) -> None:
        self.assertEqual(len(FEATURE_NAMES), 41)
        self.assertEqual(FEATURE_NAMES[:4], ("duration", "protocol_type", "service", "flag"))
        self.assertEqual(FEATURE_NAMES[-1], "dst_host_srv_rerror_rate")
        self.assertEqual(CATEGORICAL_FEATURES, ("protocol_type", "service", "flag"))
        self.assertEqual(len(NUMERIC_FEATURES), 38)
        self.assertEqual(len(COLUMN_NAMES), 43)
        self.assertEqual(COLUMN_NAMES[-2:], ("attack_label", "difficulty"))

    def test_loads_official_files_with_expected_record_counts(self) -> None:
        for path, expected_count in (
            (TRAIN_DATA_PATH, 125_973),
            (TEST_DATA_PATH, 22_544),
        ):
            with self.subTest(path=path.name):
                dataset = load_dataset(path)
                self.assertEqual(len(dataset), expected_count)
                self.assertEqual(len(dataset.features[0]), 41)
                self.assertEqual(dataset.row_numbers[0], 1)
                self.assertEqual(dataset.row_numbers[-1], expected_count)

    def test_maps_targets_and_preserves_labels_and_difficulty(self) -> None:
        contents = "\n".join(
            (
                make_record(label="normal", difficulty="2"),
                make_record(label="neptune", difficulty="7"),
                make_record(label="new_attack", difficulty="10"),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text(contents, encoding="utf-8")

            dataset = load_dataset(path)

        self.assertEqual(dataset.targets, (0, 1, 1))
        self.assertEqual(dataset.attack_labels, ("normal", "neptune", "new_attack"))
        self.assertEqual(dataset.difficulties, (2, 7, 10))
        self.assertEqual(dataset.row_numbers, (1, 2, 3))
        self.assertEqual(len(dataset.features), 3)
        self.assertEqual(len(dataset.features[0]), 41)

    def test_rejects_invalid_column_count_with_row_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "short.txt"
            path.write_text("a,b,c\n", encoding="utf-8")

            with self.assertRaisesRegex(
                DatasetValidationError, r"short\.txt row 1: expected 43 columns, found 3"
            ):
                load_dataset(path)

    def test_rejects_missing_values(self) -> None:
        record = make_record().split(",")
        record[FEATURE_NAMES.index("service")] = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.txt"
            path.write_text(",".join(record), encoding="utf-8")

            with self.assertRaisesRegex(
                DatasetValidationError, r"row 1: column 'service' is missing or empty"
            ):
                load_dataset(path)

    def test_rejects_invalid_numeric_and_difficulty_values(self) -> None:
        invalid_numeric = make_record().split(",")
        invalid_numeric[0] = "not-a-number"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-number.txt"
            path.write_text(",".join(invalid_numeric), encoding="utf-8")
            with self.assertRaisesRegex(
                DatasetValidationError, r"feature 'duration' must be numeric"
            ):
                load_dataset(path)

            path = Path(directory) / "invalid-difficulty.txt"
            path.write_text(make_record(difficulty="1.5"), encoding="utf-8")
            with self.assertRaisesRegex(
                DatasetValidationError, r"column 'difficulty' must be an integer"
            ):
                load_dataset(path)

    def test_rejects_empty_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.txt"
            path.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(
                DatasetValidationError, "dataset contains no records"
            ):
                load_dataset(path)


if __name__ == "__main__":
    unittest.main()