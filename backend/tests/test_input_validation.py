import unittest

from app.detection.input_validation import (
    FeatureRecordValidationError,
    validate_feature_record,
)
from ml.schema import CATEGORICAL_FEATURES, FEATURE_NAMES


def make_record() -> dict[str, object]:
    return {
        name: "unseen-value" if name in CATEGORICAL_FEATURES else 0
        for name in FEATURE_NAMES
    }


class SharedInputValidationTests(unittest.TestCase):
    def test_requires_all_canonical_fields_and_ignores_extra_keys(self) -> None:
        record = make_record()
        record["extra"] = object()
        validate_feature_record(record)

        del record["duration"]
        with self.assertRaisesRegex(
            FeatureRecordValidationError, "Missing required feature field.*duration"
        ):
            validate_feature_record(record)

    def test_accepts_valid_unseen_categorical_strings(self) -> None:
        validate_feature_record(
            {
                **make_record(),
                "protocol_type": "future-protocol",
                "service": "future-service",
                "flag": "FUTURE",
            }
        )

    def test_rejects_invalid_categorical_values(self) -> None:
        for feature in CATEGORICAL_FEATURES:
            for value in (None, 42, ""):
                record = make_record()
                record[feature] = value
                with self.subTest(feature=feature, value=value):
                    with self.assertRaises(FeatureRecordValidationError):
                        validate_feature_record(record)

    def test_rejects_invalid_numeric_values(self) -> None:
        invalid_values = (
            ("duration", True),
            ("duration", float("nan")),
            ("duration", float("inf")),
            ("duration", -1),
            ("count", 1.5),
            ("logged_in", 2),
            ("serror_rate", 1.01),
            ("duration", 10**10000),
        )
        for feature, value in invalid_values:
            with self.subTest(feature=feature, value_type=type(value).__name__):
                record = make_record()
                record[feature] = value
                with self.assertRaises(FeatureRecordValidationError):
                    validate_feature_record(record)


if __name__ == "__main__":
    unittest.main()
