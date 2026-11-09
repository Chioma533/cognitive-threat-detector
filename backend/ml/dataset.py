"""Loading and validation for headerless NSL-KDD records."""

import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from ml.schema import (
    CATEGORICAL_FEATURES,
    COLUMN_NAMES,
    DIFFICULTY_COLUMN,
    FEATURE_NAMES,
    ORIGINAL_ATTACK_LABEL_COLUMN,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRAIN_DATA_PATH = PROJECT_ROOT / "data" / "KDDTrain+.txt"
TEST_DATA_PATH = PROJECT_ROOT / "data" / "KDDTest+.txt"

FeatureValue: TypeAlias = str | float


class DatasetValidationError(ValueError):
    """Raised when an NSL-KDD record does not satisfy the dataset schema."""


@dataclass(frozen=True)
class NSLKDDDataset:
    """Validated feature rows and their separate targets and metadata."""

    features: tuple[tuple[FeatureValue, ...], ...]
    targets: tuple[int, ...]
    attack_labels: tuple[str, ...]
    difficulties: tuple[int, ...]
    row_numbers: tuple[int, ...]
    source: Path

    def __len__(self) -> int:
        return len(self.targets)


def load_dataset(path: str | Path) -> NSLKDDDataset:
    """Load and validate a headerless NSL-KDD file without dropping records."""
    source = Path(path)
    features: list[tuple[FeatureValue, ...]] = []
    targets: list[int] = []
    attack_labels: list[str] = []
    difficulties: list[int] = []
    row_numbers: list[int] = []

    try:
        with source.open("r", encoding="utf-8", newline="") as dataset_file:
            reader = csv.reader(dataset_file)
            for row_number, raw_row in enumerate(reader, start=1):
                if len(raw_row) != len(COLUMN_NAMES):
                    raise DatasetValidationError(
                        f"{source.name} row {row_number}: expected "
                        f"{len(COLUMN_NAMES)} columns, found {len(raw_row)}."
                    )

                row = [value.strip() for value in raw_row]
                for column_name, value in zip(COLUMN_NAMES, row):
                    if not value:
                        raise DatasetValidationError(
                            f"{source.name} row {row_number}: column "
                            f"'{column_name}' is missing or empty."
                        )

                feature_values: list[FeatureValue] = []
                for column_name, value in zip(FEATURE_NAMES, row):
                    if column_name in CATEGORICAL_FEATURES:
                        feature_values.append(value)
                        continue

                    try:
                        numeric_value = float(value)
                    except ValueError as error:
                        raise DatasetValidationError(
                            f"{source.name} row {row_number}: feature "
                            f"'{column_name}' must be numeric; found {value!r}."
                        ) from error
                    if not math.isfinite(numeric_value):
                        raise DatasetValidationError(
                            f"{source.name} row {row_number}: feature "
                            f"'{column_name}' must be finite; found {value!r}."
                        )
                    feature_values.append(numeric_value)

                attack_label = row[COLUMN_NAMES.index(ORIGINAL_ATTACK_LABEL_COLUMN)]
                try:
                    difficulty = int(row[COLUMN_NAMES.index(DIFFICULTY_COLUMN)])
                except ValueError as error:
                    raise DatasetValidationError(
                        f"{source.name} row {row_number}: column "
                        f"'{DIFFICULTY_COLUMN}' must be an integer; "
                        f"found {row[-1]!r}."
                    ) from error

                features.append(tuple(feature_values))
                attack_labels.append(attack_label)
                targets.append(0 if attack_label == "normal" else 1)
                difficulties.append(difficulty)
                row_numbers.append(row_number)
    except csv.Error as error:
        raise DatasetValidationError(
            f"{source.name}: could not parse CSV data: {error}."
        ) from error

    if not features:
        raise DatasetValidationError(f"{source.name}: dataset contains no records.")

    return NSLKDDDataset(
        features=tuple(features),
        targets=tuple(targets),
        attack_labels=tuple(attack_labels),
        difficulties=tuple(difficulties),
        row_numbers=tuple(row_numbers),
        source=source,
    )


def load_training_dataset() -> NSLKDDDataset:
    """Load the official NSL-KDD training file."""
    return load_dataset(TRAIN_DATA_PATH)


def load_test_dataset() -> NSLKDDDataset:
    """Load the official NSL-KDD test file."""
    return load_dataset(TEST_DATA_PATH)