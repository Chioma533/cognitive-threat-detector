"""Shared validation for canonical single-record NSL-KDD feature mappings."""

import math
from collections.abc import Mapping
from numbers import Real

from ml.schema import CATEGORICAL_FEATURES, FEATURE_NAMES

_RATE_FEATURES = frozenset(
    feature_name
    for feature_name in FEATURE_NAMES
    if feature_name.endswith("_rate")
)
_BINARY_FEATURES = frozenset(
    {"land", "logged_in", "root_shell", "is_host_login", "is_guest_login"}
)


class FeatureRecordValidationError(ValueError):
    """Raised when a record does not satisfy the NSL-KDD feature schema."""


def validate_feature_record(
    record: Mapping[str, object],
    *,
    error_type: type[FeatureRecordValidationError] = FeatureRecordValidationError,
) -> None:
    """Validate all canonical fields while ignoring any additional mapping keys."""
    if not isinstance(record, Mapping):
        raise error_type("Record must be a mapping of feature names to values.")

    missing_features = [name for name in FEATURE_NAMES if name not in record]
    if missing_features:
        raise error_type(
            "Missing required feature field(s): " + ", ".join(missing_features)
        )

    for feature_name in FEATURE_NAMES:
        value = record[feature_name]
        if feature_name in CATEGORICAL_FEATURES:
            if not isinstance(value, str) or not value.strip():
                raise error_type(
                    f"Feature '{feature_name}' must be a non-empty string."
                )
            continue

        if isinstance(value, bool) or not isinstance(value, Real):
            raise error_type(
                f"Feature '{feature_name}' must be a finite numeric value."
            )
        try:
            numeric_value = float(value)
        except OverflowError as error:
            raise error_type(
                f"Feature '{feature_name}' must be a finite numeric value."
            ) from error
        if not math.isfinite(numeric_value):
            raise error_type(
                f"Feature '{feature_name}' must be a finite numeric value."
            )
        if numeric_value < 0:
            raise error_type(f"Feature '{feature_name}' cannot be negative.")
        if feature_name in _RATE_FEATURES and numeric_value > 1:
            raise error_type(
                f"Rate feature '{feature_name}' must be between 0 and 1."
            )
        if feature_name in _BINARY_FEATURES and numeric_value not in (0, 1):
            raise error_type(f"Binary feature '{feature_name}' must be 0 or 1.")
        if feature_name not in _RATE_FEATURES and not numeric_value.is_integer():
            raise error_type(
                f"Count feature '{feature_name}' must be an integer value."
            )
