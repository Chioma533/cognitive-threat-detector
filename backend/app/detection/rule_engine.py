"""Independent, per-record rule evaluation for NSL-KDD traffic features."""

from collections.abc import Mapping
from typing import Literal, TypedDict

from app.detection.input_validation import (
    FeatureRecordValidationError,
    validate_feature_record,
)

Severity = Literal["low", "medium", "high"]


class FeatureCheck(TypedDict):
    name: str
    observed_value: object
    operator: str
    threshold: int | float
    condition_met: bool


class RuleResult(TypedDict):
    rule_id: str
    triggered: bool
    severity: Severity
    description: str
    features_examined: list[FeatureCheck]
    reason: str


class RuleInputValidationError(FeatureRecordValidationError):
    """Raised when a record does not satisfy the NSL-KDD feature schema."""


_RULES: tuple[
    tuple[str, str, Severity, tuple[tuple[str, str, int | float], ...], str],
    ...,
] = (
    (
        "RBD-AUTH-001",
        "Failed login evidence",
        "low",
        (("num_failed_logins", ">=", 1),),
        "One or more failed login attempts were recorded.",
    ),
    (
        "RBD-PRIV-002",
        "Privilege-shell evidence",
        "low",
        (("root_shell", "==", 1), ("su_attempted", ">", 0)),
        "A root shell was recorded or a su attempt was made.",
    ),
    (
        "RBD-COMP-003",
        "Compromise-condition evidence",
        "medium",
        (("num_compromised", ">=", 1),),
        "One or more compromise-related conditions were recorded.",
    ),
    (
        "RBD-FRAG-004",
        "Fragment anomaly",
        "medium",
        (("wrong_fragment", ">=", 1),),
        "One or more wrong IP fragments were recorded.",
    ),
    (
        "RBD-SYN-005",
        "Dense SYN-error pattern",
        "high",
        (
            ("serror_rate", "==", 1),
            ("srv_serror_rate", "==", 1),
            ("count", ">=", 256),
        ),
        "Both SYN-error rates are 1 and the connection count is at least 256.",
    ),
    (
        "RBD-SCAN-006",
        "Dense diverse-service pattern",
        "high",
        (("diff_srv_rate", "==", 1), ("count", ">=", 256)),
        "The different-service rate is 1 and the connection count is at least 256.",
    ),
    (
        "RBD-REJ-007",
        "Dense connection-rejection pattern",
        "medium",
        (
            ("rerror_rate", "==", 1),
            ("srv_rerror_rate", "==", 1),
            ("count", ">=", 256),
        ),
        "Both rejection rates are 1 and the connection count is at least 256.",
    ),
)


def _validate_record(record: Mapping[str, object]) -> None:
    validate_feature_record(record, error_type=RuleInputValidationError)


def evaluate_rules(record: Mapping[str, object]) -> list[RuleResult]:
    """Evaluate every configured rule against one validated feature record.

    Extra mapping keys are ignored; all canonical feature keys are required.
    """
    if not isinstance(record, Mapping):
        raise RuleInputValidationError("Record must be a mapping of feature names to values.")
    _validate_record(record)

    results: list[RuleResult] = []
    for rule_id, description, severity, conditions, reason in _RULES:
        feature_checks: list[FeatureCheck] = []
        for feature_name, operator, threshold in conditions:
            observed_value = record[feature_name]
            numeric_value = float(observed_value)
            if operator == ">=":
                condition_met = numeric_value >= threshold
            elif operator == ">":
                condition_met = numeric_value > threshold
            elif operator == "==":
                condition_met = numeric_value == threshold
            else:
                raise ValueError(f"Unsupported rule operator: {operator!r}")
            feature_checks.append(
                {
                    "name": feature_name,
                    "observed_value": observed_value,
                    "operator": operator,
                    "threshold": threshold,
                    "condition_met": condition_met,
                }
            )

        triggered = (
            any(check["condition_met"] for check in feature_checks)
            if rule_id == "RBD-PRIV-002"
            else all(check["condition_met"] for check in feature_checks)
        )
        results.append(
            {
                "rule_id": rule_id,
                "triggered": triggered,
                "severity": severity,
                "description": description,
                "features_examined": feature_checks,
                "reason": reason if triggered else "The complete rule condition was not met.",
            }
        )

    return results
