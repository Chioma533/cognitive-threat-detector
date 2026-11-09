import copy
import unittest
from unittest.mock import patch

from app.detection.rule_engine import (
    RuleInputValidationError,
    evaluate_rules,
)
from ml.schema import CATEGORICAL_FEATURES, FEATURE_NAMES, NUMERIC_FEATURES


RULE_IDS = (
    "RBD-AUTH-001",
    "RBD-PRIV-002",
    "RBD-COMP-003",
    "RBD-FRAG-004",
    "RBD-SYN-005",
    "RBD-SCAN-006",
    "RBD-REJ-007",
)


def make_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        feature_name: (
            "tcp" if feature_name == "protocol_type" else
            "http" if feature_name == "service" else
            "SF" if feature_name == "flag" else
            0
        )
        for feature_name in FEATURE_NAMES
    }
    record.update(overrides)
    return record


class RuleEngineTests(unittest.TestCase):
    def test_each_rule_triggers_at_its_threshold(self) -> None:
        examples = (
            ({"num_failed_logins": 1}, "RBD-AUTH-001"),
            ({"root_shell": 1}, "RBD-PRIV-002"),
            ({"su_attempted": 1}, "RBD-PRIV-002"),
            ({"num_compromised": 1}, "RBD-COMP-003"),
            ({"wrong_fragment": 1}, "RBD-FRAG-004"),
            (
                {
                    "serror_rate": 1,
                    "srv_serror_rate": 1,
                    "count": 256,
                },
                "RBD-SYN-005",
            ),
            ({"diff_srv_rate": 1, "count": 256}, "RBD-SCAN-006"),
            (
                {
                    "rerror_rate": 1,
                    "srv_rerror_rate": 1,
                    "count": 256,
                },
                "RBD-REJ-007",
            ),
        )

        for overrides, expected_rule_id in examples:
            with self.subTest(rule=expected_rule_id, overrides=overrides):
                results = evaluate_rules(make_record(**overrides))
                triggered_ids = [
                    result["rule_id"] for result in results if result["triggered"]
                ]
                self.assertIn(expected_rule_id, triggered_ids)

    def test_privilege_condition_thresholds(self) -> None:
        cases = (
            ({"root_shell": 0, "su_attempted": 0}, False),
            ({"root_shell": 1, "su_attempted": 0}, True),
            ({"root_shell": 0, "su_attempted": 1}, True),
        )
        for overrides, expected in cases:
            result = next(
                item
                for item in evaluate_rules(make_record(**overrides))
                if item["rule_id"] == "RBD-PRIV-002"
            )
            with self.subTest(overrides=overrides):
                self.assertEqual(result["triggered"], expected)

    def test_each_rule_does_not_trigger_below_threshold(self) -> None:
        examples = (
            ({"num_failed_logins": 0}, "RBD-AUTH-001"),
            ({"root_shell": 0, "su_attempted": 0}, "RBD-PRIV-002"),
            ({"num_compromised": 0}, "RBD-COMP-003"),
            ({"wrong_fragment": 0}, "RBD-FRAG-004"),
            (
                {
                    "serror_rate": 1,
                    "srv_serror_rate": 1,
                    "count": 255,
                },
                "RBD-SYN-005",
            ),
            ({"diff_srv_rate": 1, "count": 255}, "RBD-SCAN-006"),
            (
                {
                    "rerror_rate": 1,
                    "srv_rerror_rate": 1,
                    "count": 255,
                },
                "RBD-REJ-007",
            ),
        )

        for overrides, expected_rule_id in examples:
            with self.subTest(rule=expected_rule_id, overrides=overrides):
                results = evaluate_rules(make_record(**overrides))
                result = next(
                    item for item in results if item["rule_id"] == expected_rule_id
                )
                self.assertFalse(result["triggered"])

    def test_multi_feature_rules_require_every_condition(self) -> None:
        examples = (
            (
                "RBD-SYN-005",
                {"serror_rate": 1, "srv_serror_rate": 0, "count": 256},
            ),
            (
                "RBD-SYN-005",
                {"serror_rate": 0, "srv_serror_rate": 1, "count": 256},
            ),
            ("RBD-SCAN-006", {"diff_srv_rate": 0.999, "count": 256}),
            (
                "RBD-REJ-007",
                {"rerror_rate": 1, "srv_rerror_rate": 0, "count": 256},
            ),
            (
                "RBD-REJ-007",
                {"rerror_rate": 0, "srv_rerror_rate": 1, "count": 256},
            ),
        )

        for rule_id, overrides in examples:
            with self.subTest(rule=rule_id, overrides=overrides):
                result = next(
                    item
                    for item in evaluate_rules(make_record(**overrides))
                    if item["rule_id"] == rule_id
                )
                self.assertFalse(result["triggered"])

    def test_unsupported_rule_operator_is_rejected(self) -> None:
        unsupported_rule = (
            (
                "RBD-TEST-000",
                "Test rule",
                "low",
                (("num_failed_logins", "!=", 1),),
                "Test reason",
            ),
        )

        with patch("app.detection.rule_engine._RULES", unsupported_rule):
            with self.assertRaisesRegex(ValueError, "Unsupported rule operator: '!='"):
                evaluate_rules(make_record())

    def test_privilege_rule_preserves_both_condition_results(self) -> None:
        result = next(
            item
            for item in evaluate_rules(make_record(root_shell=1, su_attempted=0))
            if item["rule_id"] == "RBD-PRIV-002"
        )

        self.assertTrue(result["triggered"])
        self.assertEqual(
            [check["name"] for check in result["features_examined"]],
            ["root_shell", "su_attempted"],
        )
        self.assertEqual(
            [check["condition_met"] for check in result["features_examined"]],
            [True, False],
        )

    def test_threshold_values_immediately_below_and_above(self) -> None:
        cases = (
            ("num_failed_logins", 1, 0, 2, "RBD-AUTH-001"),
            ("num_compromised", 1, 0, 2, "RBD-COMP-003"),
            ("wrong_fragment", 1, 0, 2, "RBD-FRAG-004"),
            ("count", 256, 255, 257, "RBD-SCAN-006"),
        )

        for field, boundary, below, above, rule_id in cases:
            for value, expected in ((below, False), (boundary, True), (above, True)):
                overrides: dict[str, object] = {field: value}
                if rule_id == "RBD-SCAN-006":
                    overrides["diff_srv_rate"] = 1
                result = next(
                    item
                    for item in evaluate_rules(make_record(**overrides))
                    if item["rule_id"] == rule_id
                )
                with self.subTest(rule=rule_id, field=field, value=value):
                    self.assertEqual(result["triggered"], expected)

    def test_rate_threshold_boundaries(self) -> None:
        cases = (
            (
                "RBD-SYN-005",
                {
                    "serror_rate": 1,
                    "srv_serror_rate": 1,
                    "count": 256,
                },
                "serror_rate",
            ),
            (
                "RBD-SYN-005",
                {
                    "serror_rate": 1,
                    "srv_serror_rate": 1,
                    "count": 256,
                },
                "srv_serror_rate",
            ),
            (
                "RBD-SCAN-006",
                {"diff_srv_rate": 1, "count": 256},
                "diff_srv_rate",
            ),
            (
                "RBD-REJ-007",
                {"rerror_rate": 1, "srv_rerror_rate": 1, "count": 256},
                "rerror_rate",
            ),
            (
                "RBD-REJ-007",
                {"rerror_rate": 1, "srv_rerror_rate": 1, "count": 256},
                "srv_rerror_rate",
            ),
        )

        for rule_id, base, field in cases:
            for value, expected in ((0.999, False), (1, True)):
                overrides = dict(base)
                overrides[field] = value
                result = next(
                    item
                    for item in evaluate_rules(make_record(**overrides))
                    if item["rule_id"] == rule_id
                )
                with self.subTest(rule=rule_id, field=field, value=value):
                    self.assertEqual(result["triggered"], expected)

    def test_all_rules_return_in_stable_order_with_required_output_fields(self) -> None:
        expected_result_keys = {
            "rule_id",
            "triggered",
            "severity",
            "description",
            "features_examined",
            "reason",
        }
        expected_check_keys = {
            "name",
            "observed_value",
            "operator",
            "threshold",
            "condition_met",
        }

        first = evaluate_rules(make_record())
        second = evaluate_rules(make_record())

        self.assertEqual([item["rule_id"] for item in first], list(RULE_IDS))
        self.assertEqual(first, second)
        self.assertTrue(all(not item["triggered"] for item in first))
        for result in first:
            self.assertEqual(set(result), expected_result_keys)
            self.assertTrue(result["reason"])
            for check in result["features_examined"]:
                self.assertEqual(set(check), expected_check_keys)

    def test_multiple_rules_can_trigger_on_one_record(self) -> None:
        results = evaluate_rules(
            make_record(
                num_failed_logins=1,
                root_shell=1,
                su_attempted=1,
                num_compromised=1,
                wrong_fragment=1,
                serror_rate=1,
                srv_serror_rate=1,
                diff_srv_rate=1,
                rerror_rate=1,
                srv_rerror_rate=1,
                count=256,
            )
        )

        triggered_ids = [
            result["rule_id"] for result in results if result["triggered"]
        ]
        self.assertEqual(triggered_ids, list(RULE_IDS))

    def test_unseen_nonempty_categorical_values_are_accepted(self) -> None:
        results = evaluate_rules(
            make_record(
                protocol_type="future-protocol",
                service="future-service",
                flag="FUTURE",
            )
        )

        self.assertEqual([result["rule_id"] for result in results], list(RULE_IDS))

    def test_record_is_not_mutated(self) -> None:
        record = make_record(num_failed_logins=1, service="custom-service")
        original = copy.deepcopy(record)

        evaluate_rules(record)

        self.assertEqual(record, original)

    def test_missing_fields_are_rejected(self) -> None:
        for feature_name in FEATURE_NAMES:
            record = make_record()
            del record[feature_name]
            with self.subTest(feature=feature_name):
                with self.assertRaisesRegex(
                    RuleInputValidationError,
                    f"Missing required feature field.*{feature_name}",
                ):
                    evaluate_rules(record)

    def test_non_mapping_record_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuleInputValidationError, "must be a mapping"):
            evaluate_rules([])

    def test_invalid_numeric_values_are_rejected(self) -> None:
        invalid_values = (
            ("duration", "not-a-number"),
            ("duration", True),
            ("duration", -1),
            ("duration", 10**10000),
            ("count", 1.5),
            ("logged_in", 2),
            ("serror_rate", 1.01),
        )
        for feature_name, value in invalid_values:
            with self.subTest(feature=feature_name, value=value):
                with self.assertRaises(RuleInputValidationError):
                    evaluate_rules(make_record(**{feature_name: value}))

    def test_non_finite_numeric_values_are_rejected(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    RuleInputValidationError, "finite numeric value"
                ):
                    evaluate_rules(make_record(duration=value))

    def test_invalid_categorical_values_are_rejected(self) -> None:
        for feature_name in CATEGORICAL_FEATURES:
            for value in (None, 42, ""):
                with self.subTest(feature=feature_name, value=value):
                    with self.assertRaisesRegex(
                        RuleInputValidationError, "non-empty string"
                    ):
                        evaluate_rules(make_record(**{feature_name: value}))

    def test_numeric_schema_constants_cover_validation(self) -> None:
        self.assertEqual(set(NUMERIC_FEATURES), set(FEATURE_NAMES) - set(CATEGORICAL_FEATURES))


if __name__ == "__main__":
    unittest.main()
