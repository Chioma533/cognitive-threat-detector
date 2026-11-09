# Phase 5 Report: Rule-Based Threat Detection

## 1. Overview and objective

Phase 5 implements independent, deterministic rule-based detection for one NSL-KDD feature record at a time. The rule engine validates the record against the canonical 41-feature schema and evaluates seven provisional detection rules. It returns a structured result for every rule, whether or not that rule triggers.

The rules provide explainable feature-level checks. Their thresholds are candidates for further review, not production-validated values.

## 2. Files created or modified

| File | Phase 5 role |
|---|---|
| `backend/app/detection/rule_engine.py` | Implements input validation, seven ordered rule definitions, condition evaluation, and structured results. |
| `backend/tests/test_rule_engine.py` | Contains 17 focused unit tests for rule behavior, validation, and output. |
| `backend/ml/schema.py` | Existing canonical feature schema used by the engine; not modified for Phase 5. |
| `backend/app/detection/__init__.py` | Existing package initializer; not modified for Phase 5. |
| `docs/PHASE_5_REPORT.md` | Created to document the implemented Phase 5 behavior and test results. |

The Phase 5 work does not modify the ML training pipeline, evaluation workflow, model artifact, or previous phase reports.

## 3. Rule engine architecture and ML independence

The public entry point, `evaluate_rules(record)`, accepts a mapping for one record. It uses `FEATURE_NAMES` and `CATEGORICAL_FEATURES` from `backend/ml/schema.py` to validate the input, then evaluates the rule definitions in a fixed order:

1. `RBD-AUTH-001`
2. `RBD-PRIV-002`
3. `RBD-COMP-003`
4. `RBD-FRAG-004`
5. `RBD-SYN-005`
6. `RBD-SCAN-006`
7. `RBD-REJ-007`

The engine imports schema constants only; it does not import or call the Random Forest or read or write a model artifact. This is a standalone rule evaluator, not an ML-and-rules ensemble or a live traffic detection service.

## 4. Implemented rules

| Rule ID | Condition | Severity |
|---|---|---|
| `RBD-AUTH-001` | `num_failed_logins >= 1` | low |
| `RBD-PRIV-002` | `root_shell == 1 OR su_attempted > 0` | low |
| `RBD-COMP-003` | `num_compromised >= 1` | medium |
| `RBD-FRAG-004` | `wrong_fragment >= 1` | medium |
| `RBD-SYN-005` | `serror_rate == 1 AND srv_serror_rate == 1 AND count >= 256` | high |
| `RBD-SCAN-006` | `diff_srv_rate == 1 AND count >= 256` | high |
| `RBD-REJ-007` | `rerror_rate == 1 AND srv_rerror_rate == 1 AND count >= 256` | medium |

All thresholds shown are provisional candidates. For rules with multiple conjunctive conditions, every condition must be met. `RBD-PRIV-002` uses OR: either condition can trigger the rule. Its output retains separate checks for `root_shell` and `su_attempted`.

## 5. Input validation

Before evaluating rules, the engine:

- Requires a mapping and all 41 feature fields from the canonical schema. Missing fields raise `RuleInputValidationError`; extra mapping keys are ignored.
- Requires `protocol_type`, `service`, and `flag` to be non-empty strings. Previously unseen strings are accepted; values are not required to appear in the training dataset.
- Requires every other feature to be a real numeric value, but not a boolean. Values that cannot be represented as finite numbers, including non-finite values and oversized integers, are rejected.
- Rejects negative numeric values, rates above 1 (rates are constrained to `[0, 1]`), non-integer-valued non-rate fields, and values other than 0 or 1 for the binary fields `land`, `logged_in`, `root_shell`, `is_host_login`, and `is_guest_login`.
- Does not substitute defaults or mutate the supplied record.

`su_attempted` is validated as a nonnegative integer-valued numeric feature, not as a binary field. This is consistent with the dataset inspection, which found valid values of 2 for that feature; any value above zero meets the rule condition.

Invalid input raises an explicit `RuleInputValidationError` rather than producing rule results from incomplete or normalized data.

## 6. Structured output

For each valid input, the engine returns a list containing exactly one result per rule in the stable order shown above. Each result contains:

- `rule_id`
- `triggered`
- `severity`
- `description`
- `features_examined`
- `reason`

Each entry in `features_examined` contains `name`, `observed_value`, `operator`, `threshold`, and `condition_met`. For `RBD-PRIV-002`, both feature checks are present even if only one condition is responsible for a trigger. A rule is marked triggered only when its complete condition is satisfied: all checks for AND rules, or at least one check for the privilege OR rule. Triggered results use the rule's explanatory reason; non-triggered results state that the complete condition was not met.

The output describes only the supplied record and rule checks. It does not add timestamps, IP addresses, or other context not present in the input.

## 7. Focused testing methodology and cases

`backend/tests/test_rule_engine.py` uses Python's `unittest` framework and a schema-shaped record helper. The 17 focused test cases are:

| Test case | Coverage |
|---|---|
| `test_each_rule_triggers_at_its_threshold` | Exercises all seven rules at their thresholds, including each alternative of the privilege rule. |
| `test_privilege_condition_thresholds` | Checks the privilege OR rule with neither condition, only `root_shell`, and only `su_attempted`. |
| `test_each_rule_does_not_trigger_below_threshold` | Confirms each rule remains untriggered below threshold, including count 255 for the high-count rules. |
| `test_multi_feature_rules_require_every_condition` | Checks that missing one required rate condition prevents SYN and rejection rules from triggering, and that a sub-threshold rate prevents the scan rule. |
| `test_privilege_rule_preserves_both_condition_results` | Confirms the privilege result contains distinct checks for both inputs and preserves their individual outcomes. |
| `test_threshold_values_immediately_below_and_above` | Checks values below, at, and above selected integer boundaries for login, compromise, fragment, and count conditions. |
| `test_rate_threshold_boundaries` | Checks rate values immediately below 1 and at 1 for each applicable rate condition. |
| `test_all_rules_return_in_stable_order_with_required_output_fields` | Checks deterministic ordering, repeatable output, required result/check fields, and a valid record triggering no rules. |
| `test_multiple_rules_can_trigger_on_one_record` | Confirms all seven rules can trigger for one record. |
| `test_unseen_nonempty_categorical_values_are_accepted` | Confirms new but valid categorical strings are accepted. |
| `test_record_is_not_mutated` | Confirms evaluation leaves the supplied mapping unchanged. |
| `test_missing_fields_are_rejected` | Removes each canonical feature in turn and expects validation failure. |
| `test_non_mapping_record_is_rejected` | Confirms non-mapping input is rejected. |
| `test_invalid_numeric_values_are_rejected` | Covers non-numeric, boolean, negative, oversized, fractional count, invalid binary, and out-of-range rate inputs. |
| `test_non_finite_numeric_values_are_rejected` | Confirms NaN and positive and negative infinity are rejected. |
| `test_invalid_categorical_values_are_rejected` | Confirms missing, non-string, and empty categorical values are rejected. |
| `test_numeric_schema_constants_cover_validation` | Checks the schema's numeric and categorical feature groups cover the feature names. |

Focused rule-engine result: **17 passed, 0 failed**.

## 8. Complete backend test results

The complete backend test suite result for Phase 5 is **30 passed, 0 failed**.

## 9. Known limitations

- **Provisional thresholds:** The rules and severity assignments are candidates, not calibrated or production-validated thresholds. No operational false-positive/false-negative rates or effectiveness claims are made for them.
- **Dataset scope:** The schema and rules target NSL-KDD features. That offline benchmark does not establish performance on contemporary, live network traffic or other telemetry formats. Dataset performance should not be treated as evidence of production detection effectiveness.
- **Dataset split caveat:** The repository's NSL-KDD inspection records 610 exact full records shared between the official train and test splits and 51 shared feature vectors with conflicting binary targets. This overlap is a limitation of interpreting dataset-based evaluation; Phase 5 does not change the supplied split or validate rule performance against it.
- **Per-record scope:** The engine evaluates one supplied feature record. It does not collect or aggregate live connections, maintain state across records, or correlate evidence across time or hosts.
- **No integrated response or reasoning:** There is no ML integration, cognitive reasoning, API workflow, alert persistence, or automated response in this phase.
- **Validation scope:** Validation enforces the schema and basic numeric constraints; it does not establish that an otherwise valid record is authentic, correctly measured, or representative of network activity.

## 10. Phase 5 completion status

Phase 5 rule-based detection implementation and its focused tests are complete. All seven rules, input validation, deterministic per-rule results, and non-mutation behavior are covered by the focused suite. The complete backend suite result is **30 passed, 0 failed**.

Threshold review and validation against operational data remain future work. Live network monitoring, ML integration, cognitive reasoning, and response actions are not implemented by Phase 5.
