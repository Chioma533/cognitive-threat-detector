# Phase 3 Report: Dataset Loading, Schema Validation, and Preprocessing

**Status: Implemented and tested; review pending before Phase 4.** This report records the repository state verified on 2026-10-31. No model was trained.

## A. Phase Overview

Phase 3 loads the headerless NSL-KDD files, validates their 43-column records, separates the 41 traffic features from the attack label and difficulty metadata, derives a binary target, and provides reusable preprocessing for training and inference. This phase gives later training a consistent, validated input contract and keeps labels and metadata out of model inputs.

It follows the completed dataset inspection documented in [nsl-kdd-inspection.md](nsl-kdd-inspection.md) and precedes model training. The implementation and tests exist; Phase 4 remains blocked on review.

## B. Files Created or Modified

The following files were created or modified for Phase 3 and its documentation:

| File                                  | State    | Responsibility                                                                                                                         |
| ------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `backend/ml/__init__.py`              | Created  | Marks the ML utilities package.                                                                                                        |
| `backend/ml/schema.py`                | Created  | Defines the canonical ordered 41 features, categorical features, label and difficulty names, and complete 43-column schema.            |
| `backend/ml/dataset.py`               | Created  | Loads headerless files, validates records, separates model features and metadata, and derives binary targets without dropping records. |
| `backend/ml/preprocessing.py`         | Created  | Builds and fits a reusable `ColumnTransformer` from training data only.                                                                |
| `backend/tests/test_dataset.py`       | Created  | Tests schema, official-file loading, target/metadata behavior, and validation failures.                                                |
| `backend/tests/test_preprocessing.py` | Created  | Tests categorical encoding, excluded inputs, unknown categories, and consistent transformation dimensions.                             |
| `backend/requirements.txt`            | Modified | Declares `scikit-learn>=1.2,<2.0`.                                                                                                     |
| `docs/PROJECT_PROGRESS.md`            | Updated  | Records current project status and the Phase 4 review gate.                                                                            |
| `docs/PHASE_3_REPORT.md`              | Updated  | Records this implementation and verification.                                                                                          |

The existing Flask app factory, configuration, runner, health test, and frontend were not modified.

## C. Implementation Details

The implementation is in `backend/ml/`:

- **Loading and schema:** `schema.py` defines the canonical ordered 41 traffic features, three categorical names, the `attack_label` and `difficulty` metadata names, and the 43-column tuple. `dataset.py` reads headerless comma-delimited records with Python's `csv` module. `load_training_dataset()` and `load_test_dataset()` target the supplied files; `load_dataset(path)` supports test and other input paths. The verified official files contain 125,973 training rows and 22,544 test rows.
- **Feature and metadata split:** Each returned `NSLKDDDataset` holds 41-value feature rows separately from `targets`, `attack_labels`, `difficulties`, `row_numbers`, and `source`. Categorical features remain strings; the 38 numeric feature values are parsed as finite floats; difficulty is parsed as an integer.
- **Binary target:** `normal` maps to `0`; every other non-empty attack label maps to `1`. The original label is preserved independently in `attack_labels`.
- **Invalid or missing data:** A row must have exactly 43 columns. Empty fields, non-numeric/non-finite feature values, non-integer difficulty, and empty files raise `DatasetValidationError`. Messages include the source filename and row/column where applicable. Rows are never silently dropped. Categorical values need to be non-empty strings but are not restricted to categories observed in training.
- **Categorical encoding:** `preprocessing.py` creates a scikit-learn `ColumnTransformer` with `OneHotEncoder(handle_unknown="ignore")` for schema-derived indices of `protocol_type`, `service`, and `flag`; the 38 numeric columns use `passthrough` without scaling.
- **Training and inference reuse:** `fit_preprocessor(training_data)` fits the transformer only on `training_data.features`. The returned fitted transformer can be reused with `.transform(test_data.features)` and future 41-column feature rows; there is no separate fit on test data. Synthetic tests verify that unseen categories do not error and transformed dimensions stay consistent.
- **Excluded model inputs:** The transformer only receives the feature rows, which contain 41 values. The binary targets, original attack labels, and difficulty metadata are stored separately and cannot be selected as transformer inputs through this API.

## D. Testing and Verification

The table includes final Phase 3 runs and initial failures that were corrected. Focused and complete backend test commands ran from `backend/`; other rows identify their own command context.

| Test or verification                                                                                              | Expected result                                                                       | Actual result                                                                                                                                                                             | Status                       |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Focused dataset tests: `.venv/Scripts/python.exe -m unittest discover -s tests -p test_dataset.py -v`             | Validate schema, official-file loading, target mapping, metadata, and errors.         | 7 tests passed; the official training and test files loaded with 125,973 and 22,544 records.                                                                                              | Passed                       |
| Focused preprocessing tests: `.venv/Scripts/python.exe -m unittest discover -s tests -p test_preprocessing.py -v` | Verify categorical encoding, unknown categories, and reuse of fitted transformations. | 2 tests passed; training and test transformations had equal dimensions.                                                                                                                   | Passed                       |
| Complete backend suite: `.venv/Scripts/python.exe -m unittest discover -s tests -v`                               | Run all backend unit tests.                                                           | 10 tests passed, including the existing Flask health test.                                                                                                                                | Passed                       |
| `.venv/Scripts/python.exe -m pip check`                                                                           | Check installed package consistency.                                                  | No broken requirements found.                                                                                                                                                             | Passed                       |
| Pylance/editor diagnostics for new Python files                                                                   | Check for reported file errors.                                                       | No errors found in the schema, dataset, preprocessing, or new tests.                                                                                                                      | Passed                       |
| Initial focused preprocessing test run                                                                            | Detect loader and pipeline defects.                                                   | 2 errors: attack-label lookup used the feature-only schema. Fixed to index the canonical full schema; subsequent focused run passed.                                                      | Failed, fixed                |
| Intermediate focused preprocessing test run                                                                       | Verify the metadata lookup fix.                                                       | 1 test passed; 1 failed because the expected generated feature name used the wrong input index. The test assertion was corrected; final run passed.                                       | Failed, fixed                |
| Dependency inventory before install                                                                               | Identify missing dependencies in the selected backend venv.                           | `scikit-learn`, NumPy, SciPy, and pandas were absent; only scikit-learn was proposed/installed directly. NumPy and SciPy were installed transitively; pandas remains optional and absent. | Passed                       |
| Earlier backend test command from repository root                                                                 | Run existing backend tests.                                                           | Import failed because `app` was not on the root-level import path. Running discovery from `backend/` resolved it.                                                                         | Failed, invocation corrected |
| Earlier frontend `npm run build`                                                                                  | Build the unchanged frontend.                                                         | Passed on 2026-10-30; frontend was not changed or rebuilt for Phase 3.                                                                                                                    | Passed (prior check)         |
| Live Flask server smoke test                                                                                      | Start Flask and request `/api/v1/health` over HTTP.                                   | Not run; the existing health endpoint unit test passed in the backend suite.                                                                                                              | Not Run                      |

No tests remain failing. No model was trained. The frontend build and live-server smoke test were not repeated because Phase 3 did not modify the frontend or Flask routes.

## E. Problems Encountered

During the initial focused preprocessing run, the attack-label lookup incorrectly searched the feature-only schema and both tests errored. The loader was corrected to index the canonical 43-column schema. A subsequent run passed the unseen-category test but exposed an incorrect expected feature name in the other test; correcting that assertion produced a passing focused run. The current complete backend suite passes all 10 tests.

An earlier backend test command run from the repository root failed to import `app` because the backend directory was not on the import path. Running test discovery from `backend/` resolved the invocation issue. The selected virtual environment initially lacked scikit-learn, NumPy, and SciPy; scikit-learn was then installed into the project venv, bringing NumPy and SciPy transitively. pandas remains absent and is not required. No package was installed globally.

No unresolved test failure is known. A live HTTP smoke test was not run; the health endpoint's existing Flask test-client unit test passes. No model or fitted preprocessing artifact has been created.

## F. Technical Decisions and Justification

The implementation uses these decisions:

- **One canonical schema:** `schema.py` owns the ordered features, categorical/numeric groups, and metadata names, avoiding duplicated column definitions.
- **Strict row validation:** Wrong widths, blank cells, invalid numeric values, non-finite numerics, invalid difficulty values, and empty files raise row-aware errors. No record is silently discarded.
- **Separate metadata and target:** The immutable `NSLKDDDataset` keeps feature rows separate from binary targets, original attack labels, difficulty, and source row numbers. This preserves subtype analysis and avoids target/metadata leakage.
- **Column-aware preprocessing:** `ColumnTransformer` sends the three categorical columns through `OneHotEncoder` and passes numeric columns through. A manual encoder would require maintaining fitted category state separately.
- **Unknown categories:** `handle_unknown="ignore"` lets transformation continue for new categorical values while retaining the training-derived output shape.
- **Training-only fit:** `fit_preprocessor(training_data)` calls `fit` on the supplied object's features only. The caller must pass training data; the helper does not independently verify which split a dataset came from. Test/inference reuse uses `transform` on that fitted object.
- **No numeric scaling:** Numeric values pass through unchanged, matching the stated initial tree-based-model plan. Model selection and training are outside this phase.
- **CSV parser choice:** Python's standard `csv` module handles the headerless files without adding pandas.

## G. Current Limitations

Phase 3 provides validated feature rows and a reusable fitted transformer, but it does not train a model, persist a fitted transformer, or expose an inference/API workflow. `fit_preprocessor` relies on the caller to supply training data; it does not enforce that the `NSLKDDDataset.source` is the official training file. The tests verify train/test transformation consistency with small synthetic data, not a full transformation of the official test set. Model training, threat classification, cognitive reasoning, dashboard integration, persistence, and response execution remain unimplemented.

The existing Phase 2 inspection report records 610 exact full records shared between the official splits and 51 shared feature vectors with conflicting binary targets. This is an evaluation caveat to preserve and disclose later, not a reason to alter the supplied test set silently.

## H. Lessons and Explanation for Project Defence

- **Preprocessing** converts raw records into validated, consistently represented inputs for a later estimator. Here the loader enforces the schema, separates targets and metadata, and the fitted transformer one-hot encodes categories while passing numeric features through.
- **Headerless data** has no column-name row. The loader uses the canonical ordered schema to interpret all 43 values in every row; no data record is consumed as a header.
- **Separating 41 features from label and difficulty** preserves the boundary between observed traffic and information about the record. The original attack label is the answer to learn from; difficulty is dataset metadata. Including either in model inputs would contaminate the prediction task.
- **One-hot encoding** represents categorical values as separate indicator columns. It avoids treating names such as `tcp`, `udp`, and `icmp` as numeric magnitudes with an artificial ordering.
- **Fit on training data only** means the encoder learns its category-to-column mapping only from the object passed to `fit_preprocessor`. Tests confirm the fitted categories stay unchanged when training and test rows are transformed. The caller remains responsible for passing the training split to fit.
- **Unseen attack labels and binary classification:** The target depends only on whether the original label is `normal`. Therefore a non-empty test label not seen in training can still map to attack (`1`). This does not mean the model can identify that specific attack subtype; it only addresses the binary normal/attack task.
- **Keep the official test set out of training:** It is reserved to estimate performance on separate examples after training and model selection. Training or fitting preprocessing on it would weaken that evaluation. The inspection report also records cross-split overlap that must be disclosed when interpreting results.

## I. Next Steps Before Phase 4

1. Review the Phase 3 schema, loader, preprocessing API, and verified test results before approving Phase 4.
2. Decide whether Phase 4 needs an explicit guard tying transformer fitting to the official training file or a train/validation split. The current helper trusts its `training_data` argument.
3. After review only, define the model-training and evaluation workflow. Keep the official test split out of fitting; Phase 3 has not trained or evaluated a model.
