# Phase 4 Report: Model Training and Evaluation

## 1. Overview

Phase 4 implements and executes a reproducible binary network-traffic classification workflow using the NSL-KDD dataset. The model distinguishes `normal` records from records labeled as any attack. It does **not** classify attack subtypes.

The reported training and evaluation runs completed successfully. The generated artifact is `backend/ml/artifacts/nsl_kdd_random_forest.joblib`.

## 2. Implemented components

- `backend/ml/train.py` loads the official `KDDTrain+.txt` file through the existing dataset loader, builds and fits a preprocessing-plus-classifier pipeline, and writes a Joblib artifact.
- `backend/ml/evaluate.py` loads that artifact and the official `KDDTest+.txt` file, predicts with the fitted pipeline, and computes binary classification metrics and unseen-attack detection results.
- `backend/tests/test_model_workflow.py` covers model artifact creation/loading, prediction, evaluation metrics, and unseen-attack evaluation.
- `backend/ml/schema.py` defines feature schema version `1.0.0`.

The artifact contains the complete fitted pipeline, the attack labels observed during training, and metadata for model identity, algorithm configuration, random seed, dataset filename, training sample count, feature schema version, and training timestamp.

## 3. Model architecture and configuration

The model is a scikit-learn `Pipeline` with:

1. The existing fitted `ColumnTransformer` preprocessing implementation. It one-hot encodes the categorical traffic fields and passes numeric traffic features through.
2. `RandomForestClassifier` with 100 estimators and `random_state=42`.

| Setting | Value |
|---|---|
| Model name | RandomForestClassifier |
| Model version | 1.0.0 |
| Number of estimators | 100 |
| Random seed | 42 |
| Feature schema version | 1.0.0 |
| Training dataset | `KDDTrain+.txt` |
| Training records | 125,973 |
| Training attack labels | 22 |
| Binary targets | `normal = 0`, attack = `1` |

The original attack label and difficulty column are excluded from model features. Original attack labels are retained as metadata for evaluation.

## 4. Training procedure

Training was run with:

```text
python -m ml.train
```

The workflow loads only the official training dataset, fits preprocessing and the Random Forest in one pipeline, and saves the artifact to:

```text
backend/ml/artifacts/nsl_kdd_random_forest.joblib
```

The official test dataset is not used in training or model selection.

## 5. Evaluation methodology

Evaluation was run with:

```text
python -m ml.evaluate
```

The evaluation loads the saved artifact and official test dataset, then calls the fitted pipeline for predictions without refitting preprocessing or the classifier. It reports accuracy, precision, recall, F1-score, a confusion matrix, a classification report, actual and predicted class counts, and TP/TN/FP/FN counts.

Unseen attack categories are test labels not present in the artifact’s training attack-label set. Their results are binary attack-detection metrics: predicted as attack versus predicted as normal. They do not measure subtype classification.

## 6. Overall evaluation results

| Measure | Result |
|---|---:|
| Test records | 22,544 |
| Actual normal records | 9,711 |
| Actual attack records | 12,833 |
| Accuracy | 0.778388928317956 |
| Precision | 0.9690005984440455 |
| Recall | 0.6308735291825762 |
| F1-score | 0.7642061544270342 |

## 7. Confusion matrix interpretation

| Actual \ Predicted | Normal (0) | Attack (1) |
|---|---:|---:|
| Normal (0) | 9,452 | 259 |
| Attack (1) | 4,737 | 8,096 |

- True negatives: 9,452
- False positives: 259
- False negatives: 4,737
- True positives: 8,096

The model correctly identifies many normal records and has high precision among predicted attacks. However, it misses 4,737 attack records, reflected in the attack recall of `0.6308735291825762`. This low recall is an important limitation: a substantial share of actual attacks is classified as normal.

## 8. Unseen-attack evaluation table

The evaluation covers 17 attack categories not observed during training. These are binary attack-detection results, not attack-subtype classification results.

| Attack label | Samples | Predicted attack | Predicted normal | Recall |
|---|---:|---:|---:|---:|
| apache2 | 737 | 442 | 295 | 59.97% |
| httptunnel | 133 | 3 | 130 | 2.26% |
| mailbomb | 293 | 0 | 293 | 0.00% |
| mscan | 996 | 323 | 673 | 32.43% |
| named | 17 | 1 | 16 | 5.88% |
| processtable | 685 | 8 | 677 | 1.17% |
| ps | 15 | 2 | 13 | 13.33% |
| saint | 319 | 314 | 5 | 98.43% |
| sendmail | 14 | 0 | 14 | 0.00% |
| snmpgetattack | 178 | 0 | 178 | 0.00% |
| snmpguess | 331 | 0 | 331 | 0.00% |
| sqlattack | 2 | 1 | 1 | 50.00% |
| udpstorm | 2 | 2 | 0 | 100.00% |
| worm | 2 | 0 | 2 | 0.00% |
| xlock | 9 | 0 | 9 | 0.00% |
| xsnoop | 4 | 1 | 3 | 25.00% |
| xterm | 13 | 3 | 10 | 23.08% |
| **Total** | **3,750** | **1,100** | **2,650** | **29.33333333333333%** |

Aggregate detection recall is low at 29.33333333333333%, with substantial variation by category. The model detected 98.43% of `saint` records, while several categories had 0% recall. The 100.00% recall for `udpstorm` is based on only two samples. Overall, these results indicate weak and uneven generalization to unseen attack types.

## 9. Findings and limitations

- This is a binary classifier, not an attack-subtype classifier. Attack names are used to group evaluation results, not predicted as separate classes.
- Overall attack recall is low (`0.6308735291825762`), with 4,737 false negatives on the official test set.
- Unseen-attack generalization is weak: aggregate recall is `0.29333333333333333` across 3,750 records in 17 attack categories.
- Individual unseen-attack category results are reported in Section 8. Detection performance varies substantially across categories, indicating limited and uneven generalization to attack types absent from the training dataset.
- Results reflect the NSL-KDD dataset and its official split; they do not establish effectiveness on contemporary or live network traffic.
- No live traffic monitoring, prediction API, rule engine, cognitive reasoning, or autonomous response capability is implemented by this phase.

## 10. Phase 4 completion status

Phase 4 training and evaluation implementation is complete. The model was trained, the official test evaluation completed, and the artifact was generated at `backend/ml/artifacts/nsl_kdd_random_forest.joblib`.

The full backend test suite result was **13 passed, 0 failed**.

Training and evaluation commands:

```text
python -m ml.train
python -m ml.evaluate
```

Phase 5 has not been started.
