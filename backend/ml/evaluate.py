"""Evaluate a saved NSL-KDD model on the official test split."""

import json
from pathlib import Path
from typing import Any

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from ml.dataset import NSLKDDDataset, load_test_dataset
from ml.train import ARTIFACT_PATH, load_model_artifact


def evaluate_model(
    test_data: NSLKDDDataset | None = None,
    artifact_path: str | Path = ARTIFACT_PATH,
) -> dict[str, Any]:
    """Evaluate the persisted pipeline without fitting any preprocessing/model."""
    dataset = test_data if test_data is not None else load_test_dataset()
    artifact = load_model_artifact(artifact_path)
    pipeline = artifact["pipeline"]

    predictions = pipeline.predict(dataset.features)
    actual = dataset.targets
    matrix = confusion_matrix(actual, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(matrix[0, 0]),
        int(matrix[0, 1]),
        int(matrix[1, 0]),
        int(matrix[1, 1]),
    )

    attack_labels = artifact["training_attack_labels"]
    unseen_attack_metrics: list[dict[str, Any]] = []
    unseen_actual: list[int] = []
    unseen_predictions: list[int] = []
    for label in sorted(set(dataset.attack_labels) - attack_labels - {"normal"}):
        indices = [
            index
            for index, observed_label in enumerate(dataset.attack_labels)
            if observed_label == label
        ]
        label_predictions = [int(predictions[index]) for index in indices]
        predicted_as_attack = sum(prediction == 1 for prediction in label_predictions)
        sample_count = len(indices)
        unseen_attack_metrics.append(
            {
                "label": label,
                "sample_count": sample_count,
                "predicted_as_attack": predicted_as_attack,
                "predicted_as_normal": sample_count - predicted_as_attack,
                "detection_recall": (
                    predicted_as_attack / sample_count if sample_count else 0.0
                ),
            }
        )
        unseen_actual.extend(int(actual[index]) for index in indices)
        unseen_predictions.extend(label_predictions)

    unseen_sample_count = len(unseen_actual)
    unseen_detected_count = sum(prediction == 1 for prediction in unseen_predictions)
    actual_counts = {
        "normal": sum(target == 0 for target in actual),
        "attack": sum(target == 1 for target in actual),
    }
    prediction_counts = {
        "normal": sum(int(prediction) == 0 for prediction in predictions),
        "attack": sum(int(prediction) == 1 for prediction in predictions),
    }

    return {
        "model_metadata": artifact["metadata"],
        "total_samples": len(dataset),
        "actual_class_counts": actual_counts,
        "prediction_counts": prediction_counts,
        "metrics": {
            "accuracy": float(accuracy_score(actual, predictions)),
            "precision": float(
                precision_score(actual, predictions, zero_division=0)
            ),
            "recall": float(recall_score(actual, predictions, zero_division=0)),
            "f1_score": float(f1_score(actual, predictions, zero_division=0)),
        },
        "confusion_matrix": {
            "labels": ["normal (0)", "attack (1)"],
            "matrix": matrix.tolist(),
        },
        "true_positives": true_positive,
        "true_negatives": true_negative,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "classification_report": classification_report(
            actual,
            predictions,
            labels=[0, 1],
            target_names=["normal", "attack"],
            output_dict=True,
            zero_division=0,
        ),
        "unseen_attack_evaluation": {
            "attack_labels": unseen_attack_metrics,
            "total_samples": unseen_sample_count,
            "predicted_as_attack": unseen_detected_count,
            "predicted_as_normal": unseen_sample_count - unseen_detected_count,
            "aggregate_detection_recall": (
                unseen_detected_count / unseen_sample_count
                if unseen_sample_count
                else 0.0
            ),
        },
    }


def main() -> None:
    result = evaluate_model()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
