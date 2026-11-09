"""Train and persist the NSL-KDD binary Random Forest model."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from ml.dataset import NSLKDDDataset, load_training_dataset
from ml.preprocessing import create_preprocessor
from ml.schema import FEATURE_SCHEMA_VERSION

ARTIFACT_PATH = (
    Path(__file__).resolve().parent / "artifacts" / "nsl_kdd_random_forest.joblib"
)
MODEL_NAME = "nsl-kdd-binary-random-forest"
MODEL_VERSION = "1.0.0"
RANDOM_SEED = 42
CLASSIFIER_CONFIGURATION = {
    "n_estimators": 100,
    "random_state": RANDOM_SEED,
}


def build_pipeline() -> Pipeline:
    """Create the preprocessing and classifier pipeline before fitting."""
    classifier = RandomForestClassifier(**CLASSIFIER_CONFIGURATION)
    return Pipeline(
        steps=[
            ("preprocessing", create_preprocessor()),
            ("classifier", classifier),
        ]
    )


def create_model_artifact(
    training_data: NSLKDDDataset,
    artifact_path: str | Path = ARTIFACT_PATH,
) -> dict[str, Any]:
    """Fit on the supplied training split and save a complete model artifact."""
    pipeline = build_pipeline()
    pipeline.fit(training_data.features, training_data.targets)

    metadata = {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "algorithm": "RandomForestClassifier",
        "algorithm_configuration": CLASSIFIER_CONFIGURATION.copy(),
        "random_seed": RANDOM_SEED,
        "training_dataset": training_data.source.name,
        "training_sample_count": len(training_data),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    artifact = {
        "pipeline": pipeline,
        "training_attack_labels": {
            label for label in training_data.attack_labels if label != "normal"
        },
        "metadata": metadata,
    }

    destination = Path(artifact_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, destination)
    return artifact


def load_model_artifact(artifact_path: str | Path = ARTIFACT_PATH) -> dict[str, Any]:
    """Load a persisted artifact and verify its required top-level fields."""
    artifact = joblib.load(artifact_path)
    required_keys = {"pipeline", "training_attack_labels", "metadata"}
    if not isinstance(artifact, dict) or not required_keys.issubset(artifact):
        raise ValueError(f"{artifact_path} is not a valid NSL-KDD model artifact.")
    if not isinstance(artifact["pipeline"], Pipeline):
        raise ValueError(f"{artifact_path} does not contain a scikit-learn Pipeline.")
    if not isinstance(artifact["training_attack_labels"], set):
        raise ValueError(f"{artifact_path} has an invalid training attack-label set.")
    if not isinstance(artifact["metadata"], dict):
        raise ValueError(f"{artifact_path} has invalid model metadata.")
    return artifact


def train_model(artifact_path: str | Path = ARTIFACT_PATH) -> dict[str, Any]:
    """Train using only the official training file and save its artifact."""
    training_data = load_training_dataset()
    return create_model_artifact(training_data, artifact_path)


def main() -> None:
    artifact = train_model()
    print(
        json.dumps(
            {
                "artifact_path": str(ARTIFACT_PATH),
                "metadata": artifact["metadata"],
                "training_attack_label_count": len(
                    artifact["training_attack_labels"]
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
