"""Single-record inference adapter for the persisted NSL-KDD model."""

import math
from collections.abc import Mapping
from numbers import Integral, Real
from pathlib import Path

import numpy as np

from app.cognition.types import ModelEvidence
from app.detection.input_validation import (
    FeatureRecordValidationError,
    validate_feature_record,
)
from ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ml.train import ARTIFACT_PATH, load_model_artifact

MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
INCOMPATIBLE_MODEL_ARTIFACT = "INCOMPATIBLE_MODEL_ARTIFACT"
INVALID_INFERENCE_OUTPUT = "INVALID_INFERENCE_OUTPUT"
INFERENCE_ERROR = "INFERENCE_ERROR"


class ModelInputValidationError(FeatureRecordValidationError):
    """Raised when an input record does not satisfy the NSL-KDD feature schema."""


class _InvalidInferenceOutput(Exception):
    """Indicates malformed or unusable model prediction output."""


def _is_binary_classes(classes: object) -> bool:
    class_values = np.asarray(classes)
    if class_values.ndim != 1 or class_values.shape != (2,):
        return False

    values: list[int] = []
    for value in class_values:
        if isinstance(value, (bool, np.bool_)) or not isinstance(value, Integral):
            return False
        values.append(int(value))
    return set(values) == {0, 1}


def _validate_record(record: Mapping[str, object]) -> None:
    validate_feature_record(record, error_type=ModelInputValidationError)


class ModelInferenceService:
    """Load a fitted model once and produce validated evidence for each record."""

    def __init__(self, artifact_path: str | Path = ARTIFACT_PATH) -> None:
        self._pipeline: object | None = None
        self._metadata: dict[str, object] | None = None
        self._error_code: str | None = None
        try:
            artifact = load_model_artifact(artifact_path)
        except Exception:
            self._error_code = MODEL_UNAVAILABLE
        else:
            metadata = artifact["metadata"]
            self._metadata = metadata if isinstance(metadata, dict) else None
            if (
                self._metadata is None
                or self._metadata.get("feature_schema_version")
                != FEATURE_SCHEMA_VERSION
            ):
                self._error_code = INCOMPATIBLE_MODEL_ARTIFACT
            elif not self._has_compatible_inference_interface(
                artifact["pipeline"]
            ):
                self._error_code = INCOMPATIBLE_MODEL_ARTIFACT
            else:
                self._pipeline = artifact["pipeline"]

    @staticmethod
    def _has_compatible_inference_interface(pipeline: object) -> bool:
        try:
            if not callable(getattr(pipeline, "predict", None)) or not callable(
                getattr(pipeline, "predict_proba", None)
            ):
                return False

            named_steps = getattr(pipeline, "named_steps", None)
            if not isinstance(named_steps, Mapping):
                return False
            classifier = named_steps.get("classifier")
            return classifier is not None and _is_binary_classes(
                getattr(classifier, "classes_", None)
            )
        except Exception:
            return False

    def predict(self, record: Mapping[str, object]) -> ModelEvidence:
        """Validate one record and return evidence without masking bad inputs."""
        if not isinstance(record, Mapping):
            raise ModelInputValidationError(
                "Record must be a mapping of feature names to values."
            )
        _validate_record(record)

        if self._error_code is not None or self._pipeline is None:
            return self._unavailable(self._error_code or MODEL_UNAVAILABLE)

        row = [[record[name] for name in FEATURE_NAMES]]
        try:
            predicted_class, class_0_probability, class_1_probability = (
                self._run_inference(row)
            )
        except _InvalidInferenceOutput:
            return self._unavailable(INVALID_INFERENCE_OUTPUT)
        except Exception:
            return self._unavailable(INFERENCE_ERROR)

        return {
            "status": "available",
            "predicted_class": predicted_class,
            "predicted_label": "normal" if predicted_class == 0 else "attack",
            "class_0_probability": class_0_probability,
            "class_1_probability": class_1_probability,
            "model_name": self._metadata_value("model_name"),
            "model_version": self._metadata_value("model_version"),
            "error_code": None,
        }

    def _run_inference(
        self, row: list[list[object]]
    ) -> tuple[int, float, float]:
        pipeline = self._pipeline
        if pipeline is None:
            raise _InvalidInferenceOutput

        raw_predictions = np.asarray(pipeline.predict(row))  # type: ignore[attr-defined]
        if raw_predictions.shape != (1,):
            raise _InvalidInferenceOutput
        raw_prediction = raw_predictions[0]
        if isinstance(raw_prediction, (bool, np.bool_)) or not isinstance(
            raw_prediction, Integral
        ):
            raise _InvalidInferenceOutput
        predicted_class = int(raw_prediction)
        if predicted_class not in (0, 1):
            raise _InvalidInferenceOutput

        classifier = pipeline.named_steps["classifier"]  # type: ignore[attr-defined]
        classes = np.asarray(classifier.classes_)
        if not _is_binary_classes(classes):
            raise _InvalidInferenceOutput
        class_values: list[int] = []
        for value in classes:
            class_values.append(int(value))

        raw_probabilities = np.asarray(pipeline.predict_proba(row))  # type: ignore[attr-defined]
        if raw_probabilities.shape != (1, len(class_values)):
            raise _InvalidInferenceOutput

        probabilities: dict[int, float] = {}
        for class_value, raw_probability in zip(
            class_values, raw_probabilities[0]
        ):
            if isinstance(raw_probability, (bool, np.bool_)) or not isinstance(
                raw_probability, Real
            ):
                raise _InvalidInferenceOutput
            probability = float(raw_probability)
            if not math.isfinite(probability) or not 0 <= probability <= 1:
                raise _InvalidInferenceOutput
            probabilities[class_value] = probability

        if not math.isclose(
            sum(probabilities.values()), 1.0, rel_tol=0.0, abs_tol=1e-6
        ):
            raise _InvalidInferenceOutput

        return (
            predicted_class,
            probabilities[0],
            probabilities[1],
        )

    def _metadata_value(self, key: str) -> str | None:
        value = self._metadata.get(key) if self._metadata is not None else None
        return value if isinstance(value, str) else None

    def _unavailable(self, error_code: str) -> ModelEvidence:
        evidence: ModelEvidence = {
            "status": "unavailable",
            "predicted_class": None,
            "predicted_label": None,
            "class_0_probability": None,
            "class_1_probability": None,
            "model_name": self._metadata_value("model_name"),
            "model_version": self._metadata_value("model_version"),
            "error_code": error_code,
        }
        return evidence
