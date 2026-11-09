"""Synchronous CSV batch assessment endpoint."""

import csv
import io
from collections.abc import Mapping
from typing import Protocol
from uuid import uuid4

from flask import Blueprint, current_app, request
from werkzeug.datastructures import FileStorage

from app.api.assessments import (
    _error_response,
    _serialize_assessment,
    _serialize_decision,
    _serialize_recommendation,
)
from app.cognition.types import ConsolidatedAssessment
from app.detection.input_validation import FeatureRecordValidationError
from app.incidents.policy import determine_assessment_handling
from app.incidents.recommendations import generate_recommendations
from ml.schema import (
    CATEGORICAL_FEATURES,
    COLUMN_NAMES,
    DIFFICULTY_COLUMN,
    FEATURE_NAMES,
    NUMERIC_FEATURES,
    ORIGINAL_ATTACK_LABEL_COLUMN,
)

batch_assessments_blueprint = Blueprint("batch_assessments", __name__)

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_RECORDS = 1000


class BatchRequestError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class InvalidBatchRow(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AssessmentRunner(Protocol):
    def assess(self, record: Mapping[str, object]) -> ConsolidatedAssessment:
        """Return the existing consolidated assessment contract."""


def _read_upload(upload: FileStorage) -> str:
    content = upload.stream.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise BatchRequestError(
            "UPLOAD_TOO_LARGE", "Uploaded CSV exceeds the 10 MiB file limit.", 413
        )
    if not content:
        raise BatchRequestError("EMPTY_FILE", "Uploaded CSV is empty.")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise BatchRequestError(
            "INVALID_ENCODING", "CSV must use UTF-8 encoding."
        ) from error


def _read_csv_rows(contents: str) -> tuple[str, tuple[str, ...], list[list[str]]]:
    reader = csv.reader(io.StringIO(contents, newline=""), strict=True)
    try:
        first_row = next(reader)
    except StopIteration:
        raise BatchRequestError("EMPTY_FILE", "CSV contains no data records.")
    except csv.Error as error:
        raise BatchRequestError("MALFORMED_CSV", "CSV syntax is invalid.") from error

    if not first_row:
        raise BatchRequestError(
            "INVALID_CSV_FORMAT", "CSV must begin with a supported record or header."
        )

    first_row = [value.strip() for value in first_row]
    if len(first_row) == len(FEATURE_NAMES):
        if (
            len(set(first_row)) != len(FEATURE_NAMES)
            or set(first_row) != set(FEATURE_NAMES)
        ):
            raise BatchRequestError(
                "INVALID_CSV_FORMAT",
                "Header must contain each canonical feature name exactly once.",
            )
        layout = "canonical"
        headers = tuple(first_row)
        rows: list[list[str]] = []
    elif len(first_row) == len(COLUMN_NAMES):
        numeric_header_matches = sum(
            first_row[index] == feature_name
            for index, feature_name in enumerate(COLUMN_NAMES)
            if feature_name in NUMERIC_FEATURES
        )
        has_official_metadata_headers = (
            ORIGINAL_ATTACK_LABEL_COLUMN in first_row
            or DIFFICULTY_COLUMN in first_row
        )
        if (
            first_row == list(COLUMN_NAMES)
            or numeric_header_matches >= len(NUMERIC_FEATURES) // 2
            or has_official_metadata_headers
        ):
            raise BatchRequestError(
                "INVALID_CSV_FORMAT",
                "Only the 41-feature canonical header format is supported.",
            )
        layout = "official"
        headers = COLUMN_NAMES
        rows = [first_row]
    else:
        raise BatchRequestError(
            "INVALID_CSV_FORMAT",
            "CSV must use the 43-column NSL-KDD layout or a 41-feature header.",
        )

    try:
        for row in reader:
            rows.append([value.strip() for value in row])
            if len(rows) > MAX_RECORDS:
                raise BatchRequestError(
                    "TOO_MANY_ROWS",
                    f"CSV exceeds the {MAX_RECORDS}-record limit.",
                    413,
                )
    except csv.Error as error:
        raise BatchRequestError("MALFORMED_CSV", "CSV syntax is invalid.") from error

    if not rows:
        raise BatchRequestError("EMPTY_FILE", "CSV contains no data records.")
    return layout, headers, rows


def _convert_row(
    layout: str, headers: tuple[str, ...], row: list[str]
) -> dict[str, object]:
    expected_columns = len(COLUMN_NAMES) if layout == "official" else len(FEATURE_NAMES)
    if len(row) != expected_columns:
        raise InvalidBatchRow(
            "INVALID_ROW",
            f"Row must contain exactly {expected_columns} columns.",
        )

    if layout == "official":
        values = dict(zip(headers, row))
        if not values[ORIGINAL_ATTACK_LABEL_COLUMN]:
            raise InvalidBatchRow(
                "INVALID_ROW", "attack_label must be a non-empty string."
            )
        try:
            int(values[DIFFICULTY_COLUMN])
        except ValueError as error:
            raise InvalidBatchRow(
                "INVALID_ROW", "difficulty must be an integer."
            ) from error
        raw_features = {
            name: values[name] for name in FEATURE_NAMES
        }
    else:
        raw_features = dict(zip(headers, row))

    converted: dict[str, object] = {}
    for name in FEATURE_NAMES:
        value = raw_features[name].strip()
        if name in CATEGORICAL_FEATURES:
            if not value:
                raise InvalidBatchRow(
                    "INVALID_FEATURES",
                    f"Feature '{name}' must be a non-empty string.",
                )
            converted[name] = value
            continue
        if name not in NUMERIC_FEATURES:
            raise RuntimeError(f"Feature schema is missing numeric field {name}.")
        if not value:
            raise InvalidBatchRow(
                "INVALID_FEATURES", f"Feature '{name}' must be numeric."
            )
        try:
            converted[name] = float(value)
        except (ValueError, OverflowError) as error:
            raise InvalidBatchRow(
                "INVALID_FEATURES", f"Feature '{name}' must be numeric."
            ) from error

    return converted


@batch_assessments_blueprint.post("/api/v1/assessments/batch")
def assess_batch():
    if "file" not in request.files:
        return _error_response("MISSING_FILE", "Multipart field 'file' is required.", 400)

    upload = request.files["file"]
    try:
        contents = _read_upload(upload)
        layout, headers, rows = _read_csv_rows(contents)
    except BatchRequestError as error:
        return _error_response(error.code, str(error), error.status)

    orchestrator: AssessmentRunner = current_app.extensions[
        "assessment_orchestrator"
    ]
    results: list[dict[str, object]] = []
    row_errors: list[dict[str, object]] = []
    processing_errors: list[dict[str, object]] = []
    prediction_counts = {"normal": 0, "attack": 0, "unavailable": 0}
    risk_level_counts = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "indeterminate": 0,
    }
    handling_outcome_counts = {
        "security_incident": 0,
        "assessment_review": 0,
        "no_action": 0,
        "processing_failure": 0,
    }

    for row_number, row in enumerate(rows, start=1):
        try:
            record = _convert_row(layout, headers, row)
        except InvalidBatchRow as error:
            row_errors.append(
                {
                    "row_number": row_number,
                    "code": error.code,
                    "message": str(error),
                }
            )
            continue

        try:
            assessment = orchestrator.assess(record)
            decision = determine_assessment_handling(assessment)
            recommendations = generate_recommendations(assessment, decision)
            result = {
                "row_number": row_number,
                "assessment": _serialize_assessment(assessment),
                "handling_decision": _serialize_decision(decision),
                "recommendations": [
                    _serialize_recommendation(item) for item in recommendations
                ],
            }
        except FeatureRecordValidationError as error:
            row_errors.append(
                {
                    "row_number": row_number,
                    "code": "INVALID_FEATURES",
                    "message": str(error),
                }
            )
            continue
        except Exception:
            current_app.logger.exception(
                "Batch assessment processing failed for data row %s.", row_number
            )
            processing_errors.append(
                {
                    "row_number": row_number,
                    "code": "ASSESSMENT_PROCESSING_ERROR",
                    "message": "Assessment processing failed for this row.",
                }
            )
            continue

        results.append(result)
        model = result["assessment"]["model"]
        if model["status"] == "unavailable":
            prediction_counts["unavailable"] += 1
        else:
            prediction_counts[model["predicted_label"]] += 1
        risk_level_counts[result["assessment"]["risk"]["level"]] += 1
        handling_outcome_counts[result["handling_decision"]["outcome"]] += 1

    assessed_count = len(results)
    invalid_count = len(row_errors)
    processing_error_count = len(processing_errors)
    return {
        "batch_id": str(uuid4()),
        "total_rows": len(rows),
        "assessed_rows": assessed_count,
        "invalid_rows": invalid_count,
        "processing_errors": processing_error_count,
        "prediction_counts": prediction_counts,
        "risk_level_counts": risk_level_counts,
        "handling_outcome_counts": handling_outcome_counts,
        "results": results,
        "row_errors": row_errors,
        "processing_errors_detail": processing_errors,
    }
