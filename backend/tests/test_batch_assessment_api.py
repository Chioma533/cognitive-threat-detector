import csv
import io
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from uuid import UUID

from werkzeug.datastructures import FileStorage

from app import create_app
from app.api.batch_assessments import MAX_FILE_SIZE, MAX_RECORDS, _read_upload
from app.cognition.orchestrator import AssessmentOrchestrator
from app.cognition.types import ModelEvidence
from app.detection.input_validation import (
    FeatureRecordValidationError,
    validate_feature_record,
)
from app.detection.rule_engine import evaluate_rules
from ml.schema import (
    COLUMN_NAMES,
    DIFFICULTY_COLUMN,
    FEATURE_NAMES,
    NUMERIC_FEATURES,
    ORIGINAL_ATTACK_LABEL_COLUMN,
)


def make_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        name: (
            "tcp" if name == "protocol_type" else
            "http" if name == "service" else
            "SF" if name == "flag" else
            0.0 if name.endswith("_rate") else
            0
        )
        for name in FEATURE_NAMES
    }
    record.update(overrides)
    return record


def csv_text(rows: list[list[str]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return output.getvalue()


def official_row(
    record: Mapping[str, object] | None = None,
    *,
    attack_label: str = "normal",
    difficulty: str = "1",
) -> list[str]:
    values = record or make_record()
    return [str(values[name]) for name in FEATURE_NAMES] + [
        attack_label,
        difficulty,
    ]


def canonical_csv(
    rows: list[Mapping[str, object]],
    headers: tuple[str, ...] = FEATURE_NAMES,
) -> str:
    csv_rows = [list(headers)]
    csv_rows.extend([[str(record[name]) for name in headers] for record in rows])
    return csv_text(csv_rows)


class RoutingModel:
    def predict(self, record: Mapping[str, object]) -> ModelEvidence:
        if record["service"] in {"model-down", "both-down"}:
            return {
                "status": "unavailable",
                "predicted_class": None,
                "predicted_label": None,
                "class_0_probability": None,
                "class_1_probability": None,
                "model_name": None,
                "model_version": None,
                "error_code": "MODEL_UNAVAILABLE",
            }

        probability_by_bytes = {0: 0.1, 50: 0.55, 100: 0.85}
        probability = probability_by_bytes.get(int(record["src_bytes"]), 0.1)
        predicted_class = int(probability >= 0.5)
        return {
            "status": "available",
            "predicted_class": predicted_class,  # type: ignore[typeddict-item]
            "predicted_label": "attack" if predicted_class else "normal",
            "class_0_probability": 1.0 - probability,
            "class_1_probability": probability,
            "model_name": "test-model",
            "model_version": "test-version",
            "error_code": None,
        }


def route_rules(record: Mapping[str, object]):
    if record["service"] in {"rules-down", "both-down"}:
        raise RuntimeError("private rule failure")
    return evaluate_rules(record)


class RecordingOrchestrator:
    def __init__(self, *, fail_service: str | None = None) -> None:
        self.pipeline = AssessmentOrchestrator(
            model_service=RoutingModel(),
            rule_evaluator=route_rules,
        )
        self.fail_service = fail_service
        self.records: list[dict[str, object]] = []

    def assess(self, record: Mapping[str, object]):
        validate_feature_record(
            record, error_type=FeatureRecordValidationError
        )
        self.records.append(dict(record))
        if record["service"] == self.fail_service:
            raise RuntimeError("private assessment processing detail")
        return self.pipeline.assess(record)


class BatchAssessmentEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orchestrator = RecordingOrchestrator()
        self.app = create_app(
            {
                "TESTING": True,
                "ASSESSMENT_ORCHESTRATOR": self.orchestrator,
            }
        )
        self.client = self.app.test_client()

    def post_csv(self, content: str | bytes, filename: str = "traffic.csv"):
        data = content.encode("utf-8") if isinstance(content, str) else content
        return self.client.post(
            "/api/v1/assessments/batch",
            data={"file": (io.BytesIO(data), filename, "text/csv")},
            content_type="multipart/form-data",
        )

    def test_batch_route_requires_post_and_file(self) -> None:
        response = self.client.get("/api/v1/assessments/batch")
        self.assertEqual(response.status_code, 405)

        response = self.client.post(
            "/api/v1/assessments/batch",
            data={},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "MISSING_FILE")

    def test_empty_file_and_header_only_file_are_rejected(self) -> None:
        response = self.post_csv(b"")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "EMPTY_FILE")

        response = self.post_csv(csv_text([list(FEATURE_NAMES)]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "EMPTY_FILE")

    def test_invalid_utf8_and_malformed_csv_are_rejected(self) -> None:
        response = self.post_csv(b"\xff,\xfe\n")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_ENCODING")

        malformed = csv_text([list(FEATURE_NAMES)]) + '"' + ("x," * 40) + '"open\n'
        response = self.post_csv(malformed)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "MALFORMED_CSV")

    def test_official_format_maps_41_features_and_excludes_metadata(self) -> None:
        record = make_record(protocol_type="udp", service="future-service")
        response = self.post_csv(csv_text([official_row(
            record, attack_label="neptune", difficulty="7"
        )]))

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["total_rows"], 1)
        self.assertEqual(set(self.orchestrator.records[0]), set(FEATURE_NAMES))
        self.assertEqual(self.orchestrator.records[0]["protocol_type"], "udp")
        self.assertEqual(self.orchestrator.records[0]["service"], "future-service")
        self.assertNotIn("attack_label", str(payload))
        self.assertNotIn("difficulty", str(payload))
        UUID(payload["batch_id"])

    def test_headerless_official_row_accepts_category_values_matching_feature_names(
        self,
    ) -> None:
        record = make_record(
            protocol_type="duration",
            service="src_bytes",
            flag="count",
        )
        response = self.post_csv(csv_text([official_row(record)]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["assessed_rows"], 1)
        self.assertEqual(
            self.orchestrator.records[0]["protocol_type"], "duration"
        )
        self.assertEqual(self.orchestrator.records[0]["service"], "src_bytes")
        self.assertEqual(self.orchestrator.records[0]["flag"], "count")

    def test_unsupported_official_headers_are_rejected_before_assessment(self) -> None:
        malformed_headers = {
            "exact official header": list(COLUMN_NAMES),
            "misspelled feature": list(COLUMN_NAMES[:10])
            + ["wrong_fragment_typo"]
            + list(COLUMN_NAMES[11:]),
            "missing attack metadata name": list(COLUMN_NAMES[:-2])
            + ["label", COLUMN_NAMES[-1]],
            "altered difficulty metadata name": list(COLUMN_NAMES[:-1])
            + ["difficulty_level"],
        }
        for label, header in malformed_headers.items():
            with self.subTest(header=label):
                self.orchestrator.records.clear()
                response = self.post_csv(csv_text([header, official_row()]))

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json()["error"]["code"], "INVALID_CSV_FORMAT"
                )
                self.assertEqual(self.orchestrator.records, [])

    def test_official_metadata_headers_reject_header_when_numeric_match_threshold_fails(
        self,
    ) -> None:
        malformed_header = list(COLUMN_NAMES)
        numeric_indices = [
            index
            for index, name in enumerate(COLUMN_NAMES)
            if name in NUMERIC_FEATURES
        ]
        for index in numeric_indices[:20]:
            malformed_header[index] = f"{malformed_header[index]}_typo"

        numeric_header_matches = sum(
            malformed_header[index] == feature_name
            for index, feature_name in enumerate(COLUMN_NAMES)
            if feature_name in NUMERIC_FEATURES
        )
        self.assertLess(numeric_header_matches, len(NUMERIC_FEATURES) // 2)
        self.assertIn(ORIGINAL_ATTACK_LABEL_COLUMN, malformed_header)
        self.assertIn(DIFFICULTY_COLUMN, malformed_header)

        response = self.post_csv(
            csv_text([malformed_header, official_row()])
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "INVALID_CSV_FORMAT")
        self.assertEqual(self.orchestrator.records, [])

    def test_canonical_header_maps_by_name_in_arbitrary_order(self) -> None:
        record = make_record(duration=3, protocol_type="tcp", src_bytes=100)
        headers = tuple(reversed(FEATURE_NAMES))
        response = self.post_csv(canonical_csv([record], headers))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.orchestrator.records[0]["duration"], 3.0)
        self.assertEqual(self.orchestrator.records[0]["src_bytes"], 100.0)
        self.assertEqual(self.orchestrator.records[0]["protocol_type"], "tcp")

    def test_invalid_headers_and_unsupported_layouts_are_rejected(self) -> None:
        cases = {
            "duplicate": list(FEATURE_NAMES[:-1]) + [FEATURE_NAMES[0]],
            "missing": list(FEATURE_NAMES[:-1]) + ["unknown_feature"],
            "unknown": list(FEATURE_NAMES[:-1]) + ["unexpected"],
            "headerless 41": [str(make_record()[name]) for name in FEATURE_NAMES],
            "extra column": list(FEATURE_NAMES) + ["extra"],
            "official header": list(COLUMN_NAMES),
        }
        for label, first_row in cases.items():
            with self.subTest(layout=label):
                response = self.post_csv(csv_text([first_row]))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json()["error"]["code"], "INVALID_CSV_FORMAT"
                )
        self.assertEqual(self.orchestrator.records, [])

    def test_invalid_row_width_and_official_metadata_are_row_errors(self) -> None:
        good = official_row()
        bad_width = good[:-1]
        bad_label = official_row(attack_label=" ")
        bad_difficulty = official_row(difficulty="1.5")
        response = self.post_csv(
            csv_text([good, bad_width, bad_label, bad_difficulty, good])
        )

        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["total_rows"], 5)
        self.assertEqual(payload["assessed_rows"], 2)
        self.assertEqual(payload["invalid_rows"], 3)
        self.assertEqual([item["row_number"] for item in payload["results"]], [1, 5])
        self.assertEqual(
            [item["row_number"] for item in payload["row_errors"]], [2, 3, 4]
        )
        self.assertEqual(
            [item["code"] for item in payload["row_errors"]],
            ["INVALID_ROW", "INVALID_ROW", "INVALID_ROW"],
        )
        self.assertEqual(
            payload["total_rows"],
            payload["assessed_rows"]
            + payload["invalid_rows"]
            + payload["processing_errors"],
        )

    def test_numeric_conversion_errors_and_shared_constraints_are_row_errors(self) -> None:
        cases = (
            ("duration", ""),
            ("duration", "not-a-number"),
            ("duration", "true"),
            ("duration", "NaN"),
            ("duration", "Infinity"),
            ("duration", "1.5"),
            ("land", "2"),
            ("same_srv_rate", "1.1"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.orchestrator = RecordingOrchestrator()
                self.app = create_app(
                    {
                        "TESTING": True,
                        "ASSESSMENT_ORCHESTRATOR": self.orchestrator,
                    }
                )
                self.client = self.app.test_client()
                record = make_record()
                record[field] = value
                response = self.post_csv(canonical_csv([record]))
                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertEqual(payload["invalid_rows"], 1)
                self.assertEqual(payload["assessed_rows"], 0)
                self.assertEqual(
                    payload["row_errors"][0]["code"], "INVALID_FEATURES"
                )
                if value:
                    self.assertNotIn(value, payload["row_errors"][0]["message"])

    def test_empty_categorical_value_is_invalid_and_unseen_category_is_valid(self) -> None:
        empty_category = make_record(service="")
        unseen_category = make_record(
            protocol_type="future-protocol",
            service="future-service",
            flag="FUTURE",
        )
        response = self.post_csv(canonical_csv([empty_category, unseen_category]))
        payload = response.get_json()

        self.assertEqual(payload["assessed_rows"], 1)
        self.assertEqual(payload["invalid_rows"], 1)
        self.assertEqual(self.orchestrator.records[0]["service"], "future-service")

    def test_mixed_batch_returns_partial_results_and_actual_aggregate_counts(self) -> None:
        records = [
            make_record(src_bytes=0),
            make_record(src_bytes=50),
            make_record(src_bytes=100, num_failed_logins=1),
            make_record(service="model-down"),
            make_record(service="rules-down"),
            make_record(service="both-down"),
        ]
        response = self.post_csv(canonical_csv(records))
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["assessed_rows"], 6)
        self.assertEqual(payload["invalid_rows"], 0)
        self.assertEqual(payload["processing_errors"], 0)
        self.assertEqual(payload["prediction_counts"], {
            "normal": 2, "attack": 2, "unavailable": 2
        })
        self.assertEqual(payload["risk_level_counts"], {
            "low": 1, "medium": 1, "high": 1, "indeterminate": 3
        })
        self.assertEqual(payload["handling_outcome_counts"], {
            "security_incident": 1,
            "assessment_review": 3,
            "no_action": 1,
            "processing_failure": 1,
        })
        self.assertEqual(
            payload["handling_outcome_counts"]["security_incident"],
            sum(
                item["handling_decision"]["outcome"] == "security_incident"
                for item in payload["results"]
            ),
        )
        self.assertEqual(
            payload["prediction_counts"]["unavailable"],
            sum(
                item["assessment"]["model"]["status"] == "unavailable"
                for item in payload["results"]
            ),
        )
        self.assertTrue(all(
            recommendation["review_status"] == "pending"
            for result in payload["results"]
            for recommendation in result["recommendations"]
        ))

    def test_all_invalid_batch_returns_zero_counts_and_row_errors(self) -> None:
        first = make_record()
        second = make_record()
        first["duration"] = "bad"
        second["service"] = ""
        response = self.post_csv(canonical_csv([first, second]))
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["assessed_rows"], 0)
        self.assertEqual(payload["invalid_rows"], 2)
        self.assertEqual(payload["processing_errors"], 0)
        self.assertEqual(payload["results"], [])
        self.assertEqual(payload["prediction_counts"], {
            "normal": 0, "attack": 0, "unavailable": 0
        })
        self.assertEqual(payload["risk_level_counts"], {
            "low": 0, "medium": 0, "high": 0, "indeterminate": 0
        })

    def test_unexpected_row_error_is_isolated_and_sanitized(self) -> None:
        orchestrator = RecordingOrchestrator(fail_service="explode")
        client = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client()
        response = client.post(
            "/api/v1/assessments/batch",
            data={
                "file": (
                    io.BytesIO(canonical_csv([
                        make_record(service="explode"),
                        make_record(src_bytes=100),
                    ]).encode()),
                    "rows.csv",
                )
            },
            content_type="multipart/form-data",
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["total_rows"], 2)
        self.assertEqual(payload["assessed_rows"], 1)
        self.assertEqual(payload["processing_errors"], 1)
        self.assertEqual(payload["processing_errors_detail"][0]["row_number"], 1)
        self.assertEqual(
            payload["processing_errors_detail"][0]["code"],
            "ASSESSMENT_PROCESSING_ERROR",
        )
        self.assertNotIn("private assessment processing detail", str(payload))

    def test_counters_include_all_handling_outcomes(self) -> None:
        response = self.post_csv(canonical_csv([
            make_record(src_bytes=100),
            make_record(src_bytes=50),
            make_record(src_bytes=0),
            make_record(service="both-down"),
        ]))
        payload = response.get_json()

        self.assertEqual(payload["handling_outcome_counts"], {
            "security_incident": 1,
            "assessment_review": 1,
            "no_action": 1,
            "processing_failure": 1,
        })

    def test_file_size_limit_at_and_above_boundary(self) -> None:
        exact_file = FileStorage(stream=io.BytesIO(b"x" * MAX_FILE_SIZE))
        self.assertEqual(len(_read_upload(exact_file)), MAX_FILE_SIZE)

        too_large = b"x" * (MAX_FILE_SIZE + 1)
        response = self.post_csv(too_large)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()["error"]["code"], "UPLOAD_TOO_LARGE")
        self.assertEqual(self.orchestrator.records, [])

    def test_multipart_request_limit_returns_json_envelope(self) -> None:
        response = self.post_csv(b"x" * (11 * 1024 * 1024))

        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json()["error"]["code"], "UPLOAD_TOO_LARGE")
        self.assertEqual(self.orchestrator.records, [])

    def test_record_limit_at_and_above_boundary(self) -> None:
        rows = [make_record() for _ in range(MAX_RECORDS)]
        at_limit = self.post_csv(canonical_csv(rows))
        self.assertEqual(at_limit.status_code, 200)
        self.assertEqual(at_limit.get_json()["assessed_rows"], MAX_RECORDS)

        orchestrator = RecordingOrchestrator()
        self.client = create_app(
            {"TESTING": True, "ASSESSMENT_ORCHESTRATOR": orchestrator}
        ).test_client()
        over_limit = self.post_csv(canonical_csv(rows + [make_record()]))
        self.assertEqual(over_limit.status_code, 413)
        self.assertEqual(over_limit.get_json()["error"]["code"], "TOO_MANY_ROWS")
        self.assertEqual(orchestrator.records, [])

    def test_single_record_and_health_routes_remain_unchanged(self) -> None:
        health = self.client.get("/api/v1/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json(), {"status": "ok"})

        response = self.client.post(
            "/api/v1/assessments", json=make_record(src_bytes=100)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(response.get_json()),
            {"assessment", "handling_decision", "recommendations"},
        )

    def test_no_persistence_or_incident_service_is_initialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(
                {
                    "TESTING": True,
                    "ASSESSMENT_ORCHESTRATOR": self.orchestrator,
                    "DATABASE_PATH": Path(directory) / "incidents.sqlite3",
                }
            )
            client = app.test_client()
            response = client.post(
                "/api/v1/assessments/batch",
                data={
                    "file": (
                        io.BytesIO(canonical_csv([make_record()]).encode()),
                        "one.csv",
                    )
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(set(app.extensions), {"assessment_orchestrator"})
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
