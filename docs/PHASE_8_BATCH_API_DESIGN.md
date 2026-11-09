# Phase 8: CSV Batch Assessment API Design

## Status and source basis

This is a proposal only. No endpoint or source files were changed.

The design is based on `backend/ml/schema.py`, `backend/ml/dataset.py`,
`backend/ml/preprocessing.py`, `backend/app/api/assessments.py`,
`backend/app/cognition/orchestrator.py`,
`backend/app/incidents/policy.py`,
`backend/app/incidents/recommendations.py`, and their dataset,
preprocessing, orchestrator, input-validation, and single-assessment API tests.

## 1. Proposed endpoint and HTTP contract

Add:

```text
POST /api/v1/assessments/batch
Content-Type: multipart/form-data
```

The multipart form has one required field named `file`, containing a UTF-8 CSV.
Multipart upload is recommended over JSON batches because the frontend's
intended input is a dataset file and this avoids requiring clients to first
parse and re-encode potentially large CSV data. JSON remains the contract for
the existing single-record `POST /api/v1/assessments`.

The batch endpoint is synchronous and in-memory, with proposed limits of
**10 MiB for the uploaded CSV file** and **1,000 data records**. Flask's
`MAX_CONTENT_LENGTH` applies to the complete HTTP request body, including
multipart boundaries and headers, not only the uploaded file. Set it to
**11 MiB** (10 MiB file allowance plus up to 1 MiB multipart overhead), then
independently check the actual uploaded file byte count against **10 MiB**.
Thus, a valid 10 MiB file with ordinary multipart framing is accepted, while
both the file and total request remain bounded. Requests with more than 1 MiB
of multipart overhead exceed the request cap. These are initial prototype
safeguards, not measured capacity or production limits. Exceeding either limit
rejects the batch before assessment.

Do not change or redirect the single-record endpoint.

## 2. CSV format and column mapping

`backend/ml/schema.py` defines 41 feature fields in canonical `FEATURE_NAMES`
order, of which `protocol_type`, `service`, and `flag` are categorical. It also
defines `COLUMN_NAMES` as those 41 features followed by `attack_label` and
`difficulty`, for 43 columns total.

Support two unambiguous CSV layouts:

1. **Official NSL-KDD layout:** headerless, exactly 43 columns per row in
   `COLUMN_NAMES` order. Map the first 41 positions to `FEATURE_NAMES`. Validate
   that `attack_label` is non-empty and `difficulty` is an integer for format
   consistency, then discard both metadata fields. They must not be sent to the
   model, used for triage, or returned in row assessment results.
2. **Canonical feature-header layout:** a header row containing exactly the 41
   `FEATURE_NAMES`, each once. Map values by header name, so a client may order
   these feature columns differently. Do not allow metadata or arbitrary extra
   columns in this layout.

Do not accept a headerless 41-column file: without a header, its column order
would be an implicit client assumption rather than a declared format. Do not
silently treat an unrecognized first row as a header. Reject duplicate,
missing, or unknown headers and any row with a column count inconsistent with
the selected layout.

### CSV scalar conversion

CSV parsers yield strings, but the existing feature validator expects Python
strings for categorical fields and `numbers.Real` values for numeric fields.
Conversion is therefore an explicit step before calling the orchestrator:

1. Parse a CSV row.
2. Map its columns to the canonical feature names, by position for the
   headerless 43-column format or by name for the 41-column header format.
3. Keep the three fields in `CATEGORICAL_FEATURES` as trimmed strings. Do not
   parse category text as numbers; reject empty categorical values.
4. For fields in the authoritative `NUMERIC_FEATURES` tuple, convert their
   trimmed textual values to Python `float`, matching
   `ml.dataset.load_dataset()`. The existing validator accepts finite `Real`
   numbers, so this is a compatible Python numeric type for all feature fields.
5. Integer-constrained numeric features are determined by the actual shared
   validator: numeric fields whose names do not end in `_rate` must have an
   integer-valued number; `_rate` fields may be fractional. This behavior is
   derived from `FEATURE_NAMES`/`_RATE_FEATURES`, while binary fields are
   separately constrained by the validator's existing binary-feature set. The
   dataset loader itself parses feature numerics as floats; it does not define
   a separate integer Python type for count features. Preserve that convention:
   do not truncate or round fractional values. Pass the parsed numeric values
   through so `validate_feature_record` rejects fractional values in
   integer-constrained fields.
6. Reject empty numeric strings, invalid numeric strings, and textual boolean
   substitutes such as `true`/`false`; do not coerce them into numbers.
   Conversion errors become row-level validation errors. Do not substitute
   zero, null, or another default.
7. Leave converted `NaN` and infinity as non-finite floats so the existing
   shared validator rejects them; do not normalize them or replace them.
8. Pass a mapping containing exactly the converted 41 features to
   `AssessmentOrchestrator`. Its existing `validate_feature_record` remains the
   authority for numeric type, finiteness, nonnegative, rate, binary, integer,
   and categorical constraints.

The dataset loader's `float` conversion is the source convention for numeric
CSV features, but it does not itself enforce the shared API validator's
nonnegative, rate, binary, or integral-count constraints. The endpoint must
continue to rely on `validate_feature_record` for those rules, rather than
duplicating or weakening them.

For official NSL-KDD rows, validate `attack_label` as a non-empty trimmed
string and convert `difficulty` using the existing dataset convention
(`int(...)`), rejecting values that cannot be parsed as an integer. Convert the
41 feature fields using the sequence above. Neither metadata field is part of
the orchestrator's input mapping, triage, or result JSON.

Existing `load_dataset()` is specifically for the 43-column headerless training
and test dataset and rejects the whole file at its first invalid row. It is
useful as a reference for the schema, but does not implement the partial-row
failure behavior proposed here.

## 3. Request and response examples

### Request

```sh
curl -X POST http://127.0.0.1:5000/api/v1/assessments/batch \
  -F "file=@traffic.csv;type=text/csv"
```

A canonical-header CSV starts with the exact canonical feature names. The
abbreviated header below is illustrative only; a real request must contain all
41 names:

```csv
duration,protocol_type,service,flag,src_bytes,...,dst_host_srv_rerror_rate
0,tcp,http,SF,181,...,0
```

An official headerless NSL-KDD row contains all 41 feature values followed by
its attack label and integer difficulty. Those last two columns are excluded
from the assessment input and response.

### Response envelope

For a parsed batch with some invalid rows, return HTTP 200 with valid
assessments and row-level errors. This is a batch result, not an all-or-nothing
transaction. The following illustrates the proposed envelope; the contents of
`assessment`, `handling_decision`, and `recommendations` use the exact
single-record endpoint contracts and are omitted here for brevity:

```json
{
  "batch_id": "server-generated UUID",
  "total_rows": 2,
  "assessed_rows": 1,
  "invalid_rows": 1,
  "processing_errors": 0,
  "prediction_counts": {
    "normal": 0,
    "attack": 1,
    "unavailable": 0
  },
  "risk_level_counts": {
    "low": 0,
    "medium": 0,
    "high": 1,
    "indeterminate": 0
  },
  "handling_outcome_counts": {
    "security_incident": 1,
    "assessment_review": 0,
    "no_action": 0,
    "processing_failure": 0
  },
  "results": [
    {
      "row_number": 1,
      "assessment": "(same contract as POST /api/v1/assessments)",
      "handling_decision": "(same contract as POST /api/v1/assessments)",
      "recommendations": "(same contract as POST /api/v1/assessments)"
    }
  ],
  "row_errors": [
    {
      "row_number": 2,
      "code": "INVALID_FEATURES",
      "message": "A concise validation message identifying the bad field."
    }
  ],
  "processing_errors_detail": []
}
```

The quoted descriptions above are explanatory placeholders, not literal API
values. Real row results should contain the corresponding objects returned by
the existing single-record contract. Row numbers are one-based CSV data-record
indices, excluding a header row when present. `batch_id` is a newly generated
request correlation identifier; it does not imply persistence.

`prediction_counts` is derived from each successfully assessed result's model
evidence: available `predicted_label` values increment `normal` or `attack`;
unavailable model evidence increments `unavailable`. `risk_level_counts` and
`handling_outcome_counts` are likewise counted from returned successful
assessment and handling objects. Initialize all documented bins to zero. Do
not include invalid rows or unexpected processing failures in these counts.

`total_rows` counts parsed data records, including invalid records.
`assessed_rows` counts records for which assessment, handling, and
recommendation generation completed. `invalid_rows` is the count of row-level
format or feature validation failures. `processing_errors` counts rows where
unexpected internal assessment/triage/recommendation processing failed.
Therefore `total_rows` equals the sum of those three counts.

## 4. Validation and partial-failure policy

Validate request-level structure before processing:

- Require multipart `file`, non-empty upload, UTF-8-decodable content, and
  syntactically parseable CSV.
- Enforce upload and row limits before assessing records.
- Require one of the two exact layouts above.
- Reject empty files, header-only files, and files with no data records.
- Reject malformed CSV syntax and an invalid or ambiguous header as a
  request-level error; do not begin inference when the overall format cannot be
  determined.

For a structurally valid CSV, validate each row independently:

- Incorrect per-row column counts, empty feature fields, failed scalar
  conversion, invalid numeric or categorical values, non-finite numbers,
  invalid metadata, and shared validator failures become row errors.
  `attack_label` and `difficulty` validation applies only to official
  43-column rows.
- Report the one-based data-record row number, stable error code, and safe,
  concise message. Do not include raw exception representations or an entire
  row of potentially sensitive submitted data.
- Continue with other valid rows. One invalid row must not discard successful
  results.
- If all data rows are invalid, return HTTP 200 with zero assessed rows and row
  errors; this is a syntactically accepted batch containing no assessable rows.

Treat an unexpected failure during one record's assessment/policy/recommendation
as a row-scoped `ASSESSMENT_PROCESSING_ERROR`, log the detail server-side, and
continue with later rows. Such a failure must not be counted as an unavailable
model or rules result: those expected operational conditions are represented by
the existing source statuses and error codes in a successful assessment.

## 5. Processing strategy

Use sequential processing in the Flask request worker. For each validated row:

1. Parse the row, map columns, convert categorical/numeric CSV strings to
   correctly typed values, and build the 41-feature mapping.
2. Call the app-scoped `AssessmentOrchestrator.assess(record)`. Its shared
   validator applies the established feature constraints.
3. Call `determine_assessment_handling(assessment)`.
4. Call `generate_recommendations(assessment, decision)`.
5. Append the row-numbered result and update aggregate counters from that
   actual returned result.

This reuses the established one-record path and does not duplicate detection,
risk, reconciliation, triage, or recommendation logic. Sequential processing
avoids model thread-safety assumptions, additional worker infrastructure, and
concurrent load spikes. The app-scoped model/orchestrator is reused across
records in a request and across requests.

Enforce limits before accumulating results. A 10 MiB upload cap and 1,000-row
cap bound input, but the response includes full evidence for every successful
row and may still be sizeable; response size and runtime should be measured
before increasing limits. Do not persist inputs, assessments, or incidents.

## 6. Proposed error codes and HTTP status codes

Use the existing envelope shape `{"error": {"code": "...", "message": "..."}}`
for request-level errors. Exact codes proposed:

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `MISSING_FILE` | Multipart `file` field is absent. |
| 400 | `EMPTY_FILE` | Upload has no bytes or no data records. |
| 400 | `INVALID_ENCODING` | CSV is not valid UTF-8. |
| 400 | `MALFORMED_CSV` | CSV parser cannot read the upload. |
| 400 | `INVALID_CSV_FORMAT` | Header/layout or row structure is ambiguous or invalid at the file level. |
| 413 | `UPLOAD_TOO_LARGE` | The complete multipart request exceeds the coarse `MAX_CONTENT_LENGTH` cap or the uploaded file exceeds the exact 10 MiB file-size cap. |
| 413 | `TOO_MANY_ROWS` | CSV exceeds the maximum data-record count. |
| 200 | row-level `INVALID_ROW` / `INVALID_FEATURES` | One row is rejected while processing the remaining rows. |
| 200 | row-level `ASSESSMENT_PROCESSING_ERROR` | One record failed unexpectedly; other rows continue. |
| 500 | `BATCH_PROCESSING_ERROR` | An unexpected request-level failure prevents a valid batch response. |

Use the same concise JSON shape for HTTP 413 as other request errors. Whether a
Flask application-level error handler is needed for `MAX_CONTENT_LENGTH`
should be settled during implementation and tested; the current single-record
route has no app-wide error handler.

## 7. Proposed backend files

Minimal likely changes:

- Create `backend/app/api/batch_assessments.py` for CSV parsing, request/row
  validation orchestration, bounded batch processing, aggregate derivation,
  and response construction. Keep existing API serialization helpers shared or
  extracted only if needed without altering single-record response behavior.
- Modify `backend/app/__init__.py` to register the new blueprint and configure
  the upload byte limit. This must not construct SQLite or incident services.
- Create `backend/tests/test_batch_assessment_api.py` for Flask test-client
  coverage using injected fake orchestrators and small constructed CSVs.
- Optionally modify `backend/app/config.py` if upload-size configuration is
  made a documented setting; otherwise use one explicit application default.

Do not modify `ml/dataset.py` unless implementation proves a shared reusable
reader can preserve the new endpoint's partial-row semantics without changing
training/evaluation behavior.

## 8. Required tests

Test at minimum:

- Exact endpoint method/path, required multipart field, missing file, empty
  upload, malformed CSV, invalid UTF-8, and header-only file.
- Valid official 43-column headerless input and valid 41-column canonical
  header input.
- Header order mapping, duplicate/missing/unknown headers, unsupported
  headerless 41-column input, unexpected columns, and row column-count mismatch.
- Attack label and difficulty validation for official rows and proof neither
  reaches the orchestrator nor appears in result JSON.
- Missing/empty feature values, invalid numeric values, non-finite values,
  invalid categorical types as represented in CSV, and unseen valid categories.
- One-based row number reporting and multiple invalid rows.
- Mixed valid and invalid records return partial results and accurate counts.
- All-invalid but well-formed batch behavior.
- Independent row processing when a row's unexpected processing fails.
- Preservation of model/rule unavailable states and error codes, all four
  handling outcomes, evidence fields, and pending recommendation statuses.
- Aggregate predictions, risks, and outcomes match successful response rows;
  zero-value bins are retained.
- Byte and row limits at, below, and above boundaries.
- Orchestrator is reused and called once per valid row; no incident store,
  persistence, or response action is invoked.
- Existing `POST /api/v1/assessments` and health endpoint behavior remains
  unchanged.

## 9. Security and performance considerations

- The API currently has no authentication or authorization. The upload endpoint
  should remain limited to the local academic prototype and should not be
  represented as internet-ready.
- Uploaded data and assessments may contain sensitive traffic features. Avoid
  logging CSV content, feature rows, labels, or full assessments. Return
  concise row errors and keep internal exception detail server-side.
- Ignore client filenames for filesystem paths; do not save uploads. Parse the
  bounded request stream in memory.
- Do not accept attack labels or difficulty as assessment input. The official
  format's metadata may be minimally validated but must be removed before
  inference and not exposed in assessment output.
- Enforce both byte and record caps and consider request timeouts at deployment.
  Synchronous assessment can block a worker; row limits must remain conservative
  until measured.
- Do not add background jobs, database persistence, incident mutation APIs, or
  response execution as part of this batch contract.
- Aggregate values are descriptive counts from this uploaded batch only; they
  are not historical dashboard metrics and do not establish calibrated model
  performance.
