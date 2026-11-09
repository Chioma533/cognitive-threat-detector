# Phase 8 Implementation Report: CSV Batch Assessment and Dashboard

## 1. Overview

Phase 8 delivers a synchronous CSV batch assessment endpoint and the initial
React dashboard workflow that uses it. The batch API reuses the existing
app-scoped assessment orchestrator and response serializers. The frontend
submits CSV files without parsing or transforming their records and presents
batch summaries and row-level assessment evidence.

This phase does not add live network monitoring, incident-management routes,
incident creation from a handling decision, or response execution.

## 2. Implemented components

### Backend

- `backend/app/api/batch_assessments.py` implements
  `POST /api/v1/assessments/batch`.
- `backend/app/__init__.py` registers the batch blueprint, provides the
  app-scoped orchestrator, enforces the request-body limit, and returns a JSON
  error envelope for oversized multipart requests.
- The endpoint reuses the single-assessment serializers and existing handling
  and recommendation services. It does not construct a model or orchestrator
  per row.

### Frontend

- `frontend/src/api/client.ts` provides health checking, API error handling,
  and base-URL selection.
- `frontend/src/api/assessments.ts` submits a `FormData` request using the
  required `file` field and validates the batch response shape.
- `frontend/src/types/assessment.ts` defines the typed API response contracts.
- `frontend/src/pages/DashboardPage.tsx` and reusable components render the
  upload workflow and assessment results.
- `frontend/vite.config.ts` configures the development proxy; the example
  environment value is in `frontend/.env.example`.

## 3. CSV parsing and validation

The endpoint accepts UTF-8 CSV using one of two layouts:

1. **Official NSL-KDD record layout:** headerless, exactly 43 columns in the
   canonical `COLUMN_NAMES` order. The first 41 columns are assessment
   features. `attack_label` must be non-empty and `difficulty` must convert
   using the dataset convention. Both metadata fields are excluded from the
   orchestrator input and assessment result.
2. **Canonical feature-header layout:** a header with exactly the 41
   `FEATURE_NAMES`, each occurring once. The endpoint maps by header name, so
   feature columns may be in any order. Duplicate, missing, or unknown headers
   are rejected.

An official 43-column header is not a supported upload layout. Unsupported
headerless 41-column files, ambiguous layouts, malformed CSV, and rows with an
incorrect column count are rejected.

The three categorical feature values are trimmed strings. Numeric feature
values are converted using Python `float`, following the dataset loader
convention, then validated by the shared feature validator. Empty or invalid
numeric values are rejected; fractional values are not rounded or truncated.
The shared validator remains responsible for finite-value, range, binary, and
integer constraints. Invalid values are not replaced with defaults.

## 4. Limits and row-level failure handling

- Maximum CSV file size: **10 MiB**.
- Maximum complete multipart request body: **11 MiB**.
- Maximum data records: **1,000**.

Uploads exceeding a request-level limit are rejected before assessment with a
JSON error envelope. CSV rows are processed sequentially. A validation error
is recorded as a row error; an unexpected assessment/handling/recommendation
failure is logged server-side and recorded as a sanitized processing error.
Either kind of row failure does not stop processing of later rows. Expected
model or rule unavailability remains represented through the established
evidence status and error code rather than being counted as an unexpected row
processing failure.

## 5. Response and aggregates

The batch response contains:

- `batch_id`, `total_rows`, `assessed_rows`, `invalid_rows`, and
  `processing_errors`.
- `prediction_counts` for `normal`, `attack`, and `unavailable`.
- `risk_level_counts` for `low`, `medium`, `high`, and `indeterminate`.
- `handling_outcome_counts` for `security_incident`, `assessment_review`,
  `no_action`, and `processing_failure`.
- `results`, `row_errors`, and `processing_errors_detail`.

Each successful row result uses the existing single-assessment serialization
structure and includes its one-based CSV data-row number. Counts are
initialized with all documented categories and derived from successful
assessment results. The endpoint maintains:

`total_rows = assessed_rows + invalid_rows + processing_errors`

Invalid input rows and unexpected processing failures are reported separately.
Dataset metadata is not exposed as an assessment feature or result field.

## 6. Frontend API integration and dashboard

The frontend reads `VITE_API_BASE_URL`. In development, Vite proxies requests
through the configured API path. The health check reports the backend
connection state. Batch uploads use `FormData` and do not manually set the
multipart `Content-Type` header. HTTP error envelopes and network failures are
handled without exposing internal server exception details.

The dashboard supports CSV selection, replacement/removal, filename and file
size display, `.csv` extension validation, a client-side 10 MiB size check,
loading state, and success/failure feedback. It does not parse records in the
browser.

Displayed output includes batch totals; prediction, risk, and handling counts;
expandable row results; model evidence; individual rule findings; evidence
reconciliation; risk level and scores; explanations; human-review
recommendations; invalid-row messages; and unexpected processing errors.
Unavailable model/rule evidence and batches with partial or no successful
results are represented in the interface.

## 7. Verification results

The final repository audit reported:

- **Backend suite:** 212 tests passed, 0 failed.
- **TypeScript:** `npx tsc --noEmit` completed successfully with no reported
  diagnostics.
- **Production build:** `npm run build` completed successfully; Vite reported
  36 modules transformed.
- **Whitespace/diff check:** `git diff --check` completed successfully during
  the audit.

A successful five-record live CSV integration test was performed and reported
during development. It is recorded here as a **developer-performed test**; it
was not independently reproduced during the final audit. A successful build
and type check do not by themselves establish browser-level runtime
correctness.

## 8. Limitations and remaining integration gaps

- The batch endpoint is synchronous, sequential, and in-memory; its limits are
  prototype safeguards, not production capacity guarantees.
- There is no configured automated frontend test suite. Browser-level
  integration was not independently reproduced during the final audit.
- For a separately hosted production frontend and backend, deployment needs a
  same-origin proxy or appropriate CORS configuration.
- Incident lifecycle and SQLite persistence are implemented as internal
  backend services but are not exposed through Flask routes or the dashboard.
  A `security_incident` handling outcome does not create or persist an incident.
- Recommendations require human review; no approval workflow or response
  execution is implemented.
- The underlying model is binary, and the risk values are heuristic rather
  than calibrated probabilities. Rule thresholds remain provisional.
- NSL-KDD is an offline benchmark. The documented train/test split has record
  and feature-vector overlap, including vectors with conflicting targets.
  Reported attack recall is limited, especially for attack labels absent from
  training. See [PHASE_4_REPORT.md](PHASE_4_REPORT.md) and
  [nsl-kdd-inspection.md](nsl-kdd-inspection.md).

## 9. Completion status

The Phase 8 CSV batch API and initial dashboard integration are implemented.
Backend suite, TypeScript, and production build results are recorded above.
Live monitoring, incident UI/API integration, response execution, and
production-readiness work remain outside the implemented scope.
