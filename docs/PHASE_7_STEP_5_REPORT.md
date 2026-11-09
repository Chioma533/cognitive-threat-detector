# Phase 7, Step 5: Assessment API Integration

## Overview

This step exposes the existing single-record cognitive assessment pipeline
through `POST /api/v1/assessments`. The endpoint returns assessment evidence,
triage, and recommendations for human review. It does not create or persist
incidents and does not execute response actions.

## Request

The request body is a JSON object containing exactly the canonical 41 NSL-KDD
feature fields. Missing or unexpected fields are rejected. Feature values are
validated by the existing `AssessmentOrchestrator` and shared feature validator;
the endpoint does not repeat their numeric, categorical, or range validation.
Labels, difficulty fields, and other additional keys are not accepted.

## Response

A successful request returns HTTP 200 with these top-level fields:

- `assessment`: `model`, `rules`, `reconciliation`, `risk`, and `explanations`,
  retaining the existing evidence contract field names.
- `handling_decision`: the complete `AssessmentHandlingDecision` contract,
  including the distinct `security_incident`, `assessment_review`, `no_action`,
  and `processing_failure` outcomes.
- `recommendations`: the existing recommendation contract, including its
  `pending` human-review status.

The endpoint explicitly selects the TypedDict fields before JSON serialization.
A decision qualifying for a security incident is only a triage result; it does
not mean that an incident was created.

## Application dependency construction

`create_app()` remains callable without arguments and now accepts optional
configuration overrides. The factory uses an injected
`ASSESSMENT_ORCHESTRATOR` when supplied; otherwise it constructs one
`AssessmentOrchestrator` for that Flask application. The instance is stored in
`app.extensions["assessment_orchestrator"]` and reused for requests. The
orchestrator retains its existing unavailable-evidence behavior if model
initialization or inference is unavailable.

The factory does not construct an `SQLiteIncidentStore` or `IncidentService`.

## Error-to-HTTP mapping

- **200** — assessment processing completes, including when either or both
  evidence sources are unavailable and represented by their existing evidence
  contracts.
- **400** — malformed JSON, non-object JSON, missing or additional request
  fields, or invalid feature values. Errors use a stable JSON error envelope
  and do not include exception representations.
- **500** — unexpected assessment, triage, or recommendation processing failure.
  The exception is logged server-side; the response contains only a generic
  processing error.

## Tests and verification

The focused Flask test-client suite covers health behavior, request validation,
response fields, all triage outcome distinctions, unavailable evidence and
error-code preservation, sanitized internal errors, injected and once-per-app
orchestrator construction, and absence of SQLite writes.

Results:

- Focused API suite: **16 passed, 0 failed**.
- Complete backend suite: **191 passed, 0 failed**.

## Limitations

This is a local academic prototype endpoint, not a production-secure or
internet-ready deployment. It adds no authentication, authorization, actor
identity, persistence, incident mutation endpoints, or autonomous response
execution. Assessment requests and returned network-feature evidence are not
protected by an access-control layer in this step.
