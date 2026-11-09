# Project Progress

## Current status

The project has implemented the NSL-KDD data and model workflow, deterministic
rule detection, cognitive assessment services, SQLite incident services, the
single-record assessment API, the CSV batch API, and the initial React
dashboard. The system is an offline academic assessment prototype, not a live
network-monitoring or autonomous-response product.

## Completed and tested

- **Project foundation and health API:** Flask application factory,
  configuration, runner, and `GET /api/v1/health`.
- **NSL-KDD loading and preprocessing:** canonical 41-feature schema, strict
  43-column dataset loading, binary labels (`normal` = 0, attack = 1), metadata
  separation, and fitted categorical preprocessing.
- **Model training and evaluation:** Random Forest pipeline and evaluation
  workflow on the official split. Reported overall attack recall is 0.6309;
  reported aggregate binary detection recall for 17 attack labels absent from
  training is 29.33%. Refer to [PHASE_4_REPORT.md](PHASE_4_REPORT.md).
- **Rule and cognitive assessment:** seven deterministic rules, evidence
  reconciliation, heuristic risk assessment, and evidence-based explanations.
- **Handling and recommendations:** deterministic handling outcomes and
  recommendations marked for human review.
- **Incident service and SQLite repository:** internal incident lifecycle,
  notes, audit events, and persistence implementations with backend tests.
- **Single-record API:** `POST /api/v1/assessments`, reusing the application
  scoped orchestrator and returning assessment evidence, handling, and
  recommendations.
- **Batch assessment API:** `POST /api/v1/assessments/batch`, supporting the
  approved CSV layouts, bounded uploads, per-row validation/error isolation,
  and result-derived aggregates.
- **React dashboard:** backend health indicator, CSV upload, batch summaries,
  detailed evidence and risk views, recommendations, and row-level errors.
- **Backend suite:** the final audit ran the complete backend suite and
  observed **212 tests passing, 0 failing**. Earlier phase reports contain
  historical test totals; those are not current suite counts.
- **Frontend checks:** the final audit reported `npx tsc --noEmit` completed
  successfully and `npm run build` completed successfully (36 modules
  transformed). These checks are not a substitute for browser-level testing.
- **Developer-performed integration:** a successful five-record live CSV
  integration test was reported during development. It is recorded as a
  developer-performed test; it was not independently reproduced in the final
  audit.

## Implemented but not exposed through the application interface

- The incident lifecycle and SQLite persistence modules are implemented and
  tested internally, but the Flask factory does not register incident routes
  or wire those services into assessment handling.
- The dashboard has no incident history, investigation, note-taking, or
  lifecycle controls.
- A `security_incident` handling decision does not itself create or persist an
  incident.

## Partially implemented

- **Controlled response support:** the policy and recommendation layers classify
  outcomes and provide recommendations for review. There is no approval
  workflow, execution adapter, or response action execution.
- **Dashboard integration:** the batch workflow is implemented and its API
  contract is checked by TypeScript, but there is no configured automated
  frontend test suite. The reported five-record live test was performed during
  development rather than independently repeated by the final audit.
- **Deployment integration:** development API proxy configuration is present.
  A separately hosted production frontend/backend requires same-origin proxying
  or appropriate CORS deployment configuration.
- **Risk interpretation:** deterministic heuristic scores and levels are
  implemented but are not calibrated probabilities.

## Not implemented or outside current scope

- Live packet capture, real-time monitoring, streaming assessment, and
  chronological event correlation.
- Attack-subtype classification; the model predicts only normal versus attack.
- Automatic incident creation, incident-management HTTP endpoints, or incident
  investigation in the dashboard.
- Autonomous response execution or a human approval/execution workflow.
- Authentication, authorization, production deployment hardening, and
  production-readiness validation.
- A separately reported sensitivity evaluation that excludes overlapping
  records between the official NSL-KDD training and test files.

## Phase status

| Phase / workstream | Status | Notes |
|---|---|---|
| Project foundation | Complete | Flask factory, runner, configuration, and health route. |
| Dataset inspection and preparation | Complete | NSL-KDD schema, loader, validation, targets, and preprocessing. |
| Model training and evaluation | Complete | Binary Random Forest; results and limitations in the Phase 4 report. |
| Rule-based threat detection | Complete | Seven deterministic rules with provisional thresholds. |
| Cognitive assessment | Complete | Evidence reconciliation, heuristic risk, and explanations. |
| Incident services and SQLite persistence | Implemented internally | Not wired to Flask routes or dashboard. |
| Single-record assessment API | Complete | `POST /api/v1/assessments`. |
| CSV batch assessment API | Complete | `POST /api/v1/assessments/batch`, sequential and bounded. |
| Frontend foundation and batch dashboard | Implemented | TypeScript/build checks and developer-reported live integration; frontend automated tests are not configured. |
| Approval and response execution | Not implemented | Recommendations are for human review only. |

## Key academic limitations

NSL-KDD is an offline benchmark rather than contemporary live telemetry. The
classifier is binary and demonstrates limited attack recall, with weak and
uneven results for unseen attack labels. The dataset inspection also documents
610 exact full records shared between the official splits, 654 shared feature
vectors, and 51 shared vectors with conflicting binary targets. Preserve this
caveat when interpreting the reported test results; do not describe the system
as live, autonomous, or production-ready.

## Documentation

- [README.md](../README.md) — current project overview and setup.
- [PHASE_4_REPORT.md](PHASE_4_REPORT.md) — model evaluation and reported metrics.
- [PHASE_5_REPORT.md](PHASE_5_REPORT.md) — rule-engine implementation.
- [PHASE_8_BATCH_API_DESIGN.md](PHASE_8_BATCH_API_DESIGN.md) — approved batch API
  design.
- [PHASE_8_IMPLEMENTATION_REPORT.md](PHASE_8_IMPLEMENTATION_REPORT.md) — actual
  batch API and frontend implementation status.
- [nsl-kdd-inspection.md](nsl-kdd-inspection.md) — dataset inspection and
  split-overlap caveat.
