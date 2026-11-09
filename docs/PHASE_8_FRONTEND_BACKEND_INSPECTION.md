# Phase 8: Frontend and Backend API Inspection

## 1. Existing frontend structure

The frontend is a minimal Vite + React application:

- `frontend/index.html` — HTML document, root element, page title, and `src/main.tsx` entry script.
- `frontend/src/main.tsx` — mounts `App` through React 19 `createRoot` and imports the global stylesheet.
- `frontend/src/App.tsx` — currently renders only the project heading and “Project foundation is ready.”
- `frontend/src/style.css` — global dark background, typography, and basic main-content sizing.
- `frontend/vite.config.ts` — configures the React Vite plugin; no API proxy or other integration is configured.
- `frontend/.env.example` — provides `VITE_API_BASE_URL=http://127.0.0.1:5000/api/v1`.
- `frontend/tsconfig.json` — strict TypeScript configuration, ES2020 target, DOM libraries, Bundler resolution, React JSX transform, and no emit.

There are no pages, reusable components, layouts, router configuration, frontend API service, HTTP client wrapper, or tests in `frontend/src`. `App.tsx` is a placeholder rather than an implemented dashboard. No Tailwind configuration or Tailwind package is present in the frontend manifest. Styling is plain CSS.

## 2. Existing backend HTTP API

### Routes

The Flask factory in `backend/app/__init__.py` registers:

- `GET /api/v1/health` — returns `{"status": "ok"}`.
- `POST /api/v1/assessments` — assesses exactly one canonical feature record.

The assessment endpoint is registered by the `assessments` blueprint in `backend/app/api/assessments.py`. No HTTP routes expose incident creation, incident retrieval, lifecycle transitions, investigation notes, audit history, CSV upload, batch assessment, or response execution.

### Assessment request

The body must be a JSON object with exactly these 41 fields, defined in `backend/ml/schema.py`:

`duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent`, `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `num_outbound_cmds`, `is_host_login`, `is_guest_login`, `count`, `srv_count`, `serror_rate`, `srv_serror_rate`, `rerror_rate`, `srv_rerror_rate`, `same_srv_rate`, `diff_srv_rate`, `srv_diff_host_rate`, `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `dst_host_same_src_port_rate`, `dst_host_srv_diff_host_rate`, `dst_host_serror_rate`, `dst_host_srv_serror_rate`, `dst_host_rerror_rate`, `dst_host_srv_rerror_rate`.

The three categorical features are `protocol_type`, `service`, and `flag`; the remaining fields are numeric under the shared validator. Feature values are checked by the existing orchestrator and `validate_feature_record`, including finiteness, nonnegative values, rate bounds, binary constraints, and integer count constraints. Additional fields such as attack labels and difficulty values are rejected by the endpoint’s exact-field check.

This is not a CSV or batch contract: one HTTP request represents one feature record.

### Assessment response

HTTP 200 returns an object with exactly three top-level properties:

- `assessment`
  - `model`: `status`, `predicted_class`, `predicted_label`, `class_0_probability`, `class_1_probability`, `model_name`, `model_version`, `error_code`.
  - `rules`: `status`, `results`, `triggered_rule_ids`, `error_code`. Each rule result includes `rule_id`, `triggered`, `severity`, `description`, `features_examined`, and `reason`; feature checks include `name`, `observed_value`, `operator`, `threshold`, and `condition_met`.
  - `reconciliation`: one of the existing reconciliation values such as `agreement_attack`, `agreement_no_attack_signal`, `ml_only`, `rules_only`, or `incomplete`.
  - `risk`: `status`, `model_attack_probability`, `model_score`, `rule_score`, `combined_score`, `level`, and `policy_version`. Risk scores are heuristic assessment values; the contract does not describe them as calibrated probabilities.
  - `explanations`: a list of strings.
- `handling_decision`: `outcome`, `create_security_incident`, `create_assessment_review`, `requires_operational_review`, `category`, `severity`, `initial_status`, `reason`, `risk_level`, `reconciliation`, `model_status`, `rule_status`, and `triggered_rule_ids`. Outcomes include `security_incident`, `assessment_review`, `no_action`, and `processing_failure`.
- `recommendations`: a list of objects with `action_key`, `description`, `rationale`, `evidence_references`, and `review_status` (initially `pending`).

A `security_incident` handling outcome indicates policy qualification only. The endpoint does not create an incident or return an incident ID.

### Validation and error responses

Errors use `{"error": {"code": "...", "message": "..."}}`.

- HTTP 400, `INVALID_JSON`: malformed JSON or a request body Flask cannot parse as JSON.
- HTTP 400, `INVALID_REQUEST`: the parsed body is not an object, or it has missing or extra keys.
- HTTP 400, `INVALID_FEATURES`: shared record validation rejects one or more values.
- HTTP 500, `ASSESSMENT_PROCESSING_ERROR`: unexpected assessment, policy, or recommendation processing failure. Details are logged server-side but not returned in the response.
- HTTP 200: normal completion, including source-unavailable evidence and the `processing_failure` policy outcome when the assessment pipeline returns that structured result.

The HTTP route and status mappings are implemented in `backend/app/api/assessments.py`.

## 3. Backend service and persistence boundaries

- `backend/app/cognition/orchestrator.py` combines model inference, rule evaluation, reconciliation, risk assessment, and explanations for one validated record. It accepts a model predictor and rule evaluator as dependencies; default construction creates `ModelInferenceService` and uses the existing rule evaluator.
- `backend/app/detection/model_service.py` validates input and loads the persisted model artifact when `ModelInferenceService` is constructed. Unavailable artifact/inference states are represented through existing evidence status and error-code fields.
- `backend/app/incidents/policy.py` validates a consolidated assessment and returns a deterministic `AssessmentHandlingDecision`.
- `backend/app/incidents/recommendations.py` validates that decision against the assessment and returns deterministic evidence-referenced recommendations for human review.
- `backend/app/incidents/service.py` contains framework-independent incident creation, status transition, investigation note, and audit operations. It depends on the `IncidentStore` protocol and defaults to `InMemoryIncidentStore`.
- `backend/app/incidents/sqlite_repository.py` implements that protocol for a caller-supplied SQLite database path, with transactional incident/audit writes and revision checks.
- `backend/app/__init__.py` constructs one `AssessmentOrchestrator` per Flask application (unless `ASSESSMENT_ORCHESTRATOR` is injected) and stores it in `app.extensions`. It does not construct an `IncidentService` or `SQLiteIncidentStore`.

These incident capabilities are internal Python services, not HTTP API functionality. There is no API for listing persisted incidents; the service API is centered on creation and per-ID retrieval, notes, audit, and lifecycle operations.

## 4. Dependencies

The declared frontend runtime dependencies in `frontend/package.json` are React 19 and React DOM 19. Development dependencies include TypeScript 5.7, Vite 6, the Vite React plugin, and React type packages. There is no declared routing library, HTTP client, charting library, component library, Tailwind CSS, or frontend test runner.

Backend dependencies in `backend/requirements.txt` include Flask, python-dotenv, and scikit-learn. The SQLite repository uses Python’s built-in `sqlite3`.

## 5. Integration gaps and practical limits

### CSV upload and batch assessment

The existing endpoint cannot accept a CSV file or a list of records. A future CSV workflow needs an explicit contract and validation policy:

1. Define supported CSV headers/column order, encoding, file size and row limits, and whether labels/difficulty columns are prohibited or ignored.
2. Choose a server-side multipart upload endpoint or a separate batch JSON endpoint; neither exists now.
3. Parse and validate every row against the canonical feature schema, preserving row indices and clear per-row errors.
4. Define whether one invalid row rejects the whole batch or yields partial results, and cap work to avoid unbounded inference requests.
5. Add backend tests for file parsing, malformed rows, boundaries, and batch result shape, then build frontend upload/preview and progress/error handling against that API.

The NSL-KDD schema source describes a headerless dataset with feature columns followed by attack-label and difficulty columns. A general user-upload CSV format must be explicitly specified rather than inferred from the current single-record endpoint.

### What a frontend can display today

With an assessment request, the frontend can display model evidence and availability/error codes, rule results and observed feature checks, reconciliation, risk status and scores, explanations, handling outcome, and recommendations. It can display health status from the health endpoint.

The current API does not provide uploaded datasets, batch summaries, persisted assessment history, dashboard aggregate statistics, incident lists, investigation history, or response execution. Such statistics or incident histories must not be fabricated in the frontend.

Incident creation, persistence, lifecycle transitions, notes, and audit events exist behind Python service/store interfaces only. Exposing them requires additional backend API design and access-control decisions. In particular, the service accepts actor IDs but does not authenticate them. Current API has no authentication or authorization, so incident mutation endpoints should not be exposed in an academic dashboard without an approved security design.

## 6. Recommended frontend structure

Keep the structure small and avoid a feature/module framework:

```text
frontend/src/
  main.tsx
  App.tsx
  api/
    client.ts
    assessments.ts
  components/
    AppShell.tsx
    StatusBadge.tsx
    RiskSummary.tsx
    EvidenceCard.tsx
    RuleResultsTable.tsx
    RecommendationList.tsx
  pages/
    DashboardPage.tsx
    AssessmentPage.tsx
    DatasetUploadPage.tsx
    IncidentsPage.tsx
  types/
    assessment.ts
  style.css
```

This is a proposal, not existing code. For a small academic application, navigation could initially be handled with a few page states or links; adding a router should wait until the number of views and navigation requirements justify it. The API client should centralize the configured `VITE_API_BASE_URL`, request encoding, typed response decoding, and API error handling.

- **Dashboard overview:** show only live API health or user-session assessment summaries until backend aggregate/history endpoints exist.
- **Assessment page:** submit one feature record to the current endpoint and render results.
- **ML evidence:** show prediction, probability fields, model metadata, and availability/errors.
- **Rule evidence:** show triggered/non-triggered rules and their feature checks.
- **Evidence/risk/explanations:** display reconciliation and risk status distinctly, clarifying that heuristic scores are not calibrated probabilities.
- **Recommendations:** show action keys, rationale, evidence references, and pending review status; do not present them as executed actions.
- **Dataset upload/preview:** proposed UI only; requires a new CSV/batch backend contract first.
- **Incident management/investigation:** proposed UI only; requires incident API and authorization design first.

## 7. Proposed implementation sequence

1. Approve frontend scope and decide whether the first UI supports only manual single-record assessment or includes a CSV/batch backend project.
2. Add TypeScript interfaces matching the existing assessment response and a small API client for health and single-record assessment.
3. Build the application shell and assessment form/JSON feature-entry workflow, then add clear validation, loading, and error states.
4. Build reusable evidence, risk, rule, explanation, and recommendation display components from actual response fields.
5. Add tests and a build/type-check command appropriate to the frontend. No frontend test runner is currently declared.
6. Design CSV/batch backend support and tests before implementing dataset upload/preview.
7. Design and secure incident APIs before implementing incident listing or investigation UI. Keep mutation and response actions out of scope until authorization and actor attribution are designed.

## 8. Proposed next-step files

For an initial single-record frontend integration, likely files to create or modify are:

- Modify `frontend/src/App.tsx` for application layout/navigation.
- Create `frontend/src/api/client.ts` and `frontend/src/api/assessments.ts`.
- Create `frontend/src/types/assessment.ts`.
- Create assessment page and evidence display components under `frontend/src/pages/` and `frontend/src/components/`.
- Modify `frontend/src/style.css` for the designed UI.
- Optionally modify `frontend/vite.config.ts` only if a development proxy is selected; the current `.env.example` already provides a base URL setting.

CSV/batch support would require separate backend API and tests before corresponding upload UI. Incident UI would require separately approved incident endpoints and authorization design. No files have been created for those features as part of this inspection.
