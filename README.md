# Cognitive Cyber Threat Detection and Response System

## Project aim

This project is an academic decision-support prototype for assessing labeled
NSL-KDD network connection records. It combines binary machine-learning
evidence with deterministic feature rules, reconciles the evidence, assigns a
heuristic risk level, and presents explanations and recommendations for human
review.

It does not monitor live network traffic, correlate events over time, execute
response actions, or claim production readiness.

## Objectives

1. Examine existing cyber threat detection and response techniques and
   identify their limitations.
2. Design an architecture integrating data preprocessing, machine-learning
   detection, rule-based analysis, and response management.
3. Develop a machine-learning model that classifies network traffic records as
   normal or potentially malicious.
4. Implement a web dashboard displaying detected threats, severity levels,
   alerts, and assessment information.
5. Develop a response-support module that recommends appropriate mitigation
   measures and supports controlled response management.
6. Evaluate the system using accuracy, precision, recall, F1-score, and
   functional testing.

As supporting internal backend services, the project also implements incident
lifecycle logic and SQLite persistence. These services are not currently
exposed through Flask routes or the dashboard; they are separate from objective
6's system evaluation.

## Technology

- **Backend:** Python 3.10+, Flask, scikit-learn, NumPy, Joblib, and SQLite
  (Python standard library).
- **Frontend:** React 19, TypeScript 5.7, Vite 6, and plain CSS.
- **Dataset:** NSL-KDD `KDDTrain+.txt` and `KDDTest+.txt`.
- **Model:** scikit-learn pipeline with categorical preprocessing and
  `RandomForestClassifier` (100 estimators, random seed 42).

Installable backend dependencies are listed in
[`backend/requirements.txt`](backend/requirements.txt); frontend dependencies
are listed in [`frontend/package.json`](frontend/package.json). The frontend
does not use a component library or charting dependency.

## Dataset and classification scope

NSL-KDD records contain 41 traffic features, an original attack label, and a
difficulty value. The original label and difficulty are metadata, not model
features. The classifier maps `normal` to class `0` and every attack label to
class `1`; it does not predict attack subtypes.

The reported evaluation in
[`docs/PHASE_4_REPORT.md`](docs/PHASE_4_REPORT.md) uses the official 22,544-row
test split:

| Metric | Reported result |
|---|---:|
| Accuracy | 0.7784 |
| Attack precision | 0.9690 |
| Attack recall | 0.6309 |
| Attack F1-score | 0.7642 |
| True negatives / false positives | 9,452 / 259 |
| False negatives / true positives | 4,737 / 8,096 |

These are documented evaluation results, not a promise of performance on
current network traffic. On 3,750 test records across the 17 attack labels
absent from training, the report gives aggregate binary attack-detection recall
of 29.33%. Results vary substantially by label; this is not subtype
classification.

The dataset inspection report documents 610 exact full records shared between
the official training and test files, 654 shared feature vectors, and 51 shared
vectors with conflicting binary targets. The official evaluation should be
interpreted with this split-overlap caveat; a separately identified
overlap-excluded sensitivity analysis remains useful future work.

## Detection and assessment pipeline

For each supplied record, the assessment orchestrator validates the canonical
41 features and obtains **independent** model and rule evidence. The system
then reconciles that evidence, computes a heuristic risk score and level, and
generates explanations. Missing/unavailable evidence is represented as such
rather than treated as a negative finding. The scores are not calibrated
probabilities, and the provisional rule thresholds have not been production
validated.

The seven deterministic rules are:

| Rule | Condition | Severity |
|---|---|---|
| `RBD-AUTH-001` | `num_failed_logins >= 1` | Low |
| `RBD-PRIV-002` | `root_shell == 1 OR su_attempted > 0` | Low |
| `RBD-COMP-003` | `num_compromised >= 1` | Medium |
| `RBD-FRAG-004` | `wrong_fragment >= 1` | Medium |
| `RBD-SYN-005` | `serror_rate == 1 AND srv_serror_rate == 1 AND count >= 256` | High |
| `RBD-SCAN-006` | `diff_srv_rate == 1 AND count >= 256` | High |
| `RBD-REJ-007` | `rerror_rate == 1 AND srv_rerror_rate == 1 AND count >= 256` | Medium |

Rule triggers are evidence for assessment, not proof of malicious activity.

## HTTP API

The Flask application exposes:

- `GET /api/v1/health` — process health status.
- `POST /api/v1/assessments` — assess one JSON object containing exactly the
  canonical feature fields.
- `POST /api/v1/assessments/batch` — assess a multipart CSV upload using the
  required `file` field.

The batch endpoint accepts either a headerless 43-column NSL-KDD record layout
(`COLUMN_NAMES` order) or a 41-column canonical feature header. In the latter
format, all feature names must occur exactly once; their order may vary. The
official 43-column header is not a supported upload layout. The endpoint
validates and discards `attack_label` and `difficulty`; neither is passed to the
orchestrator or returned in assessment results.

Limits are 10 MiB per uploaded CSV, 11 MiB per complete multipart request, and
1,000 data records. CSV rows are processed sequentially. Invalid rows and
unexpected per-row processing errors are reported separately, and later rows
continue to be processed. Batch aggregates are derived from successful
assessment results.

The health endpoint indicates that Flask is responding; it does not guarantee
that the model artifact is available.

## Dashboard

The React dashboard checks backend health, accepts/removes a CSV file, enforces
the `.csv` extension and 10 MiB client-side size limit, and submits the file to
the batch API. It displays batch totals, prediction and risk counts, handling
outcomes, and expandable row assessments with model evidence, rule findings,
reconciliation, risk, explanations, recommendations, invalid rows, and
processing errors. Recommendations are labeled for human review.

The dashboard does not display incident history or manage incident records.
The API client reads `VITE_API_BASE_URL`; the development Vite proxy uses the
API path derived from that setting. For a separately hosted production
frontend and backend, deploy a same-origin proxy or configure an appropriate
cross-origin policy.

## Incident handling and response scope

Backend incident modules provide incident lifecycle logic and a SQLite
repository for incident records, notes, and audit events. These are internal
services: the Flask application does not currently register incident routes or
wire the repository into assessment handling, and the dashboard does not expose
incident investigation. A `security_incident` handling outcome is a triage
classification; it does not create or persist an incident. Recommendations
remain pending human review. No response action is executed automatically.

## Setup and execution (Windows)

Prerequisites: Python 3.10 or later, Node.js 18 or later, and npm. Run these
commands from PowerShell.

### Backend

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The model artifact is generated locally and is not included in version
control. From the `backend` directory, train it using the provided dataset
before starting the API if it is not already present:

```powershell
python -m ml.train
python run.py
```

The API defaults to `http://127.0.0.1:5000`. Check the health route with:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/v1/health
```

To reproduce the documented evaluation after training:

```powershell
python -m ml.evaluate
```

Backend host, port, and debug settings can be changed in `backend/.env`.

### Frontend

In a second PowerShell terminal:

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Open the local URL printed by Vite. The example environment file points the
development proxy at `http://127.0.0.1:5000/api/v1`. To check types and create
a production bundle:

```powershell
npx tsc --noEmit
npm run build
```

## Known limitations

- NSL-KDD is an offline, dated benchmark and does not establish effectiveness
  on contemporary operational traffic.
- This is a binary normal-versus-attack classifier, with limited overall attack
  recall and weak, uneven detection of labels absent from training.
- The official dataset split has documented record/vector overlap and
  conflicting targets; interpret the reported metrics accordingly.
- Rule thresholds are provisional. Risk scores are heuristic, not calibrated
  probabilities.
- The system does not perform live monitoring, chronological event
  correlation, attack-subtype classification, incident creation from a
  handling outcome, autonomous response, or production-ready deployment.
- Batch processing is synchronous and sequential. There is no authentication,
  authorization, or exposed incident-management API.
- The frontend has no automated test suite configured; build/type checking
  alone do not establish browser-level integration correctness.

## Documentation

See [`docs/`](docs/) for phase reports, the Phase 8 API design, dataset
inspection, model evaluation, and current project progress. The
[Phase 8 implementation report](docs/PHASE_8_IMPLEMENTATION_REPORT.md) records
the delivered batch API and dashboard.
