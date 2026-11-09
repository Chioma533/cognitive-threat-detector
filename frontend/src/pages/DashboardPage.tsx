import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { assessCsvBatch } from "../api/assessments";
import { checkBackendHealth } from "../api/client";
import AppShell from "../components/AppShell";
import MetricCard from "../components/MetricCard";
import RiskSummary from "../components/RiskSummary";
import StatusBadge, { type BadgeTone } from "../components/StatusBadge";
import type {
  BatchAssessmentResponse,
  BatchAssessmentResult,
  HandlingOutcome,
  PredictionCountKey,
} from "../types/assessment";

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const predictionRows: { key: PredictionCountKey; label: string }[] = [
  { key: "normal", label: "Normal" },
  { key: "attack", label: "Attack" },
  { key: "unavailable", label: "Unavailable" },
];
const outcomeRows: { key: HandlingOutcome; label: string }[] = [
  { key: "security_incident", label: "Security incident" },
  { key: "assessment_review", label: "Assessment review" },
  { key: "no_action", label: "No action" },
  { key: "processing_failure", label: "Processing failure" },
];

function formatFileSize(size: number): string {
  return size < 1024 * 1024
    ? `${(size / 1024).toFixed(1)} KB`
    : `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

function statusTone(value: string): BadgeTone {
  if (["attack", "high", "security_incident", "triggered"].includes(value)) {
    return "danger";
  }
  if (["medium", "assessment_review", "incomplete"].includes(value)) {
    return "warning";
  }
  if (["normal", "low", "no_action", "available"].includes(value)) {
    return "success";
  }
  if (["unavailable", "processing_failure"].includes(value)) {
    return "info";
  }
  return "neutral";
}

function readableLabel(value: string): string {
  return value.replace(/_/g, " ");
}

function ScoreValue({ value }: { value: number | null }) {
  return (
    <strong className="score-value">
      {value === null ? "Unavailable" : `${value.toFixed(1)} / 100`}
    </strong>
  );
}

function AssessmentDetail({ result }: { result: BatchAssessmentResult }) {
  const { assessment, handling_decision: decision, recommendations } = result;
  const model = assessment.model;
  const risk = assessment.risk;
  const triggeredRules = assessment.rules.results.filter((rule) => rule.triggered);

  return (
    <details className="result-detail">
      <summary>
        <span className="result-row-number">Row {result.row_number}</span>
        <span className="result-summary-label">
          {model.predicted_label
            ? `${readableLabel(model.predicted_label)} prediction`
            : "Model prediction unavailable"}
        </span>
        <StatusBadge tone={statusTone(risk.level)}>{risk.level}</StatusBadge>
        <span className="result-score">
          {risk.combined_score === null
            ? "Score unavailable"
            : `Risk ${risk.combined_score.toFixed(1)}`}
        </span>
        <span className="details-chevron" aria-hidden="true">
          +
        </span>
      </summary>
      <div className="result-detail-body">
        <div className="evidence-grid">
          <section className="evidence-card">
            <div className="evidence-card-heading">
              <h3>ML evidence</h3>
              <StatusBadge tone={statusTone(model.status)}>
                {model.status}
              </StatusBadge>
            </div>
            <dl className="detail-list">
              <div>
                <dt>Prediction</dt>
                <dd>{model.predicted_label ?? "Unavailable"}</dd>
              </div>
              <div>
                <dt>Attack probability</dt>
                <dd>
                  {model.class_1_probability === null
                    ? "Unavailable"
                    : `${(model.class_1_probability * 100).toFixed(1)}%`}
                </dd>
              </div>
              <div>
                <dt>Model</dt>
                <dd>{model.model_name ?? "Unavailable"}</dd>
              </div>
              <div>
                <dt>Model version</dt>
                <dd>{model.model_version ?? "Unavailable"}</dd>
              </div>
            </dl>
            {model.error_code && (
              <p className="evidence-note">Evidence code: {model.error_code}</p>
            )}
          </section>

          <section className="evidence-card">
            <div className="evidence-card-heading">
              <h3>Risk assessment</h3>
              <StatusBadge tone={statusTone(risk.level)}>{risk.level}</StatusBadge>
            </div>
            <dl className="detail-list">
              <div>
                <dt>Combined score</dt>
                <dd>
                  <ScoreValue value={risk.combined_score} />
                </dd>
              </div>
              <div>
                <dt>Model score</dt>
                <dd>
                  <ScoreValue value={risk.model_score} />
                </dd>
              </div>
              <div>
                <dt>Rule score</dt>
                <dd>
                  <ScoreValue value={risk.rule_score} />
                </dd>
              </div>
            </dl>
          </section>

          <section className="evidence-card">
            <div className="evidence-card-heading">
              <h3>Evidence reconciliation</h3>
              <StatusBadge tone={statusTone(assessment.reconciliation)}>
                {readableLabel(assessment.reconciliation)}
              </StatusBadge>
            </div>
            <p className="evidence-description">
              {assessment.reconciliation === "agreement_attack"
                ? "Model and rule evidence agree on an attack signal."
                : assessment.reconciliation === "agreement_no_attack_signal"
                  ? "Model and rule evidence agree that no attack signal was found."
                  : assessment.reconciliation === "incomplete"
                    ? "One or more evidence sources were unavailable."
                    : "Model and rule evidence differ; review the evidence below."}
            </p>
            <p className="evidence-note">
              Rules: {assessment.rules.status}
              {assessment.rules.error_code
                ? ` · ${assessment.rules.error_code}`
                : ""}
            </p>
          </section>

          <section className="evidence-card handling-card">
            <div className="evidence-card-heading">
              <h3>Handling decision</h3>
              <StatusBadge tone={statusTone(decision.outcome)}>
                {readableLabel(decision.outcome)}
              </StatusBadge>
            </div>
            <p className="evidence-description">{decision.reason}</p>
          </section>
        </div>

        <section className="detail-section">
          <div className="detail-section-heading">
            <h3>Rule-based detection</h3>
            <span>
              {triggeredRules.length} of {assessment.rules.results.length} rules
              triggered
            </span>
          </div>
          {assessment.rules.results.length > 0 ? (
            <div className="rule-list">
              {assessment.rules.results.map((rule) => (
                <article className="rule-item" key={rule.rule_id}>
                  <div className="rule-item-top">
                    <strong>{rule.rule_id}</strong>
                    <StatusBadge tone={rule.triggered ? "danger" : "neutral"}>
                      {rule.triggered ? "Triggered" : "Not triggered"}
                    </StatusBadge>
                  </div>
                  <p>{rule.description}</p>
                  <span className="rule-reason">{rule.reason}</span>
                  <div className="feature-checks">
                    {rule.features_examined.map((feature) => (
                      <span className="feature-check" key={feature.name}>
                        {feature.name} {feature.operator} {feature.threshold}
                        <b>{String(feature.observed_value)}</b>
                      </span>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="muted-copy">Rule results are unavailable.</p>
          )}
        </section>

        <section className="detail-section">
          <div className="detail-section-heading">
            <h3>Assessment explanations</h3>
            <span>Evidence-based</span>
          </div>
          {assessment.explanations.length > 0 ? (
            <ul className="explanation-list">
              {assessment.explanations.map((explanation, index) => (
                <li key={`${result.row_number}-explanation-${index}`}>
                  {explanation}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted-copy">No explanations were returned.</p>
          )}
        </section>

        <section className="detail-section">
          <div className="detail-section-heading">
            <h3>Recommendations</h3>
            <span>Human review required</span>
          </div>
          {recommendations.length > 0 ? (
            <div className="recommendation-list">
              {recommendations.map((recommendation, index) => (
                <article
                  className="recommendation-card"
                  key={`${recommendation.action_key}-${index}`}
                >
                  <div className="recommendation-title">
                    <strong>{recommendation.description}</strong>
                    <StatusBadge tone="warning">
                      {readableLabel(recommendation.review_status)}
                    </StatusBadge>
                  </div>
                  <p>{recommendation.rationale}</p>
                  <div className="reference-list">
                    {recommendation.evidence_references.map((reference) => (
                      <span key={reference}>{reference}</span>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="muted-copy">No recommendations were returned.</p>
          )}
        </section>
      </div>
    </details>
  );
}

function BatchResults({ batch }: { batch: BatchAssessmentResponse }) {
  return (
    <section className="panel results-panel" id="results">
      <div className="panel-heading results-heading">
        <div>
          <span className="eyebrow">Batch {batch.batch_id.slice(0, 8)}</span>
          <h2>Assessment results</h2>
        </div>
        <StatusBadge
          tone={
            batch.invalid_rows + batch.processing_errors > 0
              ? "warning"
              : "success"
          }
        >
          {batch.assessed_rows} assessed
        </StatusBadge>
      </div>

      <div className="batch-counts">
        <div className="count-group">
          <span className="count-group-label">Model predictions</span>
          <div className="count-pills">
            {predictionRows.map(({ key, label }) => (
              <span className="count-pill" key={key}>
                {label} <strong>{batch.prediction_counts[key]}</strong>
              </span>
            ))}
          </div>
        </div>
        <div className="count-group">
          <span className="count-group-label">Handling outcomes</span>
          <div className="count-pills">
            {outcomeRows.map(({ key, label }) => (
              <span className="count-pill" key={key}>
                {label} <strong>{batch.handling_outcome_counts[key]}</strong>
              </span>
            ))}
          </div>
        </div>
      </div>

      {batch.results.length > 0 ? (
        <div className="individual-results">
          {batch.results.map((result) => (
            <AssessmentDetail key={result.row_number} result={result} />
          ))}
        </div>
      ) : (
        <div className="empty-results">
          <span className="empty-results-icon" aria-hidden="true">
            ◇
          </span>
          <h3>No rows were successfully assessed</h3>
          <p>
            Review the row-level validation and processing details below.
          </p>
        </div>
      )}

      {(batch.row_errors.length > 0 ||
        batch.processing_errors_detail.length > 0) && (
        <div className="batch-errors">
          {batch.row_errors.length > 0 && (
            <section>
              <div className="detail-section-heading">
                <h3>Invalid rows</h3>
                <StatusBadge tone="warning">{batch.invalid_rows}</StatusBadge>
              </div>
              <ul className="error-list">
                {batch.row_errors.map((error) => (
                  <li key={`invalid-${error.row_number}`}>
                    <strong>Row {error.row_number}</strong>
                    <span>{error.message}</span>
                    <code>{error.code}</code>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {batch.processing_errors_detail.length > 0 && (
            <section>
              <div className="detail-section-heading">
                <h3>Processing errors</h3>
                <StatusBadge tone="danger">
                  {batch.processing_errors}
                </StatusBadge>
              </div>
              <ul className="error-list">
                {batch.processing_errors_detail.map((error) => (
                  <li key={`processing-${error.row_number}`}>
                    <strong>Row {error.row_number}</strong>
                    <span>{error.message}</span>
                    <code>{error.code}</code>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </section>
  );
}

export default function DashboardPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [batch, setBatch] = useState<BatchAssessmentResponse | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [feedback, setFeedback] = useState<{
    tone: "success" | "error";
    message: string;
  } | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<
    "checking" | "online" | "offline"
  >("checking");
  const [healthCheckCount, setHealthCheckCount] = useState(0);

  useEffect(() => {
    let active = true;
    setConnectionStatus("checking");
    checkBackendHealth()
      .then((healthy) => {
        if (active) setConnectionStatus(healthy ? "online" : "offline");
      })
      .catch(() => {
        if (active) setConnectionStatus("offline");
      });
    return () => {
      active = false;
    };
  }, [healthCheckCount]);

  function chooseFile(file: File | undefined) {
    if (!file || isUploading) return;
    setFeedback(null);
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setSelectedFile(null);
      setFeedback({ tone: "error", message: "Choose a file with the .csv extension." });
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setSelectedFile(null);
      setFeedback({ tone: "error", message: "CSV files must be 10 MiB or smaller." });
      return;
    }
    setSelectedFile(file);
    setBatch(null);
  }

  async function submitBatch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedFile || isUploading) return;
    setIsUploading(true);
    setBatch(null);
    setFeedback(null);
    try {
      const result = await assessCsvBatch(selectedFile);
      setBatch(result);
      const partial = result.invalid_rows > 0 || result.processing_errors > 0;
      setFeedback({
        tone: "success",
        message: partial
          ? `Batch completed with ${result.assessed_rows} assessed, ${result.invalid_rows} invalid, and ${result.processing_errors} processing errors.`
          : `Batch assessment complete. ${result.assessed_rows} rows assessed.`,
      });
    } catch (error) {
      setFeedback({
        tone: "error",
        message:
          error instanceof Error
            ? error.message
            : "The CSV assessment failed. Please try again.",
      });
    } finally {
      setIsUploading(false);
    }
  }

  const batchReady = batch !== null;

  return (
    <AppShell
      connectionStatus={connectionStatus}
      onCheckConnection={() => setHealthCheckCount((count) => count + 1)}
    >
      <main className="dashboard-content" id="overview">
        <section className="page-intro">
          <div>
            <div className="page-kicker">
              <span className="kicker-line" />
              THREAT ANALYSIS WORKSPACE
            </div>
            <h1>
              Cognitive Threat
              <br />
              <span>Detection</span>
            </h1>
            <p>
              Assess network traffic with machine learning, rule-based evidence,
              and transparent risk explanations.
            </p>
          </div>
          <div className="intro-graphic" aria-hidden="true">
            <div className="graphic-ring ring-one" />
            <div className="graphic-ring ring-two" />
            <div className="graphic-ring ring-three" />
            <div className="graphic-core">
              <span>CT</span>
            </div>
            <span className="graphic-node node-one" />
            <span className="graphic-node node-two" />
            <span className="graphic-node node-three" />
            <span className="graphic-signal">EVIDENCE · RISK · CONTEXT</span>
          </div>
        </section>

        <section className="metrics-grid" aria-label="Batch summary">
          <MetricCard
            label="Total rows"
            value={batch?.total_rows ?? null}
            detail={batch ? "Rows in uploaded dataset" : "Awaiting dataset"}
            accent="blue"
            icon="▤"
          />
          <MetricCard
            label="Assessed"
            value={batch?.assessed_rows ?? null}
            detail={batch ? "Successful assessments" : "Awaiting assessment"}
            accent="mint"
            icon="✓"
          />
          <MetricCard
            label="Invalid rows"
            value={batch?.invalid_rows ?? null}
            detail={batch ? "Rows rejected by validation" : "No batch submitted"}
            accent="amber"
            icon="!"
          />
          <MetricCard
            label="Processing errors"
            value={batch?.processing_errors ?? null}
            detail={batch ? "Rows not processed" : "No batch submitted"}
            accent="rose"
            icon="↗"
          />
        </section>

        <div className="dashboard-grid">
          <section className="panel upload-panel" id="upload">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Dataset ingestion</span>
                <h2>Assess a traffic dataset</h2>
              </div>
              <span className="step-indicator">01 / UPLOAD</span>
            </div>
            <p className="panel-description">
              Upload a supported CSV file. Parsing, feature mapping, and row
              validation are handled by the assessment service.
            </p>

            <form onSubmit={submitBatch}>
              <label className={`drop-zone${selectedFile ? " has-file" : ""}`}>
                <input
                  accept=".csv,text/csv"
                  className="visually-hidden"
                  disabled={isUploading}
                  onChange={(event) => {
                    chooseFile(event.currentTarget.files?.[0]);
                    event.currentTarget.value = "";
                  }}
                  type="file"
                />
                <span className="upload-icon" aria-hidden="true">
                  ↑
                </span>
                <strong>
                  {selectedFile ? "Choose a different CSV" : "Select a CSV file"}
                </strong>
                <span>or browse from your computer</span>
                <small>CSV format · Maximum file size 10 MiB</small>
              </label>

              {selectedFile && (
                <div className="selected-file">
                  <span className="file-type-mark">CSV</span>
                  <span className="file-details">
                    <strong>{selectedFile.name}</strong>
                    <span>{formatFileSize(selectedFile.size)}</span>
                  </span>
                  <button
                    className="remove-file"
                    disabled={isUploading}
                    onClick={() => {
                      setSelectedFile(null);
                      setFeedback(null);
                    }}
                    type="button"
                    aria-label="Remove selected file"
                  >
                    ×
                  </button>
                </div>
              )}

              {feedback && (
                <div className={`feedback-message ${feedback.tone}`} role="status">
                  <span aria-hidden="true">
                    {feedback.tone === "success" ? "✓" : "!"}
                  </span>
                  {feedback.message}
                </div>
              )}

              <button
                className="primary-button"
                disabled={!selectedFile || isUploading}
                type="submit"
              >
                {isUploading ? (
                  <>
                    <span className="button-spinner" />
                    Assessing dataset…
                  </>
                ) : (
                  <>
                    Run batch assessment
                    <span aria-hidden="true">→</span>
                  </>
                )}
              </button>
            </form>

            <div className="upload-footnote">
              <span className="lock-mark" aria-hidden="true">
                ◈
              </span>
              Data is assessed by the configured backend. Files are not stored
              by this interface.
            </div>
          </section>

          <RiskSummary counts={batch?.risk_level_counts ?? null} />
        </div>

        <section className="panel prediction-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Signal overview</span>
              <h2>Prediction and handling outcomes</h2>
            </div>
            {batchReady && <StatusBadge tone="info">Current batch</StatusBadge>}
          </div>
          {batch ? (
            <div className="signal-grid">
              <div className="signal-column">
                <span className="count-group-label">Model predictions</span>
                {predictionRows.map(({ key, label }) => (
                  <div className="signal-row" key={key}>
                    <span>{label}</span>
                    <strong>{batch.prediction_counts[key]}</strong>
                  </div>
                ))}
              </div>
              <div className="signal-column">
                <span className="count-group-label">Handling outcomes</span>
                {outcomeRows.map(({ key, label }) => (
                  <div className="signal-row" key={key}>
                    <span>{label}</span>
                    <strong>{batch.handling_outcome_counts[key]}</strong>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="signal-empty">
              Submit a CSV to see prediction and handling counts based on
              returned assessment results.
            </div>
          )}
        </section>

        {batch && <BatchResults batch={batch} />}

        <footer className="page-footer">
          <span>Cognitive Threat Detection</span>
          <span>Assessment outputs are decision support, not automated response.</span>
        </footer>
      </main>
    </AppShell>
  );
}
