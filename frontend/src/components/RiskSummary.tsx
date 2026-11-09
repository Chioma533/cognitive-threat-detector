import type { RiskLevelCounts } from "../types/assessment";

interface RiskSummaryProps {
  counts: RiskLevelCounts | null;
}

const levels: {
  key: keyof RiskLevelCounts;
  label: string;
  tone: string;
}[] = [
  { key: "low", label: "Low", tone: "low" },
  { key: "medium", label: "Medium", tone: "medium" },
  { key: "high", label: "High", tone: "high" },
  { key: "indeterminate", label: "Indeterminate", tone: "indeterminate" },
];

export default function RiskSummary({ counts }: RiskSummaryProps) {
  const total = counts
    ? Object.values(counts).reduce((sum, count) => sum + count, 0)
    : 0;

  return (
    <section className="panel risk-panel" aria-labelledby="risk-summary-title">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Risk distribution</span>
          <h2 id="risk-summary-title">Assessment risk levels</h2>
        </div>
        <span className="panel-heading-mark" aria-hidden="true">
          ◒
        </span>
      </div>
      {counts ? (
        <div className="risk-level-list">
          {levels.map(({ key, label, tone }) => {
            const count = counts[key];
            const width = total === 0 ? 0 : (count / total) * 100;
            return (
              <div className="risk-level-row" key={key}>
                <div className="risk-level-label">
                  <span className={`risk-dot ${tone}`} />
                  <span>{label}</span>
                  <strong>{count}</strong>
                </div>
                <div
                  className="risk-track"
                  role="img"
                  aria-label={`${label}: ${count} assessments`}
                >
                  <span
                    className={`risk-track-fill ${tone}`}
                    style={{ width: `${width}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-chart">
          <span className="empty-chart-icon" aria-hidden="true">
            ◌
          </span>
          <p>Risk levels will appear after a dataset is assessed.</p>
        </div>
      )}
    </section>
  );
}
