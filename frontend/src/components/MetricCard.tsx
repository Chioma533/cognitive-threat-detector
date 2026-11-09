interface MetricCardProps {
  label: string;
  value: number | null;
  detail: string;
  accent: "mint" | "blue" | "amber" | "rose";
  icon: string;
}

export default function MetricCard({
  label,
  value,
  detail,
  accent,
  icon,
}: MetricCardProps) {
  return (
    <article className={`metric-card ${accent}`}>
      <div className="metric-card-top">
        <span className="metric-label">{label}</span>
        <span className="metric-icon" aria-hidden="true">
          {icon}
        </span>
      </div>
      <div className="metric-value">{value === null ? "—" : value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  );
}
