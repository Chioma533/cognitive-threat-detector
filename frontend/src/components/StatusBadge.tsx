import type { ReactNode } from "react";

export type BadgeTone = "success" | "warning" | "danger" | "neutral" | "info";

interface StatusBadgeProps {
  children: ReactNode;
  tone?: BadgeTone;
}

export default function StatusBadge({
  children,
  tone = "neutral",
}: StatusBadgeProps) {
  return <span className={`status-badge ${tone}`}>{children}</span>;
}
