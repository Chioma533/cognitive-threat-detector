export type PredictionLabel = "normal" | "attack";
export type PredictionCountKey = PredictionLabel | "unavailable";
export type RiskLevel = "low" | "medium" | "high" | "indeterminate";
export type HandlingOutcome =
  | "security_incident"
  | "assessment_review"
  | "no_action"
  | "processing_failure";
export type ReconciliationOutcome =
  | "agreement_attack"
  | "agreement_no_attack_signal"
  | "ml_only"
  | "rules_only"
  | "incomplete";
export type EvidenceStatus = "available" | "unavailable";

export interface ModelEvidence {
  status: EvidenceStatus;
  predicted_class: 0 | 1 | null;
  predicted_label: PredictionLabel | null;
  class_0_probability: number | null;
  class_1_probability: number | null;
  model_name: string | null;
  model_version: string | null;
  error_code: string | null;
}

export interface FeatureCheck {
  name: string;
  observed_value: string | number;
  operator: string;
  threshold: number;
  condition_met: boolean;
}

export interface RuleResult {
  rule_id: string;
  triggered: boolean;
  severity: "low" | "medium" | "high";
  description: string;
  features_examined: FeatureCheck[];
  reason: string;
}

export interface RuleEvidence {
  status: EvidenceStatus;
  results: RuleResult[];
  triggered_rule_ids: string[];
  error_code: string | null;
}

export interface RiskAssessment {
  status: "complete" | "incomplete";
  model_attack_probability: number | null;
  model_score: number | null;
  rule_score: number | null;
  combined_score: number | null;
  level: RiskLevel;
  policy_version: string | null;
}

export interface Assessment {
  model: ModelEvidence;
  rules: RuleEvidence;
  reconciliation: ReconciliationOutcome;
  risk: RiskAssessment;
  explanations: string[];
}

export interface HandlingDecision {
  outcome: HandlingOutcome;
  create_security_incident: boolean;
  create_assessment_review: boolean;
  requires_operational_review: boolean;
  category: "security_incident" | "assessment_review" | null;
  severity: "low" | "medium" | "high" | "indeterminate" | null;
  initial_status: "new" | "open" | "under_investigation" | "resolved" | "closed" | null;
  reason: string;
  risk_level: RiskLevel;
  reconciliation: ReconciliationOutcome;
  model_status: EvidenceStatus;
  rule_status: EvidenceStatus;
  triggered_rule_ids: string[];
}

export interface Recommendation {
  action_key: string;
  description: string;
  rationale: string;
  evidence_references: string[];
  review_status: "pending";
}

export interface BatchAssessmentResult {
  row_number: number;
  assessment: Assessment;
  handling_decision: HandlingDecision;
  recommendations: Recommendation[];
}

export interface RowError {
  row_number: number;
  code: string;
  message: string;
}

export interface PredictionCounts {
  normal: number;
  attack: number;
  unavailable: number;
}

export interface RiskLevelCounts {
  low: number;
  medium: number;
  high: number;
  indeterminate: number;
}

export interface HandlingOutcomeCounts {
  security_incident: number;
  assessment_review: number;
  no_action: number;
  processing_failure: number;
}

export interface BatchAssessmentResponse {
  batch_id: string;
  total_rows: number;
  assessed_rows: number;
  invalid_rows: number;
  processing_errors: number;
  prediction_counts: PredictionCounts;
  risk_level_counts: RiskLevelCounts;
  handling_outcome_counts: HandlingOutcomeCounts;
  results: BatchAssessmentResult[];
  row_errors: RowError[];
  processing_errors_detail: RowError[];
}
