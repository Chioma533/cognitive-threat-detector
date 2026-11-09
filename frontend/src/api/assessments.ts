import { getErrorMessage, requestApi } from "./client";
import type {
  Assessment,
  BatchAssessmentResponse,
  BatchAssessmentResult,
  HandlingDecision,
  Recommendation,
  RuleResult,
} from "../types/assessment";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCountRecord(
  value: unknown,
  keys: readonly string[],
): value is Record<string, number> {
  return (
    isRecord(value) &&
    keys.every(
      (key) =>
        typeof value[key] === "number" &&
        Number.isInteger(value[key]) &&
        value[key] >= 0,
    )
  );
}

function isRowError(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.row_number === "number" &&
    typeof value.code === "string" &&
    typeof value.message === "string"
  );
}

function isOneOf<T extends string>(
  value: unknown,
  values: readonly T[],
): value is T {
  return typeof value === "string" && values.some((candidate) => candidate === value);
}

function isFiniteNumberOrNull(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isFinite(value));
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRuleResult(value: unknown): value is RuleResult {
  return (
    isRecord(value) &&
    typeof value.rule_id === "string" &&
    typeof value.triggered === "boolean" &&
    isOneOf(value.severity, ["low", "medium", "high"]) &&
    typeof value.description === "string" &&
    typeof value.reason === "string" &&
    Array.isArray(value.features_examined) &&
    value.features_examined.every(
      (feature) =>
        isRecord(feature) &&
        typeof feature.name === "string" &&
        (typeof feature.observed_value === "string" ||
          typeof feature.observed_value === "number") &&
        typeof feature.operator === "string" &&
        typeof feature.threshold === "number" &&
        typeof feature.condition_met === "boolean",
    )
  );
}

function isAssessment(value: unknown): value is Assessment {
  if (!isRecord(value) || !isRecord(value.model) || !isRecord(value.rules) ||
      !isRecord(value.risk)) {
    return false;
  }
  const model = value.model;
  const rules = value.rules;
  const risk = value.risk;
  return (
    isOneOf(model.status, ["available", "unavailable"]) &&
    (model.predicted_class === 0 ||
      model.predicted_class === 1 ||
      model.predicted_class === null) &&
    (model.predicted_label === "normal" ||
      model.predicted_label === "attack" ||
      model.predicted_label === null) &&
    isFiniteNumberOrNull(model.class_0_probability) &&
    isFiniteNumberOrNull(model.class_1_probability) &&
    (typeof model.model_name === "string" || model.model_name === null) &&
    (typeof model.model_version === "string" || model.model_version === null) &&
    (typeof model.error_code === "string" || model.error_code === null) &&
    isOneOf(rules.status, ["available", "unavailable"]) &&
    Array.isArray(rules.results) &&
    rules.results.every(isRuleResult) &&
    isStringArray(rules.triggered_rule_ids) &&
    (typeof rules.error_code === "string" || rules.error_code === null) &&
    isOneOf(value.reconciliation, [
      "agreement_attack",
      "agreement_no_attack_signal",
      "ml_only",
      "rules_only",
      "incomplete",
    ]) &&
    isOneOf(risk.status, ["complete", "incomplete"]) &&
    isFiniteNumberOrNull(risk.model_attack_probability) &&
    isFiniteNumberOrNull(risk.model_score) &&
    isFiniteNumberOrNull(risk.rule_score) &&
    isFiniteNumberOrNull(risk.combined_score) &&
    isOneOf(risk.level, ["low", "medium", "high", "indeterminate"]) &&
    (typeof risk.policy_version === "string" || risk.policy_version === null) &&
    isStringArray(value.explanations)
  );
}

function isHandlingDecision(value: unknown): value is HandlingDecision {
  return (
    isRecord(value) &&
    isOneOf(value.outcome, [
      "security_incident",
      "assessment_review",
      "no_action",
      "processing_failure",
    ]) &&
    typeof value.create_security_incident === "boolean" &&
    typeof value.create_assessment_review === "boolean" &&
    typeof value.requires_operational_review === "boolean" &&
    (value.category === "security_incident" ||
      value.category === "assessment_review" ||
      value.category === null) &&
    (value.severity === "low" ||
      value.severity === "medium" ||
      value.severity === "high" ||
      value.severity === "indeterminate" ||
      value.severity === null) &&
    (value.initial_status === "new" ||
      value.initial_status === "open" ||
      value.initial_status === "under_investigation" ||
      value.initial_status === "resolved" ||
      value.initial_status === "closed" ||
      value.initial_status === null) &&
    typeof value.reason === "string" &&
    isOneOf(value.risk_level, ["low", "medium", "high", "indeterminate"]) &&
    isOneOf(value.reconciliation, [
      "agreement_attack",
      "agreement_no_attack_signal",
      "ml_only",
      "rules_only",
      "incomplete",
    ]) &&
    isOneOf(value.model_status, ["available", "unavailable"]) &&
    isOneOf(value.rule_status, ["available", "unavailable"]) &&
    isStringArray(value.triggered_rule_ids)
  );
}

function isRecommendation(value: unknown): value is Recommendation {
  return (
    isRecord(value) &&
    typeof value.action_key === "string" &&
    typeof value.description === "string" &&
    typeof value.rationale === "string" &&
    isStringArray(value.evidence_references) &&
    value.review_status === "pending"
  );
}

function isBatchResult(value: unknown): value is BatchAssessmentResult {
  return (
    isRecord(value) &&
    typeof value.row_number === "number" &&
    Number.isInteger(value.row_number) &&
    isAssessment(value.assessment) &&
    isHandlingDecision(value.handling_decision) &&
    Array.isArray(value.recommendations) &&
    value.recommendations.every(isRecommendation)
  );
}

function isBatchAssessmentResponse(
  value: unknown,
): value is BatchAssessmentResponse {
  return (
    isRecord(value) &&
    typeof value.batch_id === "string" &&
    ["total_rows", "assessed_rows", "invalid_rows", "processing_errors"].every(
      (key) =>
        typeof value[key] === "number" &&
        Number.isInteger(value[key]) &&
        value[key] >= 0,
    ) &&
    isCountRecord(value.prediction_counts, ["normal", "attack", "unavailable"]) &&
    isCountRecord(value.risk_level_counts, [
      "low",
      "medium",
      "high",
      "indeterminate",
    ]) &&
    isCountRecord(value.handling_outcome_counts, [
      "security_incident",
      "assessment_review",
      "no_action",
      "processing_failure",
    ]) &&
    Array.isArray(value.results) &&
    value.results.every(isBatchResult) &&
    Array.isArray(value.row_errors) &&
    value.row_errors.every(isRowError) &&
    Array.isArray(value.processing_errors_detail) &&
    value.processing_errors_detail.every(isRowError)
  );
}

export async function assessCsvBatch(
  file: File,
): Promise<BatchAssessmentResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await requestApi("/assessments/batch", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    throw await getErrorMessage(response);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new Error("The backend returned an invalid assessment response.");
  }
  if (!isBatchAssessmentResponse(body)) {
    throw new Error("The backend returned an unexpected assessment response.");
  }
  return body;
}
