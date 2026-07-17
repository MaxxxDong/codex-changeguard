/** Ticket 05 untrusted page-evidence contracts. */

import type { QuarantineRecord } from "../evidence/types.js";
import type { IncidentFingerprint } from "../core/types.js";

export type PageMode = "public" | "logged_visible";

export type PageDisclosureDecision =
  | "approved"
  | "refused"
  | "not_requested";

export type LabelKind =
  | "observed_fact"
  | "author_claim"
  | "command_workaround"
  | "inference";

export type Applicability =
  | "applicable_candidate"
  | "not_applicable"
  | "insufficient_evidence"
  | "wrong_platform"
  | "wrong_surface"
  | "wrong_mechanism"
  | "chatgpt_out_of_scope"
  | "unsupported_assertion";

export type PageConfidence = "none" | "low" | "medium";

export type PageRisk = "low" | "moderate" | "high";

export type RepairDslOpKind =
  | "exact_block_removal"
  | "config_set"
  | "config_remove"
  | "unknown_unsupported";

export interface PageMetadata {
  host?: string;
  content_type?: string;
  language?: string;
  status_code?: number;
  source_label?: string;
}

/**
 * Bounded page-evidence envelope supplied by the orchestrator.
 * Production CLI/MCP never scrape browser cookies/storage/auth material.
 */
export interface PageEvidenceEnvelope {
  schema_version: 1;
  url: string;
  page_mode: PageMode;
  visible_title: string;
  visible_text: string;
  metadata: PageMetadata;
}

export interface LabeledExtractionItem {
  kind: LabelKind;
  field:
    | "symptom"
    | "platform"
    | "surface"
    | "version"
    | "error"
    | "stack_symbol"
    | "failure_phase"
    | "operation"
    | "cited_source"
    | "conclusion"
    | "other";
  value: string;
  /** Always untrusted; page text never upgrades provenance. */
  trust: "untrusted_page";
}

export interface PageExtraction {
  observed_facts: LabeledExtractionItem[];
  author_claims: LabeledExtractionItem[];
  commands_workarounds: LabeledExtractionItem[];
  inferences: LabeledExtractionItem[];
  symptoms: string[];
  platform: string | null;
  surface: string | null;
  versions: string[];
  errors: string[];
  stack_symbols: string[];
  failure_phase: string | null;
  operations: string[];
  cited_sources: string[];
  conclusions: string[];
}

/**
 * Untrusted Repair DSL candidate derived from page commands.
 * Never authorized, executed, or upgraded to Ticket 02 apply.
 */
export interface UntrustedRepairDslCandidate {
  schema_version: 1;
  candidate_id: string;
  source: "page_command";
  trust: "untrusted_page";
  status: "candidate_only";
  operation_kind: RepairDslOpKind;
  /** Path alias only when mappable; never absolute path. */
  target_path_alias: string | null;
  raw_command_sha256: string;
  /** Bounded redacted summary — never full secret-bearing command. */
  summary: string;
  /** Eligible only for later isolated Repair Capsule validation, never apply. */
  eligible_for_validation: boolean;
  refused_reasons: string[];
}

export interface PageComparison {
  applicability: Applicability;
  /** Hard-gated: wrong platform/surface/ChatGPT cannot become high via lexical match. */
  confidence: PageConfidence;
  missing_evidence: string[];
  refuting_evidence: string[];
  risk: PageRisk;
  safe_isolation_experiment: string | null;
  /** True only when a bounded DSL candidate may enter later capsule validation. */
  eligible_for_repair_capsule_validation: boolean;
  local_fingerprint_digest: string | null;
  local_surface: string | null;
  local_platform: string | null;
  page_platform: string | null;
  page_surface: string | null;
  notes: string[];
}

export interface PageEvidenceRecord {
  schema_version: 1;
  url: string;
  page_mode: PageMode;
  content_sha256: string;
  title_sha256: string;
  quarantine: QuarantineRecord | null;
  extraction: PageExtraction;
  repair_dsl_candidates: UntrustedRepairDslCandidate[];
  /** True when instruction-like / injection content was quarantined. */
  injection_quarantined: boolean;
  /** Hard guarantee: page text did not alter policy/provenance/tools. */
  policy_mutations_blocked: true;
}

/**
 * Optional injectable public-page transport (tests only).
 * Production CLI/MCP never inject a live network transport.
 */
export interface PageTransportRequest {
  url: string;
  disclosure_manifest_id: string;
  allowed_fields: string[];
}

export interface PageTransportResponse {
  visible_title: string;
  visible_text: string;
  metadata?: PageMetadata;
}

export interface PageTransport {
  fetchVisible(request: PageTransportRequest): PageTransportResponse;
}

export interface PageDisclosureField {
  field_name: string;
  trust_class: "device_only" | "redacted_structured" | "exportable_after_review";
  source_class: "user_provided" | "local_observed";
  transformation: string;
  destination: string;
  purpose: string;
  optional: boolean;
}

export interface PageDisclosureManifest {
  schema_version: 1;
  manifest_id: string;
  fields: PageDisclosureField[];
  purpose: string;
  destinations: string[];
}

export interface PageAnalysisResult {
  schema_version: 1;
  ok: boolean;
  page_evidence: PageEvidenceRecord | null;
  comparison: PageComparison | null;
  disclosure_decision: PageDisclosureDecision;
  disclosure_manifest: PageDisclosureManifest;
  transport_calls: number;
  /** Separated labels for public outputs (page content remains untrusted). */
  observed_facts: string[];
  user_reports: string[];
  hypotheses: string[];
  local_incident: IncidentFingerprint | null;
  network_used: false;
  target_mutated: false;
  repair_applied: false;
  /** Explicit: page commands never authorized. */
  repair_authorized: false;
  error_code: string | null;
  error_message: string | null;
}
