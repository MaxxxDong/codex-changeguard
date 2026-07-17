/** Ticket 10 upstream draft / routing contracts (preview-only). */

import type { QuarantineRecord } from "../evidence/types.js";
import type { IncidentFingerprint } from "../core/types.js";

export type UpstreamRoute =
  | "GITHUB_ISSUE"
  | "GITHUB_DISCUSSIONS"
  | "BUGCROWD"
  | "OPENAI_SUPPORT";

/** Current openai/codex GitHub Issue form mapping (Ticket 10). */
export type GitHubIssueForm = "APP" | "CLI" | "EXTENSION" | "OTHER";

export type DuplicateState =
  | "EXACT_DUPLICATE"
  | "RELATED_NOT_SAME"
  | "NEW_INCIDENT";

export type CaseKind =
  | "codex_product_bug"
  | "product_support_question"
  | "validated_security_vulnerability"
  | "account_billing_private";

export type ProductSurfaceHint =
  | "app"
  | "cli"
  | "extension"
  | "other"
  | "desktop"
  | "browser_control"
  | "ide"
  | "unknown";

export type ReproductionQuality =
  | "reliable"
  | "intermittent"
  | "once"
  | "unknown";

export type DisclosureDecision = "approved" | "refused" | "not_requested";

export type CapsuleStatus =
  | "PREVIEW_READY"
  | "PREVIEW_BLOCKED"
  | "GATE_FAILED"
  | "ROUTED_PRIVATE";

export type DuplicateRecommendation =
  | "subscribe_or_upvote"
  | "comment_with_delta"
  | "open_new"
  | "cross_link_related"
  | "private_report"
  | "contact_support"
  | "open_discussion";

export type EvidenceDeltaKind =
  | "platform_version"
  | "crash_signature"
  | "minimal_repro"
  | "fix_validation"
  | "rollback_result"
  | "other";

export interface PlatformInfo {
  os: string | null;
  arch: string | null;
  unknown_reason: string | null;
}

export interface ReproductionInfo {
  quality: ReproductionQuality;
  steps: string[];
  intermittent_marker: string | null;
}

export interface DuplicateCandidate {
  issue_id: string;
  title: string;
  state: "open" | "closed";
  /** exact | related | none — caller-supplied search classification. */
  similarity: "exact" | "related" | "none";
  mechanism_match: boolean;
  url: string | null;
}

export interface DuplicateSearch {
  searched: boolean;
  candidates: DuplicateCandidate[];
}

export interface EvidenceDeltaItem {
  kind: EvidenceDeltaKind;
  summary: string;
  material: boolean;
}

export interface EvidenceDelta {
  items: EvidenceDeltaItem[];
}

export interface PrivacyReviewInput {
  secrets_redacted: boolean;
  paths_redacted: boolean;
  session_excluded: boolean;
}

/**
 * Bounded orchestrator-supplied upstream preview request.
 * Production CLI/MCP never scrape secrets or open sockets.
 */
export interface UpstreamPreviewRequest {
  schema_version: 1;
  case_kind: CaseKind;
  surface: ProductSurfaceHint;
  platform: PlatformInfo;
  codex_version: string | null;
  version_unknown_reason: string | null;
  actual_behavior: string;
  technical_signals: string[];
  reproduction: ReproductionInfo;
  observed_facts: string[];
  user_reports: string[];
  hypotheses: string[];
  duplicate_search: DuplicateSearch;
  evidence_delta: EvidenceDelta;
  doctor_json: unknown | null;
  privacy_review: PrivacyReviewInput;
  /** Exact technical error strings (redacted only for secrets/paths). */
  error_strings: string[];
  /** Exact command strings (redacted only for secrets/paths). */
  command_strings: string[];
}

export interface FormBlobRecord {
  filename: string;
  blob_sha: string;
  form: GitHubIssueForm | "FEATURE" | "DOCS" | null;
  notes: string;
}

export interface OfficialFormSnapshot {
  schema_version: 1;
  snapshot_id: string;
  fetched_at: string;
  main_commit: string;
  repository: "openai/codex";
  forms: FormBlobRecord[];
  /** Integrity over snapshot payload (canonical SHA-256). */
  integrity_sha256: string;
  /**
   * Official templates instruct users to search existing issues first and
   * generally react rather than leave redundant duplicate comments.
   */
  duplicate_guidance: "search_first_reaction_only_for_duplicates";
  /** CLI form includes `codex doctor --json` field. */
  cli_form_includes_doctor_json: true;
  /** This snapshot is immutable testable evidence, not a claim of perpetual currency. */
  immutable_snapshot_disclaimer: string;
}

export interface FormSnapshotView {
  snapshot_id: string;
  fetched_at: string;
  main_commit: string;
  integrity_sha256: string;
  freshness: "fresh" | "stale";
  stale_reason: string | null;
  age_ms: number;
  forms: FormBlobRecord[];
  source: "bundled_immutable" | "transport_refresh";
}

export interface DoctorSanitizationResult {
  included: boolean;
  inclusion_manifest: string[];
  sanitized_summary: Record<string, unknown> | null;
  refused_reasons: string[];
  secrets_redacted: boolean;
  paths_redacted: boolean;
}

export interface MaintainerValueGateCheck {
  id: string;
  passed: boolean;
  detail: string;
}

export interface MaintainerValueGateResult {
  passed: boolean;
  checks: MaintainerValueGateCheck[];
  failed_ids: string[];
}

export interface DuplicateAssessment {
  state: DuplicateState;
  matched_issue_id: string | null;
  matched_issue_url: string | null;
  evidence_delta_material: boolean;
  evidence_delta_hash: string | null;
  recommendation: DuplicateRecommendation;
  /** New-issue body; null when exact-dup zero-delta or non-issue routes. */
  draft_body: string | null;
  /** Structured comment for material delta; null when zero-delta exact dup. */
  draft_comment: string | null;
  cross_link_issue_ids: string[];
}

export interface UpstreamDisclosureField {
  field_name: string;
  trust_class: "device_only" | "redacted_structured" | "exportable_after_review";
  source_class: "user_provided" | "local_observed" | "official_snapshot";
  transformation: string;
  destination: string;
  purpose: string;
  optional: boolean;
}

export interface UpstreamDisclosureManifest {
  schema_version: 1;
  manifest_id: string;
  fields: UpstreamDisclosureField[];
  purpose: string;
  destinations: string[];
}

/**
 * Optional injectable official-only form transport (tests/orchestration).
 * Production CLI/MCP inject null — no hidden network.
 */
export interface UpstreamFormTransportRequest {
  disclosure_manifest_id: string;
  allowed_hosts: string[];
  allowed_repositories: string[];
  resource: "issue_forms";
}

export interface UpstreamFormTransportResponse {
  snapshot: OfficialFormSnapshot;
}

export interface UpstreamFormTransport {
  fetchForms(
    request: UpstreamFormTransportRequest,
  ): UpstreamFormTransportResponse;
}

export interface UpstreamSubmissionCapsule {
  schema_version: 1;
  capsule_id: string;
  /** Ticket 10 is always local preview. */
  mode: "preview_only";
  locality: "local_only";
  repair_authorized: false;
  external_write: false;
  /** Ticket 11 requires separate preview + confirmation. */
  requires_ticket11_confirmation: true;
  /** Never SUBMITTED / POSTED in Ticket 10. */
  status: CapsuleStatus;
  route: UpstreamRoute;
  github_issue_form: GitHubIssueForm | null;
  form_filename: string | null;
  duplicate: DuplicateAssessment;
  maintainer_value_gate: MaintainerValueGateResult;
  form_snapshot: FormSnapshotView;
  doctor_inclusion: DoctorSanitizationResult;
  privacy_review: {
    passed: boolean;
    secrets_redacted: boolean;
    paths_redacted: boolean;
    injection_quarantined: boolean;
    quarantine: QuarantineRecord | null;
  };
  observed_facts: string[];
  user_reports: string[];
  hypotheses: string[];
  /** Exact technical strings preserved after required redaction only. */
  error_strings: string[];
  command_strings: string[];
  route_rationale: string;
  draft_title: string | null;
  draft_labels: string[];
  private_report_guidance: string | null;
  support_guidance: string | null;
  discussion_guidance: string | null;
  capsule_content_sha256: string;
}

export interface UpstreamPreviewResult {
  schema_version: 1;
  ok: boolean;
  capsule: UpstreamSubmissionCapsule | null;
  disclosure_decision: DisclosureDecision;
  disclosure_manifest: UpstreamDisclosureManifest;
  transport_calls: number;
  local_incident: IncidentFingerprint | null;
  /**
   * True only when an injected form transport actually ran (tests/orchestration).
   * Production CLI/MCP always inject null transport → false.
   */
  network_used: boolean;
  target_mutated: false;
  repair_applied: false;
  repair_authorized: false;
  external_write: false;
  /** Explicit: no SUBMITTED/POSTED in this ticket. */
  submission_status: "none";
  error_code: string | null;
  error_message: string | null;
}
