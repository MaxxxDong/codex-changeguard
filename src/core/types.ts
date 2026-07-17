/** Shared diagnosis contracts for CLI and MCP. */

export type DiagnosisState =
  | "INCONCLUSIVE"
  | "SIGNATURE_DETECTED"
  | "ISSUE_CANDIDATE"
  | "HIGH_CONFIDENCE_MATCH"
  | "SOURCE_COMPONENT_LOCATED"
  | "LOCAL_REPRO_CONFIRMED"
  | "FIX_COMMIT_LINKED"
  | "SAFE_FIX_AVAILABLE"
  | "CONFLICT";

/**
 * User-resolution statuses.
 * Ticket 01 diagnosis uses only the first three.
 * Ticket 02 recovery may emit repair/resolve/rollback statuses.
 * Ticket 09 crash-family may emit UPSTREAM_BLOCKED when a candidate
 * matches but no verifiable fix / safe applicability evidence exists.
 * Only RESOLVED_VERIFIED claims the original problem is fixed.
 */
export type UserResolutionStatus =
  | "INCONCLUSIVE"
  | "DIAGNOSIS_COMPLETE"
  | "INSUFFICIENT_LOCAL_FACTS"
  | "UPSTREAM_BLOCKED"
  | "REPAIR_PREVIEWED"
  | "REPAIR_APPLIED"
  | "RESOLVED_VERIFIED"
  | "MITIGATED_VERIFIED_BY_ROLLBACK"
  | "REPAIR_REFUSED"
  | "REPAIR_FAILED_ROLLED_BACK";

export type UpstreamContributionStatus =
  | "NONE"
  | "CANDIDATE_ONLY"
  | "NOT_APPLICABLE";

/** Sanitized crash metadata only — never dump process-memory contents. */
export type CrashInteractionPhase =
  | "neutral_dom_ready"
  | "link_click"
  | "button_click"
  | "webview_attach"
  | "media_canvas"
  | "unknown";

export type CrashPageCapability =
  | "neutral"
  | "media"
  | "canvas"
  | "complex_login"
  | "unknown";

export type CrashConcurrencyContext = "single" | "multi_side_chat" | "unknown";

export interface CrashMetadata {
  exception_code: string | null;
  faulting_module: string | null;
  faulting_symbol: string | null;
  /** Native offset bucket (e.g. 0x2e08f46); not full dump frames. */
  offset_bucket: string | null;
  gpu_child_exit_code: number | null;
  gpu_relaunch_code: number | null;
  interaction_phase: CrashInteractionPhase | null;
  page_capability: CrashPageCapability | null;
  concurrency_context: CrashConcurrencyContext | null;
  concurrent_side_chats: number | null;
  /** Coarse component id (in_app_browser, gpu_process, webview, …). */
  component: string | null;
  /** Disposable isolated profile/process available for active probes. */
  isolation_available: boolean;
  /** Prefer natural-failure evidence when true (default path). */
  natural_failure_only: boolean;
  /** Caller requested an active crash probe (refused without isolation). */
  active_probe_requested: boolean;
  /**
   * When true, dump bodies are present on disk — classifier refuses to parse
   * or export them (MVP: metadata only).
   */
  dump_contents_present: boolean;
}

export type AxisAssessmentStatus =
  | "supported"
  | "candidate"
  | "unsupported"
  | "unknown"
  | "blocked";

/** Separate local / upstream / fix axes — never collapsed into one score. */
export interface AxisAssessment {
  status: AxisAssessmentStatus;
  summary: string;
  score: number | null;
}

export interface RankedIssueCandidate {
  issue_id: string;
  family_id: string;
  rank: number;
  score: number;
  local_mechanism: AxisAssessment;
  upstream_match: AxisAssessment;
  fix_applicability: AxisAssessment;
  hard_gated: boolean;
  gate_reasons: string[];
}

export interface CrashClassificationResult {
  applicable: boolean;
  diagnosis_state: DiagnosisState;
  user_resolution_status: UserResolutionStatus;
  ranked_candidates: RankedIssueCandidate[];
  rejected_candidates: RankedIssueCandidate[];
  local_mechanism: AxisAssessment;
  upstream_match: AxisAssessment;
  fix_applicability: AxisAssessment;
  /** Always false for Ticket 09 catalog (no verified safe fix). */
  repair_authorization_eligible: false;
  next_evidence_requirements: string[];
  refused_actions: string[];
  family_id: string | null;
  summary: string;
}

export interface PlatformInfo {
  os: "macos" | "windows" | "linux" | "unknown";
  arch: string;
  sandbox_class: string | null;
}

export interface ErrorInfo {
  class: string;
  normalized_message: string;
  message_digest: string | null;
}

export interface StackFrame {
  module: string | null;
  file: string | null;
  symbol: string | null;
  line_bucket: number | null;
}

export interface ArtifactHash {
  path_alias: string;
  sha256: string;
}

export interface IncidentFingerprint {
  schema_version: 1;
  codex_version: string | null;
  build_sha: string | null;
  surface:
    | "desktop"
    | "cli"
    | "plugin"
    | "mcp"
    | "browser_control"
    | "app_server"
    | "unknown";
  platform: PlatformInfo;
  failure_phase:
    | "startup"
    | "hook_load"
    | "extension_handshake"
    | "tab_discovery"
    | "navigation"
    | "tool_call"
    | "output_decode"
    | "shutdown"
    | "unknown";
  error: ErrorInfo;
  stack_frames?: StackFrame[];
  config_keys?: string[];
  feature_ids?: string[];
  artifact_hashes?: ArtifactHash[];
  ast_signature_ids?: string[];
  /**
   * Optional sanitized crash metadata (Ticket 09). Never includes dump
   * contents; Event Viewer / Crashpad metadata fields only.
   */
  crash_metadata?: CrashMetadata | null;
  local_facts_digest: string;
}

export interface UserResolutionReceipt {
  status: UserResolutionStatus;
  summary: string;
  /** Independent of upstream contribution. */
  receipt_id: string;
}

export interface UpstreamContributionReceipt {
  status: UpstreamContributionStatus;
  summary: string;
  issue_candidates: string[];
  receipt_id: string;
}

export interface MeasuredEvidence {
  kind: string;
  detail: string;
  /** Independent measurement — never a self-declared JSON claim alone. */
  measured: boolean;
}

export interface DiagnosisResult {
  schema_version: 1;
  ok: boolean;
  diagnosis_state: DiagnosisState;
  incident_fingerprint: IncidentFingerprint | null;
  user_resolution: UserResolutionReceipt;
  upstream_contribution: UpstreamContributionReceipt;
  evidence: MeasuredEvidence[];
  /** Generic path-free error codes for callers. */
  error_code: string | null;
  error_message: string | null;
  /** Read-only ticket boundary markers. */
  network_used: false;
  target_mutated: false;
  repair_applied: false;
  /**
   * Ticket 09 crash-family classification (null when not applicable).
   * Keeps local_mechanism / upstream_match / fix_applicability separate.
   */
  crash_classification?: CrashClassificationResult | null;
  /**
   * Optional model rerank attempt recorded for audit; never overrides gates.
   * Present only when diagnose options supply model preferences.
   */
  model_ranking_applied?: boolean;
}

export interface DiagnoseOptions {
  /** When set, used only for test fixture id validation paths. */
  fixture_id?: string;
  /**
   * Optional model-preferred Issue ids for rerank experiments.
   * Cannot bypass hard gates or invent provenance/fix applicability.
   */
  model_preferred_issue_ids?: string[];
}
