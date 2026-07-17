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
 * Only RESOLVED_VERIFIED claims the original problem is fixed.
 */
export type UserResolutionStatus =
  | "INCONCLUSIVE"
  | "DIAGNOSIS_COMPLETE"
  | "INSUFFICIENT_LOCAL_FACTS"
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
}

export interface DiagnoseOptions {
  /** When set, used only for test fixture id validation paths. */
  fixture_id?: string;
}
