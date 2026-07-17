/**
 * Ticket 06 — KNOWN_GOOD, rollback, update-regression A/B, canary, supersession.
 * Contracts only; no absolute paths or secrets in public results.
 */

import type {
  MeasuredEvidence,
  UpstreamContributionReceipt,
  UserResolutionReceipt,
  UserResolutionStatus,
} from "../types.js";

/** Control-plane surfaces retained as KNOWN_GOOD (last three healthy). */
export type ControlSurface = "config" | "plugin" | "skill" | "mcp" | "hook";

export const CONTROL_SURFACES: readonly ControlSurface[] = [
  "config",
  "plugin",
  "skill",
  "mcp",
  "hook",
] as const;

/** Version guidance after canary / update lifecycle evaluation. */
export type VersionGuidance =
  | "RECOMMEND_UPGRADE"
  | "UPGRADE_CANARY_AVAILABLE"
  | "HOLD_KNOWN_GOOD"
  | "GENERAL_UPDATE_ONLY";

export type RecipeLifecycleStatus =
  | "ACTIVE_WORKAROUND"
  | "SUPERSEDED_BY_UPSTREAM_FIX";

export type LifecycleOperation =
  | "status"
  | "record_repair_backup"
  | "record_successful_start"
  | "record_known_good"
  | "apply_retention"
  | "assess_update_regression"
  | "rollback_surface"
  | "cli_version_rollback_preview"
  | "desktop_version_rollback_preview"
  | "canary"
  | "supersede_recipe";

export type BackupKind = "repair" | "known_good";

export type BackupRecordStatus =
  | "active"
  | "expired"
  | "retained_known_good"
  | "pruned";

export interface RepairBackupRecord {
  schema_version: 1;
  kind: "repair";
  backup_id: string;
  /** Registered relative path under the isolated root (ChangeGuard-owned). */
  backup_rel: string;
  original_sha256: string;
  surface: ControlSurface | "artifact";
  instance_id: string;
  created_at_ms: number;
  successful_start_count: number;
  status: BackupRecordStatus;
  content_digest: string;
}

export interface KnownGoodCheckpoint {
  schema_version: 1;
  kind: "known_good";
  checkpoint_id: string;
  surface: ControlSurface;
  instance_id: string;
  /** Live control-file relative path (registered alias resolution). */
  target_rel: string;
  backup_rel: string;
  content_sha256: string;
  created_at_ms: number;
  status: BackupRecordStatus;
  content_digest: string;
  healthy: true;
}

export type LifecycleBackupRecord = RepairBackupRecord | KnownGoodCheckpoint;

export interface RetentionDecision {
  backup_id: string;
  action: "keep" | "prune";
  reason:
    | "within_min_age"
    | "within_min_starts"
    | "expired_age_and_starts"
    | "known_good_last_three"
    | "known_good_beyond_last_three"
    | "already_pruned"
    | "corrupt_refused";
  receipt_id: string;
}

export interface RetentionReceipt {
  schema_version: 1;
  evaluated_at_ms: number;
  decisions: RetentionDecision[];
  pruned_ids: string[];
  kept_ids: string[];
  /** Paths deleted are only under registered ChangeGuard lifecycle state. */
  deleted_outside_registered_state: false;
}

export interface ABObservation {
  version: string;
  fault_reproduced: boolean;
  /** Must be true — self-declared timestamp claims are insufficient. */
  measured: true;
  mechanism_id: string;
  instance_id: string;
}

export interface UpdateRegressionAssessment {
  established: boolean;
  reason_code:
    | "AB_REGRESSION_ESTABLISHED"
    | "TIMESTAMP_ONLY_INSUFFICIENT"
    | "INSTANCE_MISMATCH"
    | "MECHANISM_MISMATCH"
    | "CONTROL_NOT_HEALTHY"
    | "TREATMENT_NOT_FAULTY"
    | "VERSIONS_NOT_DISTINCT"
    | "UNMEASURED";
  instance_id: string | null;
  mechanism_id: string | null;
  version_before: string | null;
  version_after: string | null;
}

/** Canonical CLI install-source enum (exact strings only). */
export const CLI_INSTALL_SOURCE_VALUES = [
  "official_npm",
  "official_installer",
  "homebrew_cask_official",
  "untrusted",
  "absent",
] as const;

export type CliInstallSource = (typeof CLI_INSTALL_SOURCE_VALUES)[number];

/** Official install sources that may participate in accepted CLI pin previews. */
export const OFFICIAL_CLI_INSTALL_SOURCES = [
  "official_npm",
  "official_installer",
  "homebrew_cask_official",
] as const;

export type OfficialCliInstallSource =
  (typeof OFFICIAL_CLI_INSTALL_SOURCES)[number];

/**
 * Canonical provenance-trust enum for CLI/Desktop rollback previews.
 * Exact string match only — no case fold, trim, or Unicode normalization.
 */
export const PROVENANCE_TRUST_VALUES = [
  "trusted_official",
  "untrusted",
  "absent",
] as const;

export type ProvenanceTrust = (typeof PROVENANCE_TRUST_VALUES)[number];

/**
 * Fail-closed trusted-provenance allowlist for rollback acceptance.
 * Only these exact labels may yield accepted=true (currently one value).
 */
export const TRUSTED_PROVENANCE_ALLOWLIST = ["trusted_official"] as const;

export type TrustedProvenance = (typeof TRUSTED_PROVENANCE_ALLOWLIST)[number];

export function isProvenanceTrust(v: unknown): v is ProvenanceTrust {
  return (
    v === "trusted_official" || v === "untrusted" || v === "absent"
  );
}

/** Exact allowlist gate — only `trusted_official` is trusted for rollback. */
export function isTrustedRollbackProvenance(
  v: unknown,
): v is TrustedProvenance {
  return v === "trusted_official";
}

export function isCliInstallSource(v: unknown): v is CliInstallSource {
  return (
    v === "official_npm" ||
    v === "official_installer" ||
    v === "homebrew_cask_official" ||
    v === "untrusted" ||
    v === "absent"
  );
}

export function isOfficialCliInstallSource(
  v: unknown,
): v is OfficialCliInstallSource {
  return (
    v === "official_npm" ||
    v === "official_installer" ||
    v === "homebrew_cask_official"
  );
}

/**
 * Parse untrusted caller input into a ProvenanceTrust value without casting.
 * Missing/empty → absent; known enum kept; everything else → untrusted.
 */
export function parseProvenanceTrust(v: unknown): ProvenanceTrust {
  if (v === undefined || v === null || v === "") return "absent";
  if (isProvenanceTrust(v)) return v;
  return "untrusted";
}

/**
 * Parse untrusted caller input into a CliInstallSource without casting.
 * Missing/empty → absent; known enum kept; unknown labels map to untrusted for
 * typed output only (engine still refuses non-official sources before accept).
 */
export function parseCliInstallSource(v: unknown): CliInstallSource {
  if (v === undefined || v === null || v === "") return "absent";
  if (isCliInstallSource(v)) return v;
  return "untrusted";
}

/**
 * Exact raw install-source string for allowlist checks (no coercion of unknown
 * labels). Missing/empty → "absent"; otherwise the original string.
 */
export function rawCliInstallSource(v: unknown): string {
  if (typeof v !== "string" || v.length === 0) return "absent";
  return v;
}

export interface CliVersionRollbackPreview {
  mode: "preview_only";
  accepted: boolean;
  refuse_code: string | null;
  official_source: CliInstallSource;
  version_pin: string | null;
  provenance: ProvenanceTrust;
  /** Never true — ChangeGuard does not download/store OpenAI binaries. */
  binary_stored: false;
  binary_downloaded: false;
  package_manager_shell_invoked: false;
  registered_operation: "cli_version_pin_via_official_source";
  guidance: string;
}

export interface DesktopVersionRollbackPreview {
  mode: "preview_only";
  accepted: boolean;
  refuse_code: string | null;
  signed_history_available: boolean;
  lawful_media_available: boolean;
  limited: boolean;
  /** Never true — no binary archive/redistribution. */
  binary_stored: false;
  binary_downloaded: false;
  guidance: string;
}

export interface CanaryResult {
  candidate_version: string;
  original_fault_absent: boolean;
  core_regressions_passed: boolean;
  isolated_profile: true;
  version_guidance: VersionGuidance;
  detail: string;
}

export interface RecipeRecord {
  recipe_id: string;
  status: RecipeLifecycleStatus;
  upstream_ref: string | null;
  upstream_evidence_digest: string | null;
  superseded_at_ms: number | null;
  recommendable: boolean;
}

export interface UpstreamEvidenceRef {
  /** Canonical Issue/PR/commit/release id — no crawler. */
  ref: string;
  evidence_digest: string;
  verified: boolean;
}

export interface LifecycleLedger {
  schema_version: 1;
  instance_id: string;
  repair_backups: RepairBackupRecord[];
  known_good: KnownGoodCheckpoint[];
  recipes: RecipeRecord[];
  last_retention: RetentionReceipt | null;
  last_regression: UpdateRegressionAssessment | null;
  last_canary: CanaryResult | null;
  version_guidance: VersionGuidance;
  successful_start_total: number;
  updated_at_ms: number;
  ledger_digest: string;
}

export interface LifecycleResult {
  schema_version: 1;
  ok: boolean;
  operation: LifecycleOperation;
  user_resolution: UserResolutionReceipt;
  upstream_contribution: UpstreamContributionReceipt;
  evidence: MeasuredEvidence[];
  error_code: string | null;
  error_message: string | null;
  network_used: false;
  target_mutated: boolean;
  repair_applied: false;
  /** Mitigation only — never root-cause fixed via lifecycle rollback. */
  user_status: UserResolutionStatus | null;
  ledger: LifecycleLedger | null;
  retention: RetentionReceipt | null;
  regression: UpdateRegressionAssessment | null;
  surface_rollback: {
    surface: ControlSurface;
    instance_id: string;
    checkpoint_id: string;
    resulting_sha256: string;
  } | null;
  cli_preview: CliVersionRollbackPreview | null;
  desktop_preview: DesktopVersionRollbackPreview | null;
  canary: CanaryResult | null;
  recipe: RecipeRecord | null;
  version_guidance: VersionGuidance | null;
  contribution_claim: "none" | "local_only";
}

export interface LifecycleClock {
  nowMs: () => number;
}

export interface RecordRepairBackupInput {
  targetPath: string;
  instance_id: string;
  surface?: ControlSurface | "artifact";
  /** Relative path of live file to back up (must be under target). */
  source_rel: string;
  nowMs?: number;
}

export interface RecordKnownGoodInput {
  targetPath: string;
  instance_id: string;
  surface: ControlSurface;
  nowMs?: number;
}

export interface RecordStartInput {
  targetPath: string;
  instance_id: string;
  nowMs?: number;
}

export interface ApplyRetentionInput {
  targetPath: string;
  instance_id: string;
  nowMs?: number;
}

export interface AssessRegressionInput {
  targetPath: string;
  /** When true, claim is timestamp-only (must be refused). */
  timestamp_only?: boolean;
  control: ABObservation;
  treatment: ABObservation;
  nowMs?: number;
}

export interface RollbackSurfaceInput {
  targetPath: string;
  instance_id: string;
  surface: ControlSurface;
  checkpoint_id: string;
  nowMs?: number;
}

export interface CliRollbackPreviewInput {
  targetPath: string;
  /**
   * Caller-supplied install source. Runtime-validated via exact allowlist;
   * unknown strings are never accepted as official.
   */
  official_source: string;
  version_pin: string | null;
  /**
   * Caller-supplied provenance. Runtime fail-closed: only exact
   * `trusted_official` may accept (no denylist/cast bypass).
   */
  provenance: string;
  nowMs?: number;
}

export interface DesktopRollbackPreviewInput {
  targetPath: string;
  signed_history_available: boolean;
  lawful_media_available: boolean;
  nowMs?: number;
}

export interface CanaryInput {
  targetPath: string;
  candidate_version: string;
  /** Measured: original fault no longer reproduces in isolated profile. */
  original_fault_absent: boolean;
  /** Measured: core regression suite passed. */
  core_regressions_passed: boolean;
  /**
   * Fail closed: only exact `true` means the canary was executed.
   * Omitted/false → UPGRADE_CANARY_AVAILABLE (availability only).
   */
  canary_executed?: boolean;
  nowMs?: number;
}

export interface SupersedeInput {
  targetPath: string;
  recipe_id: string;
  upstream: UpstreamEvidenceRef;
  nowMs?: number;
}

export interface LifecycleStatusInput {
  targetPath: string;
  instance_id?: string;
  nowMs?: number;
}
