/** Ticket 02 recovery contracts — Repair Capsule + authorized apply/verify/rollback. */

import type {
  MeasuredEvidence,
  UpstreamContributionReceipt,
  UserResolutionReceipt,
} from "../types.js";

/** User-resolution statuses reachable after Ticket 02 recovery. */
export type RecoveryUserStatus =
  | "INCONCLUSIVE"
  | "DIAGNOSIS_COMPLETE"
  | "INSUFFICIENT_LOCAL_FACTS"
  | "REPAIR_PREVIEWED"
  | "REPAIR_APPLIED"
  | "RESOLVED_VERIFIED"
  | "MITIGATED_VERIFIED_BY_ROLLBACK"
  | "REPAIR_REFUSED"
  | "REPAIR_FAILED_ROLLED_BACK";

export type RepairOperationKind = "exact_block_removal";

export type RepairRisk = "low" | "moderate" | "high";

export type AuthorizationTier =
  | "experimental_one_shot"
  | "bundled_reviewed";

export interface CapsuleApplicability {
  version_match: boolean;
  platform_match: boolean;
  target_hash_match: boolean;
  pattern_count_match: boolean;
}

export interface CapsuleBackupPlan {
  required: true;
  original_sha256: string;
  backup_rel: string;
  verified: boolean;
  receipt_id: string | null;
}

export interface CapsuleVerificationPlan {
  checks: string[];
  original_failure_must_not_reproduce: true;
  core_health_required: true;
}

export interface CapsuleRollbackPlan {
  recipe: string[];
  restores_original_sha256: string;
}

export interface CapsuleDisclosure {
  /** Field names only — never source bytes or secrets. */
  fields_leaving_device: string[];
  includes_source_bytes: false;
  includes_secrets: false;
}

export interface CapsuleOperation {
  kind: RepairOperationKind;
  /** Path alias only (never absolute path). */
  target_path_alias: string;
  expected_pattern_count: number;
  /** SHA-256 of canonical operation description (no source bytes). */
  operation_digest: string;
  /** SHA-256 of expected post-repair bytes when known; null if computed at apply. */
  expected_result_sha256: string | null;
}

/**
 * Full Repair Capsule preview — no installed-file source bytes, no secrets.
 * Authorization is bound to `authorization_binding` (deterministic digest).
 */
export interface RepairCapsule {
  schema_version: 1;
  capsule_id: string;
  trust_tier: "T1_community" | "T0_model_generated" | "T2_maintainer_workaround";
  mode: "preview_only" | "apply_authorized";
  authorization_tier: AuthorizationTier;
  risk: RepairRisk;
  /** One target instance / path alias. */
  target_path_alias: string;
  /** Isolated target scope digest (no absolute path leakage). */
  scope_digest: string;
  original_sha256: string;
  expected_pattern_count: number;
  operation: CapsuleOperation;
  applicability: CapsuleApplicability;
  backup: CapsuleBackupPlan;
  verification: CapsuleVerificationPlan;
  rollback: CapsuleRollbackPlan;
  dry_run_checks: string[];
  /** ISO-8601 UTC expiry; after this the capsule is invalid. */
  expires_at: string;
  /** Digest of invalidation material (hash/count/scope/ops). */
  invalidation_digest: string;
  /**
   * Deterministic authorization binding for one-shot apply.
   * Any target hash, count, scope, dependency, permission, or capsule change
   * yields a different binding — no reusable global trust token.
   */
  authorization_binding: string;
  disclosure: CapsuleDisclosure;
  human_decision: "pending" | "approved" | "rejected";
  smoke_result: "not_run" | "pass" | "fail" | "error";
}

export interface VerificationCheckResult {
  id: string;
  passed: boolean;
  detail: string;
}

export interface VerificationReport {
  passed: boolean;
  original_failure_reproduces: boolean;
  core_health_passed: boolean;
  checks: VerificationCheckResult[];
  measured_sha256: string | null;
  measured_pattern_count: number | null;
}

export interface BackupReceipt {
  backup_rel: string;
  original_sha256: string;
  verified: boolean;
  receipt_id: string;
}

export type RepairOperationName =
  | "preview"
  | "apply"
  | "verify"
  | "rollback";

/**
 * Structured result for all recovery public seams.
 * Shares receipt separation with diagnosis; does not claim external submission.
 */
export interface RepairResult {
  schema_version: 1;
  ok: boolean;
  operation: RepairOperationName;
  capsule: RepairCapsule | null;
  user_resolution: UserResolutionReceipt;
  upstream_contribution: UpstreamContributionReceipt;
  evidence: MeasuredEvidence[];
  error_code: string | null;
  error_message: string | null;
  network_used: false;
  /** True only when this operation mutated the isolated target. */
  target_mutated: boolean;
  repair_applied: boolean;
  auto_rolled_back: boolean;
  verification: VerificationReport | null;
  backup: BackupReceipt | null;
  resulting_sha256: string | null;
  /** Distinct from user_resolution; never claims external contribution. */
  contribution_claim: "none" | "local_only";
}

export interface ApplyOptions {
  /** Exact authorization binding from a prior preview of this capsule/scope. */
  authorization: string;
}

/** Sentinel relative path the harness may plant to induce verify failure. */
export const INDUCE_VERIFY_FAIL_REL = ".changeguard/test-force-verify-fail";

export const RECOVERY_STATE_DIR = ".changeguard";
export const RECOVERY_BACKUP_DIR = ".changeguard/backup";
export const RECOVERY_SESSION_REL = ".changeguard/session.json";
/** Exact capsule from the last successful preview (authorization source of truth). */
export const RECOVERY_CAPSULE_PREVIEW_REL = ".changeguard/capsule-preview.json";
