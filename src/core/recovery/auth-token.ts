/**
 * Self-contained authorization token for preview → apply without target writes.
 * Encodes capsule material + nonce/expiry; apply revalidates every live precondition.
 * No secret/signature — integrity is the deterministic authorization_binding digest.
 */
import { canonicalJson } from "./canonical.js";
import type { RepairCapsule } from "./types.js";
import {
  RECOVERY_BACKUP_DIR,
  registeredBackupRel,
} from "./types.js";
import {
  authorizationBinding,
  invalidationMaterial,
  operationDigest,
  PROTECTED_PROCESS_OP,
} from "./protected-process.js";

export const AUTH_TOKEN_PREFIX = "cg1.";
/** Hard bound on decoded token payload bytes (preview capsule is small). */
export const MAX_AUTH_TOKEN_BYTES = 24 * 1024;

const SHA256_HEX = /^[a-f0-9]{64}$/;
const NONCE_HEX = /^[a-f0-9]{32}$/;
const CAPSULE_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;

const CAPSULE_KEYS = [
  "schema_version",
  "capsule_id",
  "trust_tier",
  "mode",
  "authorization_tier",
  "risk",
  "target_path_alias",
  "scope_digest",
  "original_sha256",
  "expected_pattern_count",
  "operation",
  "applicability",
  "backup",
  "verification",
  "rollback",
  "dry_run_checks",
  "expires_at",
  "invalidation_digest",
  "authorization_binding",
  "disclosure",
  "human_decision",
  "smoke_result",
  "nonce",
] as const;

const OPERATION_KEYS = [
  "kind",
  "target_path_alias",
  "expected_pattern_count",
  "operation_digest",
  "expected_result_sha256",
] as const;

export type AuthTokenErrorCode =
  | "AUTH_INVALID"
  | "AUTH_EXPIRED"
  | "AUTH_MALFORMED";

export class AuthTokenError extends Error {
  readonly code: AuthTokenErrorCode;
  constructor(code: AuthTokenErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "AuthTokenError";
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function exactKeys(obj: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(obj);
  if (keys.length !== allowed.length) return false;
  const set = new Set(allowed);
  return keys.every((k) => set.has(k));
}

function requireString(v: unknown, max = 512): string | null {
  if (typeof v !== "string" || v.length === 0 || v.length > max) return null;
  return v;
}

function requireSha256(v: unknown): string | null {
  if (typeof v !== "string" || !SHA256_HEX.test(v)) return null;
  return v;
}

function requireBool(v: unknown): boolean | null {
  if (typeof v !== "boolean") return null;
  return v;
}

/**
 * Strict capsule validation: reject unknown/extra/mismatched fields.
 * Mutation-relevant paths and digests must match registered constants.
 */
export function strictValidateCapsule(raw: unknown): RepairCapsule {
  if (!isPlainObject(raw)) {
    throw new AuthTokenError("AUTH_MALFORMED", "Capsule material refused.");
  }
  if (!exactKeys(raw, CAPSULE_KEYS as unknown as string[])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Capsule fields refused.");
  }

  if (raw.schema_version !== 1) {
    throw new AuthTokenError("AUTH_MALFORMED", "Capsule schema refused.");
  }
  const capsule_id = requireString(raw.capsule_id, 128);
  if (!capsule_id || !CAPSULE_ID_RE.test(capsule_id)) {
    throw new AuthTokenError("AUTH_MALFORMED", "Capsule id refused.");
  }
  if (raw.trust_tier !== "T1_community") {
    throw new AuthTokenError("AUTH_MALFORMED", "Trust tier refused.");
  }
  if (raw.mode !== "apply_authorized") {
    throw new AuthTokenError("AUTH_MALFORMED", "Mode refused.");
  }
  if (raw.authorization_tier !== "experimental_one_shot") {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization tier refused.");
  }
  if (raw.risk !== "moderate") {
    throw new AuthTokenError("AUTH_MALFORMED", "Risk refused.");
  }
  if (raw.target_path_alias !== PROTECTED_PROCESS_OP.target_path_alias) {
    throw new AuthTokenError("AUTH_MALFORMED", "Target path alias refused.");
  }
  const scope_digest = requireSha256(raw.scope_digest);
  const original_sha256 = requireSha256(raw.original_sha256);
  if (!scope_digest || !original_sha256) {
    throw new AuthTokenError("AUTH_MALFORMED", "Digest fields refused.");
  }
  if (raw.expected_pattern_count !== PROTECTED_PROCESS_OP.expected_pattern_count) {
    throw new AuthTokenError("AUTH_MALFORMED", "Pattern count refused.");
  }

  if (!isPlainObject(raw.operation) || !exactKeys(raw.operation, OPERATION_KEYS as unknown as string[])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Operation fields refused.");
  }
  const op = raw.operation;
  if (op.kind !== "exact_block_removal") {
    throw new AuthTokenError("AUTH_MALFORMED", "Operation kind refused.");
  }
  if (op.target_path_alias !== PROTECTED_PROCESS_OP.target_path_alias) {
    throw new AuthTokenError("AUTH_MALFORMED", "Operation alias refused.");
  }
  if (op.expected_pattern_count !== PROTECTED_PROCESS_OP.expected_pattern_count) {
    throw new AuthTokenError("AUTH_MALFORMED", "Operation pattern count refused.");
  }
  const operation_digest = requireSha256(op.operation_digest);
  // expected_result_sha256 is required (non-null); null/removal fails closed.
  const expected_result_sha256 = requireSha256(op.expected_result_sha256);
  if (!operation_digest || !expected_result_sha256) {
    throw new AuthTokenError("AUTH_MALFORMED", "Operation digests refused.");
  }
  const registeredOp = operationDigest();
  if (operation_digest !== registeredOp) {
    throw new AuthTokenError("AUTH_MALFORMED", "Operation digest mismatch.");
  }

  if (!isPlainObject(raw.applicability) || !exactKeys(raw.applicability, [
    "version_match",
    "platform_match",
    "target_hash_match",
    "pattern_count_match",
  ])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Applicability fields refused.");
  }
  const version_match = requireBool(raw.applicability.version_match);
  const platform_match = requireBool(raw.applicability.platform_match);
  const target_hash_match = requireBool(raw.applicability.target_hash_match);
  const pattern_count_match = requireBool(raw.applicability.pattern_count_match);
  if (
    version_match === null ||
    platform_match === null ||
    target_hash_match === null ||
    pattern_count_match === null
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Applicability values refused.");
  }

  if (!isPlainObject(raw.backup) || !exactKeys(raw.backup, [
    "required",
    "original_sha256",
    "backup_rel",
    "verified",
    "receipt_id",
  ])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup fields refused.");
  }
  if (raw.backup.required !== true) {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup required flag refused.");
  }
  const backup_original = requireSha256(raw.backup.original_sha256);
  if (!backup_original || backup_original !== original_sha256) {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup original hash refused.");
  }
  const registered_backup = registeredBackupRel();
  const backup_rel = requireString(raw.backup.backup_rel, 256);
  // Must match registered constant — never trust a redirectable path.
  if (!backup_rel || backup_rel !== registered_backup) {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup path refused.");
  }
  // Defense-in-depth: backup path must stay under registered recovery backup dir.
  if (
    !backup_rel.startsWith(`${RECOVERY_BACKUP_DIR}/`) ||
    backup_rel.includes("..") ||
    backup_rel.includes("\0")
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup path refused.");
  }
  if (typeof raw.backup.verified !== "boolean") {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup verified flag refused.");
  }
  if (raw.backup.receipt_id !== null && typeof raw.backup.receipt_id !== "string") {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup receipt refused.");
  }
  if (typeof raw.backup.receipt_id === "string" && raw.backup.receipt_id.length > 256) {
    throw new AuthTokenError("AUTH_MALFORMED", "Backup receipt refused.");
  }

  if (!isPlainObject(raw.verification) || !exactKeys(raw.verification, [
    "checks",
    "original_failure_must_not_reproduce",
    "core_health_required",
  ])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Verification fields refused.");
  }
  if (
    raw.verification.original_failure_must_not_reproduce !== true ||
    raw.verification.core_health_required !== true
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Verification plan refused.");
  }
  if (
    !Array.isArray(raw.verification.checks) ||
    raw.verification.checks.length < 1 ||
    raw.verification.checks.length > 32 ||
    !raw.verification.checks.every(
      (c) => typeof c === "string" && c.length > 0 && c.length <= 256,
    )
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Verification checks refused.");
  }

  if (!isPlainObject(raw.rollback) || !exactKeys(raw.rollback, [
    "recipe",
    "restores_original_sha256",
  ])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Rollback fields refused.");
  }
  const restores = requireSha256(raw.rollback.restores_original_sha256);
  if (!restores || restores !== original_sha256) {
    throw new AuthTokenError("AUTH_MALFORMED", "Rollback hash refused.");
  }
  if (
    !Array.isArray(raw.rollback.recipe) ||
    raw.rollback.recipe.length < 1 ||
    raw.rollback.recipe.length > 32 ||
    !raw.rollback.recipe.every(
      (c) => typeof c === "string" && c.length > 0 && c.length <= 512,
    )
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Rollback recipe refused.");
  }

  if (
    !Array.isArray(raw.dry_run_checks) ||
    raw.dry_run_checks.length < 1 ||
    raw.dry_run_checks.length > 32 ||
    !raw.dry_run_checks.every(
      (c) => typeof c === "string" && c.length > 0 && c.length <= 256,
    )
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Dry-run checks refused.");
  }

  const expires_at = requireString(raw.expires_at, 64);
  if (!expires_at || !Number.isFinite(Date.parse(expires_at))) {
    throw new AuthTokenError("AUTH_MALFORMED", "Expiry refused.");
  }
  const invalidation_digest = requireSha256(raw.invalidation_digest);
  const authorization_binding = requireSha256(raw.authorization_binding);
  if (!invalidation_digest || !authorization_binding) {
    throw new AuthTokenError("AUTH_MALFORMED", "Binding digests refused.");
  }

  if (!isPlainObject(raw.disclosure) || !exactKeys(raw.disclosure, [
    "fields_leaving_device",
    "includes_source_bytes",
    "includes_secrets",
  ])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Disclosure fields refused.");
  }
  if (
    raw.disclosure.includes_source_bytes !== false ||
    raw.disclosure.includes_secrets !== false
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Disclosure flags refused.");
  }
  if (
    !Array.isArray(raw.disclosure.fields_leaving_device) ||
    raw.disclosure.fields_leaving_device.length > 64 ||
    !raw.disclosure.fields_leaving_device.every(
      (c) => typeof c === "string" && c.length <= 128,
    )
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Disclosure fields refused.");
  }

  if (
    raw.human_decision !== "pending" &&
    raw.human_decision !== "approved" &&
    raw.human_decision !== "rejected"
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Human decision refused.");
  }
  if (
    raw.smoke_result !== "not_run" &&
    raw.smoke_result !== "pass" &&
    raw.smoke_result !== "fail" &&
    raw.smoke_result !== "error"
  ) {
    throw new AuthTokenError("AUTH_MALFORMED", "Smoke result refused.");
  }

  const nonce = requireString(raw.nonce, 64);
  if (!nonce || !NONCE_HEX.test(nonce)) {
    throw new AuthTokenError("AUTH_MALFORMED", "Nonce refused.");
  }

  // Recompute invalidation + binding from registered constants + capsule material.
  const expectedInvalidation = invalidationMaterial({
    original_sha256,
    expected_pattern_count: PROTECTED_PROCESS_OP.expected_pattern_count,
    scope_digest,
    operation_digest: registeredOp,
    expected_result_sha256,
    backup_rel: registered_backup,
    capsule_id,
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
  });
  if (expectedInvalidation !== invalidation_digest) {
    throw new AuthTokenError("AUTH_MALFORMED", "Invalidation digest mismatch.");
  }
  const expectedBinding = authorizationBinding({
    capsule_id,
    scope_digest,
    original_sha256,
    expected_pattern_count: PROTECTED_PROCESS_OP.expected_pattern_count,
    operation_digest: registeredOp,
    expected_result_sha256,
    backup_rel: registered_backup,
    invalidation_digest: expectedInvalidation,
    trust_tier: "T1_community",
    authorization_tier: "experimental_one_shot",
    mode: "apply_authorized",
    target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
    expires_at,
    nonce,
  });
  if (expectedBinding !== authorization_binding) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization binding mismatch.");
  }

  return {
    schema_version: 1,
    capsule_id,
    trust_tier: "T1_community",
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
    risk: "moderate",
    target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
    scope_digest,
    original_sha256,
    expected_pattern_count: PROTECTED_PROCESS_OP.expected_pattern_count,
    operation: {
      kind: "exact_block_removal",
      target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
      expected_pattern_count: PROTECTED_PROCESS_OP.expected_pattern_count,
      operation_digest: registeredOp,
      expected_result_sha256,
    },
    applicability: {
      version_match,
      platform_match,
      target_hash_match,
      pattern_count_match,
    },
    backup: {
      required: true,
      original_sha256,
      backup_rel: registered_backup,
      verified: raw.backup.verified as boolean,
      receipt_id:
        raw.backup.receipt_id === null
          ? null
          : (raw.backup.receipt_id as string),
    },
    verification: {
      checks: raw.verification.checks as string[],
      original_failure_must_not_reproduce: true,
      core_health_required: true,
    },
    rollback: {
      recipe: raw.rollback.recipe as string[],
      restores_original_sha256: original_sha256,
    },
    dry_run_checks: raw.dry_run_checks as string[],
    expires_at,
    invalidation_digest: expectedInvalidation,
    authorization_binding: expectedBinding,
    disclosure: {
      fields_leaving_device: raw.disclosure.fields_leaving_device as string[],
      includes_source_bytes: false,
      includes_secrets: false,
    },
    human_decision: raw.human_decision as RepairCapsule["human_decision"],
    smoke_result: raw.smoke_result as RepairCapsule["smoke_result"],
    nonce,
  };
}

/** Encode a validated capsule into a bounded self-contained token. */
export function encodeAuthorizationToken(capsule: RepairCapsule): string {
  // Re-validate before encoding so callers cannot mint loose material.
  const validated = strictValidateCapsule(capsule);
  const payload = { v: 1 as const, capsule: validated };
  const raw = Buffer.from(canonicalJson(payload), "utf8");
  if (raw.length > MAX_AUTH_TOKEN_BYTES) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token too large.");
  }
  return `${AUTH_TOKEN_PREFIX}${raw.toString("base64url")}`;
}

/** Decode and strictly validate a self-contained authorization token. */
export function decodeAuthorizationToken(token: string): RepairCapsule {
  if (typeof token !== "string" || token.length < 8 || token.length > MAX_AUTH_TOKEN_BYTES * 2) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token refused.");
  }
  if (!token.startsWith(AUTH_TOKEN_PREFIX)) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token refused.");
  }
  const b64 = token.slice(AUTH_TOKEN_PREFIX.length);
  let raw: Buffer;
  try {
    raw = Buffer.from(b64, "base64url");
  } catch {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token refused.");
  }
  if (raw.length === 0 || raw.length > MAX_AUTH_TOKEN_BYTES) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token refused.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token refused.");
  }
  if (!isPlainObject(parsed) || !exactKeys(parsed, ["v", "capsule"])) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token refused.");
  }
  if (parsed.v !== 1) {
    throw new AuthTokenError("AUTH_MALFORMED", "Authorization token version refused.");
  }
  return strictValidateCapsule(parsed.capsule);
}
