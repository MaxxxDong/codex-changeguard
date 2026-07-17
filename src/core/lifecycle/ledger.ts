/**
 * Canonical lifecycle ledger: versioned JSON, atomic write via recovery helpers,
 * strict schema, no-follow path policy, digest integrity.
 */
import {
  openTargetFile,
  writeSessionState,
} from "../recovery/atomic-write.js";
import { digestObject, receiptId, sha256Text } from "../recovery/canonical.js";
import { PathSafetyError } from "../path-safety.js";
import {
  LIFECYCLE_LEDGER_REL,
  MAX_INSTANCE_ID_LEN,
  MAX_LEDGER_BYTES,
  MAX_RECORDS,
  MAX_RECIPE_ID_LEN,
  isControlSurface,
} from "./constants.js";
import type {
  KnownGoodCheckpoint,
  LifecycleLedger,
  RecipeRecord,
  RepairBackupRecord,
  RetentionReceipt,
  UpdateRegressionAssessment,
  CanaryResult,
  VersionGuidance,
  RecipeLifecycleStatus,
  BackupRecordStatus,
} from "./types.js";

const GUIDANCE = new Set<VersionGuidance>([
  "RECOMMEND_UPGRADE",
  "UPGRADE_CANARY_AVAILABLE",
  "HOLD_KNOWN_GOOD",
  "GENERAL_UPDATE_ONLY",
]);

const BACKUP_STATUS = new Set<BackupRecordStatus>([
  "active",
  "expired",
  "retained_known_good",
  "pruned",
]);

const RECIPE_STATUS = new Set<RecipeLifecycleStatus>([
  "ACTIVE_WORKAROUND",
  "SUPERSEDED_BY_UPSTREAM_FIX",
]);

/** Exact persisted key allowlists — extra/missing keys fail closed. */
const LEDGER_TOP_KEYS = [
  "schema_version",
  "instance_id",
  "repair_backups",
  "known_good",
  "recipes",
  "last_retention",
  "last_regression",
  "last_canary",
  "version_guidance",
  "successful_start_total",
  "updated_at_ms",
  "ledger_digest",
] as const;

const REPAIR_KEYS = [
  "schema_version",
  "kind",
  "backup_id",
  "backup_rel",
  "original_sha256",
  "surface",
  "instance_id",
  "created_at_ms",
  "successful_start_count",
  "status",
  "content_digest",
] as const;

const KNOWN_GOOD_KEYS = [
  "schema_version",
  "kind",
  "checkpoint_id",
  "surface",
  "instance_id",
  "target_rel",
  "backup_rel",
  "content_sha256",
  "created_at_ms",
  "status",
  "content_digest",
  "healthy",
] as const;

const RECIPE_KEYS = [
  "recipe_id",
  "status",
  "upstream_ref",
  "upstream_evidence_digest",
  "superseded_at_ms",
  "recommendable",
] as const;

const RETENTION_KEYS = [
  "schema_version",
  "evaluated_at_ms",
  "decisions",
  "pruned_ids",
  "kept_ids",
  "deleted_outside_registered_state",
] as const;

const RETENTION_DECISION_KEYS = [
  "backup_id",
  "action",
  "reason",
  "receipt_id",
] as const;

const RETENTION_REASONS = new Set<RetentionReceipt["decisions"][number]["reason"]>([
  "within_min_age",
  "within_min_starts",
  "expired_age_and_starts",
  "known_good_last_three",
  "known_good_beyond_last_three",
  "already_pruned",
  "corrupt_refused",
]);

const REGRESSION_KEYS = [
  "established",
  "reason_code",
  "instance_id",
  "mechanism_id",
  "version_before",
  "version_after",
] as const;

const CANARY_KEYS = [
  "candidate_version",
  "original_fault_absent",
  "core_regressions_passed",
  "isolated_profile",
  "version_guidance",
  "detail",
] as const;

export class LedgerError extends Error {
  readonly code: string;
  constructor(code: string, message = "Ledger refused.") {
    super(message);
    this.name = "LedgerError";
    this.code = code;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Exact key allowlist: length and membership must match (no extras/missing). */
function exactKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(obj);
  if (keys.length !== allowed.length) return false;
  const set = new Set(allowed);
  return keys.every((k) => set.has(k));
}

function requireString(v: unknown, max: number): string | null {
  if (typeof v !== "string" || v.length === 0 || v.length > max) return null;
  if (v.includes("\0")) return null;
  return v;
}

function requireSha(v: unknown): string | null {
  if (typeof v !== "string" || !/^[a-f0-9]{64}$/.test(v)) return null;
  return v;
}

function requireInt(v: unknown): number | null {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) return null;
  return v;
}

function parseRepair(raw: unknown): RepairBackupRecord | null {
  if (!isPlainObject(raw)) return null;
  const o = raw;
  if (!exactKeys(o, REPAIR_KEYS)) return null;
  if (o.schema_version !== 1 || o.kind !== "repair") return null;
  const backup_id = requireString(o.backup_id, 128);
  const backup_rel = requireString(o.backup_rel, 256);
  const original_sha256 = requireSha(o.original_sha256);
  const instance_id = requireString(o.instance_id, MAX_INSTANCE_ID_LEN);
  const created_at_ms = requireInt(o.created_at_ms);
  const successful_start_count = requireInt(o.successful_start_count);
  const content_digest = requireSha(o.content_digest);
  if (
    !backup_id ||
    !backup_rel ||
    !original_sha256 ||
    !instance_id ||
    created_at_ms === null ||
    successful_start_count === null ||
    !content_digest
  ) {
    return null;
  }
  if (typeof o.status !== "string" || !BACKUP_STATUS.has(o.status as BackupRecordStatus)) {
    return null;
  }
  const surface =
    o.surface === "artifact" ||
    (typeof o.surface === "string" && isControlSurface(o.surface))
      ? o.surface
      : null;
  if (!surface) return null;
  if (backup_rel.includes("..") || backup_rel.startsWith("/")) return null;
  const rec: RepairBackupRecord = {
    schema_version: 1,
    kind: "repair",
    backup_id,
    backup_rel,
    original_sha256,
    surface,
    instance_id,
    created_at_ms,
    successful_start_count,
    status: o.status as BackupRecordStatus,
    content_digest,
  };
  // Integrity: content_digest must match canonical record without the digest field.
  const { content_digest: _d, ...body } = rec;
  if (digestObject(body) !== content_digest) return null;
  return rec;
}

function parseKnownGood(raw: unknown): KnownGoodCheckpoint | null {
  if (!isPlainObject(raw)) return null;
  const o = raw;
  if (!exactKeys(o, KNOWN_GOOD_KEYS)) return null;
  if (o.schema_version !== 1 || o.kind !== "known_good") return null;
  if (o.healthy !== true) return null;
  const checkpoint_id = requireString(o.checkpoint_id, 128);
  const surface =
    typeof o.surface === "string" && isControlSurface(o.surface) ? o.surface : null;
  const instance_id = requireString(o.instance_id, MAX_INSTANCE_ID_LEN);
  const target_rel = requireString(o.target_rel, 256);
  const backup_rel = requireString(o.backup_rel, 256);
  const content_sha256 = requireSha(o.content_sha256);
  const created_at_ms = requireInt(o.created_at_ms);
  const content_digest = requireSha(o.content_digest);
  if (
    !checkpoint_id ||
    !surface ||
    !instance_id ||
    !target_rel ||
    !backup_rel ||
    !content_sha256 ||
    created_at_ms === null ||
    !content_digest
  ) {
    return null;
  }
  if (typeof o.status !== "string" || !BACKUP_STATUS.has(o.status as BackupRecordStatus)) {
    return null;
  }
  if (
    target_rel.includes("..") ||
    backup_rel.includes("..") ||
    target_rel.startsWith("/") ||
    backup_rel.startsWith("/")
  ) {
    return null;
  }
  const rec: KnownGoodCheckpoint = {
    schema_version: 1,
    kind: "known_good",
    checkpoint_id,
    surface,
    instance_id,
    target_rel,
    backup_rel,
    content_sha256,
    created_at_ms,
    status: o.status as BackupRecordStatus,
    content_digest,
    healthy: true,
  };
  const { content_digest: _d, ...body } = rec;
  if (digestObject(body) !== content_digest) return null;
  return rec;
}

function parseRecipe(raw: unknown): RecipeRecord | null {
  if (!isPlainObject(raw)) return null;
  const o = raw;
  if (!exactKeys(o, RECIPE_KEYS)) return null;
  const recipe_id = requireString(o.recipe_id, MAX_RECIPE_ID_LEN);
  if (!recipe_id) return null;
  if (typeof o.status !== "string" || !RECIPE_STATUS.has(o.status as RecipeLifecycleStatus)) {
    return null;
  }
  if (typeof o.recommendable !== "boolean") return null;
  const upstream_ref =
    o.upstream_ref === null
      ? null
      : requireString(o.upstream_ref, 256);
  if (o.upstream_ref !== null && upstream_ref === null) return null;
  const upstream_evidence_digest =
    o.upstream_evidence_digest === null
      ? null
      : requireSha(o.upstream_evidence_digest);
  if (o.upstream_evidence_digest !== null && !upstream_evidence_digest) return null;
  const superseded_at_ms =
    o.superseded_at_ms === null ? null : requireInt(o.superseded_at_ms);
  if (o.superseded_at_ms !== null && superseded_at_ms === null) return null;
  return {
    recipe_id,
    status: o.status as RecipeLifecycleStatus,
    upstream_ref,
    upstream_evidence_digest,
    superseded_at_ms,
    recommendable: o.recommendable,
  };
}

function parseRetentionDecision(raw: unknown): RetentionReceipt["decisions"][number] | null {
  if (!isPlainObject(raw)) return null;
  if (!exactKeys(raw, RETENTION_DECISION_KEYS)) return null;
  const backup_id = requireString(raw.backup_id, 128);
  const receipt_id = requireString(raw.receipt_id, 128);
  if (!backup_id || !receipt_id) return null;
  if (raw.action !== "keep" && raw.action !== "prune") return null;
  if (typeof raw.reason !== "string" || !RETENTION_REASONS.has(raw.reason as RetentionReceipt["decisions"][number]["reason"])) {
    return null;
  }
  return {
    backup_id,
    action: raw.action,
    reason: raw.reason as RetentionReceipt["decisions"][number]["reason"],
    receipt_id,
  };
}

function parseStringIdArray(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) return null;
  const out: string[] = [];
  for (const x of raw) {
    if (typeof x !== "string" || x.length === 0 || x.length > 128 || x.includes("\0")) {
      return null;
    }
    out.push(x);
  }
  return out;
}

function parseRetention(raw: unknown): RetentionReceipt | null {
  if (raw === null) return null;
  if (!isPlainObject(raw)) return null;
  const o = raw;
  if (!exactKeys(o, RETENTION_KEYS)) return null;
  if (o.schema_version !== 1) return null;
  const evaluated_at_ms = requireInt(o.evaluated_at_ms);
  if (evaluated_at_ms === null) return null;
  if (o.deleted_outside_registered_state !== false) return null;
  if (!Array.isArray(o.decisions)) return null;
  const decisions: RetentionReceipt["decisions"] = [];
  for (const item of o.decisions) {
    const d = parseRetentionDecision(item);
    if (!d) return null;
    decisions.push(d);
  }
  const pruned_ids = parseStringIdArray(o.pruned_ids);
  const kept_ids = parseStringIdArray(o.kept_ids);
  if (!pruned_ids || !kept_ids) return null;
  return {
    schema_version: 1,
    evaluated_at_ms,
    decisions,
    pruned_ids,
    kept_ids,
    deleted_outside_registered_state: false,
  };
}

function parseRegression(raw: unknown): UpdateRegressionAssessment | null {
  if (raw === null) return null;
  if (!isPlainObject(raw)) return null;
  const o = raw;
  if (!exactKeys(o, REGRESSION_KEYS)) return null;
  if (typeof o.established !== "boolean") return null;
  if (typeof o.reason_code !== "string") return null;
  return {
    established: o.established,
    reason_code: o.reason_code as UpdateRegressionAssessment["reason_code"],
    instance_id: o.instance_id === null ? null : String(o.instance_id),
    mechanism_id: o.mechanism_id === null ? null : String(o.mechanism_id),
    version_before: o.version_before === null ? null : String(o.version_before),
    version_after: o.version_after === null ? null : String(o.version_after),
  };
}

function parseCanary(raw: unknown): CanaryResult | null {
  if (raw === null) return null;
  if (!isPlainObject(raw)) return null;
  const o = raw;
  if (!exactKeys(o, CANARY_KEYS)) return null;
  if (o.isolated_profile !== true) return null;
  if (typeof o.candidate_version !== "string") return null;
  if (typeof o.original_fault_absent !== "boolean") return null;
  if (typeof o.core_regressions_passed !== "boolean") return null;
  if (typeof o.version_guidance !== "string" || !GUIDANCE.has(o.version_guidance as VersionGuidance)) {
    return null;
  }
  if (typeof o.detail !== "string") return null;
  return {
    candidate_version: o.candidate_version,
    original_fault_absent: o.original_fault_absent,
    core_regressions_passed: o.core_regressions_passed,
    isolated_profile: true,
    version_guidance: o.version_guidance as VersionGuidance,
    detail: o.detail,
  };
}

/** Material that is digested for ledger integrity (excludes ledger_digest). */
export function ledgerBody(ledger: Omit<LifecycleLedger, "ledger_digest">): unknown {
  return {
    schema_version: ledger.schema_version,
    instance_id: ledger.instance_id,
    repair_backups: ledger.repair_backups,
    known_good: ledger.known_good,
    recipes: ledger.recipes,
    last_retention: ledger.last_retention,
    last_regression: ledger.last_regression,
    last_canary: ledger.last_canary,
    version_guidance: ledger.version_guidance,
    successful_start_total: ledger.successful_start_total,
    updated_at_ms: ledger.updated_at_ms,
  };
}

export function sealLedger(
  partial: Omit<LifecycleLedger, "ledger_digest">,
): LifecycleLedger {
  return {
    ...partial,
    ledger_digest: digestObject(ledgerBody(partial)),
  };
}

export function emptyLedger(instance_id: string, nowMs: number): LifecycleLedger {
  return sealLedger({
    schema_version: 1,
    instance_id,
    repair_backups: [],
    known_good: [],
    recipes: [],
    last_retention: null,
    last_regression: null,
    last_canary: null,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: nowMs,
  });
}

export function parseLedger(raw: unknown): LifecycleLedger {
  if (!isPlainObject(raw)) {
    throw new LedgerError("CORRUPT_LEDGER", "Ledger schema refused.");
  }
  const o = raw;
  if (!exactKeys(o, LEDGER_TOP_KEYS)) {
    throw new LedgerError("CORRUPT_LEDGER", "Ledger schema refused.");
  }
  if (o.schema_version !== 1) {
    throw new LedgerError("CORRUPT_LEDGER", "Ledger schema refused.");
  }
  const instance_id = requireString(o.instance_id, MAX_INSTANCE_ID_LEN);
  if (!instance_id) {
    throw new LedgerError("CORRUPT_LEDGER", "Ledger instance refused.");
  }
  if (!Array.isArray(o.repair_backups) || o.repair_backups.length > MAX_RECORDS) {
    throw new LedgerError("CORRUPT_LEDGER", "Repair backups refused.");
  }
  if (!Array.isArray(o.known_good) || o.known_good.length > MAX_RECORDS) {
    throw new LedgerError("CORRUPT_LEDGER", "Known-good list refused.");
  }
  if (!Array.isArray(o.recipes) || o.recipes.length > MAX_RECORDS) {
    throw new LedgerError("CORRUPT_LEDGER", "Recipes refused.");
  }
  const repair_backups: RepairBackupRecord[] = [];
  for (const item of o.repair_backups) {
    const rec = parseRepair(item);
    if (!rec) throw new LedgerError("TAMPERED_LEDGER", "Repair backup integrity failed.");
    repair_backups.push(rec);
  }
  const known_good: KnownGoodCheckpoint[] = [];
  for (const item of o.known_good) {
    const rec = parseKnownGood(item);
    if (!rec) throw new LedgerError("TAMPERED_LEDGER", "Known-good integrity failed.");
    known_good.push(rec);
  }
  const recipes: RecipeRecord[] = [];
  for (const item of o.recipes) {
    const rec = parseRecipe(item);
    if (!rec) throw new LedgerError("CORRUPT_LEDGER", "Recipe refused.");
    recipes.push(rec);
  }
  const last_retention = parseRetention(o.last_retention ?? null);
  if (o.last_retention != null && last_retention === null) {
    throw new LedgerError("CORRUPT_LEDGER", "Retention receipt refused.");
  }
  const last_regression = parseRegression(o.last_regression ?? null);
  if (o.last_regression != null && last_regression === null) {
    throw new LedgerError("CORRUPT_LEDGER", "Regression assessment refused.");
  }
  const last_canary = parseCanary(o.last_canary ?? null);
  if (o.last_canary != null && last_canary === null) {
    throw new LedgerError("CORRUPT_LEDGER", "Canary result refused.");
  }
  if (
    typeof o.version_guidance !== "string" ||
    !GUIDANCE.has(o.version_guidance as VersionGuidance)
  ) {
    throw new LedgerError("CORRUPT_LEDGER", "Version guidance refused.");
  }
  const successful_start_total = requireInt(o.successful_start_total);
  const updated_at_ms = requireInt(o.updated_at_ms);
  if (successful_start_total === null || updated_at_ms === null) {
    throw new LedgerError("CORRUPT_LEDGER", "Ledger counters refused.");
  }
  const ledger_digest = requireSha(o.ledger_digest);
  if (!ledger_digest) {
    throw new LedgerError("TAMPERED_LEDGER", "Ledger digest missing.");
  }
  const body = {
    schema_version: 1 as const,
    instance_id,
    repair_backups,
    known_good,
    recipes,
    last_retention,
    last_regression,
    last_canary,
    version_guidance: o.version_guidance as VersionGuidance,
    successful_start_total,
    updated_at_ms,
  };
  if (digestObject(body) !== ledger_digest) {
    throw new LedgerError("TAMPERED_LEDGER", "Ledger digest mismatch.");
  }
  return { ...body, ledger_digest };
}

export function loadLedger(
  targetReal: string,
  instance_id: string,
  nowMs: number,
): LifecycleLedger {
  try {
    const f = openTargetFile(targetReal, LIFECYCLE_LEDGER_REL, MAX_LEDGER_BYTES);
    const parsed = JSON.parse(f.bytes.toString("utf8")) as unknown;
    const ledger = parseLedger(parsed);
    if (ledger.instance_id !== instance_id) {
      throw new LedgerError("INSTANCE_MISMATCH", "Ledger instance mismatch.");
    }
    return ledger;
  } catch (e) {
    if (e instanceof LedgerError) throw e;
    if (e instanceof PathSafetyError && e.code === "CANDIDATE_NOT_FOUND") {
      return emptyLedger(instance_id, nowMs);
    }
    if (e instanceof PathSafetyError && e.code === "SYMLINK_ESCAPE") {
      throw new LedgerError("SYMLINK_REFUSED", "Symlink ledger refused.");
    }
    if (e instanceof SyntaxError) {
      throw new LedgerError("CORRUPT_LEDGER", "Ledger JSON corrupt.");
    }
    throw new LedgerError("LEDGER_IO", "Ledger read failed.");
  }
}

export function saveLedger(targetReal: string, ledger: LifecycleLedger): void {
  const sealed = sealLedger({
    schema_version: ledger.schema_version,
    instance_id: ledger.instance_id,
    repair_backups: ledger.repair_backups,
    known_good: ledger.known_good,
    recipes: ledger.recipes,
    last_retention: ledger.last_retention,
    last_regression: ledger.last_regression,
    last_canary: ledger.last_canary,
    version_guidance: ledger.version_guidance,
    successful_start_total: ledger.successful_start_total,
    updated_at_ms: ledger.updated_at_ms,
  });
  writeSessionState(
    targetReal,
    LIFECYCLE_LEDGER_REL,
    sealed as unknown as Record<string, unknown>,
  );
}

export function sealRepairBackup(
  partial: Omit<RepairBackupRecord, "content_digest">,
): RepairBackupRecord {
  const body = { ...partial };
  return { ...body, content_digest: digestObject(body) };
}

export function sealKnownGood(
  partial: Omit<KnownGoodCheckpoint, "content_digest">,
): KnownGoodCheckpoint {
  const body = { ...partial };
  return { ...body, content_digest: digestObject(body) };
}

export function newId(prefix: string): string {
  return receiptId(prefix);
}

export function stableShortId(material: string): string {
  return sha256Text(material).slice(0, 16);
}
