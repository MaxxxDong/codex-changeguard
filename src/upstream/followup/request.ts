/**
 * Canonical follow-up wire parser for MCP objects and CLI request-file / inline inputs.
 * Single path: bounded size, recursive forbidden keys, exact per-operation allowlists.
 * Target and operation are supplied by the seam and never overridden by request body.
 */
import {
  FORBIDDEN_FOLLOWUP_KEYS,
  MAX_FOLLOWUP_REQUEST_BYTES,
  MAX_STRING,
} from "./limits.js";
import type { FollowupDispatchArgs, FollowupOperation } from "./types.js";

/** Max nesting depth for recursive forbidden-key scans (depth 0 = root). */
export const MAX_FOLLOWUP_REQUEST_DEPTH = 4;

/**
 * Keys never accepted from public wire (authority / privacy / executable /
 * target-op smuggling / removed public surfaces).
 */
const GLOBAL_FORBIDDEN_REQUEST_KEYS = Object.freeze([
  ...FORBIDDEN_FOLLOWUP_KEYS,
  "snapshot_path",
  "snapshotPath",
  "live_measurement_witness",
  "liveMeasurementWitness",
  "witness",
  "function",
  "shell",
  "command",
  "argv",
  "binary",
  "binary_path",
  "executable",
  "exec",
  "spawn",
  "child_process",
  "transport",
  "adapter",
  "gh_token",
  "github_token",
  "target",
  "targetPath",
  "target_path",
  "operation",
  "op",
  // Removed public wire surfaces (tests use env / direct domain APIs).
  "state_dir",
  "stateDir",
  "state-dir",
  "original_fault_absent",
  "core_regressions_passed",
  "verified",
  "stateOnly",
  "state_only",
]);

const GLOBAL_FORBIDDEN = new Set(
  GLOBAL_FORBIDDEN_REQUEST_KEYS.map((k) => k.toLowerCase()),
);

/**
 * Per-operation closed allowlists (request body only; target/op come from seam).
 * Authority booleans and state_dir are intentionally absent.
 */
const OP_ALLOWED_KEYS: Record<FollowupOperation, ReadonlySet<string>> = {
  subscribe: new Set(["issue", "now_ms"]),
  unsubscribe: new Set(["issue", "now_ms"]),
  status: new Set(["now_ms"]),
  session_hint: new Set(["now_ms"]),
  refresh: new Set(["event", "disclosure_decision", "now_ms"]),
  process_event: new Set(["event", "now_ms"]),
  validate_candidate: new Set([
    "issue",
    "candidate_version",
    "recipe_id",
    "official_evidence_item_digest",
    "official_evidence_ref",
    "baseline_target",
    "measurement_profile_id",
    "now_ms",
  ]),
};

export type FollowupRequestParseOk = {
  ok: true;
  fields: Partial<FollowupDispatchArgs>;
};

export type FollowupRequestParseFail = {
  ok: false;
  code: string;
  message: string;
};

export type FollowupRequestParseResult =
  | FollowupRequestParseOk
  | FollowupRequestParseFail;

function fail(code: string, message: string): FollowupRequestParseFail {
  return { ok: false, code, message };
}

/**
 * Scan object keys recursively for forbidden privacy / authority keys.
 * Path-free generic errors only.
 */
export function refuseForbiddenFollowupKeys(
  obj: unknown,
  depth = 0,
): FollowupRequestParseFail | null {
  if (obj === null || typeof obj !== "object") return null;
  if (depth > MAX_FOLLOWUP_REQUEST_DEPTH) {
    return fail("DEPTH_LIMIT", "Request nesting depth refused.");
  }
  if (Array.isArray(obj)) {
    for (const v of obj) {
      const r = refuseForbiddenFollowupKeys(v, depth + 1);
      if (r) return r;
    }
    return null;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const lk = k.toLowerCase();
    if (GLOBAL_FORBIDDEN.has(lk)) {
      return fail(
        "FORBIDDEN_FIELD",
        "Request contains a forbidden or non-authoritative field.",
      );
    }
    if (v && typeof v === "object") {
      const r = refuseForbiddenFollowupKeys(v, depth + 1);
      if (r) return r;
    }
  }
  return null;
}

function parseFollowupRequestObject(
  obj: Record<string, unknown>,
  operation: FollowupOperation,
): FollowupRequestParseResult {
  const forbidden = refuseForbiddenFollowupKeys(obj);
  if (forbidden) return forbidden;

  const allowed = OP_ALLOWED_KEYS[operation];
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) {
      return fail(
        "EXTRA_FIELD",
        "Follow-up request contains unknown or extra fields.",
      );
    }
  }

  const fields: Partial<FollowupDispatchArgs> = {};

  if (Object.prototype.hasOwnProperty.call(obj, "issue")) {
    const issue = obj.issue;
    if (typeof issue === "string" || typeof issue === "number") {
      fields.issue = issue;
    } else {
      return fail("INVALID_INPUT", "Invalid issue field.");
    }
  }
  if (Object.prototype.hasOwnProperty.call(obj, "event")) {
    fields.event = obj.event;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "candidate_version")) {
    if (typeof obj.candidate_version !== "string" || obj.candidate_version.length === 0) {
      return fail("INVALID_INPUT", "Invalid candidate_version.");
    }
    if (obj.candidate_version.length > MAX_STRING) {
      return fail("INVALID_INPUT", "candidate_version too long.");
    }
    fields.candidate_version = obj.candidate_version;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "recipe_id")) {
    if (typeof obj.recipe_id !== "string" || obj.recipe_id.length === 0) {
      return fail("INVALID_INPUT", "Invalid recipe_id.");
    }
    fields.recipe_id = obj.recipe_id;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "official_evidence_item_digest")) {
    if (
      typeof obj.official_evidence_item_digest !== "string" ||
      !/^[a-f0-9]{64}$/.test(obj.official_evidence_item_digest)
    ) {
      return fail("INVALID_INPUT", "Invalid official_evidence_item_digest.");
    }
    fields.official_evidence_item_digest = obj.official_evidence_item_digest;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "official_evidence_ref")) {
    if (
      typeof obj.official_evidence_ref !== "string" ||
      obj.official_evidence_ref.length === 0 ||
      obj.official_evidence_ref.length > MAX_STRING
    ) {
      return fail("INVALID_INPUT", "Invalid official_evidence_ref.");
    }
    fields.official_evidence_ref = obj.official_evidence_ref;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "baseline_target")) {
    if (typeof obj.baseline_target !== "string" || obj.baseline_target.length === 0) {
      return fail("INVALID_INPUT", "Invalid baseline_target.");
    }
    fields.baseline_target = obj.baseline_target;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "measurement_profile_id")) {
    if (
      typeof obj.measurement_profile_id !== "string" ||
      obj.measurement_profile_id.length === 0
    ) {
      return fail("INVALID_INPUT", "Invalid measurement_profile_id.");
    }
    fields.measurement_profile_id = obj.measurement_profile_id;
  }
  if (Object.prototype.hasOwnProperty.call(obj, "now_ms")) {
    if (typeof obj.now_ms !== "number" || !Number.isFinite(obj.now_ms)) {
      return fail("INVALID_INPUT", "Invalid now_ms.");
    }
    fields.now_ms = obj.now_ms;
  }
  // disclosure_decision is accepted for refresh shape parity but never upgrades network.
  if (Object.prototype.hasOwnProperty.call(obj, "disclosure_decision")) {
    const d = obj.disclosure_decision;
    if (d !== "approved" && d !== "refused" && d !== "not_requested") {
      return fail("INVALID_INPUT", "Invalid disclosure_decision.");
    }
    // Intentionally not forwarded as transport authority.
  }

  return { ok: true, fields };
}

/**
 * Parse a bounded JSON request body (string) for a known follow-up operation.
 * Does not accept target or operation overrides.
 */
export function parseFollowupRequestJson(
  raw: string,
  operation: FollowupOperation,
): FollowupRequestParseResult {
  if (Buffer.byteLength(raw, "utf8") > MAX_FOLLOWUP_REQUEST_BYTES) {
    return fail("SIZE_LIMIT", "Follow-up request exceeds size limit.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return fail("MALFORMED_JSON", "Follow-up request JSON is malformed.");
  }
  return parseFollowupWireBody(parsed, operation);
}

/**
 * Parse an already-materialized wire body (MCP tool arguments minus target/operation,
 * or a CLI-built inline object). Enforces the same size, depth, forbidden-key, and
 * allowlist rules as {@link parseFollowupRequestJson}.
 */
export function parseFollowupWireBody(
  body: unknown,
  operation: FollowupOperation,
): FollowupRequestParseResult {
  let serialized: string;
  try {
    serialized = JSON.stringify(body);
  } catch {
    return fail("INVALID_INPUT", "Follow-up request is not serializable.");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_FOLLOWUP_REQUEST_BYTES) {
    return fail("SIZE_LIMIT", "Follow-up request exceeds size limit.");
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return fail("INVALID_INPUT", "Follow-up request must be a JSON object.");
  }
  return parseFollowupRequestObject(body as Record<string, unknown>, operation);
}
