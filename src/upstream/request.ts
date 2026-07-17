import { nfkc, redactText, assertNoLeakPaths } from "../core/redact.js";
import { detectInstructionLike } from "../evidence/quarantine.js";
import {
  ALLOWED_REQUEST_KEYS,
  FORBIDDEN_UPSTREAM_KEYS,
  MAX_DELTA_ITEMS,
  MAX_DOCTOR_JSON_BYTES,
  MAX_DUPLICATE_CANDIDATES,
  MAX_FACTS,
  MAX_REPRO_STEPS,
  MAX_STRING,
  MAX_TECHNICAL_SIGNALS,
  MAX_TITLE,
  MAX_UPSTREAM_REQUEST_BYTES,
} from "./limits.js";
import type {
  CaseKind,
  DuplicateCandidate,
  EvidenceDelta,
  EvidenceDeltaKind,
  PlatformInfo,
  PrivacyReviewInput,
  ProductSurfaceHint,
  ReproductionInfo,
  ReproductionQuality,
  UpstreamPreviewRequest,
} from "./types.js";

export class UpstreamRequestError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "UpstreamRequestError";
    this.code = code;
  }
}

const PLATFORM_KEYS = Object.freeze(["os", "arch", "unknown_reason"]);
const REPRODUCTION_KEYS = Object.freeze([
  "quality",
  "steps",
  "intermittent_marker",
]);
const DUPLICATE_SEARCH_KEYS = Object.freeze(["searched", "candidates"]);
const CANDIDATE_KEYS = Object.freeze([
  "issue_id",
  "title",
  "state",
  "similarity",
  "mechanism_match",
  "url",
]);
const EVIDENCE_DELTA_KEYS = Object.freeze(["items"]);
const DELTA_ITEM_KEYS = Object.freeze(["kind", "summary", "material"]);
const PRIVACY_KEYS = Object.freeze([
  "secrets_redacted",
  "paths_redacted",
  "session_excluded",
]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function rejectForbiddenKeys(obj: Record<string, unknown>, prefix: string): void {
  for (const key of Object.keys(obj)) {
    const lower = key.toLowerCase();
    // Exact key match only — do not substring-match (e.g. secrets_redacted).
    if (FORBIDDEN_UPSTREAM_KEYS.some((f) => f.toLowerCase() === lower)) {
      throw new UpstreamRequestError(
        "FORBIDDEN_PRIVACY_FIELD",
        `Upstream request rejects privacy-sensitive field: ${prefix}${key}`,
      );
    }
  }
}

/** Fail closed on unknown keys for every structured nested object. */
function rejectExtraKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  prefix: string,
): void {
  for (const k of Object.keys(obj)) {
    if (!(allowed as readonly string[]).includes(k)) {
      throw new UpstreamRequestError(
        "EXTRA_FIELD",
        `Unknown or extra field: ${prefix}${k}`,
      );
    }
  }
}

function boundString(v: unknown, field: string, max = MAX_STRING): string {
  if (typeof v !== "string" || v.length === 0) {
    throw new UpstreamRequestError("INVALID_STRING", `Invalid ${field}.`);
  }
  if (v.length > max) {
    throw new UpstreamRequestError("STRING_LIMIT", `${field} exceeds limit.`);
  }
  return assertNoLeakPaths(redactText(nfkc(v)));
}

function optionalBoundString(
  v: unknown,
  field: string,
  max = MAX_STRING,
): string | null {
  if (v === undefined || v === null) return null;
  return boundString(v, field, max);
}

function parseCaseKind(v: unknown): CaseKind {
  if (
    v === "codex_product_bug" ||
    v === "product_support_question" ||
    v === "validated_security_vulnerability" ||
    v === "account_billing_private"
  ) {
    return v;
  }
  throw new UpstreamRequestError("INVALID_CASE_KIND", "Invalid case_kind.");
}

function parseSurface(v: unknown): ProductSurfaceHint {
  if (
    v === "app" ||
    v === "cli" ||
    v === "extension" ||
    v === "other" ||
    v === "desktop" ||
    v === "browser_control" ||
    v === "ide" ||
    v === "unknown"
  ) {
    return v;
  }
  if (v === undefined || v === null) return "unknown";
  throw new UpstreamRequestError("INVALID_SURFACE", "Invalid surface.");
}

function parsePlatform(raw: unknown): PlatformInfo {
  if (raw === undefined || raw === null) {
    return { os: null, arch: null, unknown_reason: "platform_not_provided" };
  }
  if (!isPlainObject(raw)) {
    throw new UpstreamRequestError("INVALID_PLATFORM", "platform must be an object.");
  }
  rejectForbiddenKeys(raw, "platform.");
  rejectExtraKeys(raw, PLATFORM_KEYS, "platform.");
  return {
    os: optionalBoundString(raw.os, "platform.os", 64),
    arch: optionalBoundString(raw.arch, "platform.arch", 64),
    unknown_reason: optionalBoundString(
      raw.unknown_reason,
      "platform.unknown_reason",
      256,
    ),
  };
}

function parseReproduction(raw: unknown): ReproductionInfo {
  if (!isPlainObject(raw)) {
    throw new UpstreamRequestError(
      "INVALID_REPRODUCTION",
      "reproduction must be an object.",
    );
  }
  rejectForbiddenKeys(raw, "reproduction.");
  rejectExtraKeys(raw, REPRODUCTION_KEYS, "reproduction.");
  const q = raw.quality;
  const quality: ReproductionQuality =
    q === "reliable" || q === "intermittent" || q === "once" || q === "unknown"
      ? q
      : (() => {
          throw new UpstreamRequestError(
            "INVALID_REPRO_QUALITY",
            "Invalid reproduction.quality.",
          );
        })();
  const steps: string[] = [];
  if (raw.steps !== undefined) {
    if (!Array.isArray(raw.steps)) {
      throw new UpstreamRequestError("INVALID_STEPS", "reproduction.steps must be array.");
    }
    if (raw.steps.length > MAX_REPRO_STEPS) {
      throw new UpstreamRequestError("STEPS_LIMIT", "Too many reproduction steps.");
    }
    for (const s of raw.steps) {
      steps.push(boundString(s, "reproduction.steps[]", MAX_STRING));
    }
  }
  return {
    quality,
    steps,
    intermittent_marker: optionalBoundString(
      raw.intermittent_marker,
      "reproduction.intermittent_marker",
      256,
    ),
  };
}

function parseStringArray(
  raw: unknown,
  field: string,
  maxItems: number,
  required: boolean,
): string[] {
  if (raw === undefined || raw === null) {
    if (required) {
      throw new UpstreamRequestError("MISSING_FIELD", `Missing ${field}.`);
    }
    return [];
  }
  if (!Array.isArray(raw)) {
    throw new UpstreamRequestError("INVALID_ARRAY", `${field} must be an array.`);
  }
  if (raw.length > maxItems) {
    throw new UpstreamRequestError("ARRAY_LIMIT", `${field} exceeds item limit.`);
  }
  return raw.map((s, i) => boundString(s, `${field}[${i}]`, MAX_STRING));
}

function parseCandidate(raw: unknown): DuplicateCandidate {
  if (!isPlainObject(raw)) {
    throw new UpstreamRequestError("INVALID_CANDIDATE", "Invalid duplicate candidate.");
  }
  rejectForbiddenKeys(raw, "candidate.");
  rejectExtraKeys(raw, CANDIDATE_KEYS, "candidate.");
  const issue_id = boundString(raw.issue_id, "candidate.issue_id", 128);
  const title = boundString(raw.title, "candidate.title", MAX_TITLE);
  if (raw.state !== "open" && raw.state !== "closed") {
    throw new UpstreamRequestError("INVALID_CANDIDATE_STATE", "Invalid candidate state.");
  }
  if (
    raw.similarity !== "exact" &&
    raw.similarity !== "related" &&
    raw.similarity !== "none"
  ) {
    throw new UpstreamRequestError(
      "INVALID_SIMILARITY",
      "Invalid candidate similarity.",
    );
  }
  if (typeof raw.mechanism_match !== "boolean") {
    throw new UpstreamRequestError(
      "INVALID_MECHANISM_MATCH",
      "mechanism_match must be boolean.",
    );
  }
  let url: string | null = null;
  if (raw.url !== undefined && raw.url !== null) {
    // Validate official issue URL before path redaction (https:// would look path-like).
    if (typeof raw.url !== "string" || raw.url.length === 0 || raw.url.length > 512) {
      throw new UpstreamRequestError("INVALID_CANDIDATE_URL", "Invalid candidate.url.");
    }
    const cleaned = nfkc(raw.url);
    if (!/^https:\/\/github\.com\/openai\/codex\/issues\/\d+$/i.test(cleaned)) {
      throw new UpstreamRequestError(
        "CANDIDATE_URL_REFUSED",
        "candidate.url must be an official openai/codex issue URL.",
      );
    }
    url = cleaned;
  }
  return {
    issue_id,
    title,
    state: raw.state,
    similarity: raw.similarity,
    mechanism_match: raw.mechanism_match,
    url,
  };
}

function parseDuplicateSearch(raw: unknown): UpstreamPreviewRequest["duplicate_search"] {
  if (!isPlainObject(raw)) {
    throw new UpstreamRequestError(
      "INVALID_DUPLICATE_SEARCH",
      "duplicate_search must be an object.",
    );
  }
  rejectForbiddenKeys(raw, "duplicate_search.");
  rejectExtraKeys(raw, DUPLICATE_SEARCH_KEYS, "duplicate_search.");
  if (typeof raw.searched !== "boolean") {
    throw new UpstreamRequestError(
      "INVALID_SEARCHED",
      "duplicate_search.searched must be boolean.",
    );
  }
  if (!Array.isArray(raw.candidates)) {
    throw new UpstreamRequestError(
      "INVALID_CANDIDATES",
      "duplicate_search.candidates must be an array.",
    );
  }
  if (raw.candidates.length > MAX_DUPLICATE_CANDIDATES) {
    throw new UpstreamRequestError(
      "CANDIDATES_LIMIT",
      "Too many duplicate candidates.",
    );
  }
  return {
    searched: raw.searched,
    candidates: raw.candidates.map(parseCandidate),
  };
}

function parseDeltaKind(v: unknown): EvidenceDeltaKind {
  if (
    v === "platform_version" ||
    v === "crash_signature" ||
    v === "minimal_repro" ||
    v === "fix_validation" ||
    v === "rollback_result" ||
    v === "other"
  ) {
    return v;
  }
  throw new UpstreamRequestError("INVALID_DELTA_KIND", "Invalid evidence_delta kind.");
}

function parseEvidenceDelta(raw: unknown): EvidenceDelta {
  if (raw === undefined || raw === null) {
    return { items: [] };
  }
  if (!isPlainObject(raw)) {
    throw new UpstreamRequestError(
      "INVALID_EVIDENCE_DELTA",
      "evidence_delta must be an object.",
    );
  }
  rejectForbiddenKeys(raw, "evidence_delta.");
  rejectExtraKeys(raw, EVIDENCE_DELTA_KEYS, "evidence_delta.");
  if (!Array.isArray(raw.items)) {
    throw new UpstreamRequestError(
      "INVALID_DELTA_ITEMS",
      "evidence_delta.items must be an array.",
    );
  }
  if (raw.items.length > MAX_DELTA_ITEMS) {
    throw new UpstreamRequestError("DELTA_LIMIT", "Too many evidence_delta items.");
  }
  const items = raw.items.map((it, i) => {
    if (!isPlainObject(it)) {
      throw new UpstreamRequestError(
        "INVALID_DELTA_ITEM",
        `evidence_delta.items[${i}] invalid.`,
      );
    }
    rejectForbiddenKeys(it, `evidence_delta.items[${i}].`);
    rejectExtraKeys(it, DELTA_ITEM_KEYS, `evidence_delta.items[${i}].`);
    if (typeof it.material !== "boolean") {
      throw new UpstreamRequestError(
        "INVALID_DELTA_MATERIAL",
        "evidence_delta item material must be boolean.",
      );
    }
    return {
      kind: parseDeltaKind(it.kind),
      summary: boundString(it.summary, `evidence_delta.items[${i}].summary`),
      material: it.material,
    };
  });
  return { items };
}

function parsePrivacy(raw: unknown): PrivacyReviewInput {
  if (raw === undefined || raw === null) {
    return {
      secrets_redacted: false,
      paths_redacted: false,
      session_excluded: false,
    };
  }
  if (!isPlainObject(raw)) {
    throw new UpstreamRequestError(
      "INVALID_PRIVACY",
      "privacy_review must be an object.",
    );
  }
  rejectForbiddenKeys(raw, "privacy_review.");
  rejectExtraKeys(raw, PRIVACY_KEYS, "privacy_review.");
  return {
    secrets_redacted: raw.secrets_redacted === true,
    paths_redacted: raw.paths_redacted === true,
    session_excluded: raw.session_excluded === true,
  };
}

/** Collect raw string candidates from request object for injection scan (pre-parse). */
function collectRawUserStrings(obj: Record<string, unknown>): string[] {
  const out: string[] = [];
  const push = (v: unknown): void => {
    if (typeof v === "string" && v.length > 0) out.push(v);
  };
  const pushArr = (v: unknown): void => {
    if (Array.isArray(v)) {
      for (const x of v) push(x);
    }
  };

  push(obj.actual_behavior);
  pushArr(obj.technical_signals);
  pushArr(obj.observed_facts);
  pushArr(obj.user_reports);
  pushArr(obj.hypotheses);
  pushArr(obj.error_strings);
  pushArr(obj.command_strings);

  // Platform / version strings can enter capsule draft bodies and comments.
  if (isPlainObject(obj.platform)) {
    push(obj.platform.os);
    push(obj.platform.arch);
    push(obj.platform.unknown_reason);
  }
  push(obj.codex_version);
  push(obj.version_unknown_reason);

  if (isPlainObject(obj.reproduction)) {
    pushArr(obj.reproduction.steps);
    push(obj.reproduction.intermittent_marker);
  }

  if (isPlainObject(obj.duplicate_search) && Array.isArray(obj.duplicate_search.candidates)) {
    for (const c of obj.duplicate_search.candidates) {
      if (!isPlainObject(c)) continue;
      push(c.issue_id);
      push(c.title);
      push(c.url);
    }
  }

  if (isPlainObject(obj.evidence_delta) && Array.isArray(obj.evidence_delta.items)) {
    for (const it of obj.evidence_delta.items) {
      if (isPlainObject(it)) push(it.summary);
    }
  }

  // Doctor free-text values (pre-sanitize) — any string leaf can enter summary.
  if (obj.doctor_json !== undefined && obj.doctor_json !== null) {
    collectDoctorStrings(obj.doctor_json, out, 0);
  }

  return out;
}

function collectDoctorStrings(value: unknown, out: string[], depth: number): void {
  if (depth > 6) return;
  if (typeof value === "string") {
    if (value.length > 0) out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectDoctorStrings(v, out, depth + 1);
    return;
  }
  if (isPlainObject(value)) {
    for (const v of Object.values(value)) collectDoctorStrings(v, out, depth + 1);
  }
}

/**
 * Parse and bound the orchestrator-supplied upstream preview request.
 * additionalProperties: false at top level and nested structured objects;
 * forbidden privacy keys fail closed. Injection scan runs after NFKC on every
 * user-controlled string that can enter capsule/draft.
 */
export function parseUpstreamRequest(raw: unknown): {
  request: UpstreamPreviewRequest;
  injection_detected: boolean;
  injection_reason: string | null;
  /** SHA-256 material of the NFKC-joined free-text blob when injection detected. */
  injection_material: string | null;
} {
  let serialized: string;
  try {
    serialized = typeof raw === "string" ? raw : JSON.stringify(raw);
  } catch {
    throw new UpstreamRequestError("SERIALIZE", "Request is not serializable.");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_UPSTREAM_REQUEST_BYTES) {
    throw new UpstreamRequestError("SIZE_LIMIT", "Upstream request exceeds size limit.");
  }

  let obj: unknown = raw;
  if (typeof raw === "string") {
    try {
      obj = JSON.parse(raw);
    } catch {
      throw new UpstreamRequestError("MALFORMED_JSON", "Request JSON is malformed.");
    }
  }
  if (!isPlainObject(obj)) {
    throw new UpstreamRequestError("INVALID_ROOT", "Request must be a JSON object.");
  }

  rejectForbiddenKeys(obj, "");
  for (const k of Object.keys(obj)) {
    if (!(ALLOWED_REQUEST_KEYS as readonly string[]).includes(k)) {
      throw new UpstreamRequestError(
        "EXTRA_FIELD",
        `Unknown or extra request field: ${k}`,
      );
    }
  }

  if (obj.schema_version !== 1) {
    throw new UpstreamRequestError("SCHEMA", "schema_version must be 1.");
  }

  // Detect prompt injection across ALL free-text fields after NFKC.
  const rawStrings = collectRawUserStrings(obj);
  const textBlob = rawStrings.map((s) => nfkc(s)).join("\n");
  const injection_reason = detectInstructionLike(textBlob);
  const injection_detected = injection_reason !== null;
  const injection_material = injection_detected ? textBlob : null;

  if (obj.doctor_json !== undefined && obj.doctor_json !== null) {
    let docSer: string;
    try {
      docSer = JSON.stringify(obj.doctor_json);
    } catch {
      throw new UpstreamRequestError("DOCTOR_SERIALIZE", "doctor_json not serializable.");
    }
    if (Buffer.byteLength(docSer, "utf8") > MAX_DOCTOR_JSON_BYTES) {
      throw new UpstreamRequestError("DOCTOR_SIZE", "doctor_json exceeds size limit.");
    }
  }

  const request: UpstreamPreviewRequest = {
    schema_version: 1,
    case_kind: parseCaseKind(obj.case_kind),
    surface: parseSurface(obj.surface),
    platform: parsePlatform(obj.platform),
    codex_version: optionalBoundString(obj.codex_version, "codex_version", 64),
    version_unknown_reason: optionalBoundString(
      obj.version_unknown_reason,
      "version_unknown_reason",
      256,
    ),
    actual_behavior: boundString(obj.actual_behavior, "actual_behavior"),
    technical_signals: parseStringArray(
      obj.technical_signals,
      "technical_signals",
      MAX_TECHNICAL_SIGNALS,
      true,
    ),
    reproduction: parseReproduction(obj.reproduction),
    observed_facts: parseStringArray(obj.observed_facts, "observed_facts", MAX_FACTS, true),
    user_reports: parseStringArray(obj.user_reports, "user_reports", MAX_FACTS, false),
    hypotheses: parseStringArray(obj.hypotheses, "hypotheses", MAX_FACTS, false),
    duplicate_search: parseDuplicateSearch(obj.duplicate_search),
    evidence_delta: parseEvidenceDelta(obj.evidence_delta),
    doctor_json: obj.doctor_json ?? null,
    privacy_review: parsePrivacy(obj.privacy_review),
    error_strings: parseStringArray(obj.error_strings, "error_strings", MAX_FACTS, false),
    command_strings: parseStringArray(
      obj.command_strings,
      "command_strings",
      MAX_FACTS,
      false,
    ),
  };

  return { request, injection_detected, injection_reason, injection_material };
}
