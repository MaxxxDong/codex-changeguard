import crypto from "node:crypto";
import {
  MAX_ARTIFACT_HASHES,
  MAX_AST_SIGNATURE_ID_LENGTH,
  MAX_AST_SIGNATURE_IDS,
  MAX_CONFIG_KEYS,
  MAX_FEATURE_IDS,
  MAX_STACK_FRAMES,
  MAX_STRING_FIELD,
} from "./limits.js";
import { redactText } from "./redact.js";
import type {
  ArtifactHash,
  CrashConcurrencyContext,
  CrashInteractionPhase,
  CrashMetadata,
  CrashPageCapability,
  ErrorInfo,
  IncidentFingerprint,
  PlatformInfo,
  StackFrame,
} from "./types.js";

const SURFACES = new Set([
  "desktop",
  "cli",
  "plugin",
  "mcp",
  "browser_control",
  "app_server",
  "unknown",
]);

const PHASES = new Set([
  "startup",
  "hook_load",
  "extension_handshake",
  "tab_discovery",
  "navigation",
  "tool_call",
  "output_decode",
  "shutdown",
  "unknown",
]);

const OSES = new Set(["macos", "windows", "linux", "unknown"]);

const STACK_FRAME_KEYS = new Set(["module", "file", "symbol", "line_bucket"]);
const ARTIFACT_HASH_KEYS = new Set(["path_alias", "sha256"]);

export class FingerprintError extends Error {
  readonly code: string;
  constructor(code: string, message = "Invalid incident.") {
    super(message);
    this.name = "FingerprintError";
    this.code = code;
  }
}

function asString(v: unknown, max: number, field: string): string {
  if (typeof v !== "string") {
    throw new FingerprintError("MALFORMED_INCIDENT", `Invalid ${field}.`);
  }
  if (v.length > max) {
    throw new FingerprintError("FIELD_LIMIT", `Field too long: ${field}.`);
  }
  return redactText(v);
}

function asNullableString(
  v: unknown,
  max: number,
  field: string,
): string | null {
  if (v === null || v === undefined) return null;
  return asString(v, max, field);
}

function sha256Hex(data: string | Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function parsePlatform(raw: unknown): PlatformInfo {
  if (!raw || typeof raw !== "object") {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid platform.");
  }
  const p = raw as Record<string, unknown>;
  if (Object.keys(p).some((k) => !["os", "arch", "sandbox_class"].includes(k))) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Unexpected platform field.");
  }
  if (typeof p.os !== "string" || !OSES.has(p.os)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid platform.os.");
  }
  return {
    os: p.os as PlatformInfo["os"],
    arch: asString(p.arch, 64, "platform.arch"),
    sandbox_class: asNullableString(p.sandbox_class, 128, "platform.sandbox_class"),
  };
}

function parseError(raw: unknown): ErrorInfo {
  if (!raw || typeof raw !== "object") {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid error.");
  }
  const e = raw as Record<string, unknown>;
  const allowed = new Set(["class", "normalized_message", "message_digest"]);
  for (const k of Object.keys(e)) {
    if (!allowed.has(k)) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Unexpected error field.");
    }
  }
  const cls = asString(e.class, 256, "error.class");
  const normalized_message = asString(
    e.normalized_message,
    MAX_STRING_FIELD,
    "error.normalized_message",
  );
  let message_digest: string | null = null;
  if (e.message_digest !== null && e.message_digest !== undefined) {
    if (
      typeof e.message_digest !== "string" ||
      !/^[a-f0-9]{64}$/.test(e.message_digest)
    ) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Invalid message_digest.");
    }
    message_digest = e.message_digest;
  }
  return { class: cls, normalized_message, message_digest };
}

function parseStackFrames(raw: unknown): StackFrame[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid stack_frames.");
  }
  if (raw.length > MAX_STACK_FRAMES) {
    throw new FingerprintError("FIELD_LIMIT", "Too many stack frames.");
  }
  return raw.map((item, i) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new FingerprintError("MALFORMED_INCIDENT", `Invalid stack frame ${i}.`);
    }
    const f = item as Record<string, unknown>;
    for (const k of Object.keys(f)) {
      if (!STACK_FRAME_KEYS.has(k)) {
        throw new FingerprintError(
          "MALFORMED_INCIDENT",
          "Unexpected stack_frames field.",
        );
      }
    }
    return {
      module: asNullableString(f.module, 256, "stack.module"),
      file: asNullableString(f.file, 256, "stack.file"),
      symbol: asNullableString(f.symbol, 256, "stack.symbol"),
      line_bucket:
        f.line_bucket === null || f.line_bucket === undefined
          ? null
          : typeof f.line_bucket === "number" &&
              Number.isInteger(f.line_bucket) &&
              f.line_bucket >= 0
            ? f.line_bucket
            : (() => {
                throw new FingerprintError(
                  "MALFORMED_INCIDENT",
                  "Invalid line_bucket.",
                );
              })(),
    };
  });
}

function parseStringArray(
  raw: unknown,
  maxItems: number,
  itemMax: number,
  field: string,
): string[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new FingerprintError("MALFORMED_INCIDENT", `Invalid ${field}.`);
  }
  if (raw.length > maxItems) {
    throw new FingerprintError("FIELD_LIMIT", `Too many ${field}.`);
  }
  const out = raw.map((v, i) => asString(v, itemMax, `${field}[${i}]`));
  if (new Set(out).size !== out.length) {
    throw new FingerprintError("MALFORMED_INCIDENT", `Duplicate ${field}.`);
  }
  return out;
}

function parseArtifactHashes(raw: unknown): ArtifactHash[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid artifact_hashes.");
  }
  if (raw.length > MAX_ARTIFACT_HASHES) {
    throw new FingerprintError("FIELD_LIMIT", "Too many artifact_hashes.");
  }
  const seenAliases = new Set<string>();
  return raw.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Invalid artifact hash.");
    }
    const a = item as Record<string, unknown>;
    for (const k of Object.keys(a)) {
      if (!ARTIFACT_HASH_KEYS.has(k)) {
        throw new FingerprintError(
          "MALFORMED_INCIDENT",
          "Unexpected artifact_hashes field.",
        );
      }
    }
    if (typeof a.path_alias !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(a.path_alias)) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Invalid path_alias.");
    }
    if (seenAliases.has(a.path_alias)) {
      throw new FingerprintError(
        "MALFORMED_INCIDENT",
        "Duplicate artifact path_alias.",
      );
    }
    seenAliases.add(a.path_alias);
    if (typeof a.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(a.sha256)) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Invalid sha256.");
    }
    return { path_alias: a.path_alias, sha256: a.sha256 };
  });
}

function parseAstIds(raw: unknown): string[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid ast_signature_ids.");
  }
  if (raw.length > MAX_AST_SIGNATURE_IDS) {
    throw new FingerprintError("FIELD_LIMIT", "Too many ast_signature_ids.");
  }
  const out = raw.map((v, i) => {
    if (typeof v !== "string") {
      throw new FingerprintError("MALFORMED_INCIDENT", `Invalid ast id ${i}.`);
    }
    if (v.length > MAX_AST_SIGNATURE_ID_LENGTH) {
      throw new FingerprintError(
        "FIELD_LIMIT",
        "AST signature id exceeds 128 characters.",
      );
    }
    return redactText(v);
  });
  if (new Set(out).size !== out.length) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Duplicate ast ids.");
  }
  return out;
}

const INTERACTION_PHASES = new Set<CrashInteractionPhase>([
  "neutral_dom_ready",
  "link_click",
  "button_click",
  "webview_attach",
  "media_canvas",
  "unknown",
]);

const PAGE_CAPABILITIES = new Set<CrashPageCapability>([
  "neutral",
  "media",
  "canvas",
  "complex_login",
  "unknown",
]);

const CONCURRENCY_CONTEXTS = new Set<CrashConcurrencyContext>([
  "single",
  "multi_side_chat",
  "unknown",
]);

const CRASH_METADATA_KEYS = new Set([
  "exception_code",
  "faulting_module",
  "faulting_symbol",
  "offset_bucket",
  "gpu_child_exit_code",
  "gpu_relaunch_code",
  "interaction_phase",
  "page_capability",
  "concurrency_context",
  "concurrent_side_chats",
  "component",
  "isolation_available",
  "natural_failure_only",
  "active_probe_requested",
  "dump_contents_present",
]);

function parseNullableIntCode(
  v: unknown,
  field: string,
): number | null {
  if (v === null || v === undefined) return null;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 2_147_483_647) {
    throw new FingerprintError("MALFORMED_INCIDENT", `Invalid ${field}.`);
  }
  return v;
}

function parseCrashMetadata(raw: unknown): CrashMetadata | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null) return null;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid crash_metadata.");
  }
  const m = raw as Record<string, unknown>;
  for (const k of Object.keys(m)) {
    if (!CRASH_METADATA_KEYS.has(k)) {
      throw new FingerprintError(
        "MALFORMED_INCIDENT",
        "Unexpected crash_metadata field.",
      );
    }
  }

  const asNullStr = (v: unknown, field: string, max = 256): string | null => {
    if (v === null || v === undefined) return null;
    return asString(v, max, field);
  };

  const asBool = (v: unknown, field: string, defaultVal: boolean): boolean => {
    if (v === undefined) return defaultVal;
    if (typeof v !== "boolean") {
      throw new FingerprintError("MALFORMED_INCIDENT", `Invalid ${field}.`);
    }
    return v;
  };

  let interaction_phase: CrashInteractionPhase | null = null;
  if (m.interaction_phase !== null && m.interaction_phase !== undefined) {
    if (
      typeof m.interaction_phase !== "string" ||
      !INTERACTION_PHASES.has(m.interaction_phase as CrashInteractionPhase)
    ) {
      throw new FingerprintError(
        "MALFORMED_INCIDENT",
        "Invalid interaction_phase.",
      );
    }
    interaction_phase = m.interaction_phase as CrashInteractionPhase;
  }

  let page_capability: CrashPageCapability | null = null;
  if (m.page_capability !== null && m.page_capability !== undefined) {
    if (
      typeof m.page_capability !== "string" ||
      !PAGE_CAPABILITIES.has(m.page_capability as CrashPageCapability)
    ) {
      throw new FingerprintError(
        "MALFORMED_INCIDENT",
        "Invalid page_capability.",
      );
    }
    page_capability = m.page_capability as CrashPageCapability;
  }

  let concurrency_context: CrashConcurrencyContext | null = null;
  if (m.concurrency_context !== null && m.concurrency_context !== undefined) {
    if (
      typeof m.concurrency_context !== "string" ||
      !CONCURRENCY_CONTEXTS.has(m.concurrency_context as CrashConcurrencyContext)
    ) {
      throw new FingerprintError(
        "MALFORMED_INCIDENT",
        "Invalid concurrency_context.",
      );
    }
    concurrency_context = m.concurrency_context as CrashConcurrencyContext;
  }

  let concurrent_side_chats: number | null = null;
  if (m.concurrent_side_chats !== null && m.concurrent_side_chats !== undefined) {
    if (
      typeof m.concurrent_side_chats !== "number" ||
      !Number.isInteger(m.concurrent_side_chats) ||
      m.concurrent_side_chats < 0 ||
      m.concurrent_side_chats > 1024
    ) {
      throw new FingerprintError(
        "MALFORMED_INCIDENT",
        "Invalid concurrent_side_chats.",
      );
    }
    concurrent_side_chats = m.concurrent_side_chats;
  }

  // Never accept dump body fields — keys already fail closed via allowlist.
  return {
    exception_code: asNullStr(m.exception_code, "exception_code", 64),
    faulting_module: asNullStr(m.faulting_module, "faulting_module", 256),
    faulting_symbol: asNullStr(m.faulting_symbol, "faulting_symbol", 256),
    offset_bucket: asNullStr(m.offset_bucket, "offset_bucket", 64),
    gpu_child_exit_code: parseNullableIntCode(
      m.gpu_child_exit_code,
      "gpu_child_exit_code",
    ),
    gpu_relaunch_code: parseNullableIntCode(
      m.gpu_relaunch_code,
      "gpu_relaunch_code",
    ),
    interaction_phase,
    page_capability,
    concurrency_context,
    concurrent_side_chats,
    component: asNullStr(m.component, "component", 128),
    isolation_available: asBool(m.isolation_available, "isolation_available", false),
    natural_failure_only: asBool(m.natural_failure_only, "natural_failure_only", true),
    active_probe_requested: asBool(
      m.active_probe_requested,
      "active_probe_requested",
      false,
    ),
    dump_contents_present: asBool(
      m.dump_contents_present,
      "dump_contents_present",
      false,
    ),
  };
}

/**
 * Parse and validate incident JSON text into a redacted IncidentFingerprint.
 * Declared artifact hashes and AST ids are recorded but never treated as
 * independent measurement proof.
 */
export function parseIncidentJson(text: string): IncidentFingerprint {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new FingerprintError("MALFORMED_JSON", "Malformed JSON.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Incident must be an object.");
  }
  const o = raw as Record<string, unknown>;
  const allowed = new Set([
    "schema_version",
    "codex_version",
    "build_sha",
    "surface",
    "platform",
    "failure_phase",
    "error",
    "stack_frames",
    "config_keys",
    "feature_ids",
    "artifact_hashes",
    "ast_signature_ids",
    "crash_metadata",
    "local_facts_digest",
  ]);
  for (const k of Object.keys(o)) {
    if (!allowed.has(k)) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Unexpected field.");
    }
  }
  if (o.schema_version !== 1) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid schema_version.");
  }
  if (typeof o.surface !== "string" || !SURFACES.has(o.surface)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid surface.");
  }
  if (typeof o.failure_phase !== "string" || !PHASES.has(o.failure_phase)) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid failure_phase.");
  }
  if (
    typeof o.local_facts_digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(o.local_facts_digest)
  ) {
    throw new FingerprintError("MALFORMED_INCIDENT", "Invalid local_facts_digest.");
  }
  if (o.build_sha !== null && o.build_sha !== undefined) {
    if (
      typeof o.build_sha !== "string" ||
      !/^[a-fA-F0-9]{7,64}$/.test(o.build_sha)
    ) {
      throw new FingerprintError("MALFORMED_INCIDENT", "Invalid build_sha.");
    }
  }

  const crash_metadata = parseCrashMetadata(o.crash_metadata);

  const fp: IncidentFingerprint = {
    schema_version: 1,
    codex_version: asNullableString(o.codex_version, 128, "codex_version"),
    build_sha: (o.build_sha as string | null | undefined) ?? null,
    surface: o.surface as IncidentFingerprint["surface"],
    platform: parsePlatform(o.platform),
    failure_phase: o.failure_phase as IncidentFingerprint["failure_phase"],
    error: parseError(o.error),
    stack_frames: parseStackFrames(o.stack_frames),
    config_keys: parseStringArray(o.config_keys, MAX_CONFIG_KEYS, 256, "config_keys"),
    feature_ids: parseStringArray(o.feature_ids, MAX_FEATURE_IDS, 256, "feature_ids"),
    artifact_hashes: parseArtifactHashes(o.artifact_hashes),
    ast_signature_ids: parseAstIds(o.ast_signature_ids),
    crash_metadata,
    local_facts_digest: o.local_facts_digest,
  };
  return fp;
}

/** Optional measured config-fault material (Ticket 07). */
export interface MeasuredConfigFacts {
  fault_class: string;
  config_keys: string[];
  primary_sha256: string | null;
  override_sha256: string | null;
}

/** Recompute local_facts_digest from measured fields (not self-declared alone). */
export function recomputeLocalFactsDigest(
  fp: IncidentFingerprint,
  measuredArtifactSha: string | null,
  measuredAstIds: string[],
  measuredConfig: MeasuredConfigFacts | null = null,
): string {
  const payload: Record<string, unknown> = {
    surface: fp.surface,
    platform: fp.platform,
    failure_phase: fp.failure_phase,
    error_class: fp.error.class,
    error_message: fp.error.normalized_message,
    measured_artifact_sha: measuredArtifactSha,
    measured_ast: measuredAstIds.slice().sort(),
  };
  // Only include config material when measured — keeps Tickets 01–04 digests stable.
  if (measuredConfig) {
    payload.measured_config_fault = measuredConfig.fault_class;
    payload.measured_config_keys = measuredConfig.config_keys.slice().sort();
    payload.measured_config_primary_sha = measuredConfig.primary_sha256;
    payload.measured_config_override_sha = measuredConfig.override_sha256;
  }
  return sha256Hex(JSON.stringify(payload));
}

export { sha256Hex };
