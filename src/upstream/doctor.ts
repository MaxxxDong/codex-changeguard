import { assertNoLeakPaths, redactText, nfkc } from "../core/redact.js";
import {
  FORBIDDEN_UPSTREAM_KEYS,
  MAX_DOCTOR_JSON_BYTES,
  MAX_DOCTOR_KEYS,
  MAX_DOCTOR_STRING,
  MAX_INCLUSION_MANIFEST,
} from "./limits.js";
import type { DoctorSanitizationResult } from "./types.js";

export class DoctorError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DoctorError";
    this.code = code;
  }
}

/** Keys allowed in a sanitized doctor inclusion summary (baseline diagnostics). */
const ALLOWED_DOCTOR_SUMMARY_KEYS = Object.freeze([
  "schema_version",
  "codex_version",
  "cli_version",
  "platform",
  "os",
  "arch",
  "node_version",
  "rust_version",
  "shell",
  "sandbox_mode",
  "features",
  "mcp_servers",
  "plugins",
  "skills",
  "hooks",
  "auth_mode",
  "network_mode",
  "workdir_alias",
  "status",
  "checks",
  "summary",
]);

const SENSITIVE_KEY_RE =
  /token|secret|password|cookie|session|authorization|api[_-]?key|env|credential|private/i;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function isSensitiveKey(key: string): boolean {
  if (FORBIDDEN_UPSTREAM_KEYS.some((f) => f.toLowerCase() === key.toLowerCase())) {
    return true;
  }
  // auth_mode / network_mode are allowlisted diagnostics, not secrets.
  if ((ALLOWED_DOCTOR_SUMMARY_KEYS as readonly string[]).includes(key)) {
    return false;
  }
  return SENSITIVE_KEY_RE.test(key);
}

/**
 * Recursively reject sensitive keys fail-closed (do not silently drop).
 * Unknown non-sensitive keys may be skipped at top-level via allowlist.
 */
function rejectSensitiveKeysDeep(
  value: unknown,
  path: string,
  depth: number,
): void {
  if (depth > 6) return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      rejectSensitiveKeysDeep(value[i], `${path}[${i}]`, depth + 1);
    }
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [k, v] of Object.entries(value)) {
    if (isSensitiveKey(k)) {
      throw new DoctorError(
        "DOCTOR_FORBIDDEN_KEY",
        `doctor_json rejects privacy-sensitive field: ${path}${k}`,
      );
    }
    rejectSensitiveKeysDeep(v, `${path}${k}.`, depth + 1);
  }
}

function sanitizeValue(value: unknown, depth: number): unknown {
  if (depth > 4) return "<truncated>";
  if (typeof value === "string") {
    return assertNoLeakPaths(redactText(nfkc(value))).slice(0, MAX_DOCTOR_STRING);
  }
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 32).map((v) => sanitizeValue(v, depth + 1));
  }
  if (isPlainObject(value)) {
    // Nested sensitive keys already rejected; still fail closed if any slipped.
    rejectSensitiveKeysDeep(value, "", depth);
    const out: Record<string, unknown> = {};
    let n = 0;
    for (const [k, v] of Object.entries(value)) {
      if (n >= MAX_DOCTOR_KEYS) break;
      out[k] = sanitizeValue(v, depth + 1);
      n++;
    }
    return out;
  }
  return null;
}

/**
 * Sanitize an orchestrator-supplied bounded `codex doctor --json` envelope.
 * Never executes codex or arbitrary shell; only processes provided JSON.
 * Sensitive keys are rejected recursively (fail closed), never silently dropped.
 */
export function sanitizeDoctorJson(
  raw: unknown | null | undefined,
): DoctorSanitizationResult {
  if (raw === null || raw === undefined) {
    return {
      included: false,
      inclusion_manifest: [],
      sanitized_summary: null,
      refused_reasons: ["doctor_json_not_provided"],
      secrets_redacted: false,
      paths_redacted: false,
    };
  }

  let serialized: string;
  try {
    serialized = JSON.stringify(raw);
  } catch {
    throw new DoctorError("DOCTOR_SERIALIZE", "doctor_json is not serializable.");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_DOCTOR_JSON_BYTES) {
    throw new DoctorError("DOCTOR_SIZE", "doctor_json exceeds size limit.");
  }

  if (!isPlainObject(raw)) {
    throw new DoctorError("DOCTOR_SHAPE", "doctor_json must be a JSON object.");
  }

  // Reject sensitive keys at every depth fail-closed.
  rejectSensitiveKeysDeep(raw, "", 0);

  const keys = Object.keys(raw);
  if (keys.length > MAX_DOCTOR_KEYS) {
    throw new DoctorError("DOCTOR_KEY_LIMIT", "doctor_json has too many keys.");
  }

  // Detect pre-redaction secret/path material for inclusion flags.
  const rawText = serialized;
  const secrets_redacted =
    /Bearer\s+|api[_-]?key|sk-[A-Za-z0-9]|password\s*[:=]/i.test(rawText) ||
    /token\s*[:=]/i.test(rawText) ||
    /Cookie\s*[:=]|Set-Cookie\s*[:=]/i.test(rawText);
  const paths_redacted =
    /\/Users\/|\/home\/|[A-Za-z]:\\/i.test(rawText) ||
    /\\\\[^\s]+/.test(rawText);

  const inclusion_manifest: string[] = [];
  const sanitized_summary: Record<string, unknown> = {};

  for (const key of keys) {
    if (!(ALLOWED_DOCTOR_SUMMARY_KEYS as readonly string[]).includes(key)) {
      // Drop unknown non-sensitive keys from inclusion (bounded allowlist).
      continue;
    }
    if (inclusion_manifest.length >= MAX_INCLUSION_MANIFEST) break;
    const value = sanitizeValue(raw[key], 0);
    sanitized_summary[key] = value;
    inclusion_manifest.push(key);
  }

  if (inclusion_manifest.length === 0) {
    return {
      included: false,
      inclusion_manifest: [],
      sanitized_summary: null,
      refused_reasons: ["no_allowlisted_doctor_fields"],
      secrets_redacted,
      paths_redacted,
    };
  }

  return {
    included: true,
    inclusion_manifest,
    sanitized_summary,
    refused_reasons: [],
    secrets_redacted,
    paths_redacted,
  };
}
