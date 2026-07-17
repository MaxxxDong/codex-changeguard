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
    const out: Record<string, unknown> = {};
    let n = 0;
    for (const [k, v] of Object.entries(value)) {
      if (n >= MAX_DOCTOR_KEYS) break;
      if (SENSITIVE_KEY_RE.test(k)) continue;
      if (
        FORBIDDEN_UPSTREAM_KEYS.some((f) => f.toLowerCase() === k.toLowerCase())
      ) {
        continue;
      }
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

  // Reject forbidden top-level privacy keys fail-closed (exact key match).
  for (const key of Object.keys(raw)) {
    const lower = key.toLowerCase();
    if (FORBIDDEN_UPSTREAM_KEYS.some((f) => f.toLowerCase() === lower)) {
      throw new DoctorError(
        "DOCTOR_FORBIDDEN_KEY",
        `doctor_json rejects privacy-sensitive field: ${key}`,
      );
    }
    if (SENSITIVE_KEY_RE.test(key) && !ALLOWED_DOCTOR_SUMMARY_KEYS.includes(key)) {
      throw new DoctorError(
        "DOCTOR_FORBIDDEN_KEY",
        `doctor_json rejects sensitive field: ${key}`,
      );
    }
  }

  const keys = Object.keys(raw);
  if (keys.length > MAX_DOCTOR_KEYS) {
    throw new DoctorError("DOCTOR_KEY_LIMIT", "doctor_json has too many keys.");
  }

  // Detect pre-redaction secret/path material for inclusion flags.
  const rawText = serialized;
  const secrets_redacted =
    /Bearer\s+|api[_-]?key|sk-[A-Za-z0-9]|password\s*[:=]/i.test(rawText) ||
    /token\s*[:=]/i.test(rawText);
  const paths_redacted =
    /\/Users\/|\/home\/|[A-Za-z]:\\/i.test(rawText) ||
    /\\\\[^\s]+/.test(rawText);

  const inclusion_manifest: string[] = [];
  const sanitized_summary: Record<string, unknown> = {};

  for (const key of keys) {
    if (!(ALLOWED_DOCTOR_SUMMARY_KEYS as readonly string[]).includes(key)) {
      // Drop unknown keys silently from inclusion (bounded allowlist).
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
