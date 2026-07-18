/**
 * Platform support receipt parse + structural validation (Ticket 14).
 * Does not evaluate FULL/PREVIEW — see status.ts.
 */
import crypto from "node:crypto";
import {
  isCriticalScenarioId,
  WINDOWS11_CRITICAL_SCENARIOS,
} from "./critical-scenarios.js";
import type {
  CriticalScenarioResult,
  PlatformOperatorAttestation,
  PlatformReceiptHostKind,
  PlatformReceiptPlatform,
  PlatformSupportReceipt,
  Windows11CriticalScenarioId,
} from "./types.js";

const MAX_STRING = 256;
const MAX_VERSIONS = 32;
const MAX_NOTE = 512;
const HOST_KINDS = new Set<PlatformReceiptHostKind>([
  "real_machine",
  "synthetic",
  "cross_platform_ci",
]);
const PLATFORMS = new Set<PlatformReceiptPlatform>([
  "windows",
  "macos",
  "linux",
  "wsl",
  "unknown",
]);

export class ReceiptValidationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ReceiptValidationError";
    this.code = code;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function boundString(v: unknown, field: string, max = MAX_STRING): string {
  if (typeof v !== "string" || v.length === 0 || v.length > max) {
    throw new ReceiptValidationError(
      "INVALID_FIELD",
      `Invalid receipt field: ${field}`,
    );
  }
  // Refuse absolute path-looking shapes in free text (defense in depth).
  if (
    /\/Users\//.test(v) ||
    /\/home\//.test(v) ||
    /[A-Za-z]:\\/.test(v) ||
    /\\\\[A-Za-z]/.test(v)
  ) {
    throw new ReceiptValidationError(
      "PATH_LEAK",
      `Receipt field must not contain absolute paths: ${field}`,
    );
  }
  return v;
}

function optionalString(
  v: unknown,
  field: string,
  max = MAX_STRING,
): string | null {
  if (v === null || v === undefined) return null;
  return boundString(v, field, max);
}

function parseScenario(raw: unknown): CriticalScenarioResult {
  if (!isPlainObject(raw)) {
    throw new ReceiptValidationError(
      "INVALID_SCENARIO",
      "Scenario entry must be an object.",
    );
  }
  const idRaw = boundString(raw.id, "scenario.id", 32);
  if (!isCriticalScenarioId(idRaw)) {
    throw new ReceiptValidationError(
      "UNKNOWN_SCENARIO",
      `Unknown critical scenario id: ${idRaw}`,
    );
  }
  const id = idRaw as Windows11CriticalScenarioId;
  const def = WINDOWS11_CRITICAL_SCENARIOS.find((s) => s.id === id);
  const title =
    typeof raw.title === "string" && raw.title.length > 0
      ? boundString(raw.title, "scenario.title")
      : (def?.title ?? id);
  if (typeof raw.passed !== "boolean") {
    throw new ReceiptValidationError(
      "INVALID_SCENARIO",
      `Scenario ${id} requires boolean passed.`,
    );
  }
  let evidence_digest: string | null = null;
  if (raw.evidence_digest !== null && raw.evidence_digest !== undefined) {
    const d = boundString(raw.evidence_digest, "scenario.evidence_digest", 128);
    if (!/^[a-f0-9]{16,128}$/i.test(d)) {
      throw new ReceiptValidationError(
        "INVALID_DIGEST",
        `Scenario ${id} evidence_digest must be hex.`,
      );
    }
    evidence_digest = d.toLowerCase();
  }
  const note =
    raw.note === null || raw.note === undefined
      ? null
      : boundString(raw.note, "scenario.note", MAX_NOTE);
  return {
    id,
    title,
    passed: raw.passed,
    evidence_digest,
    note,
  };
}

function parseAttestation(
  raw: unknown,
): PlatformOperatorAttestation | null {
  if (raw === null || raw === undefined) return null;
  if (!isPlainObject(raw)) {
    throw new ReceiptValidationError(
      "INVALID_ATTESTATION",
      "operator_attestation must be an object or null.",
    );
  }
  if (
    typeof raw.non_primary_profile !== "boolean" ||
    typeof raw.real_hardware !== "boolean"
  ) {
    throw new ReceiptValidationError(
      "INVALID_ATTESTATION",
      "operator_attestation requires boolean non_primary_profile and real_hardware.",
    );
  }
  return {
    non_primary_profile: raw.non_primary_profile,
    real_hardware: raw.real_hardware,
  };
}

/**
 * Parse and structurally validate a platform support receipt.
 * Throws ReceiptValidationError on malformed input.
 */
export function parsePlatformSupportReceipt(
  input: unknown,
): PlatformSupportReceipt {
  if (!isPlainObject(input)) {
    throw new ReceiptValidationError(
      "INVALID_RECEIPT",
      "Receipt must be a JSON object.",
    );
  }
  if (input.schema_version !== 1) {
    throw new ReceiptValidationError(
      "SCHEMA_VERSION",
      "receipt.schema_version must be 1.",
    );
  }
  const platformRaw = boundString(input.platform, "platform", 32);
  if (!PLATFORMS.has(platformRaw as PlatformReceiptPlatform)) {
    throw new ReceiptValidationError(
      "INVALID_PLATFORM",
      `Unknown platform: ${platformRaw}`,
    );
  }
  const hostRaw = boundString(input.host_kind, "host_kind", 32);
  if (!HOST_KINDS.has(hostRaw as PlatformReceiptHostKind)) {
    throw new ReceiptValidationError(
      "INVALID_HOST_KIND",
      `Unknown host_kind: ${hostRaw}`,
    );
  }
  if (!Array.isArray(input.critical_scenarios)) {
    throw new ReceiptValidationError(
      "INVALID_SCENARIOS",
      "critical_scenarios must be an array.",
    );
  }
  if (input.critical_scenarios.length > 32) {
    throw new ReceiptValidationError(
      "TOO_MANY_SCENARIOS",
      "Too many critical_scenarios entries.",
    );
  }
  const scenarios = input.critical_scenarios.map(parseScenario);
  // Reject duplicate scenario ids.
  const seen = new Set<string>();
  for (const s of scenarios) {
    if (seen.has(s.id)) {
      throw new ReceiptValidationError(
        "DUPLICATE_SCENARIO",
        `Duplicate scenario id: ${s.id}`,
      );
    }
    seen.add(s.id);
  }

  let codex_versions: string[] = [];
  if (input.codex_versions !== undefined && input.codex_versions !== null) {
    if (!Array.isArray(input.codex_versions)) {
      throw new ReceiptValidationError(
        "INVALID_VERSIONS",
        "codex_versions must be an array.",
      );
    }
    if (input.codex_versions.length > MAX_VERSIONS) {
      throw new ReceiptValidationError(
        "TOO_MANY_VERSIONS",
        "Too many codex_versions.",
      );
    }
    codex_versions = input.codex_versions.map((v, i) =>
      boundString(v, `codex_versions[${i}]`, 64),
    );
  }

  return {
    schema_version: 1,
    platform: platformRaw as PlatformReceiptPlatform,
    os_family: boundString(input.os_family, "os_family"),
    os_version: optionalString(input.os_version, "os_version", 64),
    os_build: optionalString(input.os_build, "os_build", 64),
    arch: boundString(input.arch, "arch", 32),
    host_kind: hostRaw as PlatformReceiptHostKind,
    codex_versions,
    instances_fingerprint: optionalString(
      input.instances_fingerprint,
      "instances_fingerprint",
      128,
    ),
    git_sha: optionalString(input.git_sha, "git_sha", 64),
    collected_at: boundString(input.collected_at, "collected_at", 64),
    critical_scenarios: scenarios,
    operator_attestation: parseAttestation(input.operator_attestation),
  };
}

/** Deterministic digest of a validated receipt (stable key order). */
export function receiptDigest(receipt: PlatformSupportReceipt): string {
  const payload = JSON.stringify(receipt);
  return crypto.createHash("sha256").update(payload).digest("hex");
}
