/**
 * Platform support receipt parse + structural validation (Ticket 14).
 * Does not evaluate FULL/PREVIEW — see status.ts.
 *
 * Full elevation additionally requires a process-local live harness witness
 * (WeakMap-sealed; not reconstructible from JSON or plain objects). See
 * sealWindowsLiveHarnessWitness — production CLI/MCP never obtain one without
 * a future controlled Windows harness run in-process.
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

/** Top-level keys allowed by schemas/platform-support-receipt.schema.json (Windows branch). */
const RECEIPT_TOP_KEYS = new Set([
  "schema_version",
  "platform",
  "os_family",
  "os_version",
  "os_build",
  "arch",
  "host_kind",
  "codex_versions",
  "instances_fingerprint",
  "git_sha",
  "collected_at",
  "critical_scenarios",
  "operator_attestation",
]);

const SCENARIO_KEYS = new Set([
  "id",
  "title",
  "passed",
  "evidence_digest",
  "note",
]);

const ATTESTATION_KEYS = new Set([
  "non_primary_profile",
  "real_hardware",
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

function rejectExtraKeys(
  obj: Record<string, unknown>,
  allowed: Set<string>,
  where: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new ReceiptValidationError(
        "EXTRA_KEY",
        `Unknown key at ${where}: ${key}`,
      );
    }
  }
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
  rejectExtraKeys(raw, SCENARIO_KEYS, "critical_scenarios[]");
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
  rejectExtraKeys(raw, ATTESTATION_KEYS, "operator_attestation");
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
 * Fail-closed on unknown extra keys (schema additionalProperties:false).
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
  rejectExtraKeys(input, RECEIPT_TOP_KEYS, "receipt");
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

/** Stable binding over critical scenarios + evidence digests (path-free). */
export function criticalScenariosBindingOf(
  scenarios: readonly CriticalScenarioResult[],
): string {
  const rows = scenarios
    .map(
      (s) =>
        `${s.id}|${s.passed ? "1" : "0"}|${s.evidence_digest ?? "-"}`,
    )
    .sort();
  return crypto
    .createHash("sha256")
    .update(`w11-scenarios:v1:${rows.join("\n")}`, "utf8")
    .digest("hex");
}

// ---------------------------------------------------------------------------
// Process-local live harness witness (not serializable / not forgeable via JSON)
// Mirrors Ticket 13 macOS live witness: WeakMap identity, not reconstructible
// from receipt JSON, CLI/MCP reload, or plain-object fakes.
// ---------------------------------------------------------------------------

const WIN_LIVE_WITNESS_BRAND = Symbol(
  "changeguard.windows_live_harness_witness",
);

/**
 * Material sealed for a just-executed controlled Windows harness run.
 * Must match the evaluated receipt binding field-for-field for Full.
 */
export interface WindowsLiveHarnessAttestation {
  receipt_digest: string;
  platform: string;
  os_family: string;
  os_version: string | null;
  os_build: string | null;
  arch: string;
  host_kind: PlatformReceiptHostKind;
  git_sha: string | null;
  collected_at: string;
  instances_fingerprint: string | null;
  /** Digest of all critical scenario ids/pass/evidence_digest bindings. */
  scenarios_binding: string;
}

export interface WindowsLiveHarnessWitness {
  readonly [WIN_LIVE_WITNESS_BRAND]: true;
}

const windowsLiveWitnessStore = new WeakMap<
  WindowsLiveHarnessWitness,
  WindowsLiveHarnessAttestation
>();

/**
 * Seal a process-local witness for a controlled Windows harness run.
 * Production CLI/MCP and validate-receipt-only runners never call this;
 * only a future in-process Windows Scenario Harness (or unit tests) may.
 * The token is an opaque object; only this process's WeakMap can resolve it.
 */
export function sealWindowsLiveHarnessWitness(
  attestation: WindowsLiveHarnessAttestation,
): WindowsLiveHarnessWitness {
  const token = { [WIN_LIVE_WITNESS_BRAND]: true as const };
  windowsLiveWitnessStore.set(token, {
    receipt_digest: attestation.receipt_digest,
    platform: attestation.platform,
    os_family: attestation.os_family,
    os_version: attestation.os_version,
    os_build: attestation.os_build,
    arch: attestation.arch,
    host_kind: attestation.host_kind,
    git_sha: attestation.git_sha,
    collected_at: attestation.collected_at,
    instances_fingerprint: attestation.instances_fingerprint,
    scenarios_binding: attestation.scenarios_binding,
  });
  return token;
}

export function isWindowsLiveHarnessWitness(
  v: unknown,
): v is WindowsLiveHarnessWitness {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as WindowsLiveHarnessWitness)[WIN_LIVE_WITNESS_BRAND] === true &&
    windowsLiveWitnessStore.has(v as WindowsLiveHarnessWitness)
  );
}

export function readWindowsLiveHarnessAttestation(
  witness: WindowsLiveHarnessWitness,
): WindowsLiveHarnessAttestation | null {
  return windowsLiveWitnessStore.get(witness) ?? null;
}

/** Build attestation material from a structurally validated receipt. */
export function windowsLiveAttestationFromReceipt(
  receipt: PlatformSupportReceipt,
): WindowsLiveHarnessAttestation {
  return {
    receipt_digest: receiptDigest(receipt),
    platform: receipt.platform,
    os_family: receipt.os_family,
    os_version: receipt.os_version,
    os_build: receipt.os_build,
    arch: receipt.arch,
    host_kind: receipt.host_kind,
    git_sha: receipt.git_sha,
    collected_at: receipt.collected_at,
    instances_fingerprint: receipt.instances_fingerprint,
    scenarios_binding: criticalScenariosBindingOf(receipt.critical_scenarios),
  };
}

/**
 * True only when witness is process-local and every bound field matches the
 * receipt. Plain objects / JSON clones never match.
 */
export function windowsLiveWitnessMatchesReceipt(
  receipt: PlatformSupportReceipt,
  witness: unknown,
): boolean {
  if (!isWindowsLiveHarnessWitness(witness)) return false;
  const att = readWindowsLiveHarnessAttestation(witness);
  if (!att) return false;
  const expected = windowsLiveAttestationFromReceipt(receipt);
  return (
    att.receipt_digest === expected.receipt_digest &&
    att.platform === expected.platform &&
    att.os_family === expected.os_family &&
    att.os_version === expected.os_version &&
    att.os_build === expected.os_build &&
    att.arch === expected.arch &&
    att.host_kind === expected.host_kind &&
    att.git_sha === expected.git_sha &&
    att.collected_at === expected.collected_at &&
    att.instances_fingerprint === expected.instances_fingerprint &&
    att.scenarios_binding === expected.scenarios_binding
  );
}
