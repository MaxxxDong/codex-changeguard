/**
 * Registered bounded probes for follow-up evidence.
 * Only allowlisted probe ids; never arbitrary paths or shell.
 *
 * Candidate validation uses a positive measurement contract:
 * absence of markers / empty dirs / caller booleans never prove success.
 */
import fs from "node:fs";
import path from "node:path";
import {
  resolveTargetDirectory,
  resolveNamedCandidate,
  readBoundedFile,
  PathSafetyError,
} from "../../core/path-safety.js";
import { sha256Canonical, sha256Text } from "../../evidence/canonical.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import type { FollowupProbeResult, RegisteredProbeId } from "./types.js";
import {
  CANDIDATE_MEASUREMENT_MAX_BYTES,
  CANDIDATE_MEASUREMENT_REL,
  CANDIDATE_MEASUREMENT_SCHEMA_VERSION,
  MAX_STRING,
  MAX_VERSION_LEN,
} from "./limits.js";

function detailOf(s: string): string {
  return assertNoLeakPaths(redactText(s)).slice(0, MAX_STRING);
}

function digestOf(material: unknown): string {
  return sha256Text(JSON.stringify(material));
}

/**
 * Run a single registered probe under an isolated target.
 * Failures are measured as passed=false, never throw into shell.
 */
export function runRegisteredProbe(
  targetPath: string,
  probe_id: RegisteredProbeId,
): FollowupProbeResult {
  try {
    const { targetReal } = resolveTargetDirectory(targetPath);
    switch (probe_id) {
      case "core_health_readonly":
        return probeCoreHealth(targetReal);
      case "config_control_probe":
        return probeConfig(targetReal);
      case "version_fingerprint_probe":
        return probeVersion(targetReal);
      case "platform_identity_probe":
        return probePlatform(targetReal);
      case "reproduction_window_probe":
        return probeRepro(targetReal);
      case "log_redaction_probe":
        return probeLogs(targetReal);
      default: {
        const _e: never = probe_id;
        void _e;
        return {
          probe_id,
          measured: true,
          passed: false,
          detail: "Unknown probe refused.",
          content_digest: digestOf({ probe_id, refused: true }),
        };
      }
    }
  } catch (e) {
    const code = e instanceof PathSafetyError ? e.code : "PROBE_ERROR";
    return {
      probe_id,
      measured: true,
      passed: false,
      detail: detailOf(`probe failed: ${code}`),
      content_digest: digestOf({ probe_id, error: code }),
    };
  }
}

export function runRegisteredProbes(
  targetPath: string,
  probe_ids: readonly RegisteredProbeId[],
): FollowupProbeResult[] {
  const out: FollowupProbeResult[] = [];
  for (const id of probe_ids) {
    out.push(runRegisteredProbe(targetPath, id));
  }
  return out;
}

function existsNamed(targetReal: string, rel: string): boolean {
  const abs = path.join(targetReal, rel);
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) return false;
    return st.isFile() || st.isDirectory();
  } catch {
    return false;
  }
}

function probeCoreHealth(targetReal: string): FollowupProbeResult {
  // Target already path-safety resolved; presence markers are informational only.
  const hasIncident = existsNamed(targetReal, "incident.json");
  const hasLifecycle = existsNamed(targetReal, ".changeguard/lifecycle");
  // Basic health is ok when the isolated target resolved (no arbitrary crawl).
  const passed = true;
  return {
    probe_id: "core_health_readonly",
    measured: true,
    passed,
    detail: detailOf(
      `core_health ok;incident=${hasIncident};lifecycle_dir=${hasLifecycle}`,
    ),
    content_digest: digestOf({
      probe: "core_health_readonly",
      hasIncident,
      hasLifecycle,
    }),
  };
}

function probeConfig(targetReal: string): FollowupProbeResult {
  const primary = existsNamed(targetReal, "config/config.toml");
  return {
    probe_id: "config_control_probe",
    measured: true,
    passed: true,
    detail: detailOf(
      primary
        ? "registered config/config.toml present (content not exported)"
        : "registered config path absent; reported as unknown",
    ),
    content_digest: digestOf({
      probe: "config_control_probe",
      present: primary,
    }),
  };
}

function probeVersion(targetReal: string): FollowupProbeResult {
  // Prefer fixture-declared version under named candidates only.
  const candidates = ["version.json", "pkg/package.json", "incident.json"];
  let found = false;
  for (const rel of candidates) {
    if (existsNamed(targetReal, rel)) {
      found = true;
      break;
    }
  }
  return {
    probe_id: "version_fingerprint_probe",
    measured: true,
    passed: true,
    detail: detailOf(
      found
        ? "version evidence candidate present under registered names"
        : "no named version evidence; fingerprint unknown",
    ),
    content_digest: digestOf({
      probe: "version_fingerprint_probe",
      found,
    }),
  };
}

function probePlatform(targetReal: string): FollowupProbeResult {
  void targetReal;
  const platform = process.platform;
  const arch = process.arch;
  return {
    probe_id: "platform_identity_probe",
    measured: true,
    passed: true,
    detail: detailOf(`platform=${platform};arch=${arch}`),
    content_digest: digestOf({
      probe: "platform_identity_probe",
      platform,
      arch,
    }),
  };
}

function probeRepro(targetReal: string): FollowupProbeResult {
  const hasIncident = existsNamed(targetReal, "incident.json");
  return {
    probe_id: "reproduction_window_probe",
    measured: true,
    passed: hasIncident,
    detail: detailOf(
      hasIncident
        ? "local incident window available for bounded reproduction notes"
        : "no incident window under registered path",
    ),
    content_digest: digestOf({
      probe: "reproduction_window_probe",
      hasIncident,
    }),
  };
}

function probeLogs(targetReal: string): FollowupProbeResult {
  // Never export raw logs; only report whether a named redacted window candidate exists.
  const candidates = ["logs/redacted-window.txt", "artifacts/redacted.log"];
  let present = false;
  for (const rel of candidates) {
    if (existsNamed(targetReal, rel)) {
      present = true;
      break;
    }
  }
  return {
    probe_id: "log_redaction_probe",
    measured: true,
    passed: true,
    detail: detailOf(
      present
        ? "named redacted log candidate present (raw logs not exported)"
        : "no named redacted log candidate; inclusion deferred",
    ),
    content_digest: digestOf({ probe: "log_redaction_probe", present }),
  };
}

// ─── Positive candidate-measurement contract ───────────────────────────────

const MEASUREMENT_KEYS = [
  "schema_version",
  "candidate_version",
  "baseline_fault_reproduced",
  "candidate_fault_absent",
  "core_regressions_passed",
  "content_sha256",
] as const;

const SHA256_HEX = /^[a-f0-9]{64}$/;

export type CandidateMeasurementVerdict =
  | "positive"
  | "negative"
  | "inconclusive";

export interface CandidateMeasurementResult {
  /** positive = all three phases true; negative = valid doc with a failed phase; inconclusive = absent/malformed. */
  verdict: CandidateMeasurementVerdict;
  measured_fault_absent: boolean | null;
  measured_core_ok: boolean | null;
  baseline_fault_reproduced: boolean | null;
  candidate_version_bound: string | null;
  detail: string;
  error_code: string | null;
  probe_results: FollowupProbeResult[];
}

function exactKeys(obj: Record<string, unknown>, keys: readonly string[]): boolean {
  const got = Object.keys(obj).sort();
  const exp = [...keys].sort();
  if (got.length !== exp.length) return false;
  for (let i = 0; i < exp.length; i++) {
    if (got[i] !== exp[i]) return false;
  }
  return true;
}

function measurementIntegrityDigest(
  body: Omit<
    {
      schema_version: number;
      candidate_version: string;
      baseline_fault_reproduced: boolean;
      candidate_fault_absent: boolean;
      core_regressions_passed: boolean;
    },
    never
  >,
): string {
  return sha256Canonical({
    schema_version: body.schema_version,
    candidate_version: body.candidate_version,
    baseline_fault_reproduced: body.baseline_fault_reproduced,
    candidate_fault_absent: body.candidate_fault_absent,
    core_regressions_passed: body.core_regressions_passed,
    content_sha256: null,
  });
}

/** Build a sealed positive/negative measurement document (tests / fixtures). */
export function sealCandidateMeasurement(input: {
  candidate_version: string;
  baseline_fault_reproduced: boolean;
  candidate_fault_absent: boolean;
  core_regressions_passed: boolean;
}): {
  schema_version: 1;
  candidate_version: string;
  baseline_fault_reproduced: boolean;
  candidate_fault_absent: boolean;
  core_regressions_passed: boolean;
  content_sha256: string;
} {
  const body = {
    schema_version: CANDIDATE_MEASUREMENT_SCHEMA_VERSION as 1,
    candidate_version: input.candidate_version,
    baseline_fault_reproduced: input.baseline_fault_reproduced,
    candidate_fault_absent: input.candidate_fault_absent,
    core_regressions_passed: input.core_regressions_passed,
  };
  return {
    ...body,
    content_sha256: measurementIntegrityDigest(body),
  };
}

function inconclusive(
  detail: string,
  code: string,
  probes: FollowupProbeResult[],
): CandidateMeasurementResult {
  return {
    verdict: "inconclusive",
    measured_fault_absent: null,
    measured_core_ok: null,
    baseline_fault_reproduced: null,
    candidate_version_bound: null,
    detail: detailOf(detail),
    error_code: code,
    probe_results: probes,
  };
}

/**
 * Load and validate the positive candidate-measurement contract.
 * Fail closed on missing/malformed/symlink/TOCTOU/digest/version mismatch.
 * Never treats empty dirs or caller booleans as success.
 */
export function loadCandidateMeasurement(
  targetPath: string,
  candidate_version: string,
): CandidateMeasurementResult {
  const core = runRegisteredProbe(targetPath, "core_health_readonly");
  const repro = runRegisteredProbe(targetPath, "reproduction_window_probe");
  const probes = [core, repro];

  if (
    typeof candidate_version !== "string" ||
    candidate_version.length === 0 ||
    candidate_version.length > MAX_VERSION_LEN
  ) {
    return inconclusive(
      "Invalid candidate_version for measurement bind.",
      "INVALID_VERSION",
      probes,
    );
  }

  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch {
    return inconclusive("Isolated target refused for measurement.", "INVALID_TARGET", probes);
  }

  let meta: ReturnType<typeof resolveNamedCandidate>;
  try {
    meta = resolveNamedCandidate(targetReal, CANDIDATE_MEASUREMENT_REL);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      if (e.code === "SYMLINK_ESCAPE") {
        return inconclusive(
          "Symlinked candidate measurement refused.",
          "MEASUREMENT_SYMLINK",
          probes,
        );
      }
      if (e.code === "CANDIDATE_NOT_FOUND") {
        return inconclusive(
          "Positive candidate measurement absent; empty/marker absence is not success.",
          "MEASUREMENT_ABSENT",
          probes,
        );
      }
      return inconclusive(
        `Candidate measurement path refused: ${e.code}`,
        "MEASUREMENT_PATH",
        probes,
      );
    }
    return inconclusive("Candidate measurement path refused.", "MEASUREMENT_PATH", probes);
  }

  if (meta.size > CANDIDATE_MEASUREMENT_MAX_BYTES) {
    return inconclusive(
      "Candidate measurement exceeds size limit.",
      "MEASUREMENT_SIZE",
      probes,
    );
  }

  let buf: Buffer;
  try {
    buf = readBoundedFile(meta.real, CANDIDATE_MEASUREMENT_MAX_BYTES, meta.preOpen);
  } catch (e) {
    const code = e instanceof PathSafetyError ? e.code : "MEASUREMENT_READ";
    return inconclusive(
      `Candidate measurement unreadable: ${code}`,
      "MEASUREMENT_READ",
      probes,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(buf.toString("utf8"));
  } catch {
    return inconclusive(
      "Candidate measurement JSON malformed.",
      "MEASUREMENT_MALFORMED",
      probes,
    );
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return inconclusive(
      "Candidate measurement shape refused.",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  const o = parsed as Record<string, unknown>;
  if (!exactKeys(o, MEASUREMENT_KEYS)) {
    return inconclusive(
      "Candidate measurement keys refused (exact allowlist).",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  if (o.schema_version !== CANDIDATE_MEASUREMENT_SCHEMA_VERSION) {
    return inconclusive(
      "Candidate measurement schema_version refused.",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  if (
    typeof o.candidate_version !== "string" ||
    o.candidate_version.length === 0 ||
    o.candidate_version.length > MAX_VERSION_LEN
  ) {
    return inconclusive(
      "Candidate measurement candidate_version refused.",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  if (typeof o.baseline_fault_reproduced !== "boolean") {
    return inconclusive(
      "baseline_fault_reproduced must be boolean.",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  if (typeof o.candidate_fault_absent !== "boolean") {
    return inconclusive(
      "candidate_fault_absent must be boolean.",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  if (typeof o.core_regressions_passed !== "boolean") {
    return inconclusive(
      "core_regressions_passed must be boolean.",
      "MEASUREMENT_SCHEMA",
      probes,
    );
  }
  if (typeof o.content_sha256 !== "string" || !SHA256_HEX.test(o.content_sha256)) {
    return inconclusive(
      "content_sha256 must be 64 hex.",
      "MEASUREMENT_DIGEST",
      probes,
    );
  }

  const expected = measurementIntegrityDigest({
    schema_version: CANDIDATE_MEASUREMENT_SCHEMA_VERSION,
    candidate_version: o.candidate_version,
    baseline_fault_reproduced: o.baseline_fault_reproduced,
    candidate_fault_absent: o.candidate_fault_absent,
    core_regressions_passed: o.core_regressions_passed,
  });
  if (expected !== o.content_sha256) {
    return inconclusive(
      "Candidate measurement content_sha256 mismatch (tamper/malformed).",
      "MEASUREMENT_DIGEST",
      probes,
    );
  }

  if (o.candidate_version !== candidate_version) {
    return inconclusive(
      "Measurement candidate_version does not match requested candidate.",
      "MEASUREMENT_VERSION_MISMATCH",
      probes,
    );
  }

  // Baseline must have positively reproduced the fault; otherwise inconclusive.
  if (o.baseline_fault_reproduced !== true) {
    return inconclusive(
      "Baseline fault was not positively reproduced; cannot prove fix.",
      "MEASUREMENT_BASELINE_MISSING",
      probes,
    );
  }

  const measured_fault_absent = o.candidate_fault_absent === true;
  const measured_core_ok = o.core_regressions_passed === true;

  if (measured_fault_absent && measured_core_ok) {
    return {
      verdict: "positive",
      measured_fault_absent: true,
      measured_core_ok: true,
      baseline_fault_reproduced: true,
      candidate_version_bound: o.candidate_version,
      detail: detailOf(
        "Positive measurement: baseline reproduced, candidate fault absent, core regressions passed.",
      ),
      error_code: null,
      probe_results: probes,
    };
  }

  return {
    verdict: "negative",
    measured_fault_absent,
    measured_core_ok,
    baseline_fault_reproduced: true,
    candidate_version_bound: o.candidate_version,
    detail: detailOf(
      `Measured negative: fault_absent=${measured_fault_absent};core_ok=${measured_core_ok}`,
    ),
    error_code: null,
    probe_results: probes,
  };
}

/**
 * Measured canary probes for candidate-fix validation in a disposable target.
 * Returns independently measured flags — caller-declared values are ignored.
 * Absence/empty-dir never proves success (inconclusive).
 */
export function measureCandidateFaultAndCore(
  targetPath: string,
  candidate_version?: string,
): {
  measured_fault_absent: boolean | null;
  measured_core_ok: boolean | null;
  verdict: CandidateMeasurementVerdict;
  probe_results: FollowupProbeResult[];
  detail: string;
  error_code: string | null;
} {
  // Without a bound version, only empty-target / path checks apply → inconclusive.
  const version =
    typeof candidate_version === "string" && candidate_version.length > 0
      ? candidate_version
      : "";
  if (!version) {
    const core = (() => {
      try {
        return runRegisteredProbe(targetPath, "core_health_readonly");
      } catch {
        return {
          probe_id: "core_health_readonly" as const,
          measured: true as const,
          passed: false,
          detail: "probe failed",
          content_digest: digestOf({ error: true }),
        };
      }
    })();
    const repro = (() => {
      try {
        return runRegisteredProbe(targetPath, "reproduction_window_probe");
      } catch {
        return {
          probe_id: "reproduction_window_probe" as const,
          measured: true as const,
          passed: false,
          detail: "probe failed",
          content_digest: digestOf({ error: true }),
        };
      }
    })();
    return {
      measured_fault_absent: null,
      measured_core_ok: null,
      verdict: "inconclusive",
      probe_results: [core, repro],
      detail: "candidate_version required for positive measurement bind",
      error_code: "MEASUREMENT_VERSION_REQUIRED",
    };
  }
  const m = loadCandidateMeasurement(targetPath, version);
  return {
    measured_fault_absent: m.measured_fault_absent,
    measured_core_ok: m.measured_core_ok,
    verdict: m.verdict,
    probe_results: m.probe_results,
    detail: m.detail,
    error_code: m.error_code,
  };
}
