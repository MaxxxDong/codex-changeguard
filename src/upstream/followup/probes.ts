/**
 * Registered bounded probes for follow-up evidence.
 * Only allowlisted probe ids; never arbitrary paths or shell.
 *
 * Candidate validation authority is the process-local registered live
 * measurement runner (Ticket 12) — never persisted self-attestation JSON.
 * canary/candidate-measurement.json, if present, is treated as deprecated
 * and always inconclusive for upgrade/supersession.
 */
import fs from "node:fs";
import path from "node:path";
import {
  resolveTargetDirectory,
  resolveNamedCandidate,
  PathSafetyError,
} from "../../core/path-safety.js";
import { sha256Text } from "../../evidence/canonical.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import type { FollowupProbeResult, RegisteredProbeId } from "./types.js";
import {
  CANDIDATE_MEASUREMENT_REL,
  MAX_STRING,
  MAX_VERSION_LEN,
} from "./limits.js";
import {
  PROTECTED_PROCESS_SHIM_PROFILE_V1,
  runRegisteredLiveMeasurement,
  type LiveMeasurementWitness,
  type RegisteredLiveMeasurementResult,
} from "../../core/lifecycle/live-measurement.js";

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

// ─── Candidate measurement (live registered profile only) ──────────────────

export type CandidateMeasurementVerdict =
  | "positive"
  | "negative"
  | "inconclusive";

export interface CandidateMeasurementResult {
  /** positive = live registered probes all pass; negative = measured fail; inconclusive = refuse. */
  verdict: CandidateMeasurementVerdict;
  measured_fault_absent: boolean | null;
  measured_core_ok: boolean | null;
  baseline_fault_reproduced: boolean | null;
  candidate_version_bound: string | null;
  profile_id: string | null;
  /** Process-local witness; never serializable authority. */
  witness: LiveMeasurementWitness | null;
  public_digests: RegisteredLiveMeasurementResult["public_digests"] | null;
  detail: string;
  error_code: string | null;
  probe_results: FollowupProbeResult[];
}

/**
 * Legacy self-attestation path is permanently deprecated.
 * Even a well-formed, self-consistent all-true JSON never grants a positive
 * verdict — content hash proves integrity only, not measurement authority.
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
    return {
      verdict: "inconclusive",
      measured_fault_absent: null,
      measured_core_ok: null,
      baseline_fault_reproduced: null,
      candidate_version_bound: null,
      profile_id: null,
      witness: null,
      public_digests: null,
      detail: detailOf("Invalid candidate_version for measurement bind."),
      error_code: "INVALID_VERSION",
      probe_results: probes,
    };
  }

  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch {
    return {
      verdict: "inconclusive",
      measured_fault_absent: null,
      measured_core_ok: null,
      baseline_fault_reproduced: null,
      candidate_version_bound: null,
      profile_id: null,
      witness: null,
      public_digests: null,
      detail: detailOf("Isolated target refused for measurement."),
      error_code: "INVALID_TARGET",
      probe_results: probes,
    };
  }

  // If a legacy file exists, explicitly refuse it as authority (adversarial coverage).
  try {
    resolveNamedCandidate(targetReal, CANDIDATE_MEASUREMENT_REL);
    return {
      verdict: "inconclusive",
      measured_fault_absent: null,
      measured_core_ok: null,
      baseline_fault_reproduced: null,
      candidate_version_bound: null,
      profile_id: null,
      witness: null,
      public_digests: null,
      detail: detailOf(
        "Legacy candidate-measurement.json is deprecated and never authorizes upgrade/supersession (self-attestation is not measurement authority).",
      ),
      error_code: "MEASUREMENT_SELF_ATTESTATION_DEPRECATED",
      probe_results: probes,
    };
  } catch (e) {
    if (e instanceof PathSafetyError && e.code === "SYMLINK_ESCAPE") {
      return {
        verdict: "inconclusive",
        measured_fault_absent: null,
        measured_core_ok: null,
        baseline_fault_reproduced: null,
        candidate_version_bound: null,
        profile_id: null,
        witness: null,
        public_digests: null,
        detail: detailOf("Symlinked candidate measurement refused."),
        error_code: "MEASUREMENT_SYMLINK",
        probe_results: probes,
      };
    }
    // Absent or other path refusal → still not authority; direct live profile required.
  }

  return {
    verdict: "inconclusive",
    measured_fault_absent: null,
    measured_core_ok: null,
    baseline_fault_reproduced: null,
    candidate_version_bound: null,
    profile_id: null,
    witness: null,
    public_digests: null,
    detail: detailOf(
      "Persisted candidate measurement never authorizes upgrade; use registered live profile measurement.",
    ),
    error_code: "MEASUREMENT_AUTHORITY_REQUIRED",
    probe_results: probes,
  };
}

/**
 * Run the closed registered live measurement profile (Phase A:
 * protected_process_shim_v1). Only this path may mint a process-local witness.
 */
export function measureWithRegisteredProfile(input: {
  targetPath: string;
  baselineTargetPath: string;
  candidate_version: string;
  profile_id: string;
  nowMs?: number;
}): CandidateMeasurementResult {
  const infoProbes: FollowupProbeResult[] = [];
  try {
    infoProbes.push(
      runRegisteredProbe(input.targetPath, "core_health_readonly"),
    );
  } catch {
    /* ignore — live runner has its own path checks */
  }

  const live = runRegisteredLiveMeasurement({
    targetPath: input.targetPath,
    baselineTargetPath: input.baselineTargetPath,
    candidate_version: input.candidate_version,
    profile_id: input.profile_id,
    nowMs: input.nowMs,
  });

  // Map ordered probe digests into FollowupProbeResult-shaped public evidence
  // (no absolute roots; digests only).
  const mappedProbes: FollowupProbeResult[] = live.public_digests.probe_digests.map(
    (d, i) => ({
      probe_id: "core_health_readonly" as RegisteredProbeId,
      measured: true as const,
      passed:
        live.verdict === "positive"
          ? true
          : live.verdict === "negative"
            ? i === 0
            : false,
      detail: detailOf(
        `registered_live_probe[${i}];digest=${d.slice(0, 12)}…;scope=artifact_level_disposable_pair`,
      ),
      content_digest: d,
    }),
  );

  return {
    verdict: live.verdict,
    measured_fault_absent: live.measured_fault_absent,
    measured_core_ok: live.measured_core_ok,
    baseline_fault_reproduced: live.baseline_fault_reproduced,
    candidate_version_bound:
      live.verdict === "inconclusive" ? null : live.candidate_version,
    profile_id: live.profile_id,
    witness: live.witness,
    public_digests: live.public_digests,
    detail: detailOf(live.detail),
    error_code: live.error_code,
    probe_results: mappedProbes.length > 0 ? mappedProbes : infoProbes,
  };
}

/**
 * Measured canary probes for candidate-fix validation.
 * Without baseline + profile, always inconclusive (no self-attestation path).
 */
export function measureCandidateFaultAndCore(
  targetPath: string,
  candidate_version?: string,
  opts?: {
    baselineTargetPath?: string;
    profile_id?: string;
    nowMs?: number;
  },
): {
  measured_fault_absent: boolean | null;
  measured_core_ok: boolean | null;
  verdict: CandidateMeasurementVerdict;
  probe_results: FollowupProbeResult[];
  detail: string;
  error_code: string | null;
  witness: LiveMeasurementWitness | null;
} {
  const version =
    typeof candidate_version === "string" && candidate_version.length > 0
      ? candidate_version
      : "";
  if (
    !version ||
    !opts?.baselineTargetPath ||
    !opts?.profile_id
  ) {
    const m = loadCandidateMeasurement(targetPath, version || "missing");
    return {
      measured_fault_absent: m.measured_fault_absent,
      measured_core_ok: m.measured_core_ok,
      verdict: "inconclusive",
      probe_results: m.probe_results,
      detail:
        "Registered live measurement requires baselineTargetPath + measurement_profile_id + candidate_version.",
      error_code: "MEASUREMENT_AUTHORITY_REQUIRED",
      witness: null,
    };
  }
  const m = measureWithRegisteredProfile({
    targetPath,
    baselineTargetPath: opts.baselineTargetPath,
    candidate_version: version,
    profile_id: opts.profile_id,
    nowMs: opts.nowMs,
  });
  return {
    measured_fault_absent: m.measured_fault_absent,
    measured_core_ok: m.measured_core_ok,
    verdict: m.verdict,
    probe_results: m.probe_results,
    detail: m.detail,
    error_code: m.error_code,
    witness: m.witness,
  };
}

export { PROTECTED_PROCESS_SHIM_PROFILE_V1 };
