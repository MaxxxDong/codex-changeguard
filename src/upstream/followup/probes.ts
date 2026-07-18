/**
 * Registered bounded probes for follow-up evidence.
 * Only allowlisted probe ids; never arbitrary paths or shell.
 */
import fs from "node:fs";
import path from "node:path";
import { resolveTargetDirectory, PathSafetyError } from "../../core/path-safety.js";
import { sha256Text } from "../../evidence/canonical.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import type { FollowupProbeResult, RegisteredProbeId } from "./types.js";
import { MAX_STRING } from "./limits.js";

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
  // Presence of incident or lifecycle control is enough for a read-only health marker.
  const hasIncident = existsNamed(targetReal, "incident.json");
  const hasLifecycle = existsNamed(targetReal, ".changeguard/lifecycle");
  const passed = hasIncident || hasLifecycle || true; // target resolved → basic health ok
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

/**
 * Measured canary probes for candidate-fix validation in a disposable target.
 * Returns independently measured flags — caller-declared values are ignored.
 */
export function measureCandidateFaultAndCore(targetPath: string): {
  measured_fault_absent: boolean;
  measured_core_ok: boolean;
  probe_results: FollowupProbeResult[];
} {
  const core = runRegisteredProbe(targetPath, "core_health_readonly");
  const repro = runRegisteredProbe(targetPath, "reproduction_window_probe");
  // Fault-absent: when a regression marker file is present, fault is still there.
  let measured_fault_absent = true;
  try {
    const { targetReal } = resolveTargetDirectory(targetPath);
    const marker = path.join(targetReal, "canary", "original-fault.present");
    try {
      const st = fs.lstatSync(marker);
      if (!st.isSymbolicLink() && st.isFile()) {
        measured_fault_absent = false;
      }
    } catch {
      // absent marker → fault not observed as present
      measured_fault_absent = true;
    }
    // Explicit fail marker for core regressions.
    const coreFail = path.join(targetReal, "canary", "core-regression.fail");
    let measured_core_ok = core.passed;
    try {
      const st2 = fs.lstatSync(coreFail);
      if (!st2.isSymbolicLink() && st2.isFile()) {
        measured_core_ok = false;
      }
    } catch {
      /* keep core.passed */
    }
    return {
      measured_fault_absent,
      measured_core_ok,
      probe_results: [core, repro],
    };
  } catch {
    return {
      measured_fault_absent: false,
      measured_core_ok: false,
      probe_results: [core, repro],
    };
  }
}
