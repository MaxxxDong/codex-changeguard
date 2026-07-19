/**
 * Trusted SessionStart path: run only when overall fingerprint changed.
 * Untrusted / skipped / failed hook states are explicit; manual scan remains equivalent.
 */
import { scanInstances } from "../instances/scan.js";
import type {
  HookTrustState,
  ScanOptions,
  ScanResult,
} from "../instances/types.js";

export interface SessionStartOptions
  extends Omit<ScanOptions, "mode" | "hookTrust"> {
  hookTrust: HookTrustState;
  /** Simulate hook runtime failure after trust is established. */
  forceFailure?: boolean;
}

/**
 * SessionStart entry used by hooks and tests.
 * - untrusted / skipped: explicit status, no state mutation, points at manual scan
 * - failed: explicit status
 * - trusted + unchanged: silent success
 * - trusted + changed: bounded read-only health check via shared scan core
 */
export function runSessionStart(opts: SessionStartOptions): ScanResult {
  const { hookTrust, forceFailure, ...rest } = opts;

  if (hookTrust === "untrusted" || hookTrust === "skipped") {
    return {
      schema_version: 1,
      ok: false,
      mode: "session_start",
      fingerprint_changed: false,
      overall_fingerprint: "",
      previous_fingerprint: null,
      primary_transition: "unchanged",
      transitions: [],
      instances: [],
      affected_instance_id: null,
      affected_resolution: "none",
      affected_resolution_reason: "no_instances",
      hook_status: hookTrust,
      health_check: null,
      silent: false,
      state_updated: false,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      error_code: hookTrust === "untrusted" ? "HOOK_UNTRUSTED" : "HOOK_SKIPPED",
      error_message:
        hookTrust === "untrusted"
          ? "SessionStart hook is untrusted; use manual scan."
          : "SessionStart hook skipped; use manual scan.",
    };
  }

  if (hookTrust === "failed" || forceFailure) {
    return {
      schema_version: 1,
      ok: false,
      mode: "session_start",
      fingerprint_changed: false,
      overall_fingerprint: "",
      previous_fingerprint: null,
      primary_transition: "unchanged",
      transitions: [],
      instances: [],
      affected_instance_id: null,
      affected_resolution: "none",
      affected_resolution_reason: "no_instances",
      hook_status: "failed",
      health_check: null,
      silent: false,
      state_updated: false,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      error_code: "HOOK_FAILED",
      error_message: "SessionStart hook failed; use manual scan.",
    };
  }

  // trusted
  return scanInstances({
    ...rest,
    mode: "session_start",
    hookTrust: "trusted",
  });
}
