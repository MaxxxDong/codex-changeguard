/**
 * Shared multi-instance scan core used by CLI, MCP, and SessionStart.
 * Single decision path — no duplicate transition logic at the edges.
 */
import path from "node:path";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import { runReadOnlyHealthCheck } from "../hooks/health-check.js";
import { classifyTransitions } from "./compare.js";
import { loadInventory, InventoryError } from "./enumerate.js";
import {
  assignPathAliases,
  overallFingerprintOf,
  toIdentity,
} from "./identity.js";
import { resolveAffectedInstance } from "./resolve.js";
import { loadState, saveState, StateError } from "./state.js";
import { buildCapabilityReport } from "../platform/capability.js";
import type { AdapterId } from "../platform/types.js";
import { enumerateSystemCandidates } from "./system-adapter.js";
import type {
  HookTrustState,
  InstanceIdentity,
  PlatformId,
  ScanOptions,
  ScanResult,
  VersionFingerprintState,
} from "./types.js";
import { readVersionEvidence } from "./version-evidence.js";

function capabilityBlockForScan(
  opts: ScanOptions,
  instances: InstanceIdentity[],
): ScanResult["platform_capability"] {
  if (opts.enumeration !== "system_registered") return null;
  const platform: PlatformId =
    opts.systemCaps?.platform ??
    instances[0]?.platform ??
    opts.platform ??
    "unknown";
  const adapter = (platform === "unknown" ? "unknown" : platform) as AdapterId;
  const report = buildCapabilityReport({ adapter });
  return {
    schema_version: 1,
    adapter: report.adapter,
    status: report.status,
    writes_enabled: report.writes_enabled,
    full_support_claimed: false,
    gaps: report.gaps.map((g) => ({
      id: g.id,
      summary: g.summary,
      status: g.status,
    })),
  };
}

function fail(
  partial: Partial<ScanResult> &
    Pick<ScanResult, "mode" | "hook_status" | "error_code" | "error_message">,
): ScanResult {
  return {
    schema_version: 1,
    ok: false,
    mode: partial.mode,
    fingerprint_changed: false,
    overall_fingerprint: "",
    previous_fingerprint: null,
    primary_transition: "unchanged",
    transitions: [],
    instances: [],
    affected_instance_id: null,
    affected_resolution: "none",
    affected_resolution_reason: "no_instances",
    hook_status: partial.hook_status,
    health_check: null,
    silent: false,
    state_updated: false,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: partial.error_code,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
  };
}

function buildIdentities(opts: ScanOptions): {
  instances: InstanceIdentity[];
  observed: ScanOptions["observed"];
} {
  if (opts.candidates && opts.candidates.length > 0) {
    const raw = opts.candidates.map((c) => {
      const ev = readVersionEvidence(c, opts.inventoryRoot);
      return toIdentity(c, ev.version, ev.build, ev.provenance);
    });
    return {
      instances: assignPathAliases(raw),
      observed: opts.observed,
    };
  }

  const enumeration = opts.enumeration ?? "fixture_inventory";

  if (enumeration === "system_registered") {
    const candidates = enumerateSystemCandidates(opts.systemCaps ?? {});
    const raw = candidates.map((c) => {
      const ev = readVersionEvidence(c, opts.inventoryRoot);
      return toIdentity(c, ev.version, ev.build, ev.provenance);
    });
    return {
      instances: assignPathAliases(raw),
      observed: opts.observed,
    };
  }

  if (typeof opts.inventoryRoot !== "string" || opts.inventoryRoot.length === 0) {
    throw new InventoryError("INVALID_ROOT", "Invalid inventory root.");
  }
  const inv = loadInventory(opts.inventoryRoot);
  const raw = inv.candidates.map((c) => {
    const ev = readVersionEvidence(c, opts.inventoryRoot);
    return toIdentity(c, ev.version, ev.build, ev.provenance);
  });
  return {
    instances: assignPathAliases(raw),
    observed: opts.observed ?? inv.observed,
  };
}

function resolveStateDir(opts: ScanOptions): string {
  if (opts.stateDir && opts.stateDir.length > 0) return opts.stateDir;
  if (opts.inventoryRoot && opts.inventoryRoot.length > 0) {
    return path.join(opts.inventoryRoot, "state");
  }
  throw new StateError("INVALID_STATE", "State directory required.");
}

/**
 * Deterministic multi-instance scan + fingerprint compare + optional health check.
 */
export function scanInstances(opts: ScanOptions): ScanResult {
  const mode = opts.mode ?? "manual_scan";
  const hookStatus: HookTrustState | null =
    mode === "session_start" ? (opts.hookTrust ?? "trusted") : null;

  try {
    const stateDir = resolveStateDir(opts);
    const { instances, observed } = buildIdentities(opts);
    const overall = overallFingerprintOf(instances);

    let previous: VersionFingerprintState | null = null;
    try {
      previous = loadState(stateDir);
    } catch (e) {
      if (e instanceof StateError && e.code === "NOT_FOUND") {
        previous = null;
      } else if (e instanceof StateError) {
        return fail({
          mode,
          hook_status: hookStatus,
          error_code: e.code,
          error_message: e.message,
        });
      } else {
        throw e;
      }
    }

    const { primary, transitions } = classifyTransitions(
      previous ? previous.instances : null,
      instances,
    );
    const fingerprint_changed =
      previous === null || previous.overall_fingerprint !== overall;

    const affected = resolveAffectedInstance(instances, observed);

    const platform_capability = capabilityBlockForScan(opts, instances);

    // SessionStart: silent when unchanged.
    if (mode === "session_start" && !fingerprint_changed) {
      return {
        schema_version: 1,
        ok: true,
        mode,
        fingerprint_changed: false,
        overall_fingerprint: overall,
        previous_fingerprint: previous?.overall_fingerprint ?? null,
        primary_transition: "unchanged",
        transitions,
        instances,
        affected_instance_id: affected.instance_id,
        affected_resolution: affected.resolution,
        affected_resolution_reason: affected.reason,
        hook_status: hookStatus,
        health_check: null,
        silent: true,
        state_updated: false,
        network_used: false,
        target_mutated: false,
        repair_applied: false,
        error_code: null,
        error_message: null,
        platform_capability,
      };
    }

    let health_check = null;
    if (mode === "session_start" && fingerprint_changed) {
      health_check = runReadOnlyHealthCheck(instances, {
        budgetMs: opts.healthBudgetMs ?? 10_000,
      });
    } else if (mode === "manual_scan" && fingerprint_changed) {
      // Manual scan remains equivalent: optional lightweight health summary.
      health_check = runReadOnlyHealthCheck(instances, {
        budgetMs: opts.healthBudgetMs ?? 10_000,
      });
    }

    let state_updated = false;
    const persist = opts.persistState !== false;
    if (persist && fingerprint_changed) {
      const now = opts.now?.() ?? new Date();
      const next: VersionFingerprintState = {
        schema_version: 1,
        updated_at: now.toISOString(),
        overall_fingerprint: overall,
        instances,
      };
      saveState(stateDir, next);
      state_updated = true;
    }

    return {
      schema_version: 1,
      ok: true,
      mode,
      fingerprint_changed,
      overall_fingerprint: overall,
      previous_fingerprint: previous?.overall_fingerprint ?? null,
      primary_transition: primary,
      transitions,
      instances,
      affected_instance_id: affected.instance_id,
      affected_resolution: affected.resolution,
      affected_resolution_reason: affected.reason,
      hook_status: hookStatus,
      health_check,
      silent: false,
      state_updated,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      error_code: null,
      error_message: null,
      platform_capability,
    };
  } catch (e) {
    if (e instanceof InventoryError || e instanceof StateError) {
      return fail({
        mode,
        hook_status: hookStatus,
        error_code: e.code,
        error_message: e.message,
      });
    }
    return fail({
      mode,
      hook_status: hookStatus,
      error_code: "INTERNAL",
      error_message: "Scan failed.",
    });
  }
}
