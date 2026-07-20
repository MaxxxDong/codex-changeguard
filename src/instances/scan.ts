/**
 * Shared multi-instance scan core used by CLI, MCP, and SessionStart.
 * Single decision path — no duplicate transition logic at the edges.
 *
 * Version identity and local artifact baselines are separate axes.
 * fingerprint_changed when either overall identity fingerprint or
 * overall artifact baseline digest changes.
 */
import path from "node:path";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import { runReadOnlyHealthCheck } from "../hooks/health-check.js";
import {
  classifyLocalArtifactDiff,
  unavailableLocalArtifactDiff,
} from "./artifact-diff.js";
import {
  measureInstanceArtifactBaselines,
  overallArtifactDigest,
} from "./artifacts.js";
import { classifyTransitions } from "./compare.js";
import { loadInventory, InventoryError } from "./enumerate.js";
import {
  assignPathAliases,
  overallFingerprintOf,
  toIdentity,
} from "./identity.js";
import { DEFAULT_SESSION_START_ARTIFACT_TIME_BUDGET_MS } from "./limits.js";
import { resolveAffectedInstance } from "./resolve.js";
import {
  loadState,
  priorArtifactBaselinesOrNull,
  saveState,
  StateError,
} from "./state.js";
import { buildCapabilityReport } from "../platform/capability.js";
import type { AdapterId } from "../platform/types.js";
import { enumerateSystemCandidates } from "./system-adapter.js";
import type {
  DiscoveredCandidate,
  HookTrustState,
  InstanceIdentity,
  LocalArtifactDiff,
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
    local_artifact_diff: unavailableLocalArtifactDiff(),
  };
}

function buildIdentities(opts: ScanOptions): {
  instances: InstanceIdentity[];
  observed: ScanOptions["observed"];
  candidates: DiscoveredCandidate[];
} {
  if (opts.candidates && opts.candidates.length > 0) {
    const candidates = opts.candidates;
    const raw = candidates.map((c) => {
      const ev = readVersionEvidence(c, opts.inventoryRoot);
      return toIdentity(c, ev.version, ev.build, ev.provenance);
    });
    return {
      instances: assignPathAliases(raw),
      observed: opts.observed,
      candidates,
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
      candidates,
    };
  }

  if (typeof opts.inventoryRoot !== "string" || opts.inventoryRoot.length === 0) {
    throw new InventoryError("INVALID_ROOT", "Invalid inventory root.");
  }
  const inv = loadInventory(opts.inventoryRoot);
  const candidates = inv.candidates;
  const raw = candidates.map((c) => {
    const ev = readVersionEvidence(c, opts.inventoryRoot);
    return toIdentity(c, ev.version, ev.build, ev.provenance);
  });
  return {
    instances: assignPathAliases(raw),
    observed: opts.observed ?? inv.observed,
    candidates,
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
 * Deterministic multi-instance scan + fingerprint compare + artifact baseline
 * + optional health check.
 */
export function scanInstances(opts: ScanOptions): ScanResult {
  const mode = opts.mode ?? "manual_scan";
  const hookStatus: HookTrustState | null =
    mode === "session_start" ? (opts.hookTrust ?? "trusted") : null;

  try {
    const stateDir = resolveStateDir(opts);
    const { instances, observed, candidates } = buildIdentities(opts);
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

    // SessionStart: default ~4s wall-clock artifact budget (injectable for tests).
    // Manual scan: no wall-clock cap unless caller injects artifactTimeBudgetMs.
    const timeBudgetMs =
      typeof opts.artifactTimeBudgetMs === "number"
        ? opts.artifactTimeBudgetMs
        : mode === "session_start"
          ? DEFAULT_SESSION_START_ARTIFACT_TIME_BUDGET_MS
          : undefined;
    const currentBaselines = measureInstanceArtifactBaselines(
      instances,
      candidates,
      {
        inventoryRoot: opts.inventoryRoot,
        timeBudgetMs,
        nowMs: opts.artifactNowMs,
      },
    );
    const currentArtifactDigest = overallArtifactDigest(currentBaselines);
    const priorArtifacts = priorArtifactBaselinesOrNull(previous);
    const local_artifact_diff: LocalArtifactDiff = classifyLocalArtifactDiff(
      priorArtifacts,
      currentBaselines,
    );

    const identityChanged =
      previous === null || previous.overall_fingerprint !== overall;
    // Derive artifact axis from validated local diff + recomputed digests so
    // public fields cannot contradict each other (e.g. fingerprint_changed=false
    // while local_artifact_diff.status=content_changed).
    const priorArtifactDigest =
      priorArtifacts === null ? null : overallArtifactDigest(priorArtifacts);
    // Incomplete wall-clock measurement (time_budget_exceeded on current) must
    // never look like silent equality even when digests match prior gaps.
    const currentTimeBudgetIncomplete = currentBaselines.some((b) =>
      b.entries.some((e) => e.status === "time_budget_exceeded"),
    );
    const artifactChanged =
      priorArtifacts === null
        ? // No prior baseline history (v1 / first scan): establish is a change.
          true
        : priorArtifactDigest !== currentArtifactDigest ||
          local_artifact_diff.status === "content_changed" ||
          local_artifact_diff.status === "partial" ||
          currentTimeBudgetIncomplete;
    const fingerprint_changed = identityChanged || artifactChanged;

    const affected = resolveAffectedInstance(instances, observed);
    const platform_capability = capabilityBlockForScan(opts, instances);

    // SessionStart: silent when both identity and artifact baselines unchanged.
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
        local_artifact_diff,
        platform_capability,
      };
    }

    let health_check = null;
    // Health only when identity axis changed (artifact-only baseline establish
    // remains a light notice without re-running health).
    if (mode === "session_start" && identityChanged) {
      health_check = runReadOnlyHealthCheck(instances, {
        budgetMs: opts.healthBudgetMs ?? 10_000,
      });
    } else if (mode === "manual_scan" && identityChanged) {
      health_check = runReadOnlyHealthCheck(instances, {
        budgetMs: opts.healthBudgetMs ?? 10_000,
      });
    }

    let state_updated = false;
    const persist = opts.persistState !== false;
    if (persist && fingerprint_changed) {
      const now = opts.now?.() ?? new Date();
      const next: VersionFingerprintState = {
        schema_version: 2,
        updated_at: now.toISOString(),
        overall_fingerprint: overall,
        instances,
        artifact_baselines: currentBaselines,
        overall_artifact_digest: currentArtifactDigest,
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
      local_artifact_diff,
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
