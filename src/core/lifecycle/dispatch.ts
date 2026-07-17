/**
 * Single dispatcher for CLI/MCP lifecycle tools.
 * Arguments are bounded JSON-ish fields — no shell, no network.
 */
import {
  applyRetention,
  assessUpdateRegression,
  lifecycleStatus,
  previewCliVersionRollback,
  previewDesktopVersionRollback,
  recordKnownGood,
  recordRepairBackup,
  recordSuccessfulStart,
  rollbackSurface,
  runCanary,
  supersedeRecipe,
} from "./engine.js";
import { isControlSurface } from "./constants.js";
import type {
  ABObservation,
  ControlSurface,
  LifecycleOperation,
  LifecycleResult,
} from "./types.js";

const OPS = new Set<LifecycleOperation>([
  "status",
  "record_repair_backup",
  "record_successful_start",
  "record_known_good",
  "apply_retention",
  "assess_update_regression",
  "rollback_surface",
  "cli_version_rollback_preview",
  "desktop_version_rollback_preview",
  "canary",
  "supersede_recipe",
]);

export function isLifecycleOperation(v: string): v is LifecycleOperation {
  return OPS.has(v as LifecycleOperation);
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function asBool(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function parseObservation(raw: unknown): ABObservation | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (o.measured !== true) return null;
  if (typeof o.fault_reproduced !== "boolean") return null;
  const version = asString(o.version);
  const mechanism_id = asString(o.mechanism_id);
  const instance_id = asString(o.instance_id);
  if (!version || !mechanism_id || !instance_id) return null;
  return {
    version,
    fault_reproduced: o.fault_reproduced,
    measured: true,
    mechanism_id,
    instance_id,
  };
}

export interface LifecycleDispatchArgs {
  target: string;
  operation: string;
  instance_id?: string;
  surface?: string;
  source_rel?: string;
  checkpoint_id?: string;
  now_ms?: number;
  timestamp_only?: boolean;
  control?: unknown;
  treatment?: unknown;
  official_source?: string;
  version_pin?: string | null;
  provenance?: string;
  signed_history_available?: boolean;
  lawful_media_available?: boolean;
  candidate_version?: string;
  original_fault_absent?: boolean;
  core_regressions_passed?: boolean;
  canary_executed?: boolean;
  recipe_id?: string;
  upstream_ref?: string;
  upstream_evidence_digest?: string;
  upstream_verified?: boolean;
}

export function dispatchLifecycle(args: LifecycleDispatchArgs): LifecycleResult {
  const op = args.operation;
  if (!isLifecycleOperation(op)) {
    return {
      schema_version: 1,
      ok: false,
      operation: "status",
      user_resolution: {
        status: "INCONCLUSIVE",
        summary: "Unknown lifecycle operation.",
        receipt_id: "lifecycle_usage",
      },
      upstream_contribution: {
        status: "NONE",
        summary: "No upstream contribution.",
        issue_candidates: [],
        receipt_id: "lifecycle_usage_up",
      },
      evidence: [],
      error_code: "UNKNOWN_OPERATION",
      error_message: "Unknown lifecycle operation.",
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      user_status: null,
      ledger: null,
      retention: null,
      regression: null,
      surface_rollback: null,
      cli_preview: null,
      desktop_preview: null,
      canary: null,
      recipe: null,
      version_guidance: null,
      contribution_claim: "none",
    };
  }

  const target = args.target;
  const nowMs = asNumber(args.now_ms);

  switch (op) {
    case "status":
      return lifecycleStatus({
        targetPath: target,
        instance_id: args.instance_id,
        nowMs,
      });
    case "record_repair_backup": {
      const instance_id = asString(args.instance_id);
      const source_rel = asString(args.source_rel);
      if (!instance_id || !source_rel) {
        return failUsage(op, "instance_id and source_rel required.");
      }
      let surface: ControlSurface | "artifact" | undefined;
      if (args.surface === "artifact") surface = "artifact";
      else if (typeof args.surface === "string" && isControlSurface(args.surface)) {
        surface = args.surface;
      }
      return recordRepairBackup({
        targetPath: target,
        instance_id,
        source_rel,
        surface,
        nowMs,
      });
    }
    case "record_successful_start": {
      const instance_id = asString(args.instance_id) ?? "default";
      return recordSuccessfulStart({ targetPath: target, instance_id, nowMs });
    }
    case "record_known_good": {
      const instance_id = asString(args.instance_id);
      const surface = asString(args.surface);
      if (!instance_id || !surface || !isControlSurface(surface)) {
        return failUsage(op, "instance_id and valid surface required.");
      }
      return recordKnownGood({
        targetPath: target,
        instance_id,
        surface,
        nowMs,
      });
    }
    case "apply_retention": {
      const instance_id = asString(args.instance_id) ?? "default";
      return applyRetention({ targetPath: target, instance_id, nowMs });
    }
    case "assess_update_regression": {
      const control = parseObservation(args.control);
      const treatment = parseObservation(args.treatment);
      if (!control || !treatment) {
        return failUsage(op, "control and treatment measured observations required.");
      }
      return assessUpdateRegression({
        targetPath: target,
        control,
        treatment,
        timestamp_only: args.timestamp_only === true,
        nowMs,
      });
    }
    case "rollback_surface": {
      const instance_id = asString(args.instance_id);
      const surface = asString(args.surface);
      const checkpoint_id = asString(args.checkpoint_id);
      if (!instance_id || !surface || !isControlSurface(surface) || !checkpoint_id) {
        return failUsage(op, "instance_id, surface, checkpoint_id required.");
      }
      return rollbackSurface({
        targetPath: target,
        instance_id,
        surface,
        checkpoint_id,
        nowMs,
      });
    }
    case "cli_version_rollback_preview": {
      // Pass raw strings; engine applies exact allowlist validation (no cast).
      const official_source = asString(args.official_source) ?? "absent";
      const provenance = asString(args.provenance) ?? "absent";
      return previewCliVersionRollback({
        targetPath: target,
        official_source,
        version_pin: args.version_pin ?? null,
        provenance,
        nowMs,
      });
    }
    case "desktop_version_rollback_preview":
      return previewDesktopVersionRollback({
        targetPath: target,
        signed_history_available: args.signed_history_available === true,
        lawful_media_available: args.lawful_media_available === true,
        nowMs,
      });
    case "canary": {
      const candidate_version = asString(args.candidate_version);
      const original_fault_absent = asBool(args.original_fault_absent);
      const core_regressions_passed = asBool(args.core_regressions_passed);
      if (
        !candidate_version ||
        original_fault_absent === null ||
        core_regressions_passed === null
      ) {
        return failUsage(
          op,
          "candidate_version, original_fault_absent, core_regressions_passed required.",
        );
      }
      return runCanary({
        targetPath: target,
        candidate_version,
        original_fault_absent,
        core_regressions_passed,
        canary_executed: args.canary_executed,
        nowMs,
      });
    }
    case "supersede_recipe": {
      const recipe_id = asString(args.recipe_id);
      const upstream_ref = asString(args.upstream_ref);
      const upstream_evidence_digest = asString(args.upstream_evidence_digest);
      if (!recipe_id || !upstream_ref || !upstream_evidence_digest) {
        return failUsage(op, "recipe_id and verified upstream evidence required.");
      }
      return supersedeRecipe({
        targetPath: target,
        recipe_id,
        upstream: {
          ref: upstream_ref,
          evidence_digest: upstream_evidence_digest,
          verified: args.upstream_verified === true,
        },
        nowMs,
      });
    }
    default:
      return failUsage("status", "Unknown lifecycle operation.");
  }
}

function failUsage(operation: LifecycleOperation, message: string): LifecycleResult {
  return {
    schema_version: 1,
    ok: false,
    operation,
    user_resolution: {
      status: "INCONCLUSIVE",
      summary: message,
      receipt_id: "lifecycle_usage",
    },
    upstream_contribution: {
      status: "NONE",
      summary: "No upstream contribution.",
      issue_candidates: [],
      receipt_id: "lifecycle_usage_up",
    },
    evidence: [],
    error_code: "USAGE",
    error_message: message,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    user_status: null,
    ledger: null,
    retention: null,
    regression: null,
    surface_rollback: null,
    cli_preview: null,
    desktop_preview: null,
    canary: null,
    recipe: null,
    version_guidance: null,
    contribution_claim: "none",
  };
}
