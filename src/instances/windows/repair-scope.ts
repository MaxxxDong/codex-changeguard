/**
 * Windows user-owned repair scope binding (Ticket 14).
 * Binds exact instance identity and reuses Ticket 02 engine semantics;
 * does not implement mutation itself.
 */
import type { InstanceIdentity } from "../types.js";
import { bindRepairTarget } from "../repair-binding.js";
import type { RepairTargetRequest } from "../types.js";
import {
  classifyWriteTarget,
  writeScopeToErrorCode,
} from "./policy.js";
import type { WindowsWriteClassification } from "./types.js";

export interface WindowsRepairScopeRequest {
  instances: InstanceIdentity[];
  /** Exact instance binding (required when multi-instance). */
  repair: RepairTargetRequest;
  /** Absolute path of the repair target (in-memory / isolated fixture). */
  targetAbs: string;
  target_path_alias: string;
  userOwnedRoots?: string[];
  managed?: {
    policy_class: string;
    admin_owned: boolean;
    signed: boolean;
    permission_bound: boolean;
  };
  affected_resolution?: "identified" | "ambiguous" | "none";
  affected_instance_id?: string | null;
}

export interface WindowsRepairScopeResult {
  ok: boolean;
  classification: WindowsWriteClassification;
  bound_instance: InstanceIdentity | null;
  error_code: string | null;
  error_message: string | null;
  /**
   * When ok, caller may proceed to Ticket 02 preview/apply against the
   * isolated target. This module never mutates.
   */
  repair_authorized_eligible: boolean;
}

/**
 * Bind repair to exactly one observed instance and classify write scope.
 * Admin/managed/forbidden → ADMIN_ACTION_REQUIRED language, no elevation.
 */
export function resolveWindowsRepairScope(
  req: WindowsRepairScopeRequest,
): WindowsRepairScopeResult {
  const binding = bindRepairTarget(req.instances, req.repair, {
    affected_resolution: req.affected_resolution,
    affected_instance_id: req.affected_instance_id,
  });

  if (!binding.ok || !binding.instance) {
    const classification = classifyWriteTarget({
      absPath: req.targetAbs,
      target_path_alias: req.target_path_alias,
      userOwnedRoots: req.userOwnedRoots,
      managed: req.managed,
      bound_instance_id: null,
    });
    return {
      ok: false,
      classification,
      bound_instance: null,
      error_code: binding.error_code ?? "AMBIGUOUS_TARGET",
      error_message:
        binding.error_message ??
        "Repair target must bind exactly one instance.",
      repair_authorized_eligible: false,
    };
  }

  const classification = classifyWriteTarget({
    absPath: req.targetAbs,
    target_path_alias: req.target_path_alias,
    userOwnedRoots: req.userOwnedRoots,
    managed: req.managed,
    bound_instance_id: binding.instance.instance_id,
  });

  const scopeCode = writeScopeToErrorCode(classification.scope);
  if (scopeCode) {
    return {
      ok: false,
      classification,
      bound_instance: binding.instance,
      error_code: scopeCode,
      error_message:
        classification.scope === "forbidden_system" ||
        classification.scope === "admin_required"
          ? "Target requires administrator/IT action; local mutation refused."
          : "Repair refused for unclear ownership.",
      repair_authorized_eligible: false,
    };
  }

  if (classification.scope !== "user_owned") {
    return {
      ok: false,
      classification,
      bound_instance: binding.instance,
      error_code: "REPAIR_REFUSED",
      error_message: "Target is not a user-owned repair path.",
      repair_authorized_eligible: false,
    };
  }

  return {
    ok: true,
    classification,
    bound_instance: binding.instance,
    error_code: null,
    error_message: null,
    repair_authorized_eligible: true,
  };
}
