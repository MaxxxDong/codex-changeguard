/**
 * Repair-target binding contract (Ticket 03 ↔ Ticket 02 interface).
 * Accepts exactly one observed instance id/fingerprint.
 * Refuses broadcast and ambiguous targets. Does not implement mutation.
 */
import { instanceFingerprintOf } from "./identity.js";
import type {
  InstanceIdentity,
  RepairTargetBinding,
  RepairTargetRequest,
} from "./types.js";

export function bindRepairTarget(
  observedInstances: InstanceIdentity[],
  request: RepairTargetRequest,
  options?: {
    /** When the scan could not identify a single affected instance. */
    affected_resolution?: "identified" | "ambiguous" | "none";
    affected_instance_id?: string | null;
  },
): RepairTargetBinding {
  if (request.broadcast === true) {
    return {
      ok: false,
      instance: null,
      error_code: "BROADCAST_REFUSED",
      error_message: "Repair target broadcast is refused.",
    };
  }
  if (Array.isArray(request.instance_ids) && request.instance_ids.length > 0) {
    if (request.instance_ids.length !== 1) {
      return {
        ok: false,
        instance: null,
        error_code: "BROADCAST_REFUSED",
        error_message: "Repair target must be exactly one instance.",
      };
    }
  }

  const requestedId =
    request.instance_id ??
    (Array.isArray(request.instance_ids) && request.instance_ids.length === 1
      ? request.instance_ids[0]
      : null);

  if (!requestedId) {
    // May bind the sole observed instance only when resolution is identified
    // or there is exactly one instance.
    if (
      options?.affected_resolution === "ambiguous" ||
      options?.affected_resolution === "none"
    ) {
      return {
        ok: false,
        instance: null,
        error_code: "AMBIGUOUS_TARGET",
        error_message: "Affected instance is ambiguous; refuse repair binding.",
      };
    }
    if (options?.affected_instance_id) {
      const hit = observedInstances.find(
        (i) => i.instance_id === options.affected_instance_id,
      );
      if (!hit) {
        return {
          ok: false,
          instance: null,
          error_code: "NOT_FOUND",
          error_message: "Repair target instance not observed.",
        };
      }
      return corroborate(hit, request.instance_fingerprint);
    }
    if (observedInstances.length === 1) {
      return corroborate(observedInstances[0]!, request.instance_fingerprint);
    }
    return {
      ok: false,
      instance: null,
      error_code: "AMBIGUOUS_TARGET",
      error_message: "Repair target requires exactly one instance id.",
    };
  }

  const matches = observedInstances.filter((i) => i.instance_id === requestedId);
  if (matches.length === 0) {
    return {
      ok: false,
      instance: null,
      error_code: "NOT_FOUND",
      error_message: "Repair target instance not observed.",
    };
  }
  if (matches.length > 1) {
    return {
      ok: false,
      instance: null,
      error_code: "AMBIGUOUS_TARGET",
      error_message: "Multiple instances share the requested id.",
    };
  }
  return corroborate(matches[0]!, request.instance_fingerprint);
}

function corroborate(
  instance: InstanceIdentity,
  fingerprint: string | null | undefined,
): RepairTargetBinding {
  if (fingerprint) {
    const expected = instanceFingerprintOf(instance);
    if (fingerprint !== expected) {
      return {
        ok: false,
        instance: null,
        error_code: "FINGERPRINT_MISMATCH",
        error_message: "Instance fingerprint does not match observed identity.",
      };
    }
  }
  return {
    ok: true,
    instance,
    error_code: null,
    error_message: null,
  };
}
