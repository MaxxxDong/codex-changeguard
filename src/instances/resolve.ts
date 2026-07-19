/**
 * Resolve the actually affected instance from process/log/launch evidence.
 * Never select the highest/newest version by default.
 * Preserve ambiguity when evidence does not identify exactly one instance.
 *
 * Without usable observed context, resolution stays `ambiguous` with reason
 * `no_observed_context` — including the single-instance case. Auto-selecting
 * the sole install is refused when there is no runtime observation.
 */
import { pathHashOf } from "./identity.js";
import type {
  AffectedResolution,
  AffectedResolutionReason,
  InstanceIdentity,
  ObservedContext,
} from "./types.js";

export interface AffectedResolutionResult {
  resolution: AffectedResolution;
  instance_id: string | null;
  matched_by: string[];
  reason: AffectedResolutionReason;
}

function hashFromPath(p: string | null | undefined): string | null {
  if (!p) return null;
  return pathHashOf(p);
}

/** True when any process/log/launch/version observation is present. */
function hasObservedEvidence(
  observed: ObservedContext | undefined | null,
): boolean {
  if (!observed) return false;
  return Boolean(
    observed.process_path ||
      observed.log_path ||
      observed.launch_path ||
      observed.process_path_hash ||
      observed.log_path_hash ||
      observed.launch_path_hash ||
      observed.process_version,
  );
}

/**
 * Evidence sources vote independently. A single unique intersection wins.
 * Highest version is never used as a tie-break.
 */
export function resolveAffectedInstance(
  instances: InstanceIdentity[],
  observed: ObservedContext | undefined,
): AffectedResolutionResult {
  if (instances.length === 0) {
    return {
      resolution: "none",
      instance_id: null,
      matched_by: [],
      reason: "no_instances",
    };
  }

  if (!hasObservedEvidence(observed)) {
    // Safe default: never auto-bind sole or multi installs without observation.
    return {
      resolution: "ambiguous",
      instance_id: null,
      matched_by: [],
      reason: "no_observed_context",
    };
  }

  const votes = new Map<string, Set<string>>();
  const add = (id: string, reason: string): void => {
    const set = votes.get(id) ?? new Set<string>();
    set.add(reason);
    votes.set(id, set);
  };

  const processHash =
    observed!.process_path_hash ?? hashFromPath(observed!.process_path ?? null);
  const logHash =
    observed!.log_path_hash ?? hashFromPath(observed!.log_path ?? null);
  const launchHash =
    observed!.launch_path_hash ?? hashFromPath(observed!.launch_path ?? null);

  for (const inst of instances) {
    if (processHash && inst.path_hash === processHash) {
      add(inst.instance_id, "process");
    }
    if (logHash && inst.path_hash === logHash) {
      add(inst.instance_id, "log");
    }
    if (launchHash && inst.path_hash === launchHash) {
      add(inst.instance_id, "launch");
    }
    if (
      observed!.process_version &&
      inst.version &&
      observed!.process_version === inst.version
    ) {
      // Version-only evidence is weak: only counts when exactly one instance has it.
      add(inst.instance_id, "process_version");
    }
  }

  // Prefer path-based evidence over version-only.
  const pathBacked = [...votes.entries()].filter(([, reasons]) =>
    [...reasons].some((r) => r === "process" || r === "log" || r === "launch"),
  );

  if (pathBacked.length === 1) {
    const [id, reasons] = pathBacked[0]!;
    return {
      resolution: "identified",
      instance_id: id,
      matched_by: [...reasons].sort(),
      reason: "identified",
    };
  }
  if (pathBacked.length > 1) {
    // Multiple distinct path hits → ambiguous (never pick newest).
    return {
      resolution: "ambiguous",
      instance_id: null,
      matched_by: pathBacked.flatMap(([, r]) => [...r]),
      reason: "conflicting_observed_evidence",
    };
  }

  // No path evidence: version-only only identifies when exactly one instance matches.
  const versionOnly = [...votes.entries()].filter(([, reasons]) =>
    reasons.has("process_version"),
  );
  if (versionOnly.length === 1) {
    const versionMatches = instances.filter(
      (i) => i.version === observed!.process_version,
    );
    if (versionMatches.length === 1) {
      return {
        resolution: "identified",
        instance_id: versionOnly[0]![0],
        matched_by: ["process_version"],
        reason: "identified",
      };
    }
    return {
      resolution: "ambiguous",
      instance_id: null,
      matched_by: ["process_version"],
      reason: "version_match_ambiguous",
    };
  }
  if (versionOnly.length > 1) {
    return {
      resolution: "ambiguous",
      instance_id: null,
      matched_by: ["process_version"],
      reason: "version_match_ambiguous",
    };
  }

  // Observed context present but insufficient to pick among installs.
  return {
    resolution: "ambiguous",
    instance_id: null,
    matched_by: [],
    reason:
      instances.length === 1
        ? "observed_evidence_no_match"
        : "multi_instance_insufficient_evidence",
  };
}
