/**
 * Resolve the actually affected instance from process/log/launch evidence.
 * Never select the highest/newest version by default.
 * Preserve ambiguity when evidence does not identify exactly one instance.
 */
import { pathHashOf } from "./identity.js";
import type {
  AffectedResolution,
  InstanceIdentity,
  ObservedContext,
} from "./types.js";

export interface AffectedResolutionResult {
  resolution: AffectedResolution;
  instance_id: string | null;
  matched_by: string[];
}

function hashFromPath(p: string | null | undefined): string | null {
  if (!p) return null;
  return pathHashOf(p);
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
    return { resolution: "none", instance_id: null, matched_by: [] };
  }
  if (!observed) {
    return { resolution: "ambiguous", instance_id: null, matched_by: [] };
  }

  const votes = new Map<string, Set<string>>();
  const add = (id: string, reason: string): void => {
    const set = votes.get(id) ?? new Set<string>();
    set.add(reason);
    votes.set(id, set);
  };

  const processHash =
    observed.process_path_hash ?? hashFromPath(observed.process_path ?? null);
  const logHash = observed.log_path_hash ?? hashFromPath(observed.log_path ?? null);
  const launchHash =
    observed.launch_path_hash ?? hashFromPath(observed.launch_path ?? null);

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
      observed.process_version &&
      inst.version &&
      observed.process_version === inst.version
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
    };
  }
  if (pathBacked.length > 1) {
    // Multiple distinct path hits → ambiguous (never pick newest).
    return {
      resolution: "ambiguous",
      instance_id: null,
      matched_by: pathBacked.flatMap(([, r]) => [...r]),
    };
  }

  // No path evidence: version-only only identifies when exactly one instance matches.
  const versionOnly = [...votes.entries()].filter(([, reasons]) =>
    reasons.has("process_version"),
  );
  if (versionOnly.length === 1) {
    const versionMatches = instances.filter(
      (i) => i.version === observed.process_version,
    );
    if (versionMatches.length === 1) {
      return {
        resolution: "identified",
        instance_id: versionOnly[0]![0],
        matched_by: ["process_version"],
      };
    }
  }

  if (instances.length === 1) {
    // Single observed install with no contradicting multi-hit evidence.
    return {
      resolution: "identified",
      instance_id: instances[0]!.instance_id,
      matched_by: ["sole_instance"],
    };
  }

  return { resolution: "ambiguous", instance_id: null, matched_by: [] };
}
