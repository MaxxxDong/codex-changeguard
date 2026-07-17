import type {
  InstanceIdentity,
  InstanceTransition,
  TransitionClass,
} from "./types.js";

/**
 * Compare dotted version tokens. Returns negative if a < b, positive if a > b,
 * 0 if equal. Non-numeric tails use localeCompare. Nulls sort as unknown.
 */
export function compareVersions(
  a: string | null,
  b: string | null,
): number {
  if (a === b) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  const pa = a.split(/[.+-]/).filter(Boolean);
  const pb = b.split(/[.+-]/).filter(Boolean);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const xa = pa[i] ?? "0";
    const xb = pb[i] ?? "0";
    const na = Number(xa);
    const nb = Number(xb);
    if (Number.isFinite(na) && Number.isFinite(nb) && String(na) === xa && String(nb) === xb) {
      if (na !== nb) return na < nb ? -1 : 1;
      continue;
    }
    const c = xa.localeCompare(xb);
    if (c !== 0) return c;
  }
  return 0;
}

function keyOf(i: InstanceIdentity): string {
  // Identity is path_hash + source + surface (stable across version changes).
  return `${i.install_source}|${i.surface}|${i.path_hash}`;
}

/**
 * Classify per-instance and overall transitions.
 * Multiple instances never collapse into one identity.
 */
export function classifyTransitions(
  previous: InstanceIdentity[] | null,
  current: InstanceIdentity[],
): { primary: TransitionClass; transitions: InstanceTransition[] } {
  if (previous === null) {
    return {
      primary: "first_baseline",
      transitions: current.map((c) => ({
        instance_id: c.instance_id,
        path_alias: c.path_alias,
        path_hash: c.path_hash,
        class: "first_baseline" as const,
        previous_version: null,
        current_version: c.version,
        previous_path_precedence: null,
        current_path_precedence: c.path_precedence,
      })),
    };
  }

  const prevMap = new Map(previous.map((p) => [keyOf(p), p]));
  const curMap = new Map(current.map((c) => [keyOf(c), c]));
  const transitions: InstanceTransition[] = [];

  for (const c of current) {
    const p = prevMap.get(keyOf(c));
    if (!p) {
      transitions.push({
        instance_id: c.instance_id,
        path_alias: c.path_alias,
        path_hash: c.path_hash,
        class: "newly_discovered",
        previous_version: null,
        current_version: c.version,
        previous_path_precedence: null,
        current_path_precedence: c.path_precedence,
      });
      continue;
    }
    let cls: TransitionClass = "unchanged";
    const vcmp = compareVersions(p.version, c.version);
    if (vcmp < 0) cls = "upgrade";
    else if (vcmp > 0) cls = "downgrade";
    // PATH precedence drift is independent of version and reported when order changes.
    if (
      p.path_precedence !== null &&
      c.path_precedence !== null &&
      p.path_precedence !== c.path_precedence
    ) {
      // If version also changed, keep version class and add a separate drift row below.
      if (cls === "unchanged") {
        cls = "path_precedence_drift";
      } else {
        transitions.push({
          instance_id: c.instance_id,
          path_alias: c.path_alias,
          path_hash: c.path_hash,
          class: "path_precedence_drift",
          previous_version: p.version,
          current_version: c.version,
          previous_path_precedence: p.path_precedence,
          current_path_precedence: c.path_precedence,
        });
      }
    } else if (
      p.version === c.version &&
      p.build === c.build &&
      p.path_precedence === c.path_precedence
    ) {
      cls = "unchanged";
    }
    transitions.push({
      instance_id: c.instance_id,
      path_alias: c.path_alias,
      path_hash: c.path_hash,
      class: cls,
      previous_version: p.version,
      current_version: c.version,
      previous_path_precedence: p.path_precedence,
      current_path_precedence: c.path_precedence,
    });
  }

  for (const p of previous) {
    if (!curMap.has(keyOf(p))) {
      transitions.push({
        instance_id: p.instance_id,
        path_alias: p.path_alias,
        path_hash: p.path_hash,
        class: "removed",
        previous_version: p.version,
        current_version: null,
        previous_path_precedence: p.path_precedence,
        current_path_precedence: null,
      });
    }
  }

  // Also detect PATH order swap when the same hashes remain but precedence map differs.
  const pathPrev = previous
    .filter((i) => i.install_source === "path")
    .sort((a, b) => (a.path_precedence ?? 0) - (b.path_precedence ?? 0));
  const pathCur = current
    .filter((i) => i.install_source === "path")
    .sort((a, b) => (a.path_precedence ?? 0) - (b.path_precedence ?? 0));
  if (
    pathPrev.length > 1 &&
    pathPrev.length === pathCur.length &&
    pathPrev.some((p, idx) => p.path_hash !== pathCur[idx]?.path_hash)
  ) {
    // Ensure at least one path_precedence_drift transition is recorded for the swap.
    const hasDrift = transitions.some((t) => t.class === "path_precedence_drift");
    if (!hasDrift) {
      for (const c of pathCur) {
        const p = pathPrev.find((x) => x.path_hash === c.path_hash);
        if (p && p.path_precedence !== c.path_precedence) {
          transitions.push({
            instance_id: c.instance_id,
            path_alias: c.path_alias,
            path_hash: c.path_hash,
            class: "path_precedence_drift",
            previous_version: p.version,
            current_version: c.version,
            previous_path_precedence: p.path_precedence,
            current_path_precedence: c.path_precedence,
          });
        }
      }
    }
  }

  const primary = pickPrimary(transitions);
  return { primary, transitions };
}

function pickPrimary(transitions: InstanceTransition[]): TransitionClass {
  if (transitions.length === 0) return "unchanged";
  const rank: TransitionClass[] = [
    "first_baseline",
    "downgrade",
    "upgrade",
    "path_precedence_drift",
    "newly_discovered",
    "removed",
    "unchanged",
  ];
  for (const r of rank) {
    if (transitions.some((t) => t.class === r)) return r;
  }
  return "unchanged";
}
