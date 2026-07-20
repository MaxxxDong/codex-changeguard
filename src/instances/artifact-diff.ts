/**
 * Deterministic local_artifact_diff truth surface (facts only).
 * Path-free, stably sorted; never invents historical artifact rows.
 */
import type {
  InstanceArtifactBaseline,
  LocalArtifactDiff,
  LocalArtifactDiffEntry,
  LocalArtifactDiffStatus,
  LocalArtifactEntry,
} from "./types.js";
import { overallArtifactDigest } from "./artifacts.js";

function emptyLists(): Pick<
  LocalArtifactDiff,
  "added" | "removed" | "hash_changed" | "gap_changed"
> {
  return { added: [], removed: [], hash_changed: [], gap_changed: [] };
}

function countEntries(baselines: InstanceArtifactBaseline[]): {
  entries: number;
  read_ok: number;
  gaps: number;
} {
  let entries = 0;
  let read_ok = 0;
  let gaps = 0;
  for (const b of baselines) {
    for (const e of b.entries) {
      entries += 1;
      if (e.status === "read_ok") read_ok += 1;
      else gaps += 1;
    }
  }
  return { entries, read_ok, gaps };
}

function entryRow(
  baseline: InstanceArtifactBaseline,
  entry: LocalArtifactEntry,
  change: LocalArtifactDiffEntry["change"],
  previous: LocalArtifactEntry | null,
): LocalArtifactDiffEntry {
  return {
    instance_id: baseline.instance_id,
    path_alias: baseline.path_alias,
    key: entry.key,
    alias: entry.alias,
    kind: entry.kind,
    change,
    previous_sha256: previous?.sha256 ?? null,
    current_sha256: entry.sha256,
    previous_status: previous?.status ?? null,
    current_status: entry.status,
    previous_size: previous?.size ?? null,
    current_size: entry.size,
  };
}

function removedRow(
  baseline: InstanceArtifactBaseline,
  previous: LocalArtifactEntry,
): LocalArtifactDiffEntry {
  return {
    instance_id: baseline.instance_id,
    path_alias: baseline.path_alias,
    key: previous.key,
    alias: previous.alias,
    kind: previous.kind,
    change: "removed",
    previous_sha256: previous.sha256,
    current_sha256: null,
    previous_status: previous.status,
    current_status: null,
    previous_size: previous.size,
    current_size: null,
  };
}

function sortDiffEntries(
  rows: LocalArtifactDiffEntry[],
): LocalArtifactDiffEntry[] {
  return [...rows].sort((a, b) => {
    const ia = a.instance_id ?? "";
    const ib = b.instance_id ?? "";
    if (ia !== ib) return ia.localeCompare(ib);
    return a.key.localeCompare(b.key);
  });
}

/**
 * Compare current measured baselines to previous persisted baselines.
 * previous === null means no prior artifact baseline (v1 state or first scan).
 */
export function classifyLocalArtifactDiff(
  previous: InstanceArtifactBaseline[] | null,
  current: InstanceArtifactBaseline[],
): LocalArtifactDiff {
  const current_digest = overallArtifactDigest(current);
  const counts = countEntries(current);
  const keys = current
    .flatMap((b) => b.entries.map((e) => e.alias))
    .sort()
    .slice(0, 64);

  if (previous === null) {
    const status: LocalArtifactDiffStatus =
      counts.entries === 0
        ? "unavailable"
        : counts.read_ok === 0
          ? "unavailable"
          : "first_baseline";
    return {
      status,
      previous_baseline_digest: null,
      current_baseline_digest: current_digest,
      ...emptyLists(),
      entry_counts: {
        measured: counts.entries,
        read_ok: counts.read_ok,
        gaps: counts.gaps,
      },
      keys,
    };
  }

  const previous_digest = overallArtifactDigest(previous);
  const prevById = new Map(previous.map((b) => [b.instance_id, b]));
  const curById = new Map(current.map((b) => [b.instance_id, b]));

  const added: LocalArtifactDiffEntry[] = [];
  const removed: LocalArtifactDiffEntry[] = [];
  const hash_changed: LocalArtifactDiffEntry[] = [];
  const gap_changed: LocalArtifactDiffEntry[] = [];

  for (const cur of current) {
    const prev = prevById.get(cur.instance_id);
    if (!prev) {
      for (const e of cur.entries) {
        added.push(entryRow(cur, e, "added", null));
      }
      continue;
    }
    const prevKeys = new Map(prev.entries.map((e) => [e.key, e]));
    const curKeys = new Map(cur.entries.map((e) => [e.key, e]));
    for (const e of cur.entries) {
      const p = prevKeys.get(e.key);
      if (!p) {
        added.push(entryRow(cur, e, "added", null));
        continue;
      }
      if (p.sha256 !== e.sha256 && p.status === "read_ok" && e.status === "read_ok") {
        hash_changed.push(entryRow(cur, e, "hash_changed", p));
        continue;
      }
      if (p.status !== e.status) {
        gap_changed.push(entryRow(cur, e, "gap_changed", p));
        continue;
      }
      if (p.sha256 !== e.sha256) {
        // status same but hash differs (e.g. both read_ok already handled);
        // treat residual digest drift as hash_changed when either side read_ok.
        if (p.status === "read_ok" || e.status === "read_ok") {
          hash_changed.push(entryRow(cur, e, "hash_changed", p));
        } else {
          gap_changed.push(entryRow(cur, e, "gap_changed", p));
        }
      }
    }
    for (const p of prev.entries) {
      if (!curKeys.has(p.key)) {
        removed.push(removedRow(cur, p));
      }
    }
  }

  for (const prev of previous) {
    if (!curById.has(prev.instance_id)) {
      for (const p of prev.entries) {
        removed.push({
          instance_id: prev.instance_id,
          path_alias: prev.path_alias,
          key: p.key,
          alias: p.alias,
          kind: p.kind,
          change: "removed",
          previous_sha256: p.sha256,
          current_sha256: null,
          previous_status: p.status,
          current_status: null,
          previous_size: p.size,
          current_size: null,
        });
      }
    }
  }

  const lists = {
    added: sortDiffEntries(added),
    removed: sortDiffEntries(removed),
    hash_changed: sortDiffEntries(hash_changed),
    gap_changed: sortDiffEntries(gap_changed),
  };

  const deltaCount =
    lists.added.length +
    lists.removed.length +
    lists.hash_changed.length +
    lists.gap_changed.length;

  // Wall-clock incompleteness is not a stable fact: even when previous and
  // current rows/digests are identical, the current measurement did not finish.
  // Do not broaden this to stable missing/symlink/oversize gaps.
  const currentHasTimeBudgetGap = current.some((b) =>
    b.entries.some((e) => e.status === "time_budget_exceeded"),
  );

  let status: LocalArtifactDiffStatus;
  if (currentHasTimeBudgetGap) {
    // Incomplete current measurement: never claim unchanged.
    status = counts.read_ok > 0 ? "partial" : "unavailable";
  } else if (deltaCount === 0 && previous_digest === current_digest) {
    status = "unchanged";
  } else if (
    lists.hash_changed.length > 0 ||
    lists.added.length > 0 ||
    lists.removed.length > 0
  ) {
    // Pure content axis: real hash / membership changes.
    // Content + gap transitions → partial (honest incomplete evidence).
    status =
      counts.gaps > 0 && counts.read_ok > 0 && lists.gap_changed.length > 0
        ? "partial"
        : "content_changed";
  } else if (lists.gap_changed.length > 0) {
    // Gap-only transitions (status flips without hash membership deltas).
    status = "partial";
  } else if (deltaCount === 0 && previous_digest !== current_digest) {
    // Digest-only disagreement with zero entry deltas is impossible after
    // validation (digests recompute from entries). Fail closed — never invent
    // content_changed from an integrity impossibility.
    status = "unavailable";
  } else if (counts.read_ok === 0) {
    status = "unavailable";
  } else {
    status = "unavailable";
  }

  return {
    status,
    previous_baseline_digest: previous_digest,
    current_baseline_digest: current_digest,
    ...lists,
    entry_counts: {
      measured: counts.entries,
      read_ok: counts.read_ok,
      gaps: counts.gaps,
    },
    keys,
  };
}

/** Unavailable surface for fail / untrusted paths (facts only). */
export function unavailableLocalArtifactDiff(): LocalArtifactDiff {
  return {
    status: "unavailable",
    previous_baseline_digest: null,
    current_baseline_digest: null,
    ...emptyLists(),
    entry_counts: { measured: 0, read_ok: 0, gaps: 0 },
    keys: [],
  };
}
