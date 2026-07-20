/**
 * Bounded ASAR component summary/diff for staged vs installed.
 * Stable path allowlist (size + optional validated integrity), .node basenames,
 * aggregate chunk buckets. Never returns bodies, offsets, hashes, or absolute paths.
 */
import {
  ASAR_STABLE_PATH_ALLOWLIST,
  MAX_COMPONENT_ARRAY,
} from "./limits.js";
import {
  parseAsarHeaderFile,
  type AsarFileEntry,
  type AsarHeaderParseResult,
} from "./asar-header.js";
import type {
  AsarComponentDiff,
  AsarNodeBasenameChange,
  AsarStablePathChange,
} from "./types.js";

function emptyDiff(
  status: AsarComponentDiff["status"],
  reason: string | null,
): AsarComponentDiff {
  return {
    status,
    reason,
    installed_file_count: null,
    staged_file_count: null,
    stable_path_changes: [],
    node_basename_changes: [],
    aggregate_buckets: [],
    truncation: {
      stable_paths_truncated: false,
      node_basenames_truncated: false,
      buckets_truncated: false,
      nodes_capped: false,
      depth_capped: false,
    },
  };
}

function indexByPath(entries: AsarFileEntry[]): Map<string, AsarFileEntry> {
  const m = new Map<string, AsarFileEntry>();
  for (const e of entries) m.set(e.path, e);
  return m;
}

function nodeBasenames(entries: AsarFileEntry[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const e of entries) {
    if (!e.is_node_module) continue;
    m.set(e.basename, (m.get(e.basename) ?? 0) + 1);
  }
  return m;
}

function bucketCounts(entries: AsarFileEntry[]): Map<string, number> {
  const m = new Map<string, number>();
  let chunk = 0;
  let other = 0;
  let node = 0;
  for (const e of entries) {
    if (e.is_node_module) {
      node += 1;
      continue;
    }
    if (e.is_chunk_like) {
      chunk += 1;
      continue;
    }
    other += 1;
  }
  m.set("chunk_like", chunk);
  m.set("native_node", node);
  m.set("other_files", other);
  return m;
}

/**
 * Classify a stable allowlisted path using size + optional validated integrity.
 * Never exposes integrity hash values.
 *
 * - `unchanged` only when both validated SHA256 hashes exist, are equal, and sizes agree
 * - validated hashes that differ → `hash_changed` (sizes stay in separate fields)
 * - size differs without dual trusted hashes (or with equal hashes) → `size_changed`
 * - equal size but missing/untrusted integrity on either side → `present_both`
 */
export function classifyStablePathChange(
  a: AsarFileEntry | undefined,
  b: AsarFileEntry | undefined,
): AsarStablePathChange["change"] {
  if (!a && !b) return "present_both"; // caller should skip
  if (a && !b) return "removed";
  if (!a && b) return "added";
  const ha = a!.integrity;
  const hb = b!.integrity;
  const sizeDiffers = a!.size !== b!.size;
  if (ha && hb) {
    if (ha.hash !== hb.hash) return "hash_changed";
    if (sizeDiffers) return "size_changed";
    return "unchanged";
  }
  if (sizeDiffers) return "size_changed";
  // Equal size but either integrity missing/untrusted → never claim unchanged.
  return "present_both";
}

function compareParsed(
  installed: AsarHeaderParseResult,
  staged: AsarHeaderParseResult,
): AsarComponentDiff {
  if (installed.status !== "ok" && staged.status !== "ok") {
    return emptyDiff(
      "unavailable",
      `both_headers:${installed.status}/${staged.status}`,
    );
  }
  if (installed.status !== "ok" || staged.status !== "ok") {
    const partial = emptyDiff(
      "partial",
      `header_status:${installed.status}/${staged.status}`,
    );
    partial.installed_file_count =
      installed.status === "ok" ? installed.file_count : null;
    partial.staged_file_count =
      staged.status === "ok" ? staged.file_count : null;
    partial.truncation.nodes_capped =
      installed.nodes_capped || staged.nodes_capped;
    partial.truncation.depth_capped =
      installed.depth_capped || staged.depth_capped;
    return partial;
  }

  const instMap = indexByPath(installed.entries);
  const stgMap = indexByPath(staged.entries);

  const stable_path_changes: AsarStablePathChange[] = [];
  let stable_trunc = false;
  for (const p of ASAR_STABLE_PATH_ALLOWLIST) {
    if (stable_path_changes.length >= MAX_COMPONENT_ARRAY) {
      stable_trunc = true;
      break;
    }
    const a = instMap.get(p);
    const b = stgMap.get(p);
    if (!a && !b) continue;
    stable_path_changes.push({
      path_alias: p,
      change: classifyStablePathChange(a, b),
      installed_size: a?.size ?? null,
      staged_size: b?.size ?? null,
    });
  }

  const instNodes = nodeBasenames(installed.entries);
  const stgNodes = nodeBasenames(staged.entries);
  const allNodeNames = [...new Set([...instNodes.keys(), ...stgNodes.keys()])].sort(
    (a, b) => a.localeCompare(b),
  );
  const node_basename_changes: AsarNodeBasenameChange[] = [];
  let node_trunc = false;
  for (const name of allNodeNames) {
    if (node_basename_changes.length >= MAX_COMPONENT_ARRAY) {
      node_trunc = true;
      break;
    }
    const hasI = instNodes.has(name);
    const hasS = stgNodes.has(name);
    if (hasI && hasS) {
      // Only report pure adds/removes for .node basenames per requirements.
      continue;
    }
    node_basename_changes.push({
      basename: name,
      change: hasI && !hasS ? "removed" : "added",
    });
  }

  const ib = bucketCounts(installed.entries);
  const sb = bucketCounts(staged.entries);
  const bucketKeys = [...new Set([...ib.keys(), ...sb.keys()])].sort();
  const aggregate_buckets: AsarComponentDiff["aggregate_buckets"] = [];
  let buckets_trunc = false;
  for (const k of bucketKeys) {
    if (aggregate_buckets.length >= MAX_COMPONENT_ARRAY) {
      buckets_trunc = true;
      break;
    }
    aggregate_buckets.push({
      bucket: k,
      installed_count: ib.get(k) ?? 0,
      staged_count: sb.get(k) ?? 0,
    });
  }

  const nodes_capped = installed.nodes_capped || staged.nodes_capped;
  const depth_capped = installed.depth_capped || staged.depth_capped;

  // Honesty: any node/depth truncation must never claim full "compared".
  if (nodes_capped || depth_capped) {
    const reasons: string[] = [];
    if (nodes_capped) reasons.push("nodes_capped");
    if (depth_capped) reasons.push("depth_capped");
    return {
      status: "partial",
      reason: reasons.join(","),
      installed_file_count: installed.file_count,
      staged_file_count: staged.file_count,
      stable_path_changes,
      node_basename_changes,
      aggregate_buckets,
      truncation: {
        stable_paths_truncated: stable_trunc,
        node_basenames_truncated: node_trunc,
        buckets_truncated: buckets_trunc,
        nodes_capped,
        depth_capped,
      },
    };
  }

  return {
    status: "compared",
    reason: null,
    installed_file_count: installed.file_count,
    staged_file_count: staged.file_count,
    stable_path_changes,
    node_basename_changes,
    aggregate_buckets,
    truncation: {
      stable_paths_truncated: stable_trunc,
      node_basenames_truncated: node_trunc,
      buckets_truncated: buckets_trunc,
      nodes_capped: false,
      depth_capped: false,
    },
  };
}

/**
 * Compare installed vs staged app.asar headers. Paths are internal only.
 */
export function compareAsarComponents(
  installedAsarAbs: string | null,
  stagedAsarAbs: string | null,
): AsarComponentDiff {
  if (!installedAsarAbs && !stagedAsarAbs) {
    return emptyDiff("unavailable", "no_asar_paths");
  }
  if (!installedAsarAbs || !stagedAsarAbs) {
    return emptyDiff("partial", "one_side_missing_asar");
  }
  try {
    const installed = parseAsarHeaderFile(installedAsarAbs);
    const staged = parseAsarHeaderFile(stagedAsarAbs);
    return compareParsed(installed, staged);
  } catch {
    return emptyDiff("unavailable", "asar_compare_exception");
  }
}
