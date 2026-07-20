/**
 * Markdown rendering of the three truth sections for compare-local-update.
 */
import type { LocalUpdateCompareResult } from "./types.js";

function bullets(items: string[], empty = "_(none)_"): string {
  if (items.length === 0) return empty;
  return items.map((s) => `- ${s}`).join("\n");
}

/**
 * Render Markdown with clearly labeled official / local / inference sections.
 */
export function formatLocalUpdateCompareMarkdown(
  result: LocalUpdateCompareResult,
): string {
  const lines: string[] = [];
  lines.push("# ChangeGuard compare-local-update");
  lines.push("");
  lines.push(`**Status:** \`${result.status}\``);
  lines.push("");
  lines.push(result.summary);
  lines.push("");
  lines.push(
    "This is a **spatial** comparison (installed vs staged). It is **not** the temporal `local_artifact_diff` SessionStart baseline.",
  );
  lines.push("");
  lines.push(
    "Safety: read-only; no install/activate/delete/repair; staged never written to instance state.",
  );
  lines.push("");

  // Section 1 — official
  lines.push("## 1. Official evidence");
  lines.push("");
  lines.push(
    `**Status:** \`${result.official_evidence.status}\` — ${result.official_evidence.label}`,
  );
  if (result.official_evidence.snapshot_id) {
    lines.push(`- Snapshot id: \`${result.official_evidence.snapshot_id}\``);
  }
  if (result.official_evidence.snapshot_content_sha256) {
    lines.push(
      `- Snapshot digest: \`${result.official_evidence.snapshot_content_sha256.slice(0, 16)}…\``,
    );
  }
  lines.push(
    `- Version-bound item count: ${result.official_evidence.version_bound_item_count}`,
  );
  if (result.official_evidence.version_bound_item_digests.length > 0) {
    lines.push("- Version-bound item digests:");
    for (const d of result.official_evidence.version_bound_item_digests) {
      lines.push(`  - \`${d.slice(0, 16)}…\``);
    }
  }
  lines.push("");
  lines.push("Notes:");
  lines.push(bullets(result.official_evidence.notes));
  lines.push("");

  // Section 2 — local observations
  const lo = result.local_observations;
  lines.push("## 2. Local observations");
  lines.push("");
  lines.push(`**Status:** \`${lo.status}\``);
  if (lo.installed) {
    lines.push(
      `- Installed: alias \`${lo.installed.alias}\` version \`${lo.installed.version}\` build \`${lo.installed.build}\` (path_hash \`${lo.installed.path_hash.slice(0, 12)}…\`)`,
    );
  } else {
    lines.push("- Installed: _(not validated)_");
  }
  lines.push(`- Staged candidates: ${lo.staged_candidates.length}`);
  for (const s of lo.staged_candidates) {
    lines.push(
      `  - \`${s.alias}\` version \`${s.version}\` build \`${s.build}\` role=\`${s.role}\``,
    );
  }
  if (lo.selected_staged) {
    lines.push(
      `- Selected staged: \`${lo.selected_staged.alias}\` (${lo.selection_reason ?? "n/a"})`,
    );
  } else {
    lines.push(`- Selected staged: _(none)_ (${lo.selection_reason ?? "n/a"})`);
  }
  lines.push(`- Version relation (staged vs installed): \`${lo.version_relation}\``);
  lines.push("");
  lines.push("### Named artifacts");
  if (lo.named_artifacts.length === 0) {
    lines.push("_(none measured)_");
  } else {
    for (const a of lo.named_artifacts) {
      lines.push(
        `- \`${a.key}\`: \`${a.change}\` (installed=${a.installed_status ?? "n/a"}, staged=${a.staged_status ?? "n/a"})`,
      );
    }
  }
  lines.push("");
  lines.push("### ASAR component summary");
  lines.push(
    `- Status: \`${lo.asar_component_diff.status}\`${lo.asar_component_diff.reason ? ` (${lo.asar_component_diff.reason})` : ""}`,
  );
  if (lo.asar_component_diff.stable_path_changes.length > 0) {
    lines.push("- Stable path changes:");
    for (const p of lo.asar_component_diff.stable_path_changes) {
      lines.push(
        `  - \`${p.path_alias}\`: \`${p.change}\` sizes ${p.installed_size ?? "n/a"} → ${p.staged_size ?? "n/a"}`,
      );
    }
  }
  if (lo.asar_component_diff.node_basename_changes.length > 0) {
    lines.push("- `.node` basename changes:");
    for (const n of lo.asar_component_diff.node_basename_changes) {
      lines.push(`  - \`${n.basename}\`: \`${n.change}\``);
    }
  }
  if (lo.asar_component_diff.aggregate_buckets.length > 0) {
    lines.push("- Aggregate buckets:");
    for (const b of lo.asar_component_diff.aggregate_buckets) {
      lines.push(
        `  - \`${b.bucket}\`: installed=${b.installed_count} staged=${b.staged_count}`,
      );
    }
  }
  const trunc = lo.asar_component_diff.truncation;
  if (trunc.nodes_capped || trunc.depth_capped) {
    lines.push(
      `- Truncation: nodes_capped=\`${trunc.nodes_capped}\` depth_capped=\`${trunc.depth_capped}\``,
    );
  }
  lines.push("");
  lines.push("### Native modules (outside ASAR)");
  const nm = lo.native_module_diff;
  lines.push(
    `- Status: \`${nm.status}\`${nm.reason ? ` (${nm.reason})` : ""}`,
  );
  if (nm.added.length > 0) {
    lines.push(`- Added basenames: ${nm.added.map((b) => `\`${b}\``).join(", ")}`);
  }
  if (nm.removed.length > 0) {
    lines.push(
      `- Removed basenames: ${nm.removed.map((b) => `\`${b}\``).join(", ")}`,
    );
  }
  if (nm.truncation.entries_capped) {
    lines.push("- Entries capped: `true`");
  }
  lines.push("");
  lines.push("Discovery notes:");
  lines.push(bullets(lo.notes));
  lines.push("");

  // Section 3 — inference
  const inf = result.inference_and_unknowns;
  lines.push("## 3. Inference and unknowns");
  lines.push("");
  lines.push("**Implications (conservative):**");
  lines.push(bullets(inf.implications));
  lines.push("");
  lines.push("**Unknowns:**");
  lines.push(bullets(inf.unknowns));
  lines.push("");
  lines.push("**Do not claim:**");
  lines.push(bullets(inf.do_not_claim));
  lines.push("");

  return lines.join("\n");
}
