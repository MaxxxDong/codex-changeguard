import type { EvidenceRefreshResult } from "../evidence/types.js";
import { MAX_IMPACT_ITEMS } from "../evidence/limits.js";
import { buildChangeToLocalGraph } from "./graph.js";
import type {
  ImpactCard,
  ImpactCardItem,
  LocalSurfaceObservation,
} from "./types.js";

/**
 * Build an Impact Card: only changes with deterministic local intersection,
 * plus UNMAPPED_CHANGE rows for official items without a registered matcher.
 * Wrong intersections are rejected (not shown as intersecting).
 */
export function buildImpactCard(
  refresh: EvidenceRefreshResult,
  local: LocalSurfaceObservation | null,
): ImpactCard {
  const base: ImpactCard = {
    schema_version: 1,
    ok: refresh.ok && local !== null,
    snapshot_id: refresh.snapshot?.snapshot_id ?? null,
    snapshot_content_sha256: refresh.snapshot?.content_sha256 ?? null,
    snapshot_fetched_at: refresh.snapshot?.fetched_at ?? null,
    stale_age_seconds: refresh.stale_age_seconds,
    stale_risk: refresh.stale_risk,
    evidence_source: refresh.source_mode,
    disclosure_decision: refresh.disclosure_decision,
    disclosure_manifest: refresh.disclosure_manifest,
    transport_calls: refresh.transport_calls,
    items: [],
    graph: {
      schema_version: 1,
      edges: [],
      unmapped_changes: [],
      graph_sha256: "",
    },
    local_surface: local,
    observed_facts: [...refresh.observed_facts],
    user_reports: [...refresh.user_reports],
    hypotheses: [...refresh.hypotheses],
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: refresh.error_code,
    error_message: refresh.error_message,
  };

  if (!local || !refresh.snapshot) {
    base.ok = false;
    if (!base.error_code) {
      base.error_code = local ? "NO_SNAPSHOT" : "NO_LOCAL_SURFACE";
      base.error_message = local
        ? "No official evidence snapshot available."
        : "Local surface observation unavailable.";
    }
    return base;
  }

  const { graph, hits } = buildChangeToLocalGraph(refresh.snapshot.items, local);
  base.graph = graph;

  const items: ImpactCardItem[] = [];
  const unmappedIds = new Set(graph.unmapped_changes.map((u) => u.evidence_id));

  for (const evidence of refresh.snapshot.items) {
    if (items.length >= MAX_IMPACT_ITEMS) break;
    const hit = hits.get(evidence.evidence_id);
    if (!hit) continue;

    if (hit.wrong_intersection) {
      items.push({
        change_id: `change_${evidence.evidence_id}`,
        evidence_id: evidence.evidence_id,
        kind: evidence.kind,
        title: evidence.title,
        status: "REJECTED_WRONG_INTERSECTION",
        local_intersections: [],
        maintainer_status: evidence.maintainer_status,
        version_range: { ...evidence.version_range },
        canonical_url: evidence.canonical_url,
        content_sha256: evidence.content_sha256,
        summary: `Rejected wrong local intersection (${hit.wrong_reason ?? "mismatch"}).`,
        quarantine_reason: evidence.quarantine?.reason ?? null,
      });
      base.observed_facts.push(
        `rejected_wrong_intersection:${evidence.evidence_id}`,
      );
      continue;
    }

    if (unmappedIds.has(evidence.evidence_id)) {
      items.push({
        change_id: `change_${evidence.evidence_id}`,
        evidence_id: evidence.evidence_id,
        kind: evidence.kind,
        title: evidence.title,
        status: "UNMAPPED_CHANGE",
        local_intersections: [],
        maintainer_status: evidence.maintainer_status,
        version_range: { ...evidence.version_range },
        canonical_url: evidence.canonical_url,
        content_sha256: evidence.content_sha256,
        summary:
          "UNMAPPED_CHANGE: no registered matcher for this official change; version remains supportable.",
        quarantine_reason: evidence.quarantine?.reason ?? null,
      });
      continue;
    }

    if (hit.intersections.length === 0) {
      // Has mapper intent but no local intersection — omit from card (not intersecting).
      // Do not claim entire version unsupported.
      base.observed_facts.push(
        `no_local_intersection:${evidence.evidence_id}`,
      );
      continue;
    }

    // Only show intersecting changes on the impact card primary list.
    items.push({
      change_id: `change_${evidence.evidence_id}`,
      evidence_id: evidence.evidence_id,
      kind: evidence.kind,
      title: evidence.title,
      status: "INTERSECTING",
      local_intersections: hit.intersections,
      maintainer_status: evidence.maintainer_status,
      version_range: { ...evidence.version_range },
      canonical_url: evidence.canonical_url,
      content_sha256: evidence.content_sha256,
      summary: `Deterministic intersection via ${[
        ...new Set(hit.intersections.map((i) => i.matcher_id)),
      ].join(", ")}.`,
      quarantine_reason: evidence.quarantine?.reason ?? null,
    });
  }

  // Ensure UNMAPPED rows from graph that weren't in items (defensive).
  for (const u of graph.unmapped_changes) {
    if (items.some((it) => it.evidence_id === u.evidence_id)) continue;
    if (items.length >= MAX_IMPACT_ITEMS) break;
    const evidence = refresh.snapshot.items.find(
      (it) => it.evidence_id === u.evidence_id,
    );
    if (!evidence) continue;
    items.push({
      change_id: `change_${evidence.evidence_id}`,
      evidence_id: evidence.evidence_id,
      kind: evidence.kind,
      title: evidence.title,
      status: "UNMAPPED_CHANGE",
      local_intersections: [],
      maintainer_status: evidence.maintainer_status,
      version_range: { ...evidence.version_range },
      canonical_url: evidence.canonical_url,
      content_sha256: evidence.content_sha256,
      summary: u.summary,
      quarantine_reason: evidence.quarantine?.reason ?? null,
    });
  }

  base.items = items;
  base.ok = true;
  base.observed_facts.push(
    `impact_items=${items.length}`,
    `graph_edges=${graph.edges.length}`,
    `unmapped=${graph.unmapped_changes.length}`,
    `graph_sha256=${graph.graph_sha256}`,
  );

  // Separate user-reported evidence titles into user_reports.
  for (const evidence of refresh.snapshot.items) {
    if (evidence.maintainer_status === "user_reported") {
      base.user_reports.push(
        `issue_or_pr:${evidence.evidence_id}:status=user_reported`,
      );
    }
  }

  return base;
}
