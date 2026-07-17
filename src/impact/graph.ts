import { sha256Canonical } from "../evidence/canonical.js";
import type { OfficialEvidenceItem } from "../evidence/types.js";
import { MAX_GRAPH_EDGES } from "../evidence/limits.js";
import {
  evidenceHasMapperIntent,
  REGISTERED_MATCHER_IDS,
  runRegisteredMatchers,
} from "./matchers.js";
import type {
  ChangeToLocalGraph,
  GraphEdge,
  LocalSurfaceObservation,
  ModelEdgeEscalationPayload,
  UnmappedChange,
} from "./types.js";

export function buildChangeToLocalGraph(
  items: OfficialEvidenceItem[],
  local: LocalSurfaceObservation,
): {
  graph: ChangeToLocalGraph;
  hits: Map<string, ReturnType<typeof runRegisteredMatchers>>;
} {
  const edges: GraphEdge[] = [];
  const unmapped_changes: UnmappedChange[] = [];
  const hits = new Map<string, ReturnType<typeof runRegisteredMatchers>>();
  let edgeSeq = 0;

  for (const item of items) {
    const hit = runRegisteredMatchers(item, local);
    hits.set(item.evidence_id, hit);

    if (hit.wrong_intersection) {
      // Wrong intersections are rejected — no edges.
      continue;
    }

    if (hit.edges.length === 0) {
      // No local intersection.
      if (evidenceHasMapperIntent(item) && item.structured.has_registered_mapper) {
        // Mapper exists but no local hit → not unmapped; simply no card row intersection.
        // Unmapped is for changes with NO registered mapper path.
      }
      if (!evidenceHasMapperIntent(item) || item.structured.has_registered_mapper === false) {
        unmapped_changes.push({
          change_id: `unmapped_${item.evidence_id}`,
          evidence_id: item.evidence_id,
          reason: "NO_REGISTERED_MATCHER",
          summary:
            "Official change has no registered local matcher; marked UNMAPPED_CHANGE (version not declared unsupported).",
        });
      }
      continue;
    }

    for (const partial of hit.edges) {
      if (edges.length >= MAX_GRAPH_EDGES) break;
      if (!REGISTERED_MATCHER_IDS.includes(partial.matcher_id)) {
        // Defense in depth: never accept unregistered matcher ids.
        continue;
      }
      edgeSeq += 1;
      edges.push({
        ...partial,
        edge_id: `edge_${edgeSeq.toString(16).padStart(4, "0")}_${partial.matcher_id}`,
      });
    }
  }

  const graph_sha256 = sha256Canonical({
    edges: edges.map((e) => ({
      edge_id: e.edge_id,
      matcher_id: e.matcher_id,
      from: e.from,
      to: e.to,
      evidence_ids: e.evidence_ids,
      provenance: e.provenance,
      confidence: e.confidence,
    })),
    unmapped_changes,
  });

  return {
    graph: {
      schema_version: 1,
      edges,
      unmapped_changes,
      graph_sha256,
    },
    hits,
  };
}

/**
 * Models cannot add/modify edges, provenance, confidence, or evidence state.
 * Any such payload is refused; the graph is returned unchanged.
 */
export function refuseModelGraphMutation(
  graph: ChangeToLocalGraph,
  payload: ModelEdgeEscalationPayload | null | undefined,
): { graph: ChangeToLocalGraph; refused: boolean; reasons: string[] } {
  if (!payload || typeof payload !== "object") {
    return { graph, refused: false, reasons: [] };
  }
  const reasons: string[] = [];
  if (payload.add_edges !== undefined) {
    reasons.push("MODEL_ADD_EDGE_REFUSED");
  }
  if (payload.modify_edges !== undefined) {
    reasons.push("MODEL_MODIFY_EDGE_REFUSED");
  }
  if (payload.set_provenance !== undefined) {
    reasons.push("MODEL_PROVENANCE_MUTATION_REFUSED");
  }
  if (payload.set_confidence !== undefined) {
    reasons.push("MODEL_CONFIDENCE_ESCALATION_REFUSED");
  }
  if (payload.set_evidence_state !== undefined) {
    reasons.push("MODEL_EVIDENCE_STATE_MUTATION_REFUSED");
  }
  if (payload.promote_user_report !== undefined) {
    reasons.push("MODEL_USER_REPORT_PROMOTION_REFUSED");
  }
  // Extra unknown keys also refused.
  for (const k of Object.keys(payload)) {
    if (
      ![
        "add_edges",
        "modify_edges",
        "set_provenance",
        "set_confidence",
        "set_evidence_state",
        "promote_user_report",
      ].includes(k)
    ) {
      reasons.push(`MODEL_UNKNOWN_GRAPH_FIELD_REFUSED:${k}`);
    }
  }
  if (reasons.length === 0) {
    return { graph, refused: false, reasons: [] };
  }
  // Return a clone of the original graph — never mutated.
  return {
    graph: {
      schema_version: 1,
      edges: graph.edges.map((e) => ({ ...e, evidence_ids: [...e.evidence_ids] })),
      unmapped_changes: graph.unmapped_changes.map((u) => ({ ...u })),
      graph_sha256: graph.graph_sha256,
    },
    refused: true,
    reasons,
  };
}
