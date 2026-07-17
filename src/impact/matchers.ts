import type { OfficialEvidenceItem } from "../evidence/types.js";
import type {
  GraphEdge,
  LocalIntersection,
  LocalSurfaceObservation,
  MatcherId,
} from "./types.js";

export interface MatcherHit {
  matcher_id: MatcherId;
  intersections: LocalIntersection[];
  edges: Omit<GraphEdge, "edge_id">[];
  /** True when the change claimed a local surface but failed platform/surface gates. */
  wrong_intersection: boolean;
  wrong_reason?: string;
}

function edgeBase(
  matcher_id: MatcherId,
  from: { kind: string; id: string },
  to: { kind: string; id: string },
  evidence: OfficialEvidenceItem,
): Omit<GraphEdge, "edge_id"> {
  return {
    edge_type: matcher_id,
    from,
    to,
    matcher_id,
    provenance: "official",
    confidence: "deterministic",
    evidence_ids: [evidence.evidence_id],
    evidence_state: evidence.evidence_state,
  };
}

function hasMapperSignal(item: OfficialEvidenceItem): boolean {
  const s = item.structured;
  return (
    s.has_registered_mapper ||
    s.config_keys.length > 0 ||
    s.component_ids.length > 0 ||
    s.surfaces.length > 0 ||
    s.artifact_aliases.length > 0 ||
    item.kind === "tag" ||
    item.kind === "release" ||
    item.kind === "diff" ||
    item.kind === "commit"
  );
}

/** Registered deterministic matchers only. */
export const REGISTERED_MATCHER_IDS: readonly MatcherId[] = Object.freeze([
  "version_tag_to_installed",
  "config_key_intersection",
  "component_to_feature",
  "component_to_plugin_skill_mcp_hook",
  "artifact_alias_intersection",
  "surface_runtime_intersection",
  "platform_intersection",
]);

export function runRegisteredMatchers(
  evidence: OfficialEvidenceItem,
  local: LocalSurfaceObservation,
): MatcherHit {
  const intersections: LocalIntersection[] = [];
  const edges: Omit<GraphEdge, "edge_id">[] = [];
  let wrong_intersection = false;
  let wrong_reason: string | undefined;

  // Explicit no-mapper flag: do not invent version/surface edges; caller marks UNMAPPED_CHANGE.
  if (evidence.structured.has_registered_mapper === false) {
    return {
      matcher_id: "config_key_intersection",
      intersections: [],
      edges: [],
      wrong_intersection: false,
    };
  }

  // Platform gate: if evidence declares platforms and local OS not listed → wrong.
  if (evidence.structured.platforms.length > 0) {
    const os = local.platform_os.toLowerCase();
    const ok = evidence.structured.platforms.some(
      (p) => p.toLowerCase() === os || p.toLowerCase() === "any",
    );
    if (!ok) {
      wrong_intersection = true;
      wrong_reason = `platform_mismatch:${evidence.structured.platforms.join(",")}`;
      return {
        matcher_id: "platform_intersection",
        intersections: [],
        edges: [],
        wrong_intersection,
        wrong_reason,
      };
    }
    // Positive platform intersection edge when platforms constrained and matched.
    intersections.push({
      surface_kind: "platform",
      local_id: local.platform_os,
      matcher_id: "platform_intersection",
      evidence_id: evidence.evidence_id,
    });
    edges.push(
      edgeBase(
        "platform_intersection",
        { kind: "official_change", id: evidence.evidence_id },
        { kind: "platform", id: local.platform_os },
        evidence,
      ),
    );
  }

  // Version tag / release → installed version.
  // Null range endpoints are non-participating (not wildcards). Both-null
  // never creates a version edge; at least one real compatible endpoint required.
  if (
    (evidence.kind === "tag" || evidence.kind === "release") &&
    local.codex_version
  ) {
    const range = evidence.version_range;
    const ver = local.codex_version;
    const norm = (v: string) => v.replace(/^v/i, "").toLowerCase();
    const endpointMatches = (endpoint: string | null): boolean => {
      if (endpoint === null || endpoint === undefined || endpoint.length === 0) {
        return false; // non-participating
      }
      return norm(endpoint) === norm(ver);
    };
    const hasRealEndpoint =
      (range.from !== null && range.from.length > 0) ||
      (range.to !== null && range.to.length > 0);
    if (
      hasRealEndpoint &&
      (endpointMatches(range.from) || endpointMatches(range.to))
    ) {
      intersections.push({
        surface_kind: "instance_version",
        local_id: ver,
        matcher_id: "version_tag_to_installed",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "version_tag_to_installed",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "instance_version", id: ver },
          evidence,
        ),
      );
    }
  }

  // Config key intersection.
  for (const key of evidence.structured.config_keys) {
    if (local.config_keys.includes(key)) {
      intersections.push({
        surface_kind: "config_key",
        local_id: key,
        matcher_id: "config_key_intersection",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "config_key_intersection",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "config_key", id: key },
          evidence,
        ),
      );
    }
  }

  // Component → feature ids.
  for (const comp of evidence.structured.component_ids) {
    if (local.feature_ids.includes(comp)) {
      intersections.push({
        surface_kind: "feature_id",
        local_id: comp,
        matcher_id: "component_to_feature",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "component_to_feature",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "feature_id", id: comp },
          evidence,
        ),
      );
    }
    // Plugin / Skill / MCP / Hook inventories.
    if (local.plugins.includes(comp)) {
      intersections.push({
        surface_kind: "plugin",
        local_id: comp,
        matcher_id: "component_to_plugin_skill_mcp_hook",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "component_to_plugin_skill_mcp_hook",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "plugin", id: comp },
          evidence,
        ),
      );
    }
    if (local.skills.includes(comp)) {
      intersections.push({
        surface_kind: "skill",
        local_id: comp,
        matcher_id: "component_to_plugin_skill_mcp_hook",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "component_to_plugin_skill_mcp_hook",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "skill", id: comp },
          evidence,
        ),
      );
    }
    if (local.mcps.includes(comp)) {
      intersections.push({
        surface_kind: "mcp",
        local_id: comp,
        matcher_id: "component_to_plugin_skill_mcp_hook",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "component_to_plugin_skill_mcp_hook",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "mcp", id: comp },
          evidence,
        ),
      );
    }
    if (local.hooks.includes(comp)) {
      intersections.push({
        surface_kind: "hook",
        local_id: comp,
        matcher_id: "component_to_plugin_skill_mcp_hook",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "component_to_plugin_skill_mcp_hook",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "hook", id: comp },
          evidence,
        ),
      );
    }
  }

  // Artifact aliases.
  for (const alias of evidence.structured.artifact_aliases) {
    if (local.artifact_aliases.includes(alias)) {
      intersections.push({
        surface_kind: "artifact_alias",
        local_id: alias,
        matcher_id: "artifact_alias_intersection",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "artifact_alias_intersection",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "artifact_alias", id: alias },
          evidence,
        ),
      );
    }
  }

  // Surface / runtime.
  for (const surf of evidence.structured.surfaces) {
    const localSurfaces = new Set([
      local.surface,
      ...local.runtime_surfaces,
    ]);
    if (localSurfaces.has(surf)) {
      intersections.push({
        surface_kind: "runtime_surface",
        local_id: surf,
        matcher_id: "surface_runtime_intersection",
        evidence_id: evidence.evidence_id,
      });
      edges.push(
        edgeBase(
          "surface_runtime_intersection",
          { kind: "official_change", id: evidence.evidence_id },
          { kind: "runtime_surface", id: surf },
          evidence,
        ),
      );
    }
  }

  // Surface declared by evidence that conflicts with local primary surface
  // (and no other positive intersection) → wrong intersection when exclusive.
  if (
    evidence.structured.surfaces.length > 0 &&
    intersections.filter((i) => i.matcher_id === "surface_runtime_intersection")
      .length === 0 &&
    evidence.structured.surfaces.every(
      (s) => s !== local.surface && !local.runtime_surfaces.includes(s),
    ) &&
    // Only mark wrong when this change is surface-scoped and has mapper intent.
    evidence.structured.has_registered_mapper &&
    evidence.structured.config_keys.length === 0 &&
    evidence.structured.component_ids.length === 0
  ) {
    wrong_intersection = true;
    wrong_reason = `surface_mismatch:${evidence.structured.surfaces.join(",")}`;
  }

  void hasMapperSignal;
  return {
    matcher_id: edges[0]?.matcher_id ?? "config_key_intersection",
    intersections,
    edges,
    wrong_intersection,
    wrong_reason,
  };
}

export function evidenceHasMapperIntent(item: OfficialEvidenceItem): boolean {
  return hasMapperSignal(item);
}
