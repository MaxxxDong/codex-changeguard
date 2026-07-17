/** Change-to-Local Graph and Impact Card contracts (Ticket 04). */

import type {
  DisclosureManifest,
  EvidenceRefreshResult,
  OfficialEvidenceItem,
  OfficialEvidenceSnapshot,
  StaleRisk,
  EvidenceSourceMode,
  DisclosureDecision,
} from "../evidence/types.js";

export type LocalSurfaceKind =
  | "instance_version"
  | "config_key"
  | "plugin"
  | "skill"
  | "mcp"
  | "hook"
  | "runtime_surface"
  | "artifact_alias"
  | "platform"
  | "feature_id";

export interface LocalSurfaceObservation {
  schema_version: 1;
  codex_version: string | null;
  surface: string;
  platform_os: string;
  platform_arch: string;
  config_keys: string[];
  feature_ids: string[];
  plugins: string[];
  skills: string[];
  mcps: string[];
  hooks: string[];
  artifact_aliases: string[];
  runtime_surfaces: string[];
}

export type MatcherId =
  | "version_tag_to_installed"
  | "config_key_intersection"
  | "component_to_feature"
  | "component_to_plugin_skill_mcp_hook"
  | "artifact_alias_intersection"
  | "surface_runtime_intersection"
  | "platform_intersection";

export interface GraphNodeRef {
  kind: string;
  id: string;
}

export interface GraphEdge {
  edge_id: string;
  edge_type: MatcherId;
  from: GraphNodeRef;
  to: GraphNodeRef;
  matcher_id: MatcherId;
  /** Only official or local_observed — never model_inferred. */
  provenance: "official" | "local_observed";
  /** Fixed confidence class; models cannot raise this. */
  confidence: "deterministic";
  evidence_ids: string[];
  evidence_state: string;
}

export interface UnmappedChange {
  change_id: string;
  evidence_id: string;
  reason: "NO_REGISTERED_MATCHER" | "NO_LOCAL_INTERSECTION";
  summary: string;
}

export interface ChangeToLocalGraph {
  schema_version: 1;
  edges: GraphEdge[];
  unmapped_changes: UnmappedChange[];
  /** Digest over edges + unmapped for integrity. */
  graph_sha256: string;
}

export type ImpactItemStatus =
  | "INTERSECTING"
  | "UNMAPPED_CHANGE"
  | "REJECTED_WRONG_INTERSECTION";

export interface LocalIntersection {
  surface_kind: LocalSurfaceKind;
  local_id: string;
  matcher_id: MatcherId;
  evidence_id: string;
}

export interface ImpactCardItem {
  change_id: string;
  evidence_id: string;
  kind: string;
  title: string;
  status: ImpactItemStatus;
  local_intersections: LocalIntersection[];
  maintainer_status: string;
  version_range: { from: string | null; to: string | null };
  canonical_url: string;
  content_sha256: string;
  summary: string;
  /** Never executable; may note quarantine. */
  quarantine_reason: string | null;
}

export interface ImpactCard {
  schema_version: 1;
  ok: boolean;
  snapshot_id: string | null;
  snapshot_content_sha256: string | null;
  snapshot_fetched_at: string | null;
  stale_age_seconds: number | null;
  stale_risk: StaleRisk;
  evidence_source: EvidenceSourceMode;
  disclosure_decision: DisclosureDecision;
  disclosure_manifest: DisclosureManifest;
  transport_calls: number;
  items: ImpactCardItem[];
  graph: ChangeToLocalGraph;
  local_surface: LocalSurfaceObservation | null;
  /** Separated claim classes. */
  observed_facts: string[];
  user_reports: string[];
  hypotheses: string[];
  network_used: false;
  target_mutated: false;
  repair_applied: false;
  error_code: string | null;
  error_message: string | null;
}

export interface ModelEdgeEscalationPayload {
  /** Forbidden model attempt to add/modify edges or raise confidence. */
  add_edges?: unknown[];
  modify_edges?: unknown[];
  set_provenance?: unknown;
  set_confidence?: unknown;
  set_evidence_state?: unknown;
  promote_user_report?: unknown;
}

export interface ImpactAssessmentResult {
  schema_version: 1;
  ok: boolean;
  impact_card: ImpactCard;
  evidence_refresh: EvidenceRefreshResult;
  /** Present when a model payload tried to mutate the graph. */
  model_mutation_refused: boolean;
  model_mutation_reasons: string[];
}

export type { OfficialEvidenceItem, OfficialEvidenceSnapshot };
