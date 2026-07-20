/**
 * Path-free contracts for manual staged local-update comparison.
 * Three truth sections must remain visibly separate.
 */

import type { ArtifactReadStatus } from "../types.js";
import type { NamedStagedArtifactKey } from "./limits.js";

/** Overall comparison status (machine-readable). */
export type LocalUpdateCompareStatus =
  | "unsupported_platform"
  | "no_installed_app"
  | "no_staged_candidate"
  | "multiple_candidates"
  | "same_version"
  | "staged_older"
  | "version_incomparable"
  | "partial"
  | "comparable_newer"
  | "error";

export type OfficialEvidenceBindingStatus =
  | "version_bound"
  | "version_unbound"
  | "unavailable"
  | "not_applicable";

export type AsarComponentDiffStatus =
  | "compared"
  | "partial"
  | "unavailable"
  | "skipped";

export type VersionRelation =
  | "newer"
  | "older"
  | "same"
  | "incomparable"
  | "unknown";

export type NamedArtifactChange =
  | "unchanged"
  | "hash_changed"
  | "size_changed"
  | "added"
  | "removed"
  | "gap"
  | "unavailable";

/** Path-free identity for installed or staged app. */
export interface LocalUpdateAppIdentity {
  /** Stable alias such as INSTALLED_1 or STAGED_1. */
  alias: string;
  /** Short path hash of logical app root (never absolute path). */
  path_hash: string;
  version: string | null;
  build: string | null;
  bundle_id: string | null;
  /** Role label — never "installed" for staged. */
  role: "installed" | "staged";
}

export interface NamedArtifactObservation {
  key: NamedStagedArtifactKey;
  change: NamedArtifactChange;
  installed_status: ArtifactReadStatus | null;
  staged_status: ArtifactReadStatus | null;
  installed_sha256: string | null;
  staged_sha256: string | null;
  installed_size: number | null;
  staged_size: number | null;
}

export interface OfficialEvidenceSection {
  status: OfficialEvidenceBindingStatus;
  /** Human-readable status label for Markdown. */
  label: string;
  snapshot_id: string | null;
  snapshot_content_sha256: string | null;
  /** Digests of items whose version_range actually binds the staged version. */
  version_bound_item_digests: string[];
  version_bound_item_count: number;
  notes: string[];
}

export interface AsarStablePathChange {
  path_alias: string;
  /**
   * Content classification from header size + optional validated SHA256 integrity.
   * `unchanged` only when both sides have equal validated integrity hashes (and sizes).
   * `hash_changed` when validated integrity hashes differ (sizes remain separate fields).
   * `present_both` when sizes match but integrity is missing/untrusted on either side.
   */
  change:
    | "added"
    | "removed"
    | "size_changed"
    | "hash_changed"
    | "unchanged"
    | "present_both";
  installed_size: number | null;
  staged_size: number | null;
}

export interface AsarNodeBasenameChange {
  basename: string;
  change: "added" | "removed" | "present_both";
}

export interface AsarComponentDiff {
  status: AsarComponentDiffStatus;
  reason: string | null;
  installed_file_count: number | null;
  staged_file_count: number | null;
  stable_path_changes: AsarStablePathChange[];
  node_basename_changes: AsarNodeBasenameChange[];
  /** Aggregate content-addressed / chunk-like path buckets. */
  aggregate_buckets: Array<{
    bucket: string;
    installed_count: number;
    staged_count: number;
  }>;
  truncation: {
    stable_paths_truncated: boolean;
    node_basenames_truncated: boolean;
    buckets_truncated: boolean;
    nodes_capped: boolean;
    depth_capped: boolean;
  };
}

/**
 * Bounded path-free observation of direct `.node` basenames under
 * Contents/Resources/native (outside ASAR). Never exposes paths or hashes.
 */
export type NativeModuleDiffStatus =
  | "compared"
  | "partial"
  | "unavailable"
  | "skipped";

export interface NativeModuleDiff {
  status: NativeModuleDiffStatus;
  reason: string | null;
  added: string[];
  removed: string[];
  truncation: {
    entries_capped: boolean;
  };
  /** True when either side's native dir was absent (not an error). */
  installed_dir_present: boolean | null;
  staged_dir_present: boolean | null;
}

export interface LocalObservationsSection {
  status: LocalUpdateCompareStatus;
  installed: LocalUpdateAppIdentity | null;
  staged_candidates: LocalUpdateAppIdentity[];
  selected_staged: LocalUpdateAppIdentity | null;
  selection_reason: string | null;
  version_relation: VersionRelation;
  named_artifacts: NamedArtifactObservation[];
  asar_component_diff: AsarComponentDiff;
  /** Sibling observation: direct native modules outside ASAR. */
  native_module_diff: NativeModuleDiff;
  discovery: {
    platform: string;
    staged_root_available: boolean;
    sessions_inspected: number;
    sessions_capped: boolean;
    /** Download dirs inspected under sessions (global). */
    download_dirs_inspected: number;
    download_dirs_capped: boolean;
    candidates_accepted: number;
    candidates_capped: boolean;
    rejection_counts: Record<string, number>;
  };
  safety: {
    network_used: false;
    target_mutated: false;
    staged_written_to_state: false;
    session_start_scanned: false;
    install_attempted: false;
  };
  notes: string[];
}

export interface InferenceAndUnknownsSection {
  status: "conservative";
  implications: string[];
  unknowns: string[];
  /** Explicit non-claims. */
  do_not_claim: string[];
}

/**
 * Canonical JSON result for compare-local-update.
 * Three top-level truth sections are always present and separate.
 */
export interface LocalUpdateCompareResult {
  schema_version: 1;
  command: "compare-local-update";
  ok: boolean;
  status: LocalUpdateCompareStatus;
  summary: string;
  official_evidence: OfficialEvidenceSection;
  local_observations: LocalObservationsSection;
  inference_and_unknowns: InferenceAndUnknownsSection;
  error_code: string | null;
  error_message: string | null;
  network_used: false;
  target_mutated: false;
  repair_applied: false;
}
