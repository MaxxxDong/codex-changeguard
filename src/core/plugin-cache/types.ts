/** Ticket 08 plugin-cache inventory / classification contracts. */

import type { PluginCacheMechanism } from "./limits.js";

export interface CacheIdentity {
  /** Path alias only — never a raw private path. */
  alias: string;
  /** Opaque identity digest (hash of alias + generation material). */
  identity_hash: string;
  generation: number;
}

export interface ComponentRecord {
  alias: string;
  version: string;
  provenance: "bundled" | "shared_cache" | "trusted_rebuild" | "local_override";
  /** Declared in inventory (contextual only until measured). */
  declared_sha256: string | null;
}

export interface PluginInventory {
  schema_version: 1;
  instance_id: string;
  cache_identity: CacheIdentity;
  components: ComponentRecord[];
  /**
   * When true, symptoms resemble plugin failure but the true class is
   * dependency-install failure — must not map to the four mechanisms.
   */
  dependency_install_failure: boolean;
}

export interface RebuildSource {
  alias: string;
  verified: true;
  expected_sha256: string;
  version: string;
}

export interface PluginManifest {
  schema_version: 1;
  required_generation: number;
  required_version: string;
  components: Array<{
    alias: string;
    expected_sha256: string;
    version: string;
    provenance: "bundled" | "shared_cache" | "trusted_rebuild";
  }>;
  rebuild_source: RebuildSource;
}

export interface ReconState {
  schema_version: 1;
  last_cycle_overwrote_local: boolean;
  /** When true, a synthetic reconciliation cycle re-applies bundled bytes. */
  will_overwrite_on_next_cycle: boolean;
  local_intent_sha256: string | null;
}

export interface MeasuredComponent {
  alias: string;
  rel: string;
  measured_sha256: string;
  size: number;
}

export interface PluginCacheObservation {
  inventory: PluginInventory;
  manifest: PluginManifest;
  recon: ReconState | null;
  cache_entry: MeasuredComponent;
  bundled_entry: MeasuredComponent | null;
  trusted_entry: MeasuredComponent;
  local_intent: MeasuredComponent | null;
  health_ok: boolean | null;
  /** Path hashes only (never raw paths). */
  cache_path_hash: string;
  instance_id: string;
}

export interface MechanismClassification {
  mechanism: PluginCacheMechanism | null;
  /** Explicit refuse of generic dependency-install misclassification. */
  refused_dependency_install_conflation: boolean;
  reason: string;
  observation: PluginCacheObservation;
}
