/**
 * Deterministic exclusive classification of the four plugin-cache mechanisms.
 * Ordered gates prevent conflation with generic dependency-install failure.
 */
import { PLUGIN_CACHE_ENTRY_ALIAS } from "./limits.js";
import type { MechanismClassification, PluginCacheObservation } from "./types.js";

function primaryComponent(obs: PluginCacheObservation) {
  const inv = obs.inventory.components.find(
    (c) => c.alias === PLUGIN_CACHE_ENTRY_ALIAS,
  );
  const man = obs.manifest.components.find(
    (c) => c.alias === PLUGIN_CACHE_ENTRY_ALIAS,
  );
  return { inv, man };
}

/**
 * Classify observation into exactly one of the four mechanisms, or null.
 * Priority (exclusive):
 * 1. Refuse dependency-install failure conflation
 * 2. dependency_version_skew — inventory version ≠ manifest required version
 * 3. stale_shared_cache — generation lag on shared_cache provenance
 * 4. reconciliation_overwrite — recon overwrote local intent
 * 5. bundled_file_corruption — current gen+version but hash ≠ expected/trusted
 */
export function classifyPluginCacheMechanism(
  obs: PluginCacheObservation,
): MechanismClassification {
  // Explicit gate: never map dependency-install failure to the four mechanisms.
  if (obs.inventory.dependency_install_failure) {
    return {
      mechanism: null,
      refused_dependency_install_conflation: true,
      reason:
        "Observed dependency-install failure markers; refused conflation with plugin-cache mechanisms.",
      observation: obs,
    };
  }

  const { inv, man } = primaryComponent(obs);
  if (!inv || !man) {
    return {
      mechanism: null,
      refused_dependency_install_conflation: false,
      reason: "Primary PLUGIN_CACHE_ENTRY component missing from inventory/manifest.",
      observation: obs,
    };
  }

  const measured = obs.cache_entry.measured_sha256;
  const expected = man.expected_sha256;
  const trusted = obs.trusted_entry.measured_sha256;
  const trustedMatchesManifest =
    trusted === obs.manifest.rebuild_source.expected_sha256;

  // Healthy gate: independent bytes match expected trusted rebuild.
  // Inventory metadata alone cannot keep a mechanism after verified restore.
  if (measured === expected && measured === trusted && trustedMatchesManifest) {
    return {
      mechanism: null,
      refused_dependency_install_conflation: true,
      reason: "Cache entry matches expected trusted rebuild; no fault mechanism.",
      observation: obs,
    };
  }

  // 2) Version skew: inventory version ≠ required AND bytes do not match rebuild.
  if (
    (inv.version !== obs.manifest.required_version || inv.version !== man.version) &&
    measured !== trusted
  ) {
    return {
      mechanism: "dependency_version_skew",
      refused_dependency_install_conflation: true,
      reason: `Component version ${inv.version} skews from required ${obs.manifest.required_version}.`,
      observation: obs,
    };
  }

  // 3) Stale shared cache: generation lag on shared_cache provenance.
  if (
    inv.provenance === "shared_cache" &&
    obs.inventory.cache_identity.generation < obs.manifest.required_generation &&
    measured !== trusted
  ) {
    return {
      mechanism: "stale_shared_cache",
      refused_dependency_install_conflation: true,
      reason: `Cache generation ${obs.inventory.cache_identity.generation} < required ${obs.manifest.required_generation}.`,
      observation: obs,
    };
  }

  // 4) Reconciliation overwrite of a local change.
  if (
    obs.recon &&
    obs.recon.last_cycle_overwrote_local === true &&
    obs.local_intent &&
    obs.recon.local_intent_sha256 === obs.local_intent.measured_sha256 &&
    measured !== obs.local_intent.measured_sha256 &&
    (obs.bundled_entry
      ? measured === obs.bundled_entry.measured_sha256
      : measured === expected)
  ) {
    return {
      mechanism: "reconciliation_overwrite",
      refused_dependency_install_conflation: true,
      reason:
        "Reconciliation overwrote local intent; cache matches bundled baseline, not local change.",
      observation: obs,
    };
  }

  // 5) Bundled file corruption: current generation+version, hash mismatch.
  const generationCurrent =
    obs.inventory.cache_identity.generation >= obs.manifest.required_generation;
  const versionCurrent = inv.version === obs.manifest.required_version;
  if (
    generationCurrent &&
    versionCurrent &&
    measured !== expected &&
    measured !== trusted &&
    trustedMatchesManifest
  ) {
    return {
      mechanism: "bundled_file_corruption",
      refused_dependency_install_conflation: true,
      reason:
        "Cache entry hash mismatches expected/trusted bytes at current generation and version (corruption).",
      observation: obs,
    };
  }

  return {
    mechanism: null,
    refused_dependency_install_conflation: true,
    reason: "Insufficient exclusive evidence for a plugin-cache mechanism.",
    observation: obs,
  };
}
