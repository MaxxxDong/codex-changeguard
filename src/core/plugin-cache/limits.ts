/** Named candidates and bounds for Ticket 08 plugin-cache fault pack. */

export const MAX_PLUGIN_CACHE_FILE_BYTES = 128 * 1024;
export const MAX_PLUGIN_JSON_BYTES = 32 * 1024;

/** Inventory / manifest / component relative paths (named only — no cache crawl). */
export const PLUGIN_CACHE_DIR = "plugin-cache";
export const PLUGIN_INVENTORY_REL = "plugin-cache/inventory.json";
export const PLUGIN_MANIFEST_REL = "plugin-cache/manifest.json";
export const PLUGIN_CACHE_ENTRY_REL = "plugin-cache/cache/entry.js";
export const PLUGIN_BUNDLED_ENTRY_REL = "plugin-cache/bundled/entry.js";
export const PLUGIN_TRUSTED_ENTRY_REL = "plugin-cache/trusted/entry.js";
export const PLUGIN_RECON_STATE_REL = "plugin-cache/recon-state.json";
export const PLUGIN_HEALTH_REL = "plugin-cache/health.json";
export const PLUGIN_LOCAL_INTENT_REL = "plugin-cache/local-intent.js";
export const PLUGIN_QUARANTINE_REL = "plugin-cache/quarantine/entry.js.quarantined";

export const PLUGIN_CACHE_ENTRY_ALIAS = "PLUGIN_CACHE_ENTRY";
export const PLUGIN_MANIFEST_ALIAS = "PLUGIN_CACHE_MANIFEST";
export const PLUGIN_TRUSTED_ALIAS = "TRUSTED_PLUGIN_ENTRY";
export const PLUGIN_BUNDLED_ALIAS = "BUNDLED_PLUGIN_ENTRY";

/** Four exclusive mechanisms — never conflated with dependency-install failure. */
export type PluginCacheMechanism =
  | "bundled_file_corruption"
  | "stale_shared_cache"
  | "dependency_version_skew"
  | "reconciliation_overwrite";

export const PLUGIN_CACHE_MECHANISMS: readonly PluginCacheMechanism[] = [
  "bundled_file_corruption",
  "stale_shared_cache",
  "dependency_version_skew",
  "reconciliation_overwrite",
] as const;

export const PLUGIN_CACHE_CAPSULE_ID = "plugin-cache-skew-experimental-v1";
