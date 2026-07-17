export {
  observePluginCache,
  isPluginCacheTarget,
  PluginCacheError,
} from "./measure.js";
export { classifyPluginCacheMechanism } from "./classify.js";
export type {
  PluginCacheObservation,
  MechanismClassification,
  PluginInventory,
  PluginManifest,
} from "./types.js";
export {
  PLUGIN_CACHE_MECHANISMS,
  PLUGIN_CACHE_CAPSULE_ID,
  PLUGIN_CACHE_ENTRY_ALIAS,
  PLUGIN_CACHE_ENTRY_REL,
  PLUGIN_MANIFEST_REL,
  PLUGIN_TRUSTED_ENTRY_REL,
  PLUGIN_QUARANTINE_REL,
  type PluginCacheMechanism,
} from "./limits.js";
