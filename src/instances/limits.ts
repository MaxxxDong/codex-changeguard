/** Bounds for Ticket 03 instance / fingerprint state + local artifact baselines. */

export const MAX_STATE_BYTES = 256 * 1024;
export const MAX_INVENTORY_BYTES = 64 * 1024;
/** Default bound for version.json / package.json / MSIX manifest metadata. */
export const MAX_VERSION_META_BYTES = 16 * 1024;
/**
 * Separate bound for App Bundle Info.plist (and other .plist) version metadata.
 * Real ChatGPT.app Info.plist is often ~20 KiB; keep a hard cap without relaxing
 * the 16 KiB JSON/manifest limit.
 */
export const MAX_PLIST_VERSION_META_BYTES = 64 * 1024;
export const MAX_INSTANCES = 64;
export const MAX_STRING = 512;
export const STATE_FILE_NAME = "version-fingerprint.json";
export const INVENTORY_FILE_NAME = "inventory.json";
/** Persisted state is always written as v2; load remains backward-readable from v1. */
export const STATE_SCHEMA_VERSION = 2 as const;
export const STATE_SCHEMA_VERSION_V1 = 1 as const;

/**
 * Per-file streaming hash cap. Sized for real macOS ChatGPT bundle components
 * (~265 MiB codex + ~198 MiB app.asar + ~3 MiB CodeResources). Over-cap is an
 * explicit gap — never a truncated hash.
 */
export const MAX_ARTIFACT_FILE_BYTES = 512 * 1024 * 1024;
/** Aggregate bytes hashed per scan (all named candidates). */
export const MAX_ARTIFACT_SCAN_BYTES = 1024 * 1024 * 1024;
/** Named artifact entries retained per instance (path-free). */
export const MAX_ARTIFACT_ENTRIES_PER_INSTANCE = 16;
/** Keys listed in SessionStart path-free context. */
export const MAX_ARTIFACT_CONTEXT_KEYS = 24;
/** Logical key / alias string bound. */
export const MAX_ARTIFACT_KEY_LEN = 64;
/** Streaming read chunk for SHA-256 (never loads whole file). */
export const ARTIFACT_HASH_CHUNK_BYTES = 1024 * 1024;
/**
 * Default wall-clock budget for packaged/session_start artifact measurement.
 * Leaves headroom under the 10s SessionStart hook timeout for enumeration + state I/O.
 */
export const DEFAULT_SESSION_START_ARTIFACT_TIME_BUDGET_MS = 4000;
