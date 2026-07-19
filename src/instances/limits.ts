/** Bounds for Ticket 03 instance / fingerprint state. */

export const MAX_STATE_BYTES = 64 * 1024;
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
export const STATE_SCHEMA_VERSION = 1 as const;
