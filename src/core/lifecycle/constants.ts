/** Registered paths and bounds for Ticket 06 lifecycle (ChangeGuard-owned only). */

import type { ControlSurface } from "./types.js";

export const LIFECYCLE_SCHEMA_VERSION = 1 as const;

/** Root of lifecycle state under an isolated target. */
export const LIFECYCLE_DIR = ".changeguard/lifecycle";
export const LIFECYCLE_LEDGER_REL = `${LIFECYCLE_DIR}/ledger.json`;
export const LIFECYCLE_BACKUPS_DIR = `${LIFECYCLE_DIR}/backups`;
export const LIFECYCLE_SURFACES_DIR = `${LIFECYCLE_DIR}/surfaces`;

/** Ordinary repair backups remain at least this long. */
export const REPAIR_BACKUP_MIN_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Ordinary repair backups remain across at least this many successful starts. */
export const REPAIR_BACKUP_MIN_STARTS = 3;

/** Last N healthy control-plane checkpoints retained as KNOWN_GOOD per surface. */
export const KNOWN_GOOD_RETAIN_COUNT = 3;

export const MAX_LEDGER_BYTES = 256 * 1024;
export const MAX_SURFACE_BYTES = 256 * 1024;
export const MAX_INSTANCE_ID_LEN = 128;
export const MAX_RECIPE_ID_LEN = 128;
export const MAX_VERSION_LEN = 64;
export const MAX_RECORDS = 64;

/**
 * Registered live control-surface relative paths under isolated fixtures.
 * Never accept absolute paths from callers for mutation targets.
 */
export const SURFACE_TARGET_REL: Record<ControlSurface, string> = {
  config: "control/config.json",
  plugin: "control/plugin.json",
  skill: "control/skill.json",
  mcp: "control/mcp.json",
  hook: "control/hook.json",
};

export function registeredRepairBackupRel(backupId: string): string {
  return `${LIFECYCLE_BACKUPS_DIR}/${backupId}.bak`;
}

export function registeredKnownGoodBackupRel(
  surface: ControlSurface,
  checkpointId: string,
): string {
  return `${LIFECYCLE_SURFACES_DIR}/${surface}/${checkpointId}.bak`;
}

export function isControlSurface(v: string): v is ControlSurface {
  return (
    v === "config" ||
    v === "plugin" ||
    v === "skill" ||
    v === "mcp" ||
    v === "hook"
  );
}
