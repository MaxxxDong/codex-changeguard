// CORRUPTED plugin entry
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.2.0";
export function health() {
  return { ok: false, version: VERSION, corrupt: true };
}
