// Local override that reconciliation should not silently discard
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.2.0";
export const LOCAL_PATCH = true;
export function health() {
  return { ok: true, version: VERSION, local: true };
}
