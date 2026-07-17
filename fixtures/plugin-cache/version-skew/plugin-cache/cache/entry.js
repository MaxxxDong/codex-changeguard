// Version-skewed entry
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "0.9.0";
export function health() {
  return { ok: true, version: VERSION };
}
