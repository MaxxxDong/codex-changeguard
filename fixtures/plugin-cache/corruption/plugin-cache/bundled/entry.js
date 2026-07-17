// ChangeGuard trusted plugin entry v1.2.0
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.2.0";
export function health() {
  return { ok: true, version: VERSION };
}
