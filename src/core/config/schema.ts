/**
 * Bounded Codex control configuration schema (Ticket 07).
 * Known keys only — unknown structure is refused, never silently accepted.
 * Does not execute configuration or import project code.
 */

/** Obsolete keys that must not appear in control config. */
export const OBSOLETE_CONFIG_KEYS = new Set([
  "legacy_experimental_shell",
  "old_sandbox_mode_v0",
]);

/** Top-level keys allowed in primary/override control TOML. */
export const KNOWN_TOP_LEVEL_KEYS = new Set([
  "model",
  "model_provider",
  "notify",
  "shell_environment_policy",
  "features",
  // obsolete keys are known so they classify as obsolete rather than unknown
  "legacy_experimental_shell",
  "old_sandbox_mode_v0",
]);

export type TomlValueType =
  | "string"
  | "boolean"
  | "integer"
  | "float"
  | "table"
  | "array"
  | "null"
  | "unknown";

export interface TomlValue {
  type: TomlValueType;
  /** Primitive or nested table/array representation. */
  value: unknown;
}

export type TomlTable = Map<string, TomlValue>;

/** Expected type for a dotted config path under the supported schema. */
export function expectedTypeForKey(dottedKey: string): TomlValueType | "string_table" | null {
  if (dottedKey === "model" || dottedKey === "model_provider") return "string";
  if (dottedKey === "notify") return "boolean";
  if (dottedKey === "shell_environment_policy") return "table";
  if (dottedKey === "shell_environment_policy.set") return "string_table";
  if (dottedKey === "features") return "table";
  if (dottedKey.startsWith("features.")) return "boolean";
  if (OBSOLETE_CONFIG_KEYS.has(dottedKey)) return "unknown";
  if (KNOWN_TOP_LEVEL_KEYS.has(dottedKey)) return "unknown";
  return null;
}

export function isSecretConfigKey(dottedKey: string): boolean {
  const lower = dottedKey.toLowerCase();
  // Nested keys under shell_environment_policy.set.* may hold secrets.
  // The set table path itself is not secret (structure only).
  if (lower.startsWith("shell_environment_policy.set.")) return true;
  return (
    lower.includes("token") ||
    lower.includes("secret") ||
    lower.includes("password") ||
    lower.includes("api_key") ||
    lower.includes("apikey")
  );
}
