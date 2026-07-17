/**
 * Redacted summaries of config values for Repair Capsules.
 * Never exports secret material; type + bounded length only.
 */
import { isSecretConfigKey, type TomlValue, type TomlValueType } from "./schema.js";
import { MAX_CONFIG_VALUE_CHARS } from "./limits.js";

export function summarizeValueType(v: TomlValue | null | undefined): TomlValueType {
  if (!v) return "null";
  return v.type;
}

/**
 * Human-readable redacted summary: type and optional non-secret length.
 * Secret keys always return type-only redaction.
 */
export function redactedValueSummary(
  dottedKey: string,
  v: TomlValue | null | undefined,
): string {
  if (!v) return "null";
  if (isSecretConfigKey(dottedKey)) {
    return `${v.type}(redacted)`;
  }
  switch (v.type) {
    case "string": {
      const s = typeof v.value === "string" ? v.value : "";
      const len = Math.min(s.length, MAX_CONFIG_VALUE_CHARS);
      // Never include string content — length only.
      return `string(len=${len})`;
    }
    case "boolean":
      return `boolean(${v.value === true ? "true" : "false"})`;
    case "integer":
    case "float":
      return `${v.type}`;
    case "table":
      return `table(keys=${countTableKeys(v.value)})`;
    case "array":
      return `array(len=${Array.isArray(v.value) ? v.value.length : 0})`;
    default:
      return `${v.type}(redacted)`;
  }
}

/**
 * New value encoding for capsule export.
 * Only non-secret, registered fix values are emitted as literal text;
 * secret targets emit redacted placeholders only.
 */
export function encodeNewValueForCapsule(
  dottedKey: string,
  newValueText: string | null,
): string | null {
  if (newValueText === null) return null;
  if (isSecretConfigKey(dottedKey)) {
    return "<redacted>";
  }
  if (newValueText.length > MAX_CONFIG_VALUE_CHARS) {
    return newValueText.slice(0, MAX_CONFIG_VALUE_CHARS);
  }
  return newValueText;
}

function countTableKeys(value: unknown): number {
  if (value instanceof Map) return value.size;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return Object.keys(value as object).length;
  }
  return 0;
}
