import crypto from "node:crypto";

/** Deterministic canonical JSON: sorted object keys, no insignificant whitespace. */
export function canonicalStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort((a, b) => a.localeCompare(b));
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    out[k] = sortValue(obj[k]);
  }
  return out;
}

export function sha256Canonical(value: unknown): string {
  return crypto
    .createHash("sha256")
    .update(canonicalStringify(value), "utf8")
    .digest("hex");
}

export function sha256Text(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}
