/** Deterministic canonical JSON + digests for authorization binding. */

import crypto from "node:crypto";

/** Stable SHA-256 hex of UTF-8 text. */
export function sha256Text(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Canonical JSON: sorted object keys, no whitespace ambiguity, arrays preserved.
 * Rejects non-finite numbers and undefined (must be explicit null).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("Non-finite number in canonical JSON.");
    }
    if (typeof value === "undefined") {
      throw new Error("Undefined in canonical JSON.");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const v = obj[key];
    if (typeof v === "undefined") continue;
    out[key] = sortKeys(v);
  }
  return out;
}

export function digestObject(value: unknown): string {
  return sha256Text(canonicalJson(value));
}

export function receiptId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}
