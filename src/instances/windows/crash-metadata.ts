/**
 * Bounded Windows crash metadata reader (Ticket 14).
 * Accepts only allowlisted structured fields; never dump bodies.
 */
import crypto from "node:crypto";
import type { WindowsCrashMetadataWindow } from "./types.js";

const ALLOWED_KEYS = new Set([
  "exception_code",
  "faulting_module",
  "faulting_symbol",
  "offset_bucket",
  "interaction_phase",
  "page_capability",
  "concurrency_context",
  "gpu_child_exit_code",
  "gpu_relaunch_code",
  // Common alternate names from CrashMetadata incident shape:
  "exception_codes",
  "module",
  "symbol",
  "offset",
  "dump_contents",
  "dump_contents_present",
  "minidump",
  "dump_body",
]);

const FORBIDDEN_BODY_KEYS = new Set([
  "dump_contents",
  "minidump",
  "dump_body",
  "raw_dump",
  "memory_dump",
]);

export class CrashMetadataError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CrashMetadataError";
    this.code = code;
  }
}

function asString(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim();
  if (t.length === 0 || t.length > 256) return null;
  return t;
}

function asNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^-?\d+$/.test(v)) return Number(v);
  return null;
}

/**
 * Parse a crash-metadata object into a bounded window.
 * Any dump body key causes refusal (not silent strip into evidence).
 */
export function parseCrashMetadataWindow(
  input: unknown,
): WindowsCrashMetadataWindow {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new CrashMetadataError(
      "INVALID_METADATA",
      "Crash metadata must be an object.",
    );
  }
  const obj = input as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_BODY_KEYS.has(key)) {
      throw new CrashMetadataError(
        "DUMP_BODY_REFUSED",
        "Crash dump bodies are refused; only structured metadata is allowed.",
      );
    }
    if (!ALLOWED_KEYS.has(key)) {
      throw new CrashMetadataError(
        "UNKNOWN_METADATA_KEY",
        `Unknown crash metadata key refused: ${key}`,
      );
    }
  }

  if (obj.dump_contents_present === true) {
    throw new CrashMetadataError(
      "DUMP_BODY_REFUSED",
      "dump_contents_present must not be true.",
    );
  }

  const exception_code =
    asString(obj.exception_code) ??
    (Array.isArray(obj.exception_codes)
      ? asString(obj.exception_codes[0])
      : null);
  const faulting_module =
    asString(obj.faulting_module) ?? asString(obj.module);
  const faulting_symbol =
    asString(obj.faulting_symbol) ?? asString(obj.symbol);
  const offset_bucket =
    asString(obj.offset_bucket) ?? asString(obj.offset);

  const window: Omit<WindowsCrashMetadataWindow, "metadata_digest"> = {
    exception_code,
    faulting_module,
    faulting_symbol,
    offset_bucket,
    interaction_phase: asString(obj.interaction_phase),
    page_capability: asString(obj.page_capability),
    concurrency_context: asString(obj.concurrency_context),
    gpu_child_exit_code: asNumber(obj.gpu_child_exit_code),
    gpu_relaunch_code: asNumber(obj.gpu_relaunch_code),
    dump_contents_present: false,
  };

  const digest = crypto
    .createHash("sha256")
    .update(JSON.stringify(window))
    .digest("hex");

  return { ...window, metadata_digest: digest };
}
