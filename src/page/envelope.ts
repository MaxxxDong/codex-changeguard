import { sha256Text } from "../evidence/canonical.js";
import { nfkc, redactText } from "../core/redact.js";
import {
  ALLOWED_ENVELOPE_KEYS,
  ALLOWED_METADATA_KEYS,
  FORBIDDEN_PAGE_ENVELOPE_KEYS,
  MAX_PAGE_ENVELOPE_BYTES,
  MAX_PAGE_METADATA_KEYS,
  MAX_PAGE_METADATA_TOKEN,
  MAX_PAGE_TITLE,
  MAX_PAGE_URL_LENGTH,
  MAX_PAGE_VISIBLE_TEXT,
} from "./limits.js";
import type { PageEvidenceEnvelope, PageMetadata, PageMode } from "./types.js";

export class PageEnvelopeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PageEnvelopeError";
    this.code = code;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function rejectForbiddenKeys(
  obj: Record<string, unknown>,
  pathPrefix: string,
): void {
  for (const key of Object.keys(obj)) {
    const lower = key.toLowerCase();
    if (
      FORBIDDEN_PAGE_ENVELOPE_KEYS.some(
        (f) => f.toLowerCase() === lower || lower.includes(f.toLowerCase()),
      )
    ) {
      throw new PageEnvelopeError(
        "FORBIDDEN_PRIVACY_FIELD",
        `Page envelope rejects privacy-sensitive field: ${pathPrefix}${key}`,
      );
    }
  }
}

function parsePageMode(v: unknown): PageMode {
  if (v === "public" || v === "logged_visible") return v;
  throw new PageEnvelopeError("INVALID_PAGE_MODE", "Invalid page_mode.");
}

function parseMetadata(raw: unknown): PageMetadata {
  if (raw === undefined || raw === null) return {};
  if (!isPlainObject(raw)) {
    throw new PageEnvelopeError("INVALID_METADATA", "metadata must be an object.");
  }
  rejectForbiddenKeys(raw, "metadata.");
  const keys = Object.keys(raw);
  if (keys.length > MAX_PAGE_METADATA_KEYS) {
    throw new PageEnvelopeError("METADATA_LIMIT", "Too many metadata keys.");
  }
  for (const k of keys) {
    if (!(ALLOWED_METADATA_KEYS as readonly string[]).includes(k)) {
      throw new PageEnvelopeError(
        "EXTRA_METADATA_KEY",
        `Unknown metadata key: ${k}`,
      );
    }
  }
  const out: PageMetadata = {};
  if (raw.host !== undefined) {
    if (typeof raw.host !== "string" || raw.host.length > MAX_PAGE_METADATA_TOKEN) {
      throw new PageEnvelopeError("INVALID_METADATA", "Invalid metadata.host.");
    }
    out.host = nfkc(raw.host).slice(0, MAX_PAGE_METADATA_TOKEN);
  }
  if (raw.content_type !== undefined) {
    if (
      typeof raw.content_type !== "string" ||
      raw.content_type.length > MAX_PAGE_METADATA_TOKEN
    ) {
      throw new PageEnvelopeError(
        "INVALID_METADATA",
        "Invalid metadata.content_type.",
      );
    }
    out.content_type = nfkc(raw.content_type).slice(0, MAX_PAGE_METADATA_TOKEN);
  }
  if (raw.language !== undefined) {
    if (
      typeof raw.language !== "string" ||
      raw.language.length > MAX_PAGE_METADATA_TOKEN
    ) {
      throw new PageEnvelopeError(
        "INVALID_METADATA",
        "Invalid metadata.language.",
      );
    }
    out.language = nfkc(raw.language).slice(0, MAX_PAGE_METADATA_TOKEN);
  }
  if (raw.status_code !== undefined) {
    if (
      typeof raw.status_code !== "number" ||
      !Number.isInteger(raw.status_code) ||
      raw.status_code < 100 ||
      raw.status_code > 599
    ) {
      throw new PageEnvelopeError(
        "INVALID_METADATA",
        "Invalid metadata.status_code.",
      );
    }
    out.status_code = raw.status_code;
  }
  if (raw.source_label !== undefined) {
    if (
      typeof raw.source_label !== "string" ||
      raw.source_label.length > MAX_PAGE_METADATA_TOKEN
    ) {
      throw new PageEnvelopeError(
        "INVALID_METADATA",
        "Invalid metadata.source_label.",
      );
    }
    out.source_label = nfkc(raw.source_label).slice(0, MAX_PAGE_METADATA_TOKEN);
  }
  return out;
}

/**
 * Parse and validate a page-evidence envelope from JSON text or object.
 * Rejects extra top-level keys, oversized payloads, and privacy-sensitive fields.
 */
export function parsePageEnvelope(input: unknown): PageEvidenceEnvelope {
  let obj: Record<string, unknown>;
  if (typeof input === "string") {
    const bytes = Buffer.byteLength(input, "utf8");
    if (bytes > MAX_PAGE_ENVELOPE_BYTES) {
      throw new PageEnvelopeError(
        "SIZE_LIMIT",
        "Page envelope exceeds size limit.",
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(input);
    } catch {
      throw new PageEnvelopeError("MALFORMED_JSON", "Malformed page envelope JSON.");
    }
    if (!isPlainObject(parsed)) {
      throw new PageEnvelopeError("MALFORMED_JSON", "Page envelope must be an object.");
    }
    obj = parsed;
  } else if (isPlainObject(input)) {
    const bytes = Buffer.byteLength(JSON.stringify(input), "utf8");
    if (bytes > MAX_PAGE_ENVELOPE_BYTES) {
      throw new PageEnvelopeError(
        "SIZE_LIMIT",
        "Page envelope exceeds size limit.",
      );
    }
    obj = input;
  } else {
    throw new PageEnvelopeError("MALFORMED_JSON", "Page envelope must be an object.");
  }

  rejectForbiddenKeys(obj, "");

  for (const k of Object.keys(obj)) {
    if (!(ALLOWED_ENVELOPE_KEYS as readonly string[]).includes(k)) {
      throw new PageEnvelopeError("EXTRA_KEY", `Unknown envelope key: ${k}`);
    }
  }

  if (obj.schema_version !== 1) {
    throw new PageEnvelopeError(
      "SCHEMA_VERSION",
      "Page envelope schema_version must be 1.",
    );
  }
  if (typeof obj.url !== "string" || obj.url.length === 0) {
    throw new PageEnvelopeError("INVALID_URL", "Page envelope url required.");
  }
  if (obj.url.length > MAX_PAGE_URL_LENGTH) {
    throw new PageEnvelopeError("URL_LIMIT", "Page URL exceeds length limit.");
  }
  // Basic URL shape; do not fetch.
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(obj.url);
  } catch {
    throw new PageEnvelopeError("INVALID_URL", "Page URL is not a valid absolute URL.");
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new PageEnvelopeError(
      "INVALID_URL",
      "Page URL must be http or https.",
    );
  }
  // Reject userinfo (credentials in URL).
  if (parsedUrl.username || parsedUrl.password) {
    throw new PageEnvelopeError(
      "INVALID_URL",
      "Page URL must not contain userinfo credentials.",
    );
  }

  const page_mode = parsePageMode(obj.page_mode);

  if (typeof obj.visible_text !== "string") {
    throw new PageEnvelopeError(
      "INVALID_VISIBLE_TEXT",
      "visible_text must be a string.",
    );
  }
  if (Buffer.byteLength(obj.visible_text, "utf8") > MAX_PAGE_VISIBLE_TEXT) {
    throw new PageEnvelopeError(
      "VISIBLE_TEXT_LIMIT",
      "visible_text exceeds size limit.",
    );
  }

  let visible_title = "";
  if (obj.visible_title !== undefined) {
    if (typeof obj.visible_title !== "string") {
      throw new PageEnvelopeError(
        "INVALID_TITLE",
        "visible_title must be a string.",
      );
    }
    if (obj.visible_title.length > MAX_PAGE_TITLE) {
      throw new PageEnvelopeError("TITLE_LIMIT", "visible_title exceeds limit.");
    }
    visible_title = obj.visible_title;
  }

  const metadata = parseMetadata(obj.metadata);
  // If host omitted, derive from URL (sanitized hostname only).
  if (!metadata.host) {
    metadata.host = parsedUrl.hostname.toLowerCase();
  }

  // NFKC + strip null/CR; redaction applied at output time for secrets/paths.
  const visible_text = nfkc(obj.visible_text)
    .replace(/\0/g, "")
    .replace(/\r/g, "");
  visible_title = nfkc(visible_title).replace(/\0/g, "").replace(/\r/g, "");

  return {
    schema_version: 1,
    url: obj.url,
    page_mode,
    visible_title,
    visible_text,
    metadata,
  };
}

export function envelopeContentSha256(env: PageEvidenceEnvelope): string {
  return sha256Text(
    `${env.url}\n${env.page_mode}\n${env.visible_title}\n${env.visible_text}`,
  );
}

export function titleSha256(env: PageEvidenceEnvelope): string {
  return sha256Text(env.visible_title);
}

/** Redact envelope text fields for any residual public output paths. */
export function redactEnvelopeText(text: string): string {
  return redactText(text);
}
