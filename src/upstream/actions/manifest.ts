import { sha256Canonical } from "../../evidence/canonical.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import {
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_NAME,
  MAX_ATTACHMENTS,
  MAX_BODY,
  MAX_COMMENT,
  MAX_STRING,
  MAX_TITLE,
  FORBIDDEN_ACTION_KEYS,
} from "./limits.js";
import type {
  AttachmentManifest,
  AttachmentManifestEntry,
  BodyManifest,
  UpstreamActionKind,
} from "./types.js";
import type { UpstreamSubmissionCapsule } from "../types.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const SAFE_NAME = /^[A-Za-z0-9._-]+$/;
const SAFE_MEDIA = /^(text|image|application)\/[a-z0-9.+-]+$/i;

export class ManifestError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "ManifestError";
  }
}

function sanitize(s: string, max: number): string {
  return assertNoLeakPaths(redactText(s)).slice(0, max);
}

function refuseForbiddenKeys(obj: unknown, path = "root"): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) refuseForbiddenKeys(obj[i], `${path}[${i}]`);
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const lower = k.toLowerCase();
    // Exact-key match only (session_excluded is a privacy flag, not a secret).
    if ((FORBIDDEN_ACTION_KEYS as readonly string[]).includes(lower)) {
      throw new ManifestError(
        "FORBIDDEN_KEY",
        `Forbidden key refused at ${path}.${k}.`,
      );
    }
    refuseForbiddenKeys(v, `${path}.${k}`);
  }
}

export function buildBodyManifest(
  action: UpstreamActionKind,
  capsule: UpstreamSubmissionCapsule,
): BodyManifest {
  let title: string | null = null;
  let body: string | null = null;
  let reaction: string | null = null;

  if (action === "create_issue") {
    title = capsule.draft_title
      ? sanitize(capsule.draft_title, MAX_TITLE)
      : "ChangeGuard-reported Codex issue";
    body = capsule.duplicate.draft_body
      ? sanitize(capsule.duplicate.draft_body, MAX_BODY)
      : null;
    if (!body) {
      throw new ManifestError(
        "MISSING_BODY",
        "create_issue requires a draft body on the capsule.",
      );
    }
  } else if (action === "comment_with_delta") {
    body = capsule.duplicate.draft_comment
      ? sanitize(capsule.duplicate.draft_comment, MAX_COMMENT)
      : null;
    if (!body) {
      throw new ManifestError(
        "MISSING_COMMENT",
        "comment_with_delta requires a draft comment on the capsule.",
      );
    }
  } else if (action === "react_upvote") {
    reaction = "+1";
  } else if (action === "subscribe") {
    // no body
  } else if (action === "attachment_upload") {
    // body optional; attachments required separately
  }

  const content_sha256 = sha256Canonical({ title, body, reaction, action });
  return { title, body, reaction, content_sha256 };
}

export function parseAttachmentManifest(
  raw: unknown,
): AttachmentManifest | null {
  if (raw === undefined || raw === null) return null;
  refuseForbiddenKeys(raw, "attachment_manifest");
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new ManifestError(
      "ATTACH_SHAPE",
      "attachment_manifest must be an object.",
    );
  }
  const o = raw as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new ManifestError(
      "ATTACH_SCHEMA",
      "attachment_manifest.schema_version must be 1.",
    );
  }
  if (!Array.isArray(o.entries)) {
    throw new ManifestError(
      "ATTACH_ENTRIES",
      "attachment_manifest.entries must be an array.",
    );
  }
  if (o.entries.length > MAX_ATTACHMENTS) {
    throw new ManifestError(
      "ATTACH_COUNT",
      `At most ${MAX_ATTACHMENTS} attachments.`,
    );
  }
  const entries: AttachmentManifestEntry[] = [];
  for (const ent of o.entries) {
    if (ent === null || typeof ent !== "object" || Array.isArray(ent)) {
      throw new ManifestError("ATTACH_ENTRY", "Invalid attachment entry.");
    }
    const e = ent as Record<string, unknown>;
    const name = e.name;
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      name.length > MAX_ATTACHMENT_NAME ||
      !SAFE_NAME.test(name) ||
      name.includes("..") ||
      name.includes("/") ||
      name.includes("\\")
    ) {
      throw new ManifestError(
        "ATTACH_NAME",
        "Attachment name must be a safe basename.",
      );
    }
    if (typeof e.content_sha256 !== "string" || !SHA256_HEX.test(e.content_sha256)) {
      throw new ManifestError(
        "ATTACH_HASH",
        "Attachment content_sha256 must be 64 hex chars.",
      );
    }
    if (
      typeof e.byte_length !== "number" ||
      !Number.isInteger(e.byte_length) ||
      e.byte_length < 0 ||
      e.byte_length > MAX_ATTACHMENT_BYTES
    ) {
      throw new ManifestError(
        "ATTACH_SIZE",
        `Attachment byte_length must be 0..${MAX_ATTACHMENT_BYTES}.`,
      );
    }
    if (
      typeof e.media_type !== "string" ||
      e.media_type.length > MAX_STRING ||
      !SAFE_MEDIA.test(e.media_type)
    ) {
      throw new ManifestError(
        "ATTACH_MEDIA",
        "Attachment media_type refused.",
      );
    }
    if (
      e.secrets_redacted !== true ||
      e.paths_redacted !== true ||
      e.session_excluded !== true
    ) {
      throw new ManifestError(
        "ATTACH_PRIVACY",
        "Attachment privacy flags must all be true (secrets/paths redacted, session excluded).",
      );
    }
    entries.push({
      name,
      content_sha256: e.content_sha256,
      byte_length: e.byte_length,
      media_type: e.media_type,
      secrets_redacted: true,
      paths_redacted: true,
      session_excluded: true,
    });
  }
  const manifest_sha256 = sha256Canonical({ schema_version: 1, entries });
  if (
    typeof o.manifest_sha256 === "string" &&
    o.manifest_sha256 !== manifest_sha256
  ) {
    throw new ManifestError(
      "ATTACH_MANIFEST_HASH",
      "attachment_manifest.manifest_sha256 mismatch.",
    );
  }
  return {
    schema_version: 1,
    entries,
    manifest_sha256,
  };
}

/**
 * Official GitHub issue/repo targets only. Do not run path-redaction on URLs
 * (redactText treats `https://…` as an absolute path after the colon).
 */
const OFFICIAL_ISSUE_URL_RE =
  /^https:\/\/github\.com\/openai\/codex\/issues(?:\/\d+)?$/;
const OFFICIAL_ISSUES_ROOT = "https://github.com/openai/codex/issues";

function officialIssueUrl(url: string): string | null {
  const trimmed = url.trim();
  if (!OFFICIAL_ISSUE_URL_RE.test(trimmed)) return null;
  if (trimmed.length > 512) return null;
  return trimmed;
}

/**
 * Resolve canonical remote target for the action from the capsule.
 */
export function resolveCanonicalTarget(
  action: UpstreamActionKind,
  capsule: UpstreamSubmissionCapsule,
): string {
  if (action === "create_issue") {
    return OFFICIAL_ISSUES_ROOT;
  }
  const url = capsule.duplicate.matched_issue_url;
  const id = capsule.duplicate.matched_issue_id;
  if (typeof url === "string") {
    const official = officialIssueUrl(url);
    if (official) return official;
  }
  if (typeof id === "string" && id.includes("#")) {
    // e.g. openai/codex#9001
    const m = /^openai\/codex#(\d+)$/.exec(id);
    if (m) return `${OFFICIAL_ISSUES_ROOT}/${m[1]}`;
  }
  // attachment_upload without a matched issue still binds the repo issues root
  // (host creates the issue first); other issue-scoped actions require a match.
  if (action === "attachment_upload") {
    return OFFICIAL_ISSUES_ROOT;
  }
  if (
    action === "comment_with_delta" ||
    action === "react_upvote" ||
    action === "subscribe"
  ) {
    throw new ManifestError(
      "MISSING_TARGET",
      "Action requires a matched official issue URL/id on the capsule.",
    );
  }
  return OFFICIAL_ISSUES_ROOT;
}
