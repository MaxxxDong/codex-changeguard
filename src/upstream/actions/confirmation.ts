/**
 * One-shot confirmation binding: nonce + expiry + exact binding digests.
 * Not an auth token; never carries secrets, cookies, or session material.
 */
import crypto from "node:crypto";
import { sha256Canonical } from "../../evidence/canonical.js";
import {
  CONFIRMATION_TOKEN_PREFIX,
  CONFIRMATION_TTL_MS,
  MAX_CONFIRMATION_BYTES,
  FORBIDDEN_ACTION_KEYS,
} from "./limits.js";
import type {
  ActionConfirmationBinding,
  AttachmentManifest,
  BodyManifest,
  PrivacyBinding,
  UpstreamActionKind,
} from "./types.js";

export type ConfirmationErrorCode =
  | "INVALID_CONFIRMATION"
  | "EXPIRED_CONFIRMATION"
  | "REPLAYED_CONFIRMATION"
  | "MALFORMED_CONFIRMATION";

export class ConfirmationError extends Error {
  readonly code: ConfirmationErrorCode;
  constructor(code: ConfirmationErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "ConfirmationError";
  }
}

const NONCE_HEX = /^[a-f0-9]{32}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const CONFIRMATION_ID_RE = /^uac_[a-f0-9]{24}$/;

/** In-process one-shot registry: successful decode+confirm consumes nonce. */
const consumedNonces = new Set<string>();

export function _resetConsumedNoncesForTests(): void {
  consumedNonces.clear();
}

function bindingMaterial(
  b: Omit<ActionConfirmationBinding, "binding_sha256">,
): unknown {
  return {
    schema_version: b.schema_version,
    confirmation_id: b.confirmation_id,
    action: b.action,
    canonical_target: b.canonical_target,
    body_manifest: b.body_manifest,
    attachment_manifest: b.attachment_manifest,
    incident_fingerprint_digest: b.incident_fingerprint_digest,
    evidence_delta_hash: b.evidence_delta_hash,
    capsule_content_sha256: b.capsule_content_sha256,
    capsule_id: b.capsule_id,
    privacy: b.privacy,
    nonce: b.nonce,
    expires_at: b.expires_at,
    idempotency_key: b.idempotency_key,
  };
}

export function computeBindingSha256(
  b: Omit<ActionConfirmationBinding, "binding_sha256">,
): string {
  return sha256Canonical(bindingMaterial(b));
}

export function mintConfirmation(input: {
  action: UpstreamActionKind;
  canonical_target: string;
  body_manifest: BodyManifest | null;
  attachment_manifest: AttachmentManifest | null;
  incident_fingerprint_digest: string;
  evidence_delta_hash: string | null;
  capsule_content_sha256: string;
  capsule_id: string;
  privacy: PrivacyBinding;
  idempotency_key: string;
  nowMs?: number;
  ttlMs?: number;
  nonce?: string;
}): { binding: ActionConfirmationBinding; token: string } {
  const now = input.nowMs ?? Date.now();
  const ttl = input.ttlMs ?? CONFIRMATION_TTL_MS;
  const nonce =
    input.nonce ?? crypto.randomBytes(16).toString("hex");
  const confirmation_id = `uac_${sha256Canonical({
    nonce,
    action: input.action,
    capsule_id: input.capsule_id,
  }).slice(0, 24)}`;
  const expires_at = new Date(now + ttl).toISOString();

  const partial: Omit<ActionConfirmationBinding, "binding_sha256"> = {
    schema_version: 1,
    confirmation_id,
    action: input.action,
    canonical_target: input.canonical_target,
    body_manifest: input.body_manifest,
    attachment_manifest: input.attachment_manifest,
    incident_fingerprint_digest: input.incident_fingerprint_digest,
    evidence_delta_hash: input.evidence_delta_hash,
    capsule_content_sha256: input.capsule_content_sha256,
    capsule_id: input.capsule_id,
    privacy: input.privacy,
    nonce,
    expires_at,
    idempotency_key: input.idempotency_key,
  };
  const binding: ActionConfirmationBinding = {
    ...partial,
    binding_sha256: computeBindingSha256(partial),
  };
  const token =
    CONFIRMATION_TOKEN_PREFIX +
    Buffer.from(JSON.stringify(binding), "utf8").toString("base64url");
  return { binding, token };
}

function refuseForbidden(obj: unknown): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (const v of obj) refuseForbidden(v);
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const lower = k.toLowerCase();
    // Exact-key match only — do not substring-match session_excluded / content_sha256.
    if ((FORBIDDEN_ACTION_KEYS as readonly string[]).includes(lower)) {
      throw new ConfirmationError(
        "MALFORMED_CONFIRMATION",
        `Forbidden key in confirmation: ${k}`,
      );
    }
    refuseForbidden(v);
  }
}

export function parseConfirmationToken(
  token: string,
  nowMs?: number,
  opts?: { allowConsumed?: boolean },
): ActionConfirmationBinding {
  if (typeof token !== "string" || !token.startsWith(CONFIRMATION_TOKEN_PREFIX)) {
    throw new ConfirmationError(
      "MALFORMED_CONFIRMATION",
      "Confirmation token prefix refused.",
    );
  }
  const b64 = token.slice(CONFIRMATION_TOKEN_PREFIX.length);
  let json: string;
  try {
    json = Buffer.from(b64, "base64url").toString("utf8");
  } catch {
    throw new ConfirmationError(
      "MALFORMED_CONFIRMATION",
      "Confirmation token encoding refused.",
    );
  }
  if (Buffer.byteLength(json, "utf8") > MAX_CONFIRMATION_BYTES) {
    throw new ConfirmationError(
      "MALFORMED_CONFIRMATION",
      "Confirmation token exceeds size limit.",
    );
  }
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new ConfirmationError(
      "MALFORMED_CONFIRMATION",
      "Confirmation token JSON malformed.",
    );
  }
  refuseForbidden(raw);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ConfirmationError(
      "MALFORMED_CONFIRMATION",
      "Confirmation must be an object.",
    );
  }
  const o = raw as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "schema_version refused.",
    );
  }
  if (
    typeof o.confirmation_id !== "string" ||
    !CONFIRMATION_ID_RE.test(o.confirmation_id)
  ) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "confirmation_id refused.",
    );
  }
  const action = o.action;
  const allowed = new Set([
    "create_issue",
    "comment_with_delta",
    "react_upvote",
    "subscribe",
    "attachment_upload",
  ]);
  if (typeof action !== "string" || !allowed.has(action)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "action refused.",
    );
  }
  if (typeof o.canonical_target !== "string" || o.canonical_target.length === 0) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "canonical_target refused.",
    );
  }
  if (
    typeof o.incident_fingerprint_digest !== "string" ||
    !SHA256_HEX.test(o.incident_fingerprint_digest)
  ) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "incident_fingerprint_digest refused.",
    );
  }
  if (
    o.evidence_delta_hash !== null &&
    (typeof o.evidence_delta_hash !== "string" ||
      !SHA256_HEX.test(o.evidence_delta_hash))
  ) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "evidence_delta_hash refused.",
    );
  }
  if (
    typeof o.capsule_content_sha256 !== "string" ||
    !SHA256_HEX.test(o.capsule_content_sha256)
  ) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "capsule_content_sha256 refused.",
    );
  }
  if (typeof o.capsule_id !== "string" || o.capsule_id.length === 0) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "capsule_id refused.",
    );
  }
  if (typeof o.nonce !== "string" || !NONCE_HEX.test(o.nonce)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "nonce refused.",
    );
  }
  if (typeof o.expires_at !== "string") {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "expires_at refused.",
    );
  }
  if (typeof o.idempotency_key !== "string" || !o.idempotency_key.startsWith("idk_")) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "idempotency_key refused.",
    );
  }
  if (typeof o.binding_sha256 !== "string" || !SHA256_HEX.test(o.binding_sha256)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "binding_sha256 refused.",
    );
  }
  const privacy = o.privacy;
  if (privacy === null || typeof privacy !== "object" || Array.isArray(privacy)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "privacy binding refused.",
    );
  }
  const pr = privacy as Record<string, unknown>;
  if (
    pr.passed !== true ||
    pr.secrets_redacted !== true ||
    pr.paths_redacted !== true ||
    pr.session_excluded !== true ||
    pr.injection_quarantined !== false
  ) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "privacy binding values refused.",
    );
  }

  const binding: ActionConfirmationBinding = {
    schema_version: 1,
    confirmation_id: o.confirmation_id,
    action: action as UpstreamActionKind,
    canonical_target: o.canonical_target,
    body_manifest: (o.body_manifest as BodyManifest | null) ?? null,
    attachment_manifest:
      (o.attachment_manifest as AttachmentManifest | null) ?? null,
    incident_fingerprint_digest: o.incident_fingerprint_digest,
    evidence_delta_hash: o.evidence_delta_hash as string | null,
    capsule_content_sha256: o.capsule_content_sha256,
    capsule_id: o.capsule_id,
    privacy: {
      passed: true,
      secrets_redacted: true,
      paths_redacted: true,
      session_excluded: true,
      injection_quarantined: false,
    },
    nonce: o.nonce,
    expires_at: o.expires_at,
    idempotency_key: o.idempotency_key,
    binding_sha256: o.binding_sha256,
  };

  const expected = computeBindingSha256({
    schema_version: binding.schema_version,
    confirmation_id: binding.confirmation_id,
    action: binding.action,
    canonical_target: binding.canonical_target,
    body_manifest: binding.body_manifest,
    attachment_manifest: binding.attachment_manifest,
    incident_fingerprint_digest: binding.incident_fingerprint_digest,
    evidence_delta_hash: binding.evidence_delta_hash,
    capsule_content_sha256: binding.capsule_content_sha256,
    capsule_id: binding.capsule_id,
    privacy: binding.privacy,
    nonce: binding.nonce,
    expires_at: binding.expires_at,
    idempotency_key: binding.idempotency_key,
  });
  if (expected !== binding.binding_sha256) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "binding_sha256 mismatch.",
    );
  }

  const now = nowMs ?? Date.now();
  const exp = Date.parse(binding.expires_at);
  if (!Number.isFinite(exp) || exp <= now) {
    throw new ConfirmationError(
      "EXPIRED_CONFIRMATION",
      "Confirmation expired.",
    );
  }

  if (!opts?.allowConsumed && consumedNonces.has(binding.nonce)) {
    throw new ConfirmationError(
      "REPLAYED_CONFIRMATION",
      "Confirmation nonce already consumed (one-shot).",
    );
  }

  return binding;
}

/** Mark nonce consumed after successful confirm path (or explicit cancel). */
export function consumeConfirmationNonce(nonce: string): void {
  consumedNonces.add(nonce);
}

export function isNonceConsumed(nonce: string): boolean {
  return consumedNonces.has(nonce);
}
