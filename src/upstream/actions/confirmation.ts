/**
 * One-shot confirmation binding: install-local HMAC + durable ledger nonce.
 * Not an auth token; never carries secrets, cookies, session material, or the HMAC key.
 * mint requires an explicit ledger context and registers the nonce before return.
 */
import crypto from "node:crypto";
import { sha256Canonical } from "../../evidence/canonical.js";
import {
  CONFIRMATION_TOKEN_PREFIX,
  CONFIRMATION_TTL_MS,
  MAX_CONFIRMATION_BYTES,
  FORBIDDEN_ACTION_KEYS,
} from "./limits.js";
import {
  ConfirmationLedger,
  LedgerError,
  openConfirmationLedger,
  _resetConfirmationLedgerForTests,
  type ClaimForExecuteResult,
} from "./ledger.js";
import { computeIdempotencyKey } from "./idempotency.js";
import { isOfficialCanonicalTarget } from "./manifest.js";
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
  | "IN_FLIGHT_CONFIRMATION"
  | "MALFORMED_CONFIRMATION"
  | "UNREGISTERED_CONFIRMATION";

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

export interface MintConfirmationInput {
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
  /** Required ledger context — mint is not a public write bypass without preview registration. */
  ledger: ConfirmationLedger;
  nowMs?: number;
  ttlMs?: number;
  nonce?: string;
}

function bindingMaterial(
  b: Omit<ActionConfirmationBinding, "binding_sha256" | "mac">,
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
  b: Omit<ActionConfirmationBinding, "binding_sha256" | "mac">,
): string {
  return sha256Canonical(bindingMaterial(b));
}

/** HMAC over binding digests; key never enters token/log/receipt. */
export function computeConfirmationMac(
  key: Buffer,
  partial: Omit<ActionConfirmationBinding, "mac">,
): string {
  const material = sha256Canonical({
    schema_version: partial.schema_version,
    confirmation_id: partial.confirmation_id,
    action: partial.action,
    canonical_target: partial.canonical_target,
    body_manifest: partial.body_manifest,
    attachment_manifest: partial.attachment_manifest,
    incident_fingerprint_digest: partial.incident_fingerprint_digest,
    evidence_delta_hash: partial.evidence_delta_hash,
    capsule_content_sha256: partial.capsule_content_sha256,
    capsule_id: partial.capsule_id,
    privacy: partial.privacy,
    nonce: partial.nonce,
    expires_at: partial.expires_at,
    idempotency_key: partial.idempotency_key,
    binding_sha256: partial.binding_sha256,
  });
  return crypto.createHmac("sha256", key).update(material, "utf8").digest("hex");
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  if (!/^[a-f0-9]+$/i.test(a) || !/^[a-f0-9]+$/i.test(b)) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

/**
 * Mint a confirmation token. Registers the nonce in the ledger first.
 * Internal / test seam: requires explicit ledger; cannot mint offline without key+ledger.
 */
export function mintConfirmation(input: MintConfirmationInput): {
  binding: ActionConfirmationBinding;
  token: string;
} {
  if (!input.ledger) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "mintConfirmation requires an explicit confirmation ledger context.",
    );
  }
  const now = input.nowMs ?? Date.now();
  const ttl = input.ttlMs ?? CONFIRMATION_TTL_MS;
  const nonce = input.nonce ?? crypto.randomBytes(16).toString("hex");
  if (!NONCE_HEX.test(nonce)) {
    throw new ConfirmationError("INVALID_CONFIRMATION", "nonce refused.");
  }
  const confirmation_id = `uac_${sha256Canonical({
    nonce,
    action: input.action,
    capsule_id: input.capsule_id,
  }).slice(0, 24)}`;
  const expires_at = new Date(now + ttl).toISOString();

  const partial: Omit<ActionConfirmationBinding, "binding_sha256" | "mac"> = {
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
  const binding_sha256 = computeBindingSha256(partial);
  const key = input.ledger.loadOrCreateHmacKey();
  const mac = computeConfirmationMac(key, { ...partial, binding_sha256 });
  const binding: ActionConfirmationBinding = {
    ...partial,
    binding_sha256,
    mac,
  };

  // Register before returning token — offline-minted tokens cannot skip this.
  try {
    input.ledger.register(
      {
        nonce,
        confirmation_id,
        binding_sha256,
        expires_at,
        registered_at_ms: now,
        action: input.action,
        canonical_target: input.canonical_target,
        idempotency_key: input.idempotency_key,
      },
      now,
    );
  } catch (e) {
    if (e instanceof LedgerError) {
      throw new ConfirmationError(
        "INVALID_CONFIRMATION",
        `Ledger registration refused: ${e.code}`,
      );
    }
    throw e;
  }

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

export interface ParseConfirmationOptions {
  allowConsumed?: boolean;
  /** Required for HMAC + registration checks. */
  ledger?: ConfirmationLedger | null;
  ledgerRoot?: string | null;
  nowMs?: number;
  /**
   * When true (confirm path), re-check official target allowlist, recompute
   * idempotency/body/attachment digests, and refuse privacy/forbidden shapes.
   */
  revalidateForConfirm?: boolean;
}

function resolveLedger(
  opts?: ParseConfirmationOptions,
): ConfirmationLedger {
  if (opts?.ledger) return opts.ledger;
  return openConfirmationLedger(opts?.ledgerRoot);
}

/**
 * Re-validate confirm-time invariants that offline-forged tokens could otherwise skip.
 */
export function revalidateConfirmationBinding(
  binding: ActionConfirmationBinding,
): void {
  if (!isOfficialCanonicalTarget(binding.canonical_target)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "canonical_target is not on the official allowlist.",
    );
  }
  const privacy = binding.privacy;
  if (
    privacy.passed !== true ||
    privacy.secrets_redacted !== true ||
    privacy.paths_redacted !== true ||
    privacy.session_excluded !== true ||
    privacy.injection_quarantined !== false
  ) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "privacy binding values refused.",
    );
  }

  refuseForbidden(binding.body_manifest);
  refuseForbidden(binding.attachment_manifest);

  if (binding.body_manifest) {
    const expectedBody = sha256Canonical({
      title: binding.body_manifest.title,
      body: binding.body_manifest.body,
      reaction: binding.body_manifest.reaction,
      action: binding.action,
    });
    if (expectedBody !== binding.body_manifest.content_sha256) {
      throw new ConfirmationError(
        "INVALID_CONFIRMATION",
        "body_manifest content_sha256 mismatch.",
      );
    }
  }
  if (binding.attachment_manifest) {
    const expectedAtt = sha256Canonical({
      schema_version: 1,
      entries: binding.attachment_manifest.entries,
    });
    if (expectedAtt !== binding.attachment_manifest.manifest_sha256) {
      throw new ConfirmationError(
        "INVALID_CONFIRMATION",
        "attachment_manifest.manifest_sha256 mismatch.",
      );
    }
    for (const e of binding.attachment_manifest.entries) {
      if (
        e.secrets_redacted !== true ||
        e.paths_redacted !== true ||
        e.session_excluded !== true
      ) {
        throw new ConfirmationError(
          "INVALID_CONFIRMATION",
          "attachment privacy flags refused.",
        );
      }
    }
  }

  const expectedIdk = computeIdempotencyKey({
    canonical_target: binding.canonical_target,
    incident_fingerprint_digest: binding.incident_fingerprint_digest,
    evidence_delta_hash: binding.evidence_delta_hash,
    action: binding.action,
    body_manifest: binding.body_manifest,
    attachment_manifest: binding.attachment_manifest,
  });
  if (expectedIdk !== binding.idempotency_key) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "idempotency_key recompute mismatch.",
    );
  }
}

export function parseConfirmationToken(
  token: string,
  nowMs?: number,
  opts?: ParseConfirmationOptions,
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
  if (typeof o.mac !== "string" || !SHA256_HEX.test(o.mac)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "confirmation mac refused.",
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
    mac: o.mac,
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

  const now = nowMs ?? opts?.nowMs ?? Date.now();
  const exp = Date.parse(binding.expires_at);
  if (!Number.isFinite(exp) || exp <= now) {
    throw new ConfirmationError(
      "EXPIRED_CONFIRMATION",
      "Confirmation expired.",
    );
  }

  // Install-local HMAC + durable registration (not offline-recomputable).
  let ledger: ConfirmationLedger;
  try {
    ledger = resolveLedger({ ...opts, nowMs: now });
  } catch (e) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      e instanceof Error ? e.message : "Confirmation ledger unavailable.",
    );
  }

  let key: Buffer;
  try {
    key = ledger.loadOrCreateHmacKey();
  } catch (e) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      e instanceof Error ? e.message : "HMAC key unavailable.",
    );
  }
  const expectedMac = computeConfirmationMac(key, {
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
    binding_sha256: binding.binding_sha256,
  });
  if (!timingSafeEqualHex(expectedMac, binding.mac)) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "Confirmation mac verification failed.",
    );
  }

  const entry = ledger.getEntry(binding.nonce, now);
  if (!entry) {
    throw new ConfirmationError(
      "UNREGISTERED_CONFIRMATION",
      "Confirmation nonce not registered (preview required).",
    );
  }
  if (entry.binding_sha256 !== binding.binding_sha256) {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "Ledger binding_sha256 mismatch.",
    );
  }
  if (entry.status === "in_flight") {
    if (!opts?.allowConsumed) {
      throw new ConfirmationError(
        "IN_FLIGHT_CONFIRMATION",
        "Confirmation in_flight (exclusive claim held; no retry).",
      );
    }
  } else if (
    entry.status === "consumed" ||
    entry.status === "terminal_uncertain"
  ) {
    if (!opts?.allowConsumed) {
      throw new ConfirmationError(
        "REPLAYED_CONFIRMATION",
        entry.status === "terminal_uncertain"
          ? "Confirmation terminal_uncertain (one-shot; no retry)."
          : "Confirmation nonce already consumed (one-shot).",
      );
    }
  } else if (entry.status !== "registered") {
    throw new ConfirmationError(
      "INVALID_CONFIRMATION",
      "Ledger entry status refused.",
    );
  }

  if (opts?.revalidateForConfirm) {
    revalidateConfirmationBinding(binding);
  }

  return binding;
}

/**
 * Exclusive claim before adapter.execute: registered → in_flight CAS.
 * Losers must not execute (IN_FLIGHT_NO_RETRY / REPLAYED).
 */
export function claimConfirmationForExecute(
  nonce: string,
  ledgerOrRoot?: ConfirmationLedger | string | null,
  nowMs?: number,
  binding_sha256?: string,
): ClaimForExecuteResult {
  const ledger =
    ledgerOrRoot instanceof ConfirmationLedger
      ? ledgerOrRoot
      : openConfirmationLedger(ledgerOrRoot);
  return ledger.claimForExecute(nonce, { binding_sha256, nowMs });
}

/** Mark nonce consumed after success / cancel / found-duplicate. */
export function consumeConfirmationNonce(
  nonce: string,
  ledgerOrRoot?: ConfirmationLedger | string | null,
  nowMs?: number,
): void {
  const ledger =
    ledgerOrRoot instanceof ConfirmationLedger
      ? ledgerOrRoot
      : openConfirmationLedger(ledgerOrRoot);
  try {
    ledger.markConsumed(nonce, nowMs);
  } catch (e) {
    if (e instanceof LedgerError && e.code === "LEDGER_NOT_REGISTERED") {
      // Still treat as terminal for caller safety — surface as replay on next parse.
      return;
    }
    throw e;
  }
}

/** Persist terminal_uncertain after ambiguous timeout without safe retry. */
export function markConfirmationTerminalUncertain(
  nonce: string,
  ledgerOrRoot?: ConfirmationLedger | string | null,
  nowMs?: number,
): void {
  const ledger =
    ledgerOrRoot instanceof ConfirmationLedger
      ? ledgerOrRoot
      : openConfirmationLedger(ledgerOrRoot);
  try {
    ledger.markTerminalUncertain(nonce, nowMs);
  } catch (e) {
    if (e instanceof LedgerError && e.code === "LEDGER_NOT_REGISTERED") {
      return;
    }
    throw e;
  }
}

/**
 * Best-effort terminal_uncertain after possible remote side effects.
 * Never restores registered; leave in_flight if mark fails (safe terminal).
 */
export function tryMarkConfirmationTerminalUncertain(
  nonce: string,
  ledgerOrRoot?: ConfirmationLedger | string | null,
  nowMs?: number,
): void {
  try {
    markConfirmationTerminalUncertain(nonce, ledgerOrRoot, nowMs);
  } catch {
    /* leave in_flight claim as crash-safe terminal */
  }
}

/**
 * Best-effort consumed mark after confirmed success/duplicate.
 * If mark fails, durable in_flight remains the safe terminal (no second execute).
 */
export function tryConsumeConfirmationNonce(
  nonce: string,
  ledgerOrRoot?: ConfirmationLedger | string | null,
  nowMs?: number,
): boolean {
  try {
    consumeConfirmationNonce(nonce, ledgerOrRoot, nowMs);
    return true;
  } catch {
    return false;
  }
}

export function isNonceConsumed(
  nonce: string,
  ledgerOrRoot?: ConfirmationLedger | string | null,
  nowMs?: number,
): boolean {
  const ledger =
    ledgerOrRoot instanceof ConfirmationLedger
      ? ledgerOrRoot
      : openConfirmationLedger(ledgerOrRoot);
  return ledger.isTerminal(nonce, nowMs);
}

/** Tests: wipe durable ledger (replaces in-process Set reset). */
export function _resetConsumedNoncesForTests(ledgerRoot?: string | null): void {
  _resetConfirmationLedgerForTests(ledgerRoot);
}

export {
  openConfirmationLedger,
  _resetConfirmationLedgerForTests,
  ConfirmationLedger,
};
