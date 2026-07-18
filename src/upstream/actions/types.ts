/**
 * Ticket 11 confirmed upstream action contracts.
 * Production seams never inject a real gh/browser adapter; host integration
 * supplies a capability-injected adapter. Default runtime is unavailable.
 */

import type { UpstreamSubmissionCapsule } from "../types.js";
import type { IncidentFingerprint } from "../../core/types.js";

/** Separately previewed + confirmed action kinds (only these). */
export type UpstreamActionKind =
  | "create_issue"
  | "comment_with_delta"
  | "react_upvote"
  | "subscribe"
  | "attachment_upload";

/**
 * Auth capability only — never a token, cookie, or session material.
 * Host reports whether an already-authenticated surface is available.
 */
export type AuthCapabilityKind =
  | "gh_authenticated"
  | "visible_browser_authenticated"
  | "unavailable";

export type ActionPreviewStatus =
  | "PREVIEW_READY"
  | "BLOCKED_CAPSULE"
  | "PRIVACY_FAILED"
  | "UNSUPPORTED_ACTION"
  | "INVALID_INPUT";

export type ActionConfirmStatus =
  | "EXECUTED"
  | "CANCELLED"
  | "AUTH_UNAVAILABLE"
  | "ADAPTER_UNAVAILABLE"
  | "BLOCKED_CAPSULE"
  | "INVALID_CONFIRMATION"
  | "EXPIRED_CONFIRMATION"
  | "REPLAYED_CONFIRMATION"
  | "DUPLICATE_EXISTING"
  | "UNCERTAIN_NO_RETRY"
  | "PRIVACY_FAILED"
  | "FAILED";

export type ConfirmDecision = "confirm" | "cancel";

export interface AttachmentManifestEntry {
  /** Basename only — never absolute path. */
  name: string;
  /** Content SHA-256 of attachment bytes (orchestrator-supplied). */
  content_sha256: string;
  /** Declared byte length (bounded). */
  byte_length: number;
  /** MIME class only (e.g. text/plain, image/png). */
  media_type: string;
  /** Privacy: secrets/paths already redacted in attachment. */
  secrets_redacted: boolean;
  paths_redacted: boolean;
  session_excluded: boolean;
}

export interface AttachmentManifest {
  schema_version: 1;
  entries: AttachmentManifestEntry[];
  /** Integrity over entries. */
  manifest_sha256: string;
}

export interface BodyManifest {
  /** Title for create_issue; null for other actions. */
  title: string | null;
  /** Body or comment text; null for react/subscribe. */
  body: string | null;
  /** Reaction name for react_upvote (e.g. "+1"); null otherwise. */
  reaction: string | null;
  /** Content hash of title+body+reaction material. */
  content_sha256: string;
}

export interface PrivacyBinding {
  passed: boolean;
  secrets_redacted: boolean;
  paths_redacted: boolean;
  session_excluded: boolean;
  injection_quarantined: boolean;
}

/**
 * One-shot confirmation binding material.
 * Binds exact canonical target, action, body/attachment, incident digest,
 * evidence delta hash, capsule content hash, privacy result, nonce, expiry.
 */
export interface ActionConfirmationBinding {
  schema_version: 1;
  confirmation_id: string;
  action: UpstreamActionKind;
  canonical_target: string;
  body_manifest: BodyManifest | null;
  attachment_manifest: AttachmentManifest | null;
  incident_fingerprint_digest: string;
  evidence_delta_hash: string | null;
  capsule_content_sha256: string;
  capsule_id: string;
  privacy: PrivacyBinding;
  nonce: string;
  expires_at: string;
  idempotency_key: string;
  /** Integrity digest of the binding fields (excluding this field). */
  binding_sha256: string;
}

/**
 * Minimal Upstream Contribution Receipt after successful external action.
 * Independent of local repair status; never includes secrets or body text.
 */
export interface UpstreamActionReceipt {
  schema_version: 1;
  /** Distinct from diagnosis upstream_contribution receipt. */
  kind: "upstream_contribution_action";
  action: UpstreamActionKind;
  canonical_url: string;
  timestamp: string;
  receipt_hash: string;
  idempotency_key: string;
  /** Remote-side receipt id when known; never a token. */
  remote_receipt_id: string | null;
}

export interface AuthCapabilityReport {
  kind: AuthCapabilityKind;
  /** Human-readable capability note; never contains secrets. */
  detail: string;
  /** True only when host reports an already-authenticated session is usable. */
  authenticated: boolean;
}

/** Adapter execute request — no tokens; host owns auth. */
export interface AdapterExecuteRequest {
  action: UpstreamActionKind;
  canonical_target: string;
  body_manifest: BodyManifest | null;
  attachment_manifest: AttachmentManifest | null;
  idempotency_key: string;
  confirmation_id: string;
}

export type AdapterExecuteOutcome =
  | "success"
  | "auth_unavailable"
  | "duplicate_existing"
  | "timeout_ambiguous"
  | "failed";

export interface AdapterExecuteResult {
  outcome: AdapterExecuteOutcome;
  /** Canonical URL of the created/updated remote resource when known. */
  canonical_url: string | null;
  remote_receipt_id: string | null;
  timestamp: string | null;
  /** Existing remote action found under same idempotency (duplicate path). */
  existing_idempotency_key: string | null;
  error_code: string | null;
  error_message: string | null;
}

export type AdapterQueryOutcome =
  | "found"
  | "not_found"
  | "uncertain";

export interface AdapterQueryResult {
  outcome: AdapterQueryOutcome;
  receipt: UpstreamActionReceipt | null;
  error_code: string | null;
  error_message: string | null;
}

/**
 * Capability-injected host adapter for real gh / visible-browser execution.
 * Production CLI/MCP inject null / unavailable — never child_process/gh here.
 */
export interface UpstreamActionAdapter {
  getAuthCapability(): AuthCapabilityReport;
  execute(request: AdapterExecuteRequest): AdapterExecuteResult;
  queryByIdempotencyKey(idempotency_key: string): AdapterQueryResult;
}

export interface ActionPreviewResult {
  schema_version: 1;
  ok: boolean;
  status: ActionPreviewStatus;
  action: UpstreamActionKind | null;
  canonical_target: string | null;
  body_manifest: BodyManifest | null;
  attachment_manifest: AttachmentManifest | null;
  privacy: PrivacyBinding | null;
  incident_fingerprint_digest: string | null;
  evidence_delta_hash: string | null;
  capsule_content_sha256: string | null;
  capsule_id: string | null;
  /** One-shot confirmation token (ua1.…); null when not preview-ready. */
  confirmation_token: string | null;
  confirmation: ActionConfirmationBinding | null;
  idempotency_key: string | null;
  auth_capability: AuthCapabilityReport;
  local_incident: IncidentFingerprint | null;
  network_used: false;
  target_mutated: false;
  repair_applied: false;
  repair_authorized: false;
  /** Preview never performs external write. */
  external_write: false;
  error_code: string | null;
  error_message: string | null;
}

export interface ActionConfirmResult {
  schema_version: 1;
  ok: boolean;
  status: ActionConfirmStatus;
  action: UpstreamActionKind | null;
  decision: ConfirmDecision | null;
  /** Present only on EXECUTED or DUPLICATE_EXISTING with known remote state. */
  receipt: UpstreamActionReceipt | null;
  idempotency_key: string | null;
  auth_capability: AuthCapabilityReport;
  confirmation_id: string | null;
  local_incident: IncidentFingerprint | null;
  network_used: boolean;
  target_mutated: false;
  repair_applied: false;
  repair_authorized: false;
  /**
   * True only when the injected adapter reports a successful or existing remote write.
   * Cancellation / auth unavailable / uncertain never set this true.
   */
  external_write: boolean;
  error_code: string | null;
  error_message: string | null;
}

/** Capsule gate diagnostic (structured; never raw secrets). */
export interface CapsuleGateCheck {
  id: string;
  passed: boolean;
  detail: string;
}

export interface CapsuleGateResult {
  passed: boolean;
  checks: CapsuleGateCheck[];
  failed_ids: string[];
  /** Recommendation-derived allowlist of actions for this capsule. */
  allowed_actions: UpstreamActionKind[];
  capsule: UpstreamSubmissionCapsule | null;
}
