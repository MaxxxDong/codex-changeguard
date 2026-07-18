import { diagnose } from "../../core/diagnose.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import { sha256Canonical } from "../../evidence/canonical.js";
import { createUnavailableAdapter } from "./adapter.js";
import { gateCapsuleForActions, isActionAllowed } from "./capsule-gate.js";
import { mintConfirmation } from "./confirmation.js";
import {
  computeIdempotencyKey,
  incidentFingerprintDigest,
} from "./idempotency.js";
import { UPSTREAM_ACTION_KINDS } from "./limits.js";
import {
  buildBodyManifest,
  ManifestError,
  parseAttachmentManifest,
  resolveCanonicalTarget,
} from "./manifest.js";
import type {
  ActionPreviewResult,
  ActionPreviewStatus,
  AuthCapabilityReport,
  BodyManifest,
  UpstreamActionAdapter,
  UpstreamActionKind,
} from "./types.js";

export interface ActionPreviewOptions {
  targetPath: string;
  /** Ticket 10 UpstreamSubmissionCapsule (object). */
  capsule: unknown;
  action: unknown;
  /** Optional attachment manifest (required for attachment_upload). */
  attachment_manifest?: unknown;
  /** Injectable adapter; production passes null → unavailable. */
  adapter?: UpstreamActionAdapter | null;
  nowMs?: number;
  /** Deterministic nonce for tests. */
  nonce?: string;
}

function emptyPreview(
  partial: Partial<ActionPreviewResult> &
    Pick<ActionPreviewResult, "ok" | "status" | "auth_capability">,
): ActionPreviewResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    status: partial.status,
    action: partial.action ?? null,
    canonical_target: partial.canonical_target ?? null,
    body_manifest: partial.body_manifest ?? null,
    attachment_manifest: partial.attachment_manifest ?? null,
    privacy: partial.privacy ?? null,
    incident_fingerprint_digest: partial.incident_fingerprint_digest ?? null,
    evidence_delta_hash: partial.evidence_delta_hash ?? null,
    capsule_content_sha256: partial.capsule_content_sha256 ?? null,
    capsule_id: partial.capsule_id ?? null,
    confirmation_token: partial.confirmation_token ?? null,
    confirmation: partial.confirmation ?? null,
    idempotency_key: partial.idempotency_key ?? null,
    auth_capability: partial.auth_capability,
    local_incident: partial.local_incident ?? null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    external_write: false,
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
  };
}

function parseAction(raw: unknown): UpstreamActionKind | null {
  if (typeof raw !== "string") return null;
  if ((UPSTREAM_ACTION_KINDS as readonly string[]).includes(raw)) {
    return raw as UpstreamActionKind;
  }
  if (raw === "react" || raw === "upvote" || raw === "react/upvote") {
    return "react_upvote";
  }
  return null;
}

function bodyForAction(
  action: UpstreamActionKind,
  capsule: NonNullable<ReturnType<typeof gateCapsuleForActions>["capsule"]>,
): BodyManifest {
  if (action === "attachment_upload") {
    return {
      title: null,
      body: null,
      reaction: null,
      content_sha256: sha256Canonical({
        title: null,
        body: null,
        reaction: null,
        action,
      }),
    };
  }
  return buildBodyManifest(action, capsule);
}

/**
 * Preview a single upstream action bound to a valid Ticket 10 capsule.
 * Never performs external write; emits a one-shot confirmation binding.
 */
export function previewUpstreamAction(
  options: ActionPreviewOptions,
): ActionPreviewResult {
  const adapter = options.adapter ?? createUnavailableAdapter();
  let auth_capability: AuthCapabilityReport;
  try {
    auth_capability = adapter.getAuthCapability();
  } catch {
    auth_capability = {
      kind: "unavailable",
      detail: "Adapter auth capability probe failed.",
      authenticated: false,
    };
  }

  const action = parseAction(options.action);
  if (!action) {
    return emptyPreview({
      ok: false,
      status: "INVALID_INPUT",
      auth_capability,
      error_code: "INVALID_ACTION",
      error_message:
        "Action must be one of: create_issue, comment_with_delta, react_upvote, subscribe, attachment_upload.",
    });
  }

  let local_incident = null;
  try {
    const d = diagnose(options.targetPath);
    local_incident = d.incident_fingerprint;
  } catch {
    local_incident = null;
  }

  const gate = gateCapsuleForActions(options.capsule);
  if (!gate.passed || !gate.capsule) {
    const status: ActionPreviewStatus =
      gate.failed_ids.some((id) => id.startsWith("privacy"))
        ? "PRIVACY_FAILED"
        : "BLOCKED_CAPSULE";
    return emptyPreview({
      ok: false,
      status,
      action,
      auth_capability,
      local_incident,
      error_code: status,
      error_message:
        gate.checks.find((c) => !c.passed)?.detail ??
        "Capsule cannot become actions.",
    });
  }

  if (!isActionAllowed(gate, action)) {
    return emptyPreview({
      ok: false,
      status: "UNSUPPORTED_ACTION",
      action,
      auth_capability,
      local_incident,
      capsule_id: gate.capsule.capsule_id,
      capsule_content_sha256: gate.capsule.capsule_content_sha256,
      error_code: "UNSUPPORTED_ACTION",
      error_message: `Action ${action} is not allowed for recommendation ${gate.capsule.duplicate.recommendation}.`,
    });
  }

  try {
    const attachment_manifest = parseAttachmentManifest(
      options.attachment_manifest,
    );
    if (action === "attachment_upload") {
      if (!attachment_manifest || attachment_manifest.entries.length === 0) {
        return emptyPreview({
          ok: false,
          status: "INVALID_INPUT",
          action,
          auth_capability,
          local_incident,
          error_code: "ATTACHMENTS_REQUIRED",
          error_message:
            "attachment_upload requires a non-empty attachment_manifest.",
        });
      }
    }

    const body_manifest = bodyForAction(action, gate.capsule);
    const canonical_target = resolveCanonicalTarget(action, gate.capsule);
    const incident_fingerprint_digest =
      incidentFingerprintDigest(local_incident);
    const evidence_delta_hash = gate.capsule.duplicate.evidence_delta_hash;
    const privacy = {
      passed: gate.capsule.privacy_review.passed,
      secrets_redacted: gate.capsule.privacy_review.secrets_redacted,
      paths_redacted: gate.capsule.privacy_review.paths_redacted,
      session_excluded: gate.capsule.privacy_review.session_excluded,
      injection_quarantined: gate.capsule.privacy_review.injection_quarantined,
    };

    const idempotency_key = computeIdempotencyKey({
      canonical_target,
      incident_fingerprint_digest,
      evidence_delta_hash,
      action,
      body_manifest,
      attachment_manifest,
    });

    const { binding, token } = mintConfirmation({
      action,
      canonical_target,
      body_manifest,
      attachment_manifest,
      incident_fingerprint_digest,
      evidence_delta_hash,
      capsule_content_sha256: gate.capsule.capsule_content_sha256,
      capsule_id: gate.capsule.capsule_id,
      privacy,
      idempotency_key,
      nowMs: options.nowMs,
      nonce: options.nonce,
    });

    return emptyPreview({
      ok: true,
      status: "PREVIEW_READY",
      action,
      canonical_target,
      body_manifest,
      attachment_manifest,
      privacy,
      incident_fingerprint_digest,
      evidence_delta_hash,
      capsule_content_sha256: gate.capsule.capsule_content_sha256,
      capsule_id: gate.capsule.capsule_id,
      confirmation_token: token,
      confirmation: binding,
      idempotency_key,
      auth_capability,
      local_incident,
    });
  } catch (e) {
    const code = e instanceof ManifestError ? e.code : "PREVIEW_FAILED";
    const msg = e instanceof Error ? e.message : "Action preview failed.";
    return emptyPreview({
      ok: false,
      status: code === "ATTACH_PRIVACY" ? "PRIVACY_FAILED" : "INVALID_INPUT",
      action,
      auth_capability,
      local_incident,
      error_code: code,
      error_message: msg,
    });
  }
}
