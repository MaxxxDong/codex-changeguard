import { sha256Canonical, sha256Text } from "../../evidence/canonical.js";
import type { BodyManifest, AttachmentManifest, UpstreamActionKind } from "./types.js";

/**
 * Idempotency key: canonical target + incident fingerprint digest +
 * evidence delta + action + content material.
 * Exact same diagnosis/action/content cannot execute twice.
 */
export function computeIdempotencyKey(input: {
  canonical_target: string;
  incident_fingerprint_digest: string;
  evidence_delta_hash: string | null;
  action: UpstreamActionKind;
  body_manifest: BodyManifest | null;
  attachment_manifest: AttachmentManifest | null;
}): string {
  const content = {
    canonical_target: input.canonical_target,
    incident_fingerprint_digest: input.incident_fingerprint_digest,
    evidence_delta_hash: input.evidence_delta_hash,
    action: input.action,
    body_content_sha256: input.body_manifest?.content_sha256 ?? null,
    attachment_manifest_sha256: input.attachment_manifest?.manifest_sha256 ?? null,
  };
  return `idk_${sha256Canonical(content)}`;
}

export function receiptHash(input: {
  action: UpstreamActionKind;
  canonical_url: string;
  timestamp: string;
  idempotency_key: string;
  remote_receipt_id: string | null;
}): string {
  return sha256Canonical({
    kind: "upstream_contribution_action",
    action: input.action,
    canonical_url: input.canonical_url,
    timestamp: input.timestamp,
    idempotency_key: input.idempotency_key,
    remote_receipt_id: input.remote_receipt_id,
  });
}

export function incidentFingerprintDigest(
  fingerprint: unknown | null,
): string {
  if (fingerprint === null || fingerprint === undefined) {
    return sha256Text("incident:none");
  }
  return sha256Canonical(fingerprint);
}
