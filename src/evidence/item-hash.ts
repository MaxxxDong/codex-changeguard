import { sha256Canonical, sha256Text } from "./canonical.js";
import type {
  EvidenceKind,
  EvidenceState,
  MaintainerStatus,
  OfficialEvidenceItem,
  OfficialStructuredPayload,
  QuarantineRecord,
  VersionRange,
} from "./types.js";

/**
 * Canonical persisted item integrity material.
 * Hash covers identity fields that must fail closed on tamper, including
 * derived origin and evidence_state. Raw prose bodies are not re-stored;
 * quarantined originals contribute only via quarantine.original_sha256.
 */
export function itemIntegrityMaterial(fields: {
  kind: EvidenceKind | string;
  canonical_url: string;
  origin: string;
  title: string;
  structured: OfficialStructuredPayload;
  version_range: VersionRange;
  maintainer_status: MaintainerStatus | string;
  evidence_state: EvidenceState | string;
  quarantine: QuarantineRecord | null;
}): Record<string, unknown> {
  return {
    kind: fields.kind,
    canonical_url: fields.canonical_url,
    origin: fields.origin,
    title: fields.title,
    structured: fields.structured,
    version_range: fields.version_range,
    maintainer_status: fields.maintainer_status,
    evidence_state: fields.evidence_state,
    quarantine: fields.quarantine,
  };
}

export function computeItemContentSha256(fields: {
  kind: EvidenceKind | string;
  canonical_url: string;
  origin: string;
  title: string;
  structured: OfficialStructuredPayload;
  version_range: VersionRange;
  maintainer_status: MaintainerStatus | string;
  evidence_state: EvidenceState | string;
  quarantine: QuarantineRecord | null;
}): string {
  return sha256Canonical(itemIntegrityMaterial(fields));
}

/** Snapshot-level integrity hash over full validated items (canonical contract). */
export function computeSnapshotContentSha256(fields: {
  schema_version: 1;
  snapshot_id: string;
  fetched_at: string;
  origin_allowlist: readonly string[];
  items: readonly OfficialEvidenceItem[];
}): string {
  return sha256Canonical({
    schema_version: 1,
    snapshot_id: fields.snapshot_id,
    fetched_at: fields.fetched_at,
    origin_allowlist: fields.origin_allowlist,
    items: fields.items,
  });
}

/** Empty-body digest used only when callers need a body fingerprint without storage. */
export function emptyBodySha256(): string {
  return sha256Text("");
}
