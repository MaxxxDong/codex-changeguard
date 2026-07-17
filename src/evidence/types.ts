/** Official evidence, disclosure, transport, and snapshot contracts (Ticket 04). */

export type TrustClass =
  | "device_only"
  | "redacted_structured"
  | "exportable_after_review";

export type SourceClass =
  | "local_observed"
  | "user_provided"
  | "official_snapshot"
  | "official_live";

export type EvidenceKind =
  | "doc"
  | "release"
  | "tag"
  | "diff"
  | "issue"
  | "pr"
  | "commit";

export type EvidenceState =
  | "fresh"
  | "stale"
  | "snapshot"
  | "unavailable";

export type MaintainerStatus =
  | "official"
  | "maintainer"
  | "user_reported"
  | "community"
  | "unknown";

export type DisclosureDecision = "approved" | "refused" | "not_requested";

export type EvidenceSourceMode =
  | "live_refresh"
  | "bundled_snapshot"
  | "stale_snapshot"
  | "unavailable_snapshot";

export type StaleRisk = "none" | "low" | "medium" | "high" | "unavailable";

export interface DisclosureField {
  field_name: string;
  trust_class: TrustClass;
  source_class: SourceClass;
  transformation: string;
  destination: string;
  purpose: string;
  optional: boolean;
}

export interface DisclosureManifest {
  schema_version: 1;
  manifest_id: string;
  fields: DisclosureField[];
  purpose: string;
  destinations: string[];
}

export interface VersionRange {
  from: string | null;
  to: string | null;
}

export interface QuarantineRecord {
  quarantined: true;
  reason: string;
  original_sha256: string;
  /** Safe placeholder — never the original instruction-like body. */
  placeholder: string;
}

/**
 * Official evidence item after validation, allowlist, and quarantine.
 * Prose fields are either absent or replaced with quarantined placeholders.
 */
export interface OfficialEvidenceItem {
  schema_version: 1;
  evidence_id: string;
  kind: EvidenceKind;
  canonical_url: string;
  origin: string;
  fetched_at: string;
  version_range: VersionRange;
  evidence_state: EvidenceState;
  content_sha256: string;
  snapshot_id: string;
  title: string;
  /** Structured, allowlisted metadata only — never free-form executable content. */
  structured: OfficialStructuredPayload;
  maintainer_status: MaintainerStatus;
  quarantine: QuarantineRecord | null;
}

export interface OfficialStructuredPayload {
  /** Config/schema keys referenced by the change (when known). */
  config_keys: string[];
  /** Component / module / feature identifiers. */
  component_ids: string[];
  /** Surfaces touched: plugin, skill, mcp, hook, runtime, desktop, cli, … */
  surfaces: string[];
  /** Artifact / module path aliases when known. */
  artifact_aliases: string[];
  /** Platform constraints; empty means unspecified. */
  platforms: string[];
  /** Optional short non-instruction summary tokens. */
  summary_tokens: string[];
  /** True when a registered matcher class applies; false forces UNMAPPED when no other matcher hits. */
  has_registered_mapper: boolean;
}

export interface OfficialEvidenceSnapshot {
  schema_version: 1;
  snapshot_id: string;
  fetched_at: string;
  origin_allowlist: string[];
  items: OfficialEvidenceItem[];
  content_sha256: string;
  immutable: true;
}

/** Raw transport payload before validation/quarantine (orchestration injects). */
export interface RawOfficialTransportItem {
  kind: EvidenceKind;
  canonical_url: string;
  origin?: string;
  version_range?: VersionRange;
  title?: string;
  body?: string;
  structured?: Partial<OfficialStructuredPayload>;
  maintainer_status?: MaintainerStatus;
  content?: string;
}

/**
 * Explicit local context eligible for disclosure after redaction/bounds.
 * Only populated, sendable fields are included in the outbound transport request.
 */
export interface LocalDisclosureContext {
  codex_version?: string | null;
  surface?: string | null;
  platform_os?: string | null;
  platform_arch?: string | null;
  config_keys?: readonly string[] | null;
  feature_ids?: readonly string[] | null;
  error_class?: string | null;
}

/**
 * Sanitized outbound transport request. Field set must match the disclosure
 * manifest's non-device_only fields exactly (plus fixed allowlist metadata).
 */
export interface OfficialTransportRequest {
  disclosure_manifest_id: string;
  allowed_hosts: readonly string[];
  allowed_repositories: readonly string[];
  resource_kinds: readonly EvidenceKind[];
  /** Populated sendable local fields only (exact keys listed in manifest). */
  codex_version?: string;
  surface?: string;
  platform_os?: string;
  platform_arch?: string;
  config_keys?: readonly string[];
  feature_ids?: readonly string[];
  error_class?: string;
}

export interface OfficialTransportResponse {
  fetched_at: string;
  items: RawOfficialTransportItem[];
}

/**
 * Injectable transport. Trusted Codex orchestration supplies an implementation
 * only after disclosure approval. Production core never opens sockets itself.
 */
export interface OfficialTransport {
  fetch(request: OfficialTransportRequest): OfficialTransportResponse;
}

export interface TransportCallLog {
  calls: OfficialTransportRequest[];
  get callCount(): number;
}

export interface EvidenceRefreshResult {
  schema_version: 1;
  ok: boolean;
  disclosure_manifest: DisclosureManifest;
  disclosure_decision: DisclosureDecision;
  transport_calls: number;
  source_mode: EvidenceSourceMode;
  snapshot: OfficialEvidenceSnapshot | null;
  stale_age_seconds: number | null;
  stale_risk: StaleRisk;
  error_code: string | null;
  error_message: string | null;
  /** Separated claim classes for public surfaces. */
  observed_facts: string[];
  user_reports: string[];
  hypotheses: string[];
  /** Exact sanitized outbound request when transport was called; otherwise null. */
  transport_request: OfficialTransportRequest | null;
}
