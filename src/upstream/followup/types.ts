/**
 * Ticket 12 — maintainer follow-up & upstream-fix closure contracts.
 * Explicit local subscriptions only; zero network by default; external_write: false.
 */

import type {
  MeasuredEvidence,
  UpstreamContributionReceipt,
  UserResolutionReceipt,
} from "../../core/types.js";
import type { QuarantineRecord } from "../../evidence/types.js";
import type { VersionGuidance } from "../../core/lifecycle/types.js";
import type {
  MAINTAINER_INTENTS,
  REGISTERED_PROBE_IDS,
  UPSTREAM_DISPOSITIONS,
} from "./limits.js";

export type MaintainerIntent = (typeof MAINTAINER_INTENTS)[number];
export type UpstreamDisposition = (typeof UPSTREAM_DISPOSITIONS)[number];
export type RegisteredProbeId = (typeof REGISTERED_PROBE_IDS)[number];

export type FollowupOperation =
  | "subscribe"
  | "unsubscribe"
  | "status"
  | "session_hint"
  | "refresh"
  | "process_event"
  | "validate_candidate";

export type FollowupStatus =
  | "OK"
  | "SILENT"
  | "REFRESH_DUE"
  | "NO_NEW_EVIDENCE"
  | "DISPOSITION_APPLIED"
  | "REPLY_DRAFT_READY"
  | "CANDIDATE_VALIDATED"
  | "CANDIDATE_REGRESSED"
  | "SUPERSEDED"
  | "ADAPTER_UNAVAILABLE"
  | "REFUSED"
  | "INVALID_INPUT"
  | "LEDGER_ERROR"
  | "UNAUTHORIZED_ISSUE"
  | "UNAUTHORIZED_REPOSITORY";

/** Canonical openai/codex issue identity (number only; no absolute local paths). */
export interface CanonicalIssueRef {
  host: "github.com";
  repository: "openai/codex";
  issue_number: number;
  /** Stable canonical URL without query/fragment. */
  canonical_url: string;
}

export interface SubscriptionRecord {
  issue_number: number;
  canonical_url: string;
  subscribed_at_ms: number;
  last_refresh_at_ms: number | null;
  last_event_digest: string | null;
  last_disposition: UpstreamDisposition | null;
  /** Migrated duplicate target when disposition=duplicate. */
  duplicate_of_issue: number | null;
  active: boolean;
}

export interface FollowupEventRecord {
  event_id: string;
  issue_number: number;
  disposition: UpstreamDisposition;
  /** Digest of normalized event material (never raw secrets). */
  event_digest: string;
  processed_at_ms: number;
  intents: MaintainerIntent[];
  probe_ids: RegisteredProbeId[];
  evidence_capsule_id: string | null;
  reply_draft_digest: string | null;
}

export interface FollowupLedger {
  schema_version: 1;
  subscriptions: SubscriptionRecord[];
  events: FollowupEventRecord[];
  updated_at_ms: number;
  ledger_digest: string;
}

export interface IntentDetectionResult {
  intents: MaintainerIntent[];
  quarantine: QuarantineRecord | null;
  instruction_like: boolean;
  /** Normalized prose is never executable and never becomes shell argv. */
  prose_treated_as_data: true;
}

export interface MappedProbePlan {
  intents: MaintainerIntent[];
  probe_ids: RegisteredProbeId[];
  /** Probes that will actually run under the isolated target. */
  runnable: RegisteredProbeId[];
}

export interface FollowupProbeResult {
  probe_id: RegisteredProbeId;
  measured: true;
  passed: boolean;
  /** Bounded redacted detail — no absolute paths / secrets. */
  detail: string;
  content_digest: string;
}

export interface EvidenceCapsule {
  schema_version: 1;
  capsule_id: string;
  issue_number: number;
  canonical_url: string;
  intents: MaintainerIntent[];
  probe_results: FollowupProbeResult[];
  privacy: {
    secrets_redacted: true;
    paths_redacted: true;
    session_excluded: true;
    injection_quarantined: boolean;
    passed: boolean;
  };
  quarantine: QuarantineRecord | null;
  /** Always false — Ticket 11 owns any real write after separate confirmation. */
  external_write: false;
  mode: "preview_only";
  locality: "local_only";
  requires_ticket11_confirmation: true;
  content_sha256: string;
}

export interface ReplyDraft {
  schema_version: 1;
  /** Never auto-posted. */
  external_write: false;
  draft_comment: string | null;
  draft_status: "READY" | "BLOCKED" | "NO_NEW_EVIDENCE" | "DISPOSITION_ONLY";
  privacy_passed: boolean;
  evidence_capsule_id: string | null;
  content_digest: string;
}

export interface DispositionPolicyResult {
  disposition: UpstreamDisposition;
  /** Never true — ChangeGuard never auto-reopens. */
  auto_reopen: false;
  /** Never true — never cross-posts. */
  cross_post: false;
  /** Never true — never comments/reacts without Ticket 11. */
  auto_comment: false;
  auto_react: false;
  /** When disposition=duplicate, migrate subscription to this issue. */
  migrate_to_issue: number | null;
  user_guidance: string;
  respect_upstream: true;
}

export interface CandidateValidationInput {
  /**
   * Disposable candidate root (measured for fault-absent + core health).
   * Must be a real distinct disposable isolated target.
   */
  targetPath: string;
  /**
   * Separate disposable baseline root that must reproduce the original fault.
   * Required for the registered live measurement profile.
   */
  baselineTargetPath: string;
  issue_number: number;
  candidate_version: string;
  recipe_id: string;
  /**
   * Closed registered measurement profile id (Phase A: protected_process_shim_v1).
   * Unknown / omitted profiles fail closed (UNSUPPORTED_PROFILE).
   */
  measurement_profile_id: string;
  /**
   * Allowlisted official evidence item content_sha256 (64 hex).
   * Required for supersession; never accepted as free-form "verified".
   * Must bind to exactly one pinned snapshot item with matching canonical URL.
   */
  official_evidence_item_digest: string;
  official_evidence_ref: string;
  /**
   * Caller-declared flags are ignored for upgrade/supersession decisions.
   * Present only so adversarial callers cannot smuggle authority.
   */
  original_fault_absent?: boolean;
  core_regressions_passed?: boolean;
  verified?: boolean;
  /**
   * @deprecated Caller-controlled snapshot_path is not accepted as an official
   * trust root. Production and public candidate validation always use the
   * immutable bundled official snapshot. If supplied, it is ignored.
   */
  snapshot_path?: string;
  nowMs?: number;
}

export interface CandidateValidationResult {
  ok: boolean;
  status: FollowupStatus;
  measured_fault_absent: boolean | null;
  measured_core_ok: boolean | null;
  version_guidance: VersionGuidance | null;
  recipe_status: "ACTIVE_WORKAROUND" | "SUPERSEDED_BY_UPSTREAM_FIX" | null;
  recipe_recommendable: boolean | null;
  official_evidence_item_digest: string | null;
  /** Never true — guidance only; no binary install/mutate. */
  binary_downloaded: false;
  binary_installed: false;
  workaround_uninstalled: false;
  detail: string;
  probe_results: FollowupProbeResult[];
  evidence: MeasuredEvidence[];
  error_code: string | null;
  error_message: string | null;
}

export interface FollowupResult {
  schema_version: 1;
  ok: boolean;
  operation: FollowupOperation;
  status: FollowupStatus;
  user_resolution: UserResolutionReceipt;
  upstream_contribution: UpstreamContributionReceipt;
  subscription: SubscriptionRecord | null;
  subscriptions: SubscriptionRecord[] | null;
  disposition: DispositionPolicyResult | null;
  intents: MaintainerIntent[] | null;
  probe_plan: MappedProbePlan | null;
  evidence_capsule: EvidenceCapsule | null;
  reply_draft: ReplyDraft | null;
  candidate: CandidateValidationResult | null;
  ledger: FollowupLedger | null;
  /** SessionStart path-free hint or null when silent. */
  session_hint: string | null;
  evidence: MeasuredEvidence[];
  error_code: string | null;
  error_message: string | null;
  network_used: false;
  target_mutated: boolean;
  repair_applied: false;
  external_write: false;
  /** Production without injected adapter never writes remotely. */
  adapter_status: "unavailable" | "not_applicable";
  contribution_claim: "none" | "local_only";
}

export interface SubscribeInput {
  targetPath: string;
  /** Canonical github.com/openai/codex/issues/N URL or issue number string. */
  issue: string | number;
  nowMs?: number;
  stateDir?: string;
}

export interface UnsubscribeInput {
  targetPath: string;
  issue: string | number;
  nowMs?: number;
  stateDir?: string;
}

export interface StatusInput {
  targetPath: string;
  nowMs?: number;
  stateDir?: string;
}

export interface SessionHintInput {
  targetPath: string;
  nowMs?: number;
  stateDir?: string;
}

export interface RefreshInput {
  targetPath: string;
  /**
   * Optional local event snapshot for a subscribed issue (no network).
   * Production without snapshot → silent / no-new-evidence.
   */
  event?: unknown;
  /**
   * Disclosure decision for any injected transport. Default network is never used.
   * Transport without `approved` is fail-closed.
   */
  disclosure_decision?: "approved" | "refused" | "not_requested";
  /**
   * Injected transport handle only (tests/orchestration). Production omits/null.
   * Non-null without approved disclosure → REFUSED. Core never opens sockets.
   */
  transport?: unknown | null;
  nowMs?: number;
  stateDir?: string;
}

export interface ProcessEventInput {
  targetPath: string;
  event: unknown;
  nowMs?: number;
  stateDir?: string;
}

export interface FollowupDispatchArgs {
  target: string;
  operation: string;
  issue?: string | number;
  event?: unknown;
  candidate_version?: string;
  recipe_id?: string;
  official_evidence_item_digest?: string;
  official_evidence_ref?: string;
  original_fault_absent?: boolean;
  core_regressions_passed?: boolean;
  verified?: boolean;
  now_ms?: number;
  state_dir?: string;
}
