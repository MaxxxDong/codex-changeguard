/**
 * Product contract: only Ticket 10 capsules with valid integrity, status,
 * privacy gate, recommendation, and content hash may become actions.
 * Blocked / gate-failed / private-only capsules can never become actions.
 */
import { sha256Canonical } from "../../evidence/canonical.js";
import type {
  DuplicateRecommendation,
  UpstreamSubmissionCapsule,
} from "../types.js";
import type {
  CapsuleGateCheck,
  CapsuleGateResult,
  UpstreamActionKind,
} from "./types.js";

const ACTIONABLE_STATUS = new Set(["PREVIEW_READY"]);

/** Recommendation → allowed action kinds (only these may be previewed). */
const RECOMMENDATION_ACTIONS: Record<
  DuplicateRecommendation,
  readonly UpstreamActionKind[]
> = {
  open_new: ["create_issue", "attachment_upload"],
  comment_with_delta: ["comment_with_delta", "attachment_upload"],
  subscribe_or_upvote: ["react_upvote", "subscribe"],
  cross_link_related: ["create_issue", "attachment_upload"],
  open_discussion: [], // Ticket 11 action surface is issue-oriented only
  private_report: [],
  contact_support: [],
  blocked: [],
};

function check(
  id: string,
  passed: boolean,
  detail: string,
): CapsuleGateCheck {
  return { id, passed, detail };
}

/**
 * Recompute capsule_content_sha256 the same way Ticket 10 does:
 * hash the full capsule with capsule_content_sha256 nulled.
 */
export function recomputeCapsuleContentSha256(
  capsule: UpstreamSubmissionCapsule,
): string {
  return sha256Canonical({
    ...capsule,
    capsule_content_sha256: null,
  });
}

export function allowedActionsForRecommendation(
  recommendation: DuplicateRecommendation,
): UpstreamActionKind[] {
  return [...(RECOMMENDATION_ACTIONS[recommendation] ?? [])];
}

/**
 * Validate a Ticket 10 capsule for Ticket 11 action eligibility.
 * Never mutates the capsule; never promotes blocked/gate-failed.
 */
export function gateCapsuleForActions(
  raw: unknown,
): CapsuleGateResult {
  const checks: CapsuleGateCheck[] = [];
  const fail = (
    id: string,
    detail: string,
    extra: CapsuleGateCheck[] = [],
  ): CapsuleGateResult => {
    const all = [...checks, check(id, false, detail), ...extra];
    return {
      passed: false,
      checks: all,
      failed_ids: all.filter((c) => !c.passed).map((c) => c.id),
      allowed_actions: [],
      capsule: null,
    };
  };

  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return fail("shape", "Capsule must be a plain object.");
  }
  const c = raw as Record<string, unknown>;

  if (c.schema_version !== 1) {
    return fail("schema_version", "schema_version must be 1.");
  }
  checks.push(check("schema_version", true, "schema_version=1"));

  if (c.mode !== "preview_only") {
    return fail("mode", "Capsule mode must be preview_only.");
  }
  checks.push(check("mode", true, "preview_only"));

  if (c.locality !== "local_only") {
    return fail("locality", "Capsule locality must be local_only.");
  }
  checks.push(check("locality", true, "local_only"));

  if (c.external_write !== false) {
    return fail("external_write", "Capsule external_write must be false.");
  }
  checks.push(check("external_write", true, "false"));

  if (c.repair_authorized !== false) {
    return fail("repair_authorized", "repair_authorized must be false.");
  }
  checks.push(check("repair_authorized", true, "false"));

  if (c.requires_ticket11_confirmation !== true) {
    return fail(
      "requires_ticket11_confirmation",
      "Capsule must require Ticket 11 confirmation.",
    );
  }
  checks.push(
    check("requires_ticket11_confirmation", true, "true"),
  );

  const status = c.status;
  if (typeof status !== "string") {
    return fail("status", "Capsule status missing.");
  }
  // Blocked / gate-failed / private routes can never become public actions.
  if (status === "PREVIEW_BLOCKED" || status === "GATE_FAILED") {
    return fail(
      "status_blocked",
      `Blocked/gate-failed capsule cannot become actions (status=${status}).`,
    );
  }
  if (status === "ROUTED_PRIVATE") {
    return fail(
      "status_private",
      "ROUTED_PRIVATE capsules never become public GitHub actions.",
    );
  }
  if (!ACTIONABLE_STATUS.has(status)) {
    return fail("status", `Status ${status} is not actionable.`);
  }
  checks.push(check("status", true, "PREVIEW_READY"));

  const privacy = c.privacy_review;
  if (
    privacy === null ||
    typeof privacy !== "object" ||
    Array.isArray(privacy)
  ) {
    return fail("privacy_shape", "privacy_review missing.");
  }
  const pr = privacy as Record<string, unknown>;
  if (pr.passed !== true) {
    return fail("privacy_passed", "privacy_review.passed must be true.");
  }
  if (pr.secrets_redacted !== true) {
    return fail("privacy_secrets", "secrets_redacted must be true.");
  }
  if (pr.paths_redacted !== true) {
    return fail("privacy_paths", "paths_redacted must be true.");
  }
  if (pr.session_excluded !== true) {
    return fail("privacy_session", "session_excluded must be true.");
  }
  if (pr.injection_quarantined === true) {
    return fail("privacy_injection", "injection-quarantined capsule refused.");
  }
  checks.push(check("privacy", true, "privacy gate passed"));

  const gate = c.maintainer_value_gate;
  if (gate === null || typeof gate !== "object" || Array.isArray(gate)) {
    return fail("maintainer_gate_shape", "maintainer_value_gate missing.");
  }
  if ((gate as Record<string, unknown>).passed !== true) {
    return fail(
      "maintainer_gate",
      "maintainer_value_gate.passed must be true.",
    );
  }
  checks.push(check("maintainer_gate", true, "passed"));

  const dup = c.duplicate;
  if (dup === null || typeof dup !== "object" || Array.isArray(dup)) {
    return fail("duplicate_shape", "duplicate assessment missing.");
  }
  const recommendation = (dup as Record<string, unknown>)
    .recommendation as DuplicateRecommendation | undefined;
  if (typeof recommendation !== "string") {
    return fail("recommendation", "duplicate.recommendation missing.");
  }
  if (recommendation === "blocked") {
    return fail(
      "recommendation_blocked",
      "blocked recommendation cannot become actions.",
    );
  }
  const allowed = allowedActionsForRecommendation(recommendation);
  if (allowed.length === 0) {
    return fail(
      "recommendation_non_actionable",
      `Recommendation ${recommendation} has no Ticket 11 actions.`,
    );
  }
  checks.push(
    check(
      "recommendation",
      true,
      `recommendation=${recommendation}; actions=${allowed.join(",")}`,
    ),
  );

  if (typeof c.capsule_content_sha256 !== "string") {
    return fail("content_hash_missing", "capsule_content_sha256 missing.");
  }
  if (typeof c.capsule_id !== "string") {
    return fail("capsule_id", "capsule_id missing.");
  }

  // Integrity: recompute content hash; refuse tampered capsules.
  const capsule = c as unknown as UpstreamSubmissionCapsule;
  let recomputed: string;
  try {
    recomputed = recomputeCapsuleContentSha256(capsule);
  } catch {
    return fail("content_hash_compute", "Failed to recompute content hash.");
  }
  if (recomputed !== c.capsule_content_sha256) {
    return fail(
      "content_hash_mismatch",
      "capsule_content_sha256 does not match capsule integrity.",
    );
  }
  checks.push(check("content_hash", true, "capsule_content_sha256 valid"));

  return {
    passed: true,
    checks,
    failed_ids: [],
    allowed_actions: allowed,
    capsule,
  };
}

export function isActionAllowed(
  gate: CapsuleGateResult,
  action: UpstreamActionKind,
): boolean {
  return gate.passed && gate.allowed_actions.includes(action);
}
