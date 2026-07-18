/**
 * Single dispatcher for CLI/MCP follow-up tools.
 * Strict allowlists; additionalProperties refused at MCP schema layer.
 */
import {
  followupStatus,
  processFollowupEvent,
  refreshFollowup,
  sessionFollowupHint,
  subscribeIssue,
  unsubscribeIssue,
  validateCandidate,
} from "./engine.js";
import { parseCanonicalIssue, IssueUrlError } from "./issue-url.js";
import type { FollowupOperation, FollowupResult } from "./types.js";

const OPS = new Set<FollowupOperation>([
  "subscribe",
  "unsubscribe",
  "status",
  "session_hint",
  "refresh",
  "process_event",
  "validate_candidate",
]);

export function isFollowupOperation(v: string): v is FollowupOperation {
  return OPS.has(v as FollowupOperation);
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
  /** Disposable baseline root for registered live measurement (Ticket 12). */
  baseline_target?: string;
  /** Closed measurement profile id (Phase A: protected_process_shim_v1). */
  measurement_profile_id?: string;
  original_fault_absent?: boolean;
  core_regressions_passed?: boolean;
  verified?: boolean;
  now_ms?: number;
  state_dir?: string;
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function dispatchFollowup(args: FollowupDispatchArgs): FollowupResult {
  const op = args.operation;
  if (!isFollowupOperation(op)) {
    return {
      schema_version: 1,
      ok: false,
      operation: "status",
      status: "INVALID_INPUT",
      user_resolution: {
        status: "INCONCLUSIVE",
        summary: "Unknown follow-up operation.",
        receipt_id: "followup_usage",
      },
      upstream_contribution: {
        status: "NONE",
        summary: "No upstream contribution.",
        issue_candidates: [],
        receipt_id: "followup_usage_up",
      },
      subscription: null,
      subscriptions: null,
      disposition: null,
      intents: null,
      probe_plan: null,
      evidence_capsule: null,
      reply_draft: null,
      candidate: null,
      ledger: null,
      session_hint: null,
      evidence: [],
      error_code: "UNKNOWN_OPERATION",
      error_message: "Unknown follow-up operation.",
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      external_write: false,
      adapter_status: "not_applicable",
      contribution_claim: "none",
    };
  }

  const target = args.target;
  const nowMs = asNumber(args.now_ms);
  const stateDir = asString(args.state_dir) ?? undefined;

  switch (op) {
    case "subscribe": {
      const issue = args.issue;
      if (issue === undefined || issue === null || issue === "") {
        return failUsage(op, "issue required.");
      }
      return subscribeIssue({
        targetPath: target,
        issue: issue as string | number,
        nowMs,
        stateDir,
      });
    }
    case "unsubscribe": {
      const issue = args.issue;
      if (issue === undefined || issue === null || issue === "") {
        return failUsage(op, "issue required.");
      }
      return unsubscribeIssue({
        targetPath: target,
        issue: issue as string | number,
        nowMs,
        stateDir,
      });
    }
    case "status":
      return followupStatus({ targetPath: target, nowMs, stateDir });
    case "session_hint":
      return sessionFollowupHint({ targetPath: target, nowMs, stateDir });
    case "refresh":
      return refreshFollowup({
        targetPath: target,
        event: args.event,
        nowMs,
        stateDir,
      });
    case "process_event": {
      if (args.event === undefined) {
        return failUsage(op, "event required.");
      }
      return processFollowupEvent({
        targetPath: target,
        event: args.event,
        nowMs,
        stateDir,
      });
    }
    case "validate_candidate": {
      const candidate_version = asString(args.candidate_version);
      const recipe_id = asString(args.recipe_id);
      const official_evidence_item_digest = asString(
        args.official_evidence_item_digest,
      );
      const official_evidence_ref = asString(args.official_evidence_ref);
      const issue = args.issue;
      if (
        !candidate_version ||
        !recipe_id ||
        !official_evidence_item_digest ||
        !official_evidence_ref ||
        issue === undefined ||
        issue === null ||
        issue === ""
      ) {
        return failUsage(
          op,
          "issue, candidate_version, recipe_id, official_evidence_item_digest, official_evidence_ref required.",
        );
      }
      let issue_number: number;
      try {
        issue_number = parseCanonicalIssue(issue as string | number).issue_number;
      } catch (e) {
        const msg =
          e instanceof IssueUrlError ? e.message : "Invalid issue for candidate validation.";
        return failUsage(op, msg);
      }
      // baseline + closed profile required for live measurement authority.
      // Missing fields fail closed inside validateCandidateFix (no CLI boolean bypass).
      return validateCandidate({
        targetPath: target,
        baselineTargetPath: asString(args.baseline_target) ?? "",
        measurement_profile_id: asString(args.measurement_profile_id) ?? "",
        issue_number,
        candidate_version,
        recipe_id,
        official_evidence_item_digest,
        official_evidence_ref,
        original_fault_absent: args.original_fault_absent,
        core_regressions_passed: args.core_regressions_passed,
        verified: args.verified,
        nowMs,
      });
    }
    default:
      return failUsage("status", "Unknown follow-up operation.");
  }
}

function failUsage(operation: FollowupOperation, message: string): FollowupResult {
  return {
    schema_version: 1,
    ok: false,
    operation,
    status: "INVALID_INPUT",
    user_resolution: {
      status: "INCONCLUSIVE",
      summary: message,
      receipt_id: "followup_usage",
    },
    upstream_contribution: {
      status: "NONE",
      summary: "No upstream contribution.",
      issue_candidates: [],
      receipt_id: "followup_usage_up",
    },
    subscription: null,
    subscriptions: null,
    disposition: null,
    intents: null,
    probe_plan: null,
    evidence_capsule: null,
    reply_draft: null,
    candidate: null,
    ledger: null,
    session_hint: null,
    evidence: [],
    error_code: "USAGE",
    error_message: message,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    external_write: false,
    adapter_status: "not_applicable",
    contribution_claim: "none",
  };
}
