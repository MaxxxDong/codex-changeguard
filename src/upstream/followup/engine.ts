/**
 * Ticket 12 follow-up orchestration: explicit subscriptions, disposition,
 * maintainer intent → registered probes, evidence capsule, reply draft,
 * SessionStart refresh-due hint (no fetch), candidate validation.
 *
 * Production default: zero network, silent when nothing changed,
 * external_write: false, ADAPTER_UNAVAILABLE for remote writes.
 */
import { receiptId } from "../../core/recovery/canonical.js";
import { sha256Canonical, sha256Text } from "../../evidence/canonical.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import { resolveTargetDirectory, PathSafetyError } from "../../core/path-safety.js";
import type {
  MeasuredEvidence,
  UpstreamContributionReceipt,
  UserResolutionReceipt,
} from "../../core/types.js";
import { applyDispositionPolicy, isUpstreamDisposition } from "./disposition.js";
import { detectMaintainerIntents, mapIntentsToProbes } from "./intent.js";
import { parseCanonicalIssue, IssueUrlError } from "./issue-url.js";
import {
  appendEvent,
  emptyFollowupLedger,
  findSubscription,
  FollowupLedgerError,
  loadFollowupLedger,
  resolveFollowupStateRoot,
  withFollowupLedgerTransaction,
  upsertSubscription,
} from "./ledger.js";
import { buildEvidenceCapsule, buildReplyDraft } from "./capsule.js";
import { runRegisteredProbes } from "./probes.js";
import { validateCandidateFix } from "./candidate.js";
import {
  FORBIDDEN_FOLLOWUP_KEYS,
  MAX_FOLLOWUP_REQUEST_BYTES,
  MAX_PROSE,
  MAX_STRING,
  REFRESH_DUE_HINT,
  REFRESH_MIN_INTERVAL_MS,
} from "./limits.js";
import type {
  CandidateValidationInput,
  FollowupEventRecord,
  FollowupLedger,
  FollowupOperation,
  FollowupResult,
  FollowupStatus,
  ProcessEventInput,
  RefreshInput,
  SessionHintInput,
  StatusInput,
  SubscribeInput,
  SubscriptionRecord,
  UnsubscribeInput,
  UpstreamDisposition,
} from "./types.js";

function nowOf(n?: number): number {
  return typeof n === "number" && Number.isFinite(n) ? n : Date.now();
}

function userReceipt(
  status: UserResolutionReceipt["status"],
  summary: string,
): UserResolutionReceipt {
  return {
    status,
    summary: assertNoLeakPaths(redactText(summary)).slice(0, MAX_STRING),
    receipt_id: receiptId("followup_user"),
  };
}

function upstreamReceipt(
  status: UpstreamContributionReceipt["status"],
  summary: string,
  issue_candidates: string[] = [],
): UpstreamContributionReceipt {
  return {
    status,
    summary: assertNoLeakPaths(redactText(summary)).slice(0, MAX_STRING),
    issue_candidates,
    receipt_id: receiptId("followup_up"),
  };
}

function baseResult(
  partial: Partial<FollowupResult> &
    Pick<FollowupResult, "ok" | "operation" | "status">,
): FollowupResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    operation: partial.operation,
    status: partial.status,
    user_resolution:
      partial.user_resolution ??
      userReceipt("INCONCLUSIVE", partial.error_message ?? "Follow-up incomplete."),
    upstream_contribution:
      partial.upstream_contribution ??
      upstreamReceipt("NONE", "No upstream contribution."),
    subscription: partial.subscription ?? null,
    subscriptions: partial.subscriptions ?? null,
    disposition: partial.disposition ?? null,
    intents: partial.intents ?? null,
    probe_plan: partial.probe_plan ?? null,
    evidence_capsule: partial.evidence_capsule ?? null,
    reply_draft: partial.reply_draft ?? null,
    candidate: partial.candidate ?? null,
    ledger: partial.ledger ?? null,
    session_hint: partial.session_hint ?? null,
    evidence: partial.evidence ?? [],
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
    network_used: false,
    target_mutated: partial.target_mutated ?? false,
    repair_applied: false,
    external_write: false,
    adapter_status: partial.adapter_status ?? "unavailable",
    contribution_claim: partial.contribution_claim ?? "local_only",
  };
}

function fail(
  operation: FollowupOperation,
  status: FollowupStatus,
  code: string,
  message: string,
): FollowupResult {
  return baseResult({
    ok: false,
    operation,
    status,
    error_code: code,
    error_message: message,
    user_resolution: userReceipt("INCONCLUSIVE", message),
    contribution_claim: "none",
    adapter_status: "not_applicable",
  });
}

function mapError(operation: FollowupOperation, e: unknown): FollowupResult {
  if (e instanceof FollowupLedgerError) {
    return fail(operation, "LEDGER_ERROR", e.code, e.message);
  }
  if (e instanceof IssueUrlError) {
    const st: FollowupStatus =
      e.code === "UNAUTHORIZED_REPOSITORY"
        ? "UNAUTHORIZED_REPOSITORY"
        : e.code === "UNAUTHORIZED_ISSUE"
          ? "UNAUTHORIZED_ISSUE"
          : "INVALID_INPUT";
    return fail(operation, st, e.code, e.message);
  }
  if (e instanceof PathSafetyError) {
    return fail(operation, "REFUSED", e.code, e.message);
  }
  return fail(operation, "REFUSED", "INTERNAL", "Follow-up operation failed.");
}

function stateRoot(override?: string): string {
  return resolveFollowupStateRoot(override ?? null);
}

/** Refuse forbidden privacy keys anywhere in object (shallow + one nested level). */
function refuseForbiddenKeys(obj: unknown, path = "root"): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (const v of obj) refuseForbiddenKeys(v, path);
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const lk = k.toLowerCase();
    if ((FORBIDDEN_FOLLOWUP_KEYS as readonly string[]).includes(lk)) {
      throw new Error(`Forbidden key refused: ${k}`);
    }
    if (v && typeof v === "object") refuseForbiddenKeys(v, `${path}.${k}`);
  }
}

export function subscribeIssue(input: SubscribeInput): FollowupResult {
  const op: FollowupOperation = "subscribe";
  try {
    resolveTargetDirectory(input.targetPath);
    const ref = parseCanonicalIssue(input.issue);
    const nowMs = nowOf(input.nowMs);
    const root = stateRoot(input.stateDir);
    return withFollowupLedgerTransaction(root, nowMs, (ledger) => {
      const existing = findSubscription(ledger, ref.issue_number);
      if (existing) {
        // Idempotent re-subscribe — no persist
        return {
          ledger,
          persist: false,
          result: baseResult({
            ok: true,
            operation: op,
            status: "OK",
            subscription: existing,
            ledger,
            user_resolution: userReceipt(
              "DIAGNOSIS_COMPLETE",
              `Already subscribed to #${ref.issue_number}.`,
            ),
            upstream_contribution: upstreamReceipt(
              "CANDIDATE_ONLY",
              "Local subscription only; no network.",
              [ref.canonical_url],
            ),
            evidence: [
              {
                kind: "followup_subscribe_idempotent",
                detail: `issue=${ref.issue_number}`,
                measured: true,
              },
            ],
            target_mutated: false,
            adapter_status: "not_applicable",
          }),
        };
      }
      const sub: SubscriptionRecord = {
        issue_number: ref.issue_number,
        canonical_url: ref.canonical_url,
        subscribed_at_ms: nowMs,
        last_refresh_at_ms: null,
        last_event_digest: null,
        last_disposition: null,
        duplicate_of_issue: null,
        active: true,
      };
      const next = upsertSubscription(ledger, sub, nowMs);
      return {
        ledger: next,
        persist: true,
        result: baseResult({
          ok: true,
          operation: op,
          status: "OK",
          subscription: sub,
          ledger: next,
          user_resolution: userReceipt(
            "DIAGNOSIS_COMPLETE",
            `Subscribed to #${ref.issue_number} (explicit local only).`,
          ),
          upstream_contribution: upstreamReceipt(
            "CANDIDATE_ONLY",
            "Local subscription recorded; no crawler or daemon.",
            [ref.canonical_url],
          ),
          evidence: [
            {
              kind: "followup_subscribed",
              detail: `issue=${ref.issue_number}`,
              measured: true,
            },
          ],
          target_mutated: true,
          adapter_status: "not_applicable",
        }),
      };
    });
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Forbidden key")) {
      return fail(op, "REFUSED", "FORBIDDEN_KEY", e.message);
    }
    return mapError(op, e);
  }
}

export function unsubscribeIssue(input: UnsubscribeInput): FollowupResult {
  const op: FollowupOperation = "unsubscribe";
  try {
    resolveTargetDirectory(input.targetPath);
    const ref = parseCanonicalIssue(input.issue);
    const nowMs = nowOf(input.nowMs);
    const root = stateRoot(input.stateDir);
    return withFollowupLedgerTransaction(root, nowMs, (ledger) => {
      const existing = findSubscription(ledger, ref.issue_number);
      if (!existing) {
        return {
          ledger,
          persist: false,
          result: baseResult({
            ok: true,
            operation: op,
            status: "OK",
            subscription: null,
            ledger,
            user_resolution: userReceipt(
              "DIAGNOSIS_COMPLETE",
              `No active subscription for #${ref.issue_number}.`,
            ),
            target_mutated: false,
            adapter_status: "not_applicable",
            contribution_claim: "none",
          }),
        };
      }
      const sub: SubscriptionRecord = { ...existing, active: false };
      const next = upsertSubscription(ledger, sub, nowMs);
      return {
        ledger: next,
        persist: true,
        result: baseResult({
          ok: true,
          operation: op,
          status: "OK",
          subscription: sub,
          ledger: next,
          user_resolution: userReceipt(
            "DIAGNOSIS_COMPLETE",
            `Unsubscribed from #${ref.issue_number}.`,
          ),
          evidence: [
            {
              kind: "followup_unsubscribed",
              detail: `issue=${ref.issue_number}`,
              measured: true,
            },
          ],
          target_mutated: true,
          adapter_status: "not_applicable",
          contribution_claim: "none",
        }),
      };
    });
  } catch (e) {
    return mapError(op, e);
  }
}

export function followupStatus(input: StatusInput): FollowupResult {
  const op: FollowupOperation = "status";
  try {
    resolveTargetDirectory(input.targetPath);
    const nowMs = nowOf(input.nowMs);
    const root = stateRoot(input.stateDir);
    const ledger = loadFollowupLedger(root, nowMs);
    const active = ledger.subscriptions.filter((s) => s.active);
    return baseResult({
      ok: true,
      operation: op,
      status: "OK",
      subscriptions: active,
      ledger,
      user_resolution: userReceipt(
        "DIAGNOSIS_COMPLETE",
        `Active subscriptions: ${active.length}.`,
      ),
      target_mutated: false,
      adapter_status: "not_applicable",
      contribution_claim: "none",
    });
  } catch (e) {
    return mapError(op, e);
  }
}

/**
 * SessionStart seam: path-free local "refresh due" hint only; never fetch.
 * Silent when no subscription is due.
 */
export function sessionFollowupHint(input: SessionHintInput): FollowupResult {
  const op: FollowupOperation = "session_hint";
  try {
    resolveTargetDirectory(input.targetPath);
    const nowMs = nowOf(input.nowMs);
    const root = stateRoot(input.stateDir);
    const ledger = loadFollowupLedger(root, nowMs);
    const due = ledger.subscriptions.some((s) => {
      if (!s.active) return false;
      if (s.last_refresh_at_ms === null) return true;
      return nowMs - s.last_refresh_at_ms >= REFRESH_MIN_INTERVAL_MS;
    });
    if (!due) {
      return baseResult({
        ok: true,
        operation: op,
        status: "SILENT",
        session_hint: null,
        ledger,
        user_resolution: userReceipt("DIAGNOSIS_COMPLETE", "No follow-up refresh due."),
        target_mutated: false,
        adapter_status: "not_applicable",
        contribution_claim: "none",
      });
    }
    return baseResult({
      ok: true,
      operation: op,
      status: "REFRESH_DUE",
      session_hint: REFRESH_DUE_HINT,
      ledger,
      user_resolution: userReceipt(
        "DIAGNOSIS_COMPLETE",
        "Follow-up refresh due (local hint only; no network fetch).",
      ),
      evidence: [
        {
          kind: "followup_session_hint",
          detail: REFRESH_DUE_HINT,
          measured: true,
        },
      ],
      target_mutated: false,
      adapter_status: "not_applicable",
      contribution_claim: "none",
    });
  } catch (e) {
    return mapError(op, e);
  }
}

/**
 * Manual refresh: zero network. Without a local event snapshot → NO_NEW_EVIDENCE.
 * With event for a subscribed issue → process_event path.
 */
export function refreshFollowup(input: RefreshInput): FollowupResult {
  const op: FollowupOperation = "refresh";
  try {
    resolveTargetDirectory(input.targetPath);
    const nowMs = nowOf(input.nowMs);
    const root = stateRoot(input.stateDir);
    // Disclosure gate: any injected transport requires approved disclosure.
    // Production path injects null/omits transport → zero network.
    if (input.transport != null && input.transport !== undefined) {
      const decision = input.disclosure_decision ?? "not_requested";
      if (decision !== "approved") {
        return fail(
          op,
          "REFUSED",
          "DISCLOSURE_REFUSED",
          "Injected follow-up transport requires approved disclosure; no network.",
        );
      }
      // Even with approval, this core phase never opens sockets — local event only.
      // Adapter remains unavailable; network_used stays false.
    }
    if (!input.event) {
      // Touch refresh timestamps for due subscriptions (local only) under lock.
      return withFollowupLedgerTransaction(root, nowMs, (ledger) => {
        let next: FollowupLedger = ledger;
        let changed = false;
        for (const s of ledger.subscriptions) {
          if (!s.active) continue;
          const due =
            s.last_refresh_at_ms === null ||
            nowMs - s.last_refresh_at_ms >= REFRESH_MIN_INTERVAL_MS;
          if (due) {
            next = upsertSubscription(
              next,
              { ...s, last_refresh_at_ms: nowMs },
              nowMs,
            );
            changed = true;
          }
        }
        return {
          ledger: next,
          persist: changed,
          result: baseResult({
            ok: true,
            operation: op,
            status: "NO_NEW_EVIDENCE",
            ledger: next,
            reply_draft: buildReplyDraft({
              capsule: null,
              disposition: "open_active",
              no_new_evidence: true,
              injection: false,
            }),
            user_resolution: userReceipt(
              "DIAGNOSIS_COMPLETE",
              "No local event snapshot; zero network; no new evidence.",
            ),
            evidence: [
              {
                kind: "followup_no_new_evidence",
                detail: "refresh_without_event",
                measured: true,
              },
            ],
            target_mutated: changed,
            adapter_status: "unavailable",
          }),
        };
      });
    }
    return processFollowupEvent({
      targetPath: input.targetPath,
      event: input.event,
      nowMs,
      stateDir: input.stateDir,
    });
  } catch (e) {
    return mapError(op, e);
  }
}

interface ParsedEvent {
  issue_number: number;
  disposition: UpstreamDisposition;
  maintainer_prose: string;
  duplicate_of_issue: number | null;
  event_id: string;
}

function parseEventEnvelope(raw: unknown): ParsedEvent {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("INVALID_EVENT");
  }
  const bytes = Buffer.byteLength(JSON.stringify(raw), "utf8");
  if (bytes > MAX_FOLLOWUP_REQUEST_BYTES) {
    throw new Error("SIZE_LIMIT");
  }
  refuseForbiddenKeys(raw);
  const o = raw as Record<string, unknown>;
  // Strict allowlist of top-level keys
  const allowed = new Set([
    "schema_version",
    "issue",
    "issue_number",
    "disposition",
    "maintainer_prose",
    "duplicate_of_issue",
    "event_id",
  ]);
  for (const k of Object.keys(o)) {
    if (!allowed.has(k)) {
      throw new Error("EXTRA_FIELD");
    }
  }
  if (o.schema_version !== undefined && o.schema_version !== 1) {
    throw new Error("INVALID_SCHEMA");
  }
  let issue_number: number;
  if (o.issue !== undefined) {
    issue_number = parseCanonicalIssue(o.issue as string | number).issue_number;
  } else if (o.issue_number !== undefined) {
    issue_number = parseCanonicalIssue(o.issue_number as string | number).issue_number;
  } else {
    throw new Error("MISSING_ISSUE");
  }
  if (!isUpstreamDisposition(o.disposition)) {
    throw new Error("INVALID_DISPOSITION");
  }
  const prose =
    typeof o.maintainer_prose === "string"
      ? o.maintainer_prose.slice(0, MAX_PROSE)
      : "";
  let duplicate_of_issue: number | null = null;
  if (o.duplicate_of_issue !== undefined && o.duplicate_of_issue !== null) {
    duplicate_of_issue = parseCanonicalIssue(
      o.duplicate_of_issue as string | number,
    ).issue_number;
  }
  const event_id =
    typeof o.event_id === "string" && o.event_id.length > 0
      ? o.event_id.slice(0, 128)
      : `ev_${sha256Text(`${issue_number}:${o.disposition}:${prose}`).slice(0, 24)}`;
  return {
    issue_number,
    disposition: o.disposition,
    maintainer_prose: prose,
    duplicate_of_issue,
    event_id,
  };
}

export function processFollowupEvent(input: ProcessEventInput): FollowupResult {
  const op: FollowupOperation = "process_event";
  try {
    resolveTargetDirectory(input.targetPath);
    const nowMs = nowOf(input.nowMs);
    const root = stateRoot(input.stateDir);

    let parsed: ParsedEvent;
    try {
      parsed = parseEventEnvelope(input.event);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "INVALID_EVENT";
      return fail(op, "INVALID_INPUT", msg, `Event envelope refused: ${msg}`);
    }

    const ref = parseCanonicalIssue(parsed.issue_number);
    const event_digest = sha256Canonical({
      issue_number: parsed.issue_number,
      disposition: parsed.disposition,
      prose: parsed.maintainer_prose,
      duplicate_of_issue: parsed.duplicate_of_issue,
    });

    // Probes/intents are pure/local and do not touch the ledger; compute outside
    // the lock window when possible, but subscription checks + mutations are locked.
    const disposition = applyDispositionPolicy({
      disposition: parsed.disposition,
      duplicate_of_issue: parsed.duplicate_of_issue,
    });
    if (
      disposition.auto_reopen ||
      disposition.cross_post ||
      disposition.auto_comment ||
      disposition.auto_react
    ) {
      return fail(op, "REFUSED", "FORBIDDEN_AUTO_ACTION", "Forbidden auto-action.");
    }

    const intentResult = detectMaintainerIntents(parsed.maintainer_prose);
    const probe_plan = mapIntentsToProbes(intentResult.intents);
    const probe_results = intentResult.instruction_like
      ? []
      : runRegisteredProbes(input.targetPath, probe_plan.runnable);

    const capsule = buildEvidenceCapsule({
      issue_number: ref.issue_number,
      canonical_url: ref.canonical_url,
      intents: intentResult.intents,
      probe_results,
      quarantine: intentResult.quarantine,
    });

    const reply_draft = buildReplyDraft({
      capsule,
      disposition: parsed.disposition,
      no_new_evidence: false,
      injection: intentResult.instruction_like,
    });

    return withFollowupLedgerTransaction(root, nowMs, (ledger) => {
      const sub = findSubscription(ledger, ref.issue_number);
      if (!sub) {
        return {
          ledger,
          persist: false,
          result: fail(
            op,
            "UNAUTHORIZED_ISSUE",
            "NOT_SUBSCRIBED",
            "Issue is not on the explicit local subscription list.",
          ),
        };
      }

      // Idempotent replay: same digest → no new evidence
      if (sub.last_event_digest === event_digest) {
        return {
          ledger,
          persist: false,
          result: baseResult({
            ok: true,
            operation: op,
            status: "NO_NEW_EVIDENCE",
            subscription: sub,
            ledger,
            reply_draft: buildReplyDraft({
              capsule: null,
              disposition: parsed.disposition,
              no_new_evidence: true,
              injection: false,
            }),
            user_resolution: userReceipt(
              "DIAGNOSIS_COMPLETE",
              "Event already processed (idempotent); no new evidence.",
            ),
            evidence: [
              {
                kind: "followup_replay",
                detail: `issue=${ref.issue_number}`,
                measured: true,
              },
            ],
            target_mutated: false,
            adapter_status: "unavailable",
          }),
        };
      }

      // Update subscription + migration
      let nextSub: SubscriptionRecord = {
        ...sub,
        last_refresh_at_ms: nowMs,
        last_event_digest: event_digest,
        last_disposition: parsed.disposition,
        duplicate_of_issue: disposition.migrate_to_issue,
      };

      let nextLedger = ledger;
      if (
        parsed.disposition === "duplicate" &&
        disposition.migrate_to_issue !== null
      ) {
        nextSub = { ...nextSub, active: false };
        nextLedger = upsertSubscription(nextLedger, nextSub, nowMs);
        const migRef = parseCanonicalIssue(disposition.migrate_to_issue);
        const existingMig = findSubscription(nextLedger, migRef.issue_number);
        if (!existingMig) {
          nextLedger = upsertSubscription(
            nextLedger,
            {
              issue_number: migRef.issue_number,
              canonical_url: migRef.canonical_url,
              subscribed_at_ms: nowMs,
              last_refresh_at_ms: nowMs,
              last_event_digest: null,
              last_disposition: "open_active",
              duplicate_of_issue: null,
              active: true,
            },
            nowMs,
          );
        }
      } else {
        nextLedger = upsertSubscription(nextLedger, nextSub, nowMs);
      }

      const eventRec: FollowupEventRecord = {
        event_id: parsed.event_id,
        issue_number: ref.issue_number,
        disposition: parsed.disposition,
        event_digest,
        processed_at_ms: nowMs,
        intents: intentResult.intents,
        probe_ids: probe_plan.probe_ids,
        evidence_capsule_id: capsule?.capsule_id ?? null,
        reply_draft_digest: reply_draft.content_digest,
      };
      nextLedger = appendEvent(nextLedger, eventRec, nowMs);

      const status: FollowupStatus = intentResult.instruction_like
        ? "REFUSED"
        : reply_draft.draft_status === "READY"
          ? "REPLY_DRAFT_READY"
          : "DISPOSITION_APPLIED";

      const evidence: MeasuredEvidence[] = [
        {
          kind: "followup_disposition",
          detail: `disposition=${parsed.disposition};auto_reopen=false`,
          measured: true,
        },
        {
          kind: "followup_intents",
          detail: intentResult.intents.join(","),
          measured: true,
        },
      ];
      if (capsule) {
        evidence.push({
          kind: "followup_evidence_capsule",
          detail: capsule.capsule_id,
          measured: true,
        });
      }

      return {
        ledger: nextLedger,
        persist: true,
        result: baseResult({
          ok: !intentResult.instruction_like,
          operation: op,
          status,
          subscription: nextSub,
          disposition,
          intents: intentResult.intents,
          probe_plan,
          evidence_capsule: capsule,
          reply_draft,
          ledger: nextLedger,
          user_resolution: userReceipt(
            intentResult.instruction_like ? "INCONCLUSIVE" : "DIAGNOSIS_COMPLETE",
            disposition.user_guidance,
          ),
          upstream_contribution: upstreamReceipt(
            "CANDIDATE_ONLY",
            "Reply draft is local-only; Ticket 11 confirmation required before any write. Adapter unavailable in production.",
            [ref.canonical_url],
          ),
          evidence,
          target_mutated: true,
          adapter_status: "unavailable",
          error_code: intentResult.instruction_like ? "INJECTION_QUARANTINED" : null,
          error_message: intentResult.instruction_like
            ? "Maintainer prose contained instruction-like content; quarantined; no probes; no draft export of raw text."
            : null,
        }),
      };
    });
  } catch (e) {
    return mapError(op, e);
  }
}

export function validateCandidate(input: CandidateValidationInput): FollowupResult {
  const op: FollowupOperation = "validate_candidate";
  try {
    const candidate = validateCandidateFix(input);
    return baseResult({
      ok: candidate.ok,
      operation: op,
      status: candidate.status,
      candidate,
      user_resolution: userReceipt(
        candidate.ok ? "DIAGNOSIS_COMPLETE" : "INCONCLUSIVE",
        candidate.detail,
      ),
      upstream_contribution: upstreamReceipt(
        candidate.status === "SUPERSEDED" ? "CANDIDATE_ONLY" : "NONE",
        candidate.status === "SUPERSEDED"
          ? "Official fix supersession recorded locally; guidance only."
          : "No supersession.",
      ),
      evidence: candidate.evidence,
      error_code: candidate.error_code,
      error_message: candidate.error_message,
      target_mutated: candidate.ok && candidate.status === "SUPERSEDED",
      adapter_status: "not_applicable",
      contribution_claim:
        candidate.status === "SUPERSEDED" ? "local_only" : "none",
    });
  } catch (e) {
    return mapError(op, e);
  }
}

/** Empty ledger helper for tests. */
export function _emptyLedgerForTests(nowMs: number) {
  return emptyFollowupLedger(nowMs);
}
