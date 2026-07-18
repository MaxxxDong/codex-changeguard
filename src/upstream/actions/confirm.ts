import { diagnose } from "../../core/diagnose.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import { createUnavailableAdapter } from "./adapter.js";
import {
  ConfirmationError,
  consumeConfirmationNonce,
  markConfirmationTerminalUncertain,
  openConfirmationLedger,
  parseConfirmationToken,
  ConfirmationLedger,
} from "./confirmation.js";
import { receiptHash } from "./idempotency.js";
import type {
  ActionConfirmResult,
  ActionConfirmStatus,
  AuthCapabilityReport,
  ConfirmDecision,
  UpstreamActionAdapter,
  UpstreamActionReceipt,
} from "./types.js";

export interface ActionConfirmOptions {
  targetPath: string;
  /** One-shot confirmation token from preview (ua1.…). */
  confirmation_token: string;
  /** User decision: confirm or cancel. */
  decision: unknown;
  /** Injectable adapter; production passes null → unavailable. */
  adapter?: UpstreamActionAdapter | null;
  nowMs?: number;
  /** Injectible confirmation ledger root (tests / controlled state). */
  ledgerRoot?: string | null;
  /** Pre-opened ledger (preferred when sharing across calls). */
  ledger?: ConfirmationLedger | null;
}

function emptyConfirm(
  partial: Partial<ActionConfirmResult> &
    Pick<ActionConfirmResult, "ok" | "status" | "auth_capability">,
): ActionConfirmResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    status: partial.status,
    action: partial.action ?? null,
    decision: partial.decision ?? null,
    receipt: partial.receipt ?? null,
    idempotency_key: partial.idempotency_key ?? null,
    auth_capability: partial.auth_capability,
    confirmation_id: partial.confirmation_id ?? null,
    local_incident: partial.local_incident ?? null,
    network_used: partial.network_used ?? false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    external_write: partial.external_write ?? false,
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
  };
}

function parseDecision(raw: unknown): ConfirmDecision | null {
  if (raw === "confirm" || raw === "cancel") return raw;
  return null;
}

function buildReceipt(input: {
  action: UpstreamActionReceipt["action"];
  canonical_url: string;
  timestamp: string;
  idempotency_key: string;
  remote_receipt_id: string | null;
}): UpstreamActionReceipt {
  return {
    schema_version: 1,
    kind: "upstream_contribution_action",
    action: input.action,
    canonical_url: input.canonical_url,
    timestamp: input.timestamp,
    idempotency_key: input.idempotency_key,
    remote_receipt_id: input.remote_receipt_id,
    receipt_hash: receiptHash(input),
  };
}

function resolveLedger(options: ActionConfirmOptions): ConfirmationLedger {
  if (options.ledger) return options.ledger;
  return openConfirmationLedger(options.ledgerRoot);
}

/**
 * Confirm or cancel a separately previewed upstream action.
 * Cancellation / auth unavailable remain pure draft — never simulate success.
 * Ambiguous timeout queries remote by idempotency key; never blind-retries.
 * Cancel / success / uncertain permanently terminate the nonce in the durable ledger.
 */
export function confirmUpstreamAction(
  options: ActionConfirmOptions,
): ActionConfirmResult {
  const adapter = options.adapter ?? createUnavailableAdapter();
  const ledger = resolveLedger(options);
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

  const decision = parseDecision(options.decision);
  if (!decision) {
    return emptyConfirm({
      ok: false,
      status: "INVALID_CONFIRMATION",
      auth_capability,
      error_code: "INVALID_DECISION",
      error_message: "decision must be confirm or cancel.",
    });
  }

  let local_incident = null;
  try {
    local_incident = diagnose(options.targetPath).incident_fingerprint;
  } catch {
    local_incident = null;
  }

  let binding;
  try {
    binding = parseConfirmationToken(options.confirmation_token, options.nowMs, {
      ledger,
      revalidateForConfirm: true,
    });
  } catch (e) {
    let status: ActionConfirmStatus = "INVALID_CONFIRMATION";
    let code = "INVALID_CONFIRMATION";
    if (e instanceof ConfirmationError) {
      if (e.code === "EXPIRED_CONFIRMATION") {
        status = "EXPIRED_CONFIRMATION";
        code = e.code;
      } else if (e.code === "REPLAYED_CONFIRMATION") {
        status = "REPLAYED_CONFIRMATION";
        code = e.code;
      } else if (e.code === "UNREGISTERED_CONFIRMATION") {
        status = "INVALID_CONFIRMATION";
        code = e.code;
      } else {
        code = e.code;
      }
    }
    return emptyConfirm({
      ok: false,
      status,
      decision,
      auth_capability,
      local_incident,
      error_code: code,
      error_message: e instanceof Error ? e.message : "Confirmation refused.",
    });
  }

  // Cancellation: pure draft; consume nonce so it cannot be confirmed later.
  if (decision === "cancel") {
    consumeConfirmationNonce(binding.nonce, ledger, options.nowMs);
    return emptyConfirm({
      ok: true,
      status: "CANCELLED",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: false,
      external_write: false,
    });
  }

  // Privacy binding must still hold.
  if (
    !binding.privacy.passed ||
    !binding.privacy.secrets_redacted ||
    !binding.privacy.paths_redacted ||
    !binding.privacy.session_excluded ||
    binding.privacy.injection_quarantined
  ) {
    return emptyConfirm({
      ok: false,
      status: "PRIVACY_FAILED",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      error_code: "PRIVACY_FAILED",
      error_message: "Privacy binding failed; refuse external write.",
    });
  }

  // Auth / adapter unavailable: pure draft, never simulate success.
  // Nonce stays registered so a later confirm can proceed when capability exists.
  if (
    !auth_capability.authenticated ||
    auth_capability.kind === "unavailable"
  ) {
    return emptyConfirm({
      ok: false,
      status:
        auth_capability.kind === "unavailable"
          ? "ADAPTER_UNAVAILABLE"
          : "AUTH_UNAVAILABLE",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: false,
      external_write: false,
      error_code:
        auth_capability.kind === "unavailable"
          ? "ADAPTER_UNAVAILABLE"
          : "AUTH_UNAVAILABLE",
      error_message:
        "Authentication or runtime adapter unavailable; remaining pure draft. Never simulates success.",
    });
  }

  // Execute via injected adapter only (host owns real gh/browser).
  let exec;
  try {
    exec = adapter.execute({
      action: binding.action,
      canonical_target: binding.canonical_target,
      body_manifest: binding.body_manifest,
      attachment_manifest: binding.attachment_manifest,
      idempotency_key: binding.idempotency_key,
      confirmation_id: binding.confirmation_id,
    });
  } catch {
    return emptyConfirm({
      ok: false,
      status: "FAILED",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: true,
      external_write: false,
      error_code: "ADAPTER_EXECUTE_ERROR",
      error_message: "Adapter execute threw; no success claimed.",
    });
  }

  if (exec.outcome === "auth_unavailable") {
    return emptyConfirm({
      ok: false,
      status: "AUTH_UNAVAILABLE",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: true,
      external_write: false,
      error_code: exec.error_code ?? "AUTH_UNAVAILABLE",
      error_message:
        exec.error_message ?? "Auth unavailable; pure draft retained.",
    });
  }

  if (exec.outcome === "duplicate_existing") {
    consumeConfirmationNonce(binding.nonce, ledger, options.nowMs);
    const url = exec.canonical_url ?? binding.canonical_target;
    const ts = exec.timestamp ?? new Date(options.nowMs ?? Date.now()).toISOString();
    const receipt = buildReceipt({
      action: binding.action,
      canonical_url: url,
      timestamp: ts,
      idempotency_key: binding.idempotency_key,
      remote_receipt_id: exec.remote_receipt_id,
    });
    return emptyConfirm({
      ok: true,
      status: "DUPLICATE_EXISTING",
      action: binding.action,
      decision,
      receipt,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: true,
      external_write: true,
    });
  }

  if (exec.outcome === "timeout_ambiguous") {
    // Never blind-retry. Query remote by same idempotency key.
    let query;
    try {
      query = adapter.queryByIdempotencyKey(binding.idempotency_key);
    } catch {
      markConfirmationTerminalUncertain(binding.nonce, ledger, options.nowMs);
      return emptyConfirm({
        ok: false,
        status: "UNCERTAIN_NO_RETRY",
        action: binding.action,
        decision,
        confirmation_id: binding.confirmation_id,
        idempotency_key: binding.idempotency_key,
        auth_capability,
        local_incident,
        network_used: true,
        external_write: false,
        error_code: "UNCERTAIN_NO_RETRY",
        error_message:
          "Timeout query failed; stopping without retry to avoid duplicates.",
      });
    }

    if (query.outcome === "found" && query.receipt) {
      consumeConfirmationNonce(binding.nonce, ledger, options.nowMs);
      return emptyConfirm({
        ok: true,
        status: "DUPLICATE_EXISTING",
        action: binding.action,
        decision,
        receipt: query.receipt,
        confirmation_id: binding.confirmation_id,
        idempotency_key: binding.idempotency_key,
        auth_capability,
        local_incident,
        network_used: true,
        external_write: true,
      });
    }

    // not_found or uncertain → stop UNCERTAIN_NO_RETRY (never blind retry)
    // Persist terminal_uncertain so the same token cannot re-execute.
    markConfirmationTerminalUncertain(binding.nonce, ledger, options.nowMs);
    return emptyConfirm({
      ok: false,
      status: "UNCERTAIN_NO_RETRY",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: true,
      external_write: false,
      error_code: "UNCERTAIN_NO_RETRY",
      error_message:
        query.outcome === "not_found"
          ? "Timeout with remote not found; refuse blind retry (UNCERTAIN_NO_RETRY)."
          : "Timeout with remote state uncertain; refuse blind retry (UNCERTAIN_NO_RETRY).",
    });
  }

  if (exec.outcome === "failed") {
    return emptyConfirm({
      ok: false,
      status: "FAILED",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: true,
      external_write: false,
      error_code: exec.error_code ?? "FAILED",
      error_message: exec.error_message ?? "Remote action failed.",
    });
  }

  // success
  if (!exec.canonical_url || !exec.timestamp) {
    markConfirmationTerminalUncertain(binding.nonce, ledger, options.nowMs);
    return emptyConfirm({
      ok: false,
      status: "UNCERTAIN_NO_RETRY",
      action: binding.action,
      decision,
      confirmation_id: binding.confirmation_id,
      idempotency_key: binding.idempotency_key,
      auth_capability,
      local_incident,
      network_used: true,
      external_write: false,
      error_code: "INCOMPLETE_REMOTE_RESULT",
      error_message:
        "Adapter success missing URL/timestamp; refuse to invent receipt.",
    });
  }

  consumeConfirmationNonce(binding.nonce, ledger, options.nowMs);
  const receipt = buildReceipt({
    action: binding.action,
    canonical_url: exec.canonical_url,
    timestamp: exec.timestamp,
    idempotency_key: binding.idempotency_key,
    remote_receipt_id: exec.remote_receipt_id,
  });

  return emptyConfirm({
    ok: true,
    status: "EXECUTED",
    action: binding.action,
    decision,
    receipt,
    confirmation_id: binding.confirmation_id,
    idempotency_key: binding.idempotency_key,
    auth_capability,
    local_incident,
    network_used: true,
    external_write: true,
  });
}
