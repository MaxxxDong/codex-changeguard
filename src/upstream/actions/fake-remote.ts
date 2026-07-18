/**
 * Deterministic controlled remote double for Scenario Harness.
 * In-memory only — no sockets, no child_process, no tokens.
 */
import { receiptHash } from "./idempotency.js";
import type {
  AdapterExecuteRequest,
  AdapterExecuteResult,
  AdapterQueryResult,
  AuthCapabilityReport,
  AuthCapabilityKind,
  UpstreamActionAdapter,
  UpstreamActionReceipt,
} from "./types.js";

export type FakeRemoteMode =
  | "success"
  | "auth_unavailable"
  | "timeout_found"
  | "timeout_not_found"
  | "timeout_uncertain"
  | "duplicate_existing"
  | "failed";

export interface FakeRemoteOptions {
  mode?: FakeRemoteMode;
  authKind?: AuthCapabilityKind;
  /** Pre-seeded receipts keyed by idempotency key. */
  existing?: Map<string, UpstreamActionReceipt>;
  /** Fixed timestamp for deterministic receipts. */
  nowIso?: string;
  /** Base URL for synthetic remote resources. */
  baseUrl?: string;
}

export interface FakeRemoteAdapter extends UpstreamActionAdapter {
  readonly store: Map<string, UpstreamActionReceipt>;
  readonly mode: FakeRemoteMode;
  setMode(mode: FakeRemoteMode): void;
  seed(receipt: UpstreamActionReceipt): void;
}

export function createFakeRemoteAdapter(
  options: FakeRemoteOptions = {},
): FakeRemoteAdapter {
  let mode: FakeRemoteMode = options.mode ?? "success";
  const store = new Map<string, UpstreamActionReceipt>(
    options.existing ? [...options.existing.entries()] : [],
  );
  const baseUrl =
    options.baseUrl ?? "https://github.com/openai/codex/issues";
  const authKind: AuthCapabilityKind =
    options.authKind ??
    (mode === "auth_unavailable" ? "unavailable" : "gh_authenticated");

  function now(): string {
    return options.nowIso ?? "2026-07-18T12:00:00.000Z";
  }

  function authReport(): AuthCapabilityReport {
    if (authKind === "unavailable" || mode === "auth_unavailable") {
      return {
        kind: "unavailable",
        detail: "Fake remote reports authentication unavailable.",
        authenticated: false,
      };
    }
    return {
      kind: authKind,
      detail:
        authKind === "gh_authenticated"
          ? "Fake remote: gh session present (no token material)."
          : "Fake remote: visible browser session present (no cookie material).",
      authenticated: true,
    };
  }

  function buildReceipt(
    request: AdapterExecuteRequest,
    url: string,
    remoteId: string,
  ): UpstreamActionReceipt {
    const timestamp = now();
    const partial = {
      action: request.action,
      canonical_url: url,
      timestamp,
      idempotency_key: request.idempotency_key,
      remote_receipt_id: remoteId,
    };
    return {
      schema_version: 1,
      kind: "upstream_contribution_action",
      action: partial.action,
      canonical_url: partial.canonical_url,
      timestamp: partial.timestamp,
      idempotency_key: partial.idempotency_key,
      remote_receipt_id: partial.remote_receipt_id,
      receipt_hash: receiptHash(partial),
    };
  }

  const adapter: FakeRemoteAdapter = {
    get store() {
      return store;
    },
    get mode() {
      return mode;
    },
    setMode(m: FakeRemoteMode) {
      mode = m;
    },
    seed(receipt: UpstreamActionReceipt) {
      store.set(receipt.idempotency_key, receipt);
    },
    getAuthCapability() {
      return authReport();
    },
    execute(request: AdapterExecuteRequest): AdapterExecuteResult {
      // Idempotent: existing key always returns duplicate_existing.
      const existing = store.get(request.idempotency_key);
      if (existing && mode !== "timeout_found") {
        // When already stored from a prior success, report duplicate.
        if (mode === "success" || mode === "duplicate_existing") {
          return {
            outcome: "duplicate_existing",
            canonical_url: existing.canonical_url,
            remote_receipt_id: existing.remote_receipt_id,
            timestamp: existing.timestamp,
            existing_idempotency_key: existing.idempotency_key,
            error_code: "DUPLICATE_EXISTING",
            error_message: "Same diagnosis/action already executed.",
          };
        }
      }

      if (mode === "auth_unavailable") {
        return {
          outcome: "auth_unavailable",
          canonical_url: null,
          remote_receipt_id: null,
          timestamp: null,
          existing_idempotency_key: null,
          error_code: "AUTH_UNAVAILABLE",
          error_message: "Authentication unavailable; draft only.",
        };
      }

      if (mode === "failed") {
        return {
          outcome: "failed",
          canonical_url: null,
          remote_receipt_id: null,
          timestamp: null,
          existing_idempotency_key: null,
          error_code: "REMOTE_FAILED",
          error_message: "Controlled remote failure.",
        };
      }

      if (
        mode === "timeout_found" ||
        mode === "timeout_not_found" ||
        mode === "timeout_uncertain"
      ) {
        return {
          outcome: "timeout_ambiguous",
          canonical_url: null,
          remote_receipt_id: null,
          timestamp: null,
          existing_idempotency_key: null,
          error_code: "TIMEOUT_AMBIGUOUS",
          error_message:
            "Ambiguous timeout; caller must query by idempotency key.",
        };
      }

      if (mode === "duplicate_existing") {
        // Seed a synthetic existing if missing.
        const url =
          request.canonical_target.startsWith("http")
            ? request.canonical_target
            : `${baseUrl}/dup`;
        const receipt = buildReceipt(request, url, "remote_existing_1");
        store.set(request.idempotency_key, receipt);
        return {
          outcome: "duplicate_existing",
          canonical_url: receipt.canonical_url,
          remote_receipt_id: receipt.remote_receipt_id,
          timestamp: receipt.timestamp,
          existing_idempotency_key: receipt.idempotency_key,
          error_code: "DUPLICATE_EXISTING",
          error_message: "Remote already has this action.",
        };
      }

      // success
      const remoteId = `remote_${store.size + 1}`;
      let url: string;
      if (request.action === "create_issue") {
        url = `${baseUrl}/${9000 + store.size + 1}`;
      } else if (request.canonical_target.startsWith("http")) {
        url = request.canonical_target;
      } else {
        url = `${baseUrl}/action`;
      }
      const receipt = buildReceipt(request, url, remoteId);
      store.set(request.idempotency_key, receipt);
      return {
        outcome: "success",
        canonical_url: receipt.canonical_url,
        remote_receipt_id: receipt.remote_receipt_id,
        timestamp: receipt.timestamp,
        existing_idempotency_key: null,
        error_code: null,
        error_message: null,
      };
    },
    queryByIdempotencyKey(idempotency_key: string): AdapterQueryResult {
      if (mode === "timeout_uncertain") {
        return {
          outcome: "uncertain",
          receipt: null,
          error_code: "QUERY_UNCERTAIN",
          error_message: "Remote state not conclusively known.",
        };
      }
      if (mode === "timeout_not_found") {
        return {
          outcome: "not_found",
          receipt: null,
          error_code: "QUERY_NOT_FOUND",
          error_message: "No remote action for idempotency key.",
        };
      }
      if (mode === "timeout_found") {
        let receipt = store.get(idempotency_key);
        if (!receipt) {
          // Synthesize found receipt for harness determinism.
          receipt = {
            schema_version: 1,
            kind: "upstream_contribution_action",
            action: "create_issue",
            canonical_url: `${baseUrl}/timeout-found`,
            timestamp: now(),
            idempotency_key,
            remote_receipt_id: "remote_timeout_found",
            receipt_hash: "",
          };
          receipt.receipt_hash = receiptHash({
            action: receipt.action,
            canonical_url: receipt.canonical_url,
            timestamp: receipt.timestamp,
            idempotency_key: receipt.idempotency_key,
            remote_receipt_id: receipt.remote_receipt_id,
          });
          store.set(idempotency_key, receipt);
        }
        return {
          outcome: "found",
          receipt,
          error_code: null,
          error_message: null,
        };
      }
      const hit = store.get(idempotency_key);
      if (hit) {
        return {
          outcome: "found",
          receipt: hit,
          error_code: null,
          error_message: null,
        };
      }
      return {
        outcome: "not_found",
        receipt: null,
        error_code: "QUERY_NOT_FOUND",
        error_message: "No remote action for idempotency key.",
      };
    },
  };

  return adapter;
}
