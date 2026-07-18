/**
 * Capability-injected adapter contract for Ticket 11.
 * Production CLI/MCP never inject a real gh/browser executor.
 * Real host integration must supply an adapter that uses already-authenticated
 * sessions only — never request/store/display tokens, cookies, or sessions.
 */
import type {
  AuthCapabilityReport,
  AdapterExecuteRequest,
  AdapterExecuteResult,
  AdapterQueryResult,
  UpstreamActionAdapter,
} from "./types.js";

/** Default production adapter: capability unavailable; never simulates success. */
export function createUnavailableAdapter(): UpstreamActionAdapter {
  return {
    getAuthCapability(): AuthCapabilityReport {
      return {
        kind: "unavailable",
        detail:
          "Runtime capability unavailable: no gh_authenticated or visible_browser_authenticated adapter injected. Real GitHub/browser writes are not performed in this unauthorized development path.",
        authenticated: false,
      };
    },
    execute(_request: AdapterExecuteRequest): AdapterExecuteResult {
      return {
        outcome: "auth_unavailable",
        canonical_url: null,
        remote_receipt_id: null,
        timestamp: null,
        existing_idempotency_key: null,
        error_code: "ADAPTER_UNAVAILABLE",
        error_message:
          "No capability-injected upstream action adapter. Refuse to simulate success.",
      };
    },
    queryByIdempotencyKey(_key: string): AdapterQueryResult {
      return {
        outcome: "uncertain",
        receipt: null,
        error_code: "ADAPTER_UNAVAILABLE",
        error_message: "Cannot query remote state without an injected adapter.",
      };
    },
  };
}

/**
 * Wrap an adapter so callers can observe call counts (tests/harness).
 * Does not add network or child_process capabilities.
 */
export function instrumentActionAdapter(
  inner: UpstreamActionAdapter,
): UpstreamActionAdapter & {
  executeCalls: number;
  queryCalls: number;
  lastExecute: AdapterExecuteRequest | null;
  lastQueryKey: string | null;
} {
  const state = {
    executeCalls: 0,
    queryCalls: 0,
    lastExecute: null as AdapterExecuteRequest | null,
    lastQueryKey: null as string | null,
  };
  return {
    get executeCalls() {
      return state.executeCalls;
    },
    get queryCalls() {
      return state.queryCalls;
    },
    get lastExecute() {
      return state.lastExecute;
    },
    get lastQueryKey() {
      return state.lastQueryKey;
    },
    getAuthCapability() {
      return inner.getAuthCapability();
    },
    execute(request: AdapterExecuteRequest) {
      state.executeCalls += 1;
      state.lastExecute = request;
      return inner.execute(request);
    },
    queryByIdempotencyKey(key: string) {
      state.queryCalls += 1;
      state.lastQueryKey = key;
      return inner.queryByIdempotencyKey(key);
    },
  };
}
