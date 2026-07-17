import type {
  PageTransport,
  PageTransportRequest,
  PageTransportResponse,
} from "./types.js";

/**
 * Deterministic fake page transport for Scenario Harness only.
 * Production CLI/MCP never inject a live network transport.
 */
export function createFakePageTransport(
  response: PageTransportResponse,
): PageTransport {
  return {
    fetchVisible(_request: PageTransportRequest): PageTransportResponse {
      return {
        visible_title: response.visible_title,
        visible_text: response.visible_text,
        metadata: response.metadata ? { ...response.metadata } : undefined,
      };
    },
  };
}

export function createFailingPageTransport(
  message = "page transport failed",
): PageTransport {
  return {
    fetchVisible(): PageTransportResponse {
      throw new Error(message);
    },
  };
}

export function instrumentPageTransport(inner: PageTransport): PageTransport & {
  callCount: number;
  lastRequest: PageTransportRequest | null;
} {
  const state = {
    callCount: 0,
    lastRequest: null as PageTransportRequest | null,
  };
  return {
    get callCount() {
      return state.callCount;
    },
    get lastRequest() {
      return state.lastRequest;
    },
    fetchVisible(request: PageTransportRequest): PageTransportResponse {
      state.callCount += 1;
      state.lastRequest = request;
      return inner.fetchVisible(request);
    },
  };
}
