import type {
  OfficialTransport,
  OfficialTransportRequest,
  OfficialTransportResponse,
  TransportCallLog,
} from "./types.js";

/**
 * Wrap a transport to count and record calls. Used by harness proofs for
 * zero-call refusal and approved online fake refresh.
 */
export function instrumentTransport(
  inner: OfficialTransport,
): OfficialTransport & TransportCallLog {
  const calls: OfficialTransportRequest[] = [];
  return {
    get calls() {
      return calls.slice();
    },
    get callCount() {
      return calls.length;
    },
    fetch(request: OfficialTransportRequest): OfficialTransportResponse {
      // Record a deep copy of the exact outbound payload for audit proofs.
      calls.push(structuredCloneRequest(request));
      return inner.fetch(request);
    },
  };
}

function structuredCloneRequest(
  request: OfficialTransportRequest,
): OfficialTransportRequest {
  return {
    disclosure_manifest_id: request.disclosure_manifest_id,
    allowed_hosts: [...request.allowed_hosts],
    allowed_repositories: [...request.allowed_repositories],
    resource_kinds: [...request.resource_kinds],
    ...(request.codex_version !== undefined
      ? { codex_version: request.codex_version }
      : {}),
    ...(request.surface !== undefined ? { surface: request.surface } : {}),
    ...(request.platform_os !== undefined
      ? { platform_os: request.platform_os }
      : {}),
    ...(request.platform_arch !== undefined
      ? { platform_arch: request.platform_arch }
      : {}),
    ...(request.config_keys !== undefined
      ? { config_keys: [...request.config_keys] }
      : {}),
    ...(request.feature_ids !== undefined
      ? { feature_ids: [...request.feature_ids] }
      : {}),
    ...(request.error_class !== undefined
      ? { error_class: request.error_class }
      : {}),
  };
}

/** Deterministic local fake transport for Scenario Harness (never real network). */
export function createFakeTransport(
  response: OfficialTransportResponse | (() => OfficialTransportResponse),
): OfficialTransport {
  return {
    fetch(_request: OfficialTransportRequest): OfficialTransportResponse {
      void _request;
      return typeof response === "function" ? response() : response;
    },
  };
}

export function createFailingTransport(
  message = "Transport unavailable.",
): OfficialTransport {
  return {
    fetch(_request: OfficialTransportRequest): OfficialTransportResponse {
      void _request;
      throw new Error(message);
    },
  };
}
