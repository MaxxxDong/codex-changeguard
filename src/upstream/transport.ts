import type {
  OfficialFormSnapshot,
  UpstreamFormTransport,
  UpstreamFormTransportRequest,
  UpstreamFormTransportResponse,
} from "./types.js";
import { OFFICIAL_HOSTS, OFFICIAL_REPOSITORY } from "./limits.js";

export interface UpstreamTransportCallLog {
  readonly calls: UpstreamFormTransportRequest[];
  readonly callCount: number;
}

export function instrumentUpstreamTransport(
  inner: UpstreamFormTransport,
): UpstreamFormTransport & UpstreamTransportCallLog {
  const calls: UpstreamFormTransportRequest[] = [];
  return {
    get calls() {
      return calls.slice();
    },
    get callCount() {
      return calls.length;
    },
    fetchForms(request: UpstreamFormTransportRequest): UpstreamFormTransportResponse {
      calls.push({
        disclosure_manifest_id: request.disclosure_manifest_id,
        allowed_hosts: [...request.allowed_hosts],
        allowed_repositories: [...request.allowed_repositories],
        resource: request.resource,
      });
      return inner.fetchForms(request);
    },
  };
}

/** Deterministic local fake transport for harness proofs (never real network). */
export function createFakeFormTransport(
  snapshot: OfficialFormSnapshot | (() => OfficialFormSnapshot),
): UpstreamFormTransport {
  return {
    fetchForms(request: UpstreamFormTransportRequest): UpstreamFormTransportResponse {
      // Enforce allowlist on fake transport so tests catch host/repo drift.
      for (const h of request.allowed_hosts) {
        if (!(OFFICIAL_HOSTS as readonly string[]).includes(h)) {
          throw new Error("Fake transport refused non-allowlisted host.");
        }
      }
      for (const r of request.allowed_repositories) {
        if (r !== OFFICIAL_REPOSITORY) {
          throw new Error("Fake transport refused non-allowlisted repository.");
        }
      }
      if (request.resource !== "issue_forms") {
        throw new Error("Fake transport refused non-forms resource.");
      }
      const snap = typeof snapshot === "function" ? snapshot() : snapshot;
      return { snapshot: snap };
    },
  };
}

export function createFailingFormTransport(
  message = "Form transport unavailable.",
): UpstreamFormTransport {
  return {
    fetchForms(_request: UpstreamFormTransportRequest): UpstreamFormTransportResponse {
      void _request;
      throw new Error(message);
    },
  };
}
