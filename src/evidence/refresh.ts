import crypto from "node:crypto";
import {
  buildDisclosureManifest,
  buildTransportRequest,
} from "./disclosure.js";
import {
  MAX_FETCHED_AT_FUTURE_SKEW_SECONDS,
  STALE_HIGH_SECONDS,
  STALE_LOW_SECONDS,
  STALE_MEDIUM_SECONDS,
} from "./limits.js";
import { EvidenceNormalizeError, normalizeRawItems } from "./normalize.js";
import {
  buildSnapshotFromItems,
  loadBundledSnapshot,
  relabelSnapshotState,
  SnapshotError,
} from "./snapshot.js";
import type {
  DisclosureDecision,
  EvidenceRefreshResult,
  LocalDisclosureContext,
  OfficialTransport,
  OfficialTransportRequest,
  StaleRisk,
} from "./types.js";

export interface RefreshOptions {
  /** Required before any transport call. */
  disclosure_decision: DisclosureDecision;
  /** Injected only by trusted orchestration after approval. */
  transport?: OfficialTransport | null;
  /** Override bundled snapshot path (tests). */
  snapshot_path?: string;
  /** Clock for stale age (ms since epoch). */
  now_ms?: number;
  /** Optional local context for disclosure materialization. */
  local_context?: LocalDisclosureContext;
}

function computeStale(
  fetchedAt: string,
  nowMs: number,
): { stale_age_seconds: number; stale_risk: StaleRisk } {
  const fetchedMs = Date.parse(fetchedAt);
  if (Number.isNaN(fetchedMs)) {
    return { stale_age_seconds: 0, stale_risk: "unavailable" };
  }
  const age = Math.max(0, Math.floor((nowMs - fetchedMs) / 1000));
  let stale_risk: StaleRisk = "none";
  if (age >= STALE_HIGH_SECONDS) stale_risk = "high";
  else if (age >= STALE_MEDIUM_SECONDS) stale_risk = "medium";
  else if (age >= STALE_LOW_SECONDS) stale_risk = "low";
  return { stale_age_seconds: age, stale_risk };
}

/**
 * Validate transport fetched_at syntax and future skew.
 * Returns age/risk or throws EvidenceNormalizeError on hard failures.
 */
export function validateTransportFetchedAt(
  fetchedAt: unknown,
  nowMs: number,
): { fetched_at: string; stale_age_seconds: number; stale_risk: StaleRisk } {
  if (typeof fetchedAt !== "string") {
    throw new EvidenceNormalizeError(
      "FETCHED_AT",
      "Transport fetched_at must be an ISO-8601 UTC string.",
    );
  }
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(fetchedAt) ||
    Number.isNaN(Date.parse(fetchedAt))
  ) {
    throw new EvidenceNormalizeError(
      "FETCHED_AT",
      "Transport fetched_at has invalid syntax.",
    );
  }
  const fetchedMs = Date.parse(fetchedAt);
  const skewSeconds = Math.floor((fetchedMs - nowMs) / 1000);
  if (skewSeconds > MAX_FETCHED_AT_FUTURE_SKEW_SECONDS) {
    throw new EvidenceNormalizeError(
      "FETCHED_AT_FUTURE",
      "Transport fetched_at is unreasonably far in the future.",
    );
  }
  const stale = computeStale(fetchedAt, nowMs);
  return { fetched_at: fetchedAt, ...stale };
}

function baseResult(
  partial: Partial<EvidenceRefreshResult> &
    Pick<
      EvidenceRefreshResult,
      | "disclosure_manifest"
      | "disclosure_decision"
      | "transport_calls"
      | "source_mode"
      | "ok"
    >,
): EvidenceRefreshResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    disclosure_manifest: partial.disclosure_manifest,
    disclosure_decision: partial.disclosure_decision,
    transport_calls: partial.transport_calls,
    source_mode: partial.source_mode,
    snapshot: partial.snapshot ?? null,
    stale_age_seconds: partial.stale_age_seconds ?? null,
    stale_risk: partial.stale_risk ?? "unavailable",
    error_code: partial.error_code ?? null,
    error_message: partial.error_message ?? null,
    observed_facts: partial.observed_facts ?? [],
    user_reports: partial.user_reports ?? [],
    hypotheses: partial.hypotheses ?? [],
    transport_request: partial.transport_request ?? null,
  };
}

function loadStaleFallback(
  options: RefreshOptions,
  nowMs: number,
  evidence_state: "stale" | "snapshot",
): {
  snapshot: ReturnType<typeof relabelSnapshotState>;
  stale: { stale_age_seconds: number; stale_risk: StaleRisk };
} {
  const snap = loadBundledSnapshot(options.snapshot_path);
  const labeled = relabelSnapshotState(snap, evidence_state);
  const stale = computeStale(labeled.fetched_at, nowMs);
  return { snapshot: labeled, stale };
}

/**
 * Official evidence refresh orchestration.
 *
 * - Always builds an exact disclosure manifest first.
 * - On refused/not_requested: never calls transport; uses bundled snapshot.
 * - On approved: may call injected transport once; on failure falls back to stale snapshot.
 * - Transport request field set exactly matches the disclosure manifest sendable fields.
 * - Production core does not open network sockets; transport is injected.
 */
export function refreshOfficialEvidence(
  options: RefreshOptions,
): EvidenceRefreshResult {
  const nowMs = options.now_ms ?? Date.now();
  const local_context = options.local_context ?? {};
  const manifest = buildDisclosureManifest(local_context);
  const decision = options.disclosure_decision;

  // Refusal / not requested: local snapshot only, zero transport calls.
  if (decision === "refused" || decision === "not_requested") {
    try {
      const { snapshot: labeled, stale } = loadStaleFallback(
        options,
        nowMs,
        "snapshot",
      );
      return baseResult({
        ok: true,
        disclosure_manifest: manifest,
        disclosure_decision: decision,
        transport_calls: 0,
        source_mode: "bundled_snapshot",
        snapshot: labeled,
        stale_age_seconds: stale.stale_age_seconds,
        stale_risk: stale.stale_risk === "none" ? "low" : stale.stale_risk,
        transport_request: null,
        observed_facts: [
          "disclosure_manifest_produced",
          "transport_not_called",
          "bundled_snapshot_loaded",
          `snapshot_sha256=${labeled.content_sha256}`,
        ],
        user_reports: [],
        hypotheses: [],
      });
    } catch (e) {
      const msg =
        e instanceof SnapshotError ? e.message : "Snapshot unavailable.";
      return baseResult({
        ok: false,
        disclosure_manifest: manifest,
        disclosure_decision: decision,
        transport_calls: 0,
        source_mode: "unavailable_snapshot",
        stale_risk: "unavailable",
        error_code: e instanceof SnapshotError ? e.code : "SNAPSHOT_ERROR",
        error_message: msg,
        transport_request: null,
        observed_facts: ["disclosure_manifest_produced", "transport_not_called"],
      });
    }
  }

  // Approved path: transport only if injected.
  if (!options.transport) {
    try {
      const { snapshot: labeled, stale } = loadStaleFallback(
        options,
        nowMs,
        "stale",
      );
      return baseResult({
        ok: true,
        disclosure_manifest: manifest,
        disclosure_decision: decision,
        transport_calls: 0,
        source_mode: "stale_snapshot",
        snapshot: labeled,
        stale_age_seconds: stale.stale_age_seconds,
        stale_risk: stale.stale_risk === "none" ? "low" : stale.stale_risk,
        transport_request: null,
        observed_facts: [
          "disclosure_authorized",
          "transport_not_injected",
          "stale_snapshot_fallback",
          `snapshot_sha256=${labeled.content_sha256}`,
        ],
        user_reports: [],
        hypotheses: [
          "Live official refresh was authorized but no transport was injected by orchestration.",
        ],
      });
    } catch (e) {
      return baseResult({
        ok: false,
        disclosure_manifest: manifest,
        disclosure_decision: decision,
        transport_calls: 0,
        source_mode: "unavailable_snapshot",
        stale_risk: "unavailable",
        error_code: e instanceof SnapshotError ? e.code : "SNAPSHOT_ERROR",
        error_message:
          e instanceof SnapshotError ? e.message : "Snapshot unavailable.",
        transport_request: null,
        observed_facts: ["disclosure_authorized", "transport_not_injected"],
      });
    }
  }

  // Approved + transport: exactly one fetch attempt with exact disclosed payload.
  let transport_calls = 0;
  let transport_request: OfficialTransportRequest | null = null;
  try {
    transport_request = buildTransportRequest(manifest, local_context);
    transport_calls = 1;
    const response = options.transport.fetch(transport_request);
    const freshness = validateTransportFetchedAt(response.fetched_at, nowMs);

    // Ancient / high-stale responses cannot be labeled fresh/live_refresh.
    if (freshness.stale_risk === "high") {
      throw new EvidenceNormalizeError(
        "FETCHED_AT_STALE",
        "Transport fetched_at is too stale for live_refresh/fresh labeling.",
      );
    }

    const snapshot_id = `live_${crypto.randomBytes(8).toString("hex")}`;
    const fetched_at = freshness.fetched_at;
    const items = normalizeRawItems(response.items, {
      snapshot_id,
      fetched_at,
      evidence_state: "fresh",
    });
    const snapshot = buildSnapshotFromItems(items, { snapshot_id, fetched_at });
    const user_reports = items
      .filter((it) => it.maintainer_status === "user_reported")
      .map((it) => `user_reported:${it.evidence_id}`);
    const quarantined = items
      .filter((it) => it.quarantine)
      .map((it) => `quarantined:${it.evidence_id}:${it.quarantine!.reason}`);
    return baseResult({
      ok: true,
      disclosure_manifest: manifest,
      disclosure_decision: decision,
      transport_calls,
      source_mode: "live_refresh",
      snapshot,
      stale_age_seconds: freshness.stale_age_seconds,
      stale_risk: freshness.stale_risk,
      transport_request,
      observed_facts: [
        "disclosure_authorized",
        "transport_called_once",
        "live_snapshot_built",
        `snapshot_sha256=${snapshot.content_sha256}`,
        `item_count=${items.length}`,
        ...quarantined,
      ],
      user_reports,
      hypotheses: [],
    });
  } catch (e) {
    // Transport failure / validation / stale → timestamped immutable snapshot.
    try {
      const { snapshot: labeled, stale } = loadStaleFallback(
        options,
        nowMs,
        "stale",
      );
      const errMsg =
        e instanceof EvidenceNormalizeError
          ? e.message
          : e instanceof Error
            ? "Transport or validation failed."
            : "Transport failed.";
      return baseResult({
        ok: true,
        disclosure_manifest: manifest,
        disclosure_decision: decision,
        transport_calls,
        source_mode: "stale_snapshot",
        snapshot: labeled,
        stale_age_seconds: stale.stale_age_seconds,
        stale_risk: stale.stale_risk === "none" ? "medium" : stale.stale_risk,
        error_code:
          e instanceof EvidenceNormalizeError ? e.code : "TRANSPORT_FAILED",
        error_message: errMsg,
        transport_request,
        observed_facts: [
          "disclosure_authorized",
          "transport_failed",
          "stale_snapshot_fallback",
          `snapshot_sha256=${labeled.content_sha256}`,
        ],
        user_reports: [],
        hypotheses: [
          "Official live refresh failed; results reflect a timestamped immutable snapshot with elevated stale risk.",
        ],
      });
    } catch {
      return baseResult({
        ok: false,
        disclosure_manifest: manifest,
        disclosure_decision: decision,
        transport_calls,
        source_mode: "unavailable_snapshot",
        stale_risk: "unavailable",
        error_code: "TRANSPORT_AND_SNAPSHOT_FAILED",
        error_message: "Transport failed and snapshot unavailable.",
        transport_request,
        observed_facts: ["disclosure_authorized", "transport_failed"],
      });
    }
  }
}
