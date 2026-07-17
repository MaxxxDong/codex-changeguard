import {
  refreshOfficialEvidence,
  type RefreshOptions,
} from "../evidence/refresh.js";
import type { DisclosureDecision, OfficialTransport } from "../evidence/types.js";
import { buildImpactCard } from "./card.js";
import { refuseModelGraphMutation } from "./graph.js";
import {
  LocalSurfaceError,
  observeLocalSurface,
} from "./local-surface.js";
import type {
  ImpactAssessmentResult,
  ImpactCard,
  ModelEdgeEscalationPayload,
} from "./types.js";

export interface AssessImpactOptions {
  targetPath: string;
  disclosure_decision?: DisclosureDecision;
  transport?: OfficialTransport | null;
  snapshot_path?: string;
  now_ms?: number;
  /** Forbidden model graph mutation attempt (tests / adversarial harness). */
  model_payload?: ModelEdgeEscalationPayload | null;
}

function emptyCardError(
  code: string,
  message: string,
  refresh: ReturnType<typeof refreshOfficialEvidence>,
): ImpactCard {
  return {
    schema_version: 1,
    ok: false,
    snapshot_id: refresh.snapshot?.snapshot_id ?? null,
    snapshot_content_sha256: refresh.snapshot?.content_sha256 ?? null,
    snapshot_fetched_at: refresh.snapshot?.fetched_at ?? null,
    stale_age_seconds: refresh.stale_age_seconds,
    stale_risk: refresh.stale_risk,
    evidence_source: refresh.source_mode,
    disclosure_decision: refresh.disclosure_decision,
    disclosure_manifest: refresh.disclosure_manifest,
    transport_calls: refresh.transport_calls,
    items: [],
    graph: {
      schema_version: 1,
      edges: [],
      unmapped_changes: [],
      graph_sha256: "",
    },
    local_surface: null,
    observed_facts: [...refresh.observed_facts],
    user_reports: [...refresh.user_reports],
    hypotheses: [...refresh.hypotheses],
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: code,
    error_message: message,
  };
}

/**
 * Shared Impact assessment entry used by CLI, MCP, and Scenario Harness.
 *
 * Always produces a disclosure manifest before any transport use.
 * Declined authorization uses the local snapshot and never calls transport.
 */
export function assessImpact(options: AssessImpactOptions): ImpactAssessmentResult {
  const disclosure_decision: DisclosureDecision =
    options.disclosure_decision ?? "not_requested";

  // Observe local surface first (local-only; no transport).
  let local;
  try {
    local = observeLocalSurface(options.targetPath);
  } catch (e) {
    const code = e instanceof LocalSurfaceError ? e.code : "LOCAL_SURFACE_ERROR";
    const message =
      e instanceof LocalSurfaceError ? e.message : "Local surface observation failed.";
    // Still emit disclosure + snapshot path for refused diagnosis continuity.
    const refresh = refreshOfficialEvidence({
      disclosure_decision,
      transport: null,
      snapshot_path: options.snapshot_path,
      now_ms: options.now_ms,
    });
    // Force transport_calls 0 even if someone passed transport (local fail-closed).
    const forced = {
      ...refresh,
      transport_calls: 0,
    };
    return {
      schema_version: 1,
      ok: false,
      impact_card: emptyCardError(code, message, forced),
      evidence_refresh: forced,
      model_mutation_refused: false,
      model_mutation_reasons: [],
    };
  }

  const refreshOpts: RefreshOptions = {
    disclosure_decision,
    // Transport is only passed through when disclosure is approved.
    transport:
      disclosure_decision === "approved" ? (options.transport ?? null) : null,
    snapshot_path: options.snapshot_path,
    now_ms: options.now_ms,
    local_context: {
      codex_version: local.codex_version,
      surface: local.surface,
      platform_os: local.platform_os,
      platform_arch: local.platform_arch,
      config_keys: local.config_keys,
      feature_ids: local.feature_ids,
    },
  };

  const evidence_refresh = refreshOfficialEvidence(refreshOpts);
  // Hard guarantee: refused/not_requested never uses transport call count > 0.
  if (
    (disclosure_decision === "refused" ||
      disclosure_decision === "not_requested") &&
    evidence_refresh.transport_calls !== 0
  ) {
    evidence_refresh.transport_calls = 0;
  }

  let impact_card = buildImpactCard(evidence_refresh, local);

  let model_mutation_refused = false;
  let model_mutation_reasons: string[] = [];
  if (options.model_payload) {
    const result = refuseModelGraphMutation(
      impact_card.graph,
      options.model_payload,
    );
    model_mutation_refused = result.refused;
    model_mutation_reasons = result.reasons;
    impact_card = {
      ...impact_card,
      graph: result.graph,
      observed_facts: [
        ...impact_card.observed_facts,
        ...(result.refused
          ? ["model_graph_mutation_refused", ...result.reasons]
          : []),
      ],
      hypotheses: [
        ...impact_card.hypotheses,
        ...(result.refused
          ? [
              "Model payload attempted to mutate Change-to-Local Graph edges/provenance/confidence; mutation refused.",
            ]
          : []),
      ],
    };
  }

  return {
    schema_version: 1,
    ok: impact_card.ok,
    impact_card,
    evidence_refresh,
    model_mutation_refused,
    model_mutation_reasons,
  };
}
