import { diagnose } from "../core/diagnose.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type { IncidentFingerprint } from "../core/types.js";
import {
  buildPageDisclosureManifest,
  pageTransportPermitted,
} from "./disclosure.js";
import {
  envelopeContentSha256,
  PageEnvelopeError,
  parsePageEnvelope,
  titleSha256,
} from "./envelope.js";
import { extractPageContent } from "./extract.js";
import { comparePageToLocal } from "./compare.js";
import {
  assertCandidatesNotAuthorized,
  pageCommandsToDslCandidates,
} from "./dsl-candidates.js";
import type {
  PageAnalysisResult,
  PageDisclosureDecision,
  PageEvidenceEnvelope,
  PageEvidenceRecord,
  PageTransport,
} from "./types.js";

export interface AnalyzePageOptions {
  /** Isolated target with local incident fingerprint (Ticket 01 shape). */
  targetPath: string;
  /**
   * Page-evidence envelope as object or JSON string.
   * Orchestrator-supplied sanitized visible content — preferred path.
   */
  envelope: unknown;
  disclosure_decision?: PageDisclosureDecision;
  /**
   * Injectable public-page transport (tests/orchestration only).
   * Production CLI/MCP pass null — no hidden network.
   */
  transport?: PageTransport | null;
}

function emptyResult(
  partial: Partial<PageAnalysisResult> &
    Pick<PageAnalysisResult, "ok" | "disclosure_decision" | "disclosure_manifest">,
): PageAnalysisResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    page_evidence: partial.page_evidence ?? null,
    comparison: partial.comparison ?? null,
    disclosure_decision: partial.disclosure_decision,
    disclosure_manifest: partial.disclosure_manifest,
    transport_calls: partial.transport_calls ?? 0,
    observed_facts: partial.observed_facts ?? [],
    user_reports: partial.user_reports ?? [],
    hypotheses: partial.hypotheses ?? [],
    local_incident: partial.local_incident ?? null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
  };
}

/**
 * Shared Ticket 05 core: analyze untrusted page evidence against local incident.
 *
 * - Envelope is orchestrator-supplied sanitized visible content by default.
 * - Optional public transport requires disclosure approved + injection; production never injects.
 * - Logged-page mode never reads cookies/storage/tokens/auth/request bodies.
 * - Page text is quarantined untrusted data; commands become candidate-only DSL.
 * - Never mutates target, never authorizes repair, never opens sockets from production seams.
 */
export function analyzePage(options: AnalyzePageOptions): PageAnalysisResult {
  const disclosure_decision: PageDisclosureDecision =
    options.disclosure_decision ?? "not_requested";

  let envelope: PageEvidenceEnvelope;
  try {
    envelope = parsePageEnvelope(options.envelope);
  } catch (e) {
    const code = e instanceof PageEnvelopeError ? e.code : "ENVELOPE_ERROR";
    const message =
      e instanceof PageEnvelopeError ? e.message : "Invalid page envelope.";
    const manifest = buildPageDisclosureManifest(null);
    return emptyResult({
      ok: false,
      disclosure_decision,
      disclosure_manifest: manifest,
      transport_calls: 0,
      error_code: code,
      error_message: message,
      observed_facts: ["envelope_rejected"],
    });
  }

  const disclosure_manifest = buildPageDisclosureManifest(envelope);
  let transport_calls = 0;

  // Optional public retrieval only with explicit disclosure + injected transport.
  // Logged_visible mode never uses transport (orchestrator-supplied content only).
  const transport = options.transport ?? null;
  if (
    envelope.page_mode === "public" &&
    pageTransportPermitted(disclosure_decision, transport !== null)
  ) {
    try {
      const resp = transport!.fetchVisible({
        url: envelope.url,
        disclosure_manifest_id: disclosure_manifest.manifest_id,
        allowed_fields: ["page_url", "page_mode"],
      });
      transport_calls = 1;
      // Merge transport visible content as untrusted replacement when provided.
      envelope = parsePageEnvelope({
        schema_version: 1,
        url: envelope.url,
        page_mode: envelope.page_mode,
        visible_title: resp.visible_title || envelope.visible_title,
        visible_text: resp.visible_text || envelope.visible_text,
        metadata: { ...envelope.metadata, ...(resp.metadata ?? {}) },
      });
    } catch {
      // Transport failure falls back to orchestrator-supplied envelope.
      transport_calls = 1;
    }
  } else if (
    disclosure_decision !== "approved" ||
    transport === null ||
    envelope.page_mode === "logged_visible"
  ) {
    transport_calls = 0;
  }

  // Load local incident via shared diagnose core (read-only).
  const diagnosis = diagnose(options.targetPath);
  const local_incident: IncidentFingerprint | null =
    diagnosis.incident_fingerprint;

  const extracted = extractPageContent(envelope);
  const repair_dsl_candidates = pageCommandsToDslCandidates(
    extracted.extraction,
  );
  assertCandidatesNotAuthorized(repair_dsl_candidates);

  const page_evidence: PageEvidenceRecord = {
    schema_version: 1,
    url: envelope.url,
    page_mode: envelope.page_mode,
    content_sha256: envelopeContentSha256(envelope),
    title_sha256: titleSha256(envelope),
    quarantine: extracted.quarantine,
    extraction: extracted.extraction,
    repair_dsl_candidates,
    injection_quarantined: extracted.injection_quarantined,
    policy_mutations_blocked: true,
  };

  const comparison = comparePageToLocal(
    envelope,
    extracted.extraction,
    local_incident,
    repair_dsl_candidates,
    extracted.injection_quarantined,
  );

  // Separated public labels (Ticket 04 style).
  const observed_facts: string[] = [
    "page_analysis_read_only",
    "network_used_false_unless_injected_transport",
    `transport_calls:${transport_calls}`,
    `page_mode:${envelope.page_mode}`,
    "policy_mutations_blocked",
    "repair_not_authorized_from_page",
  ];
  if (transport_calls === 0) {
    observed_facts.push("transport_not_called");
  }
  if (extracted.injection_quarantined) {
    observed_facts.push("page_injection_quarantined");
  }
  if (page_evidence.extraction.platform) {
    observed_facts.push(`page_platform:${page_evidence.extraction.platform}`);
  }

  const user_reports: string[] = [
    ...page_evidence.extraction.symptoms.map((s) => `symptom:${s}`),
    ...page_evidence.extraction.conclusions.map((c) => `conclusion:${c}`),
    ...page_evidence.extraction.author_claims.map(
      (a) => `claim:${a.field}:${a.value}`,
    ),
  ].slice(0, 32);

  const hypotheses: string[] = [
    ...page_evidence.extraction.inferences.map((i) => `inference:${i.value}`),
    `applicability:${comparison.applicability}`,
    `confidence:${comparison.confidence}`,
  ].slice(0, 32);

  // Injection / page text must not alter tool selection or disclosure decision.
  // We re-assert the original decision and zero repair authorization.
  return emptyResult({
    ok: true,
    page_evidence,
    comparison,
    disclosure_decision,
    disclosure_manifest,
    transport_calls,
    observed_facts,
    user_reports,
    hypotheses,
    local_incident,
    error_code: null,
    error_message: null,
  });
}
