import type { IncidentFingerprint } from "../core/types.js";
import { CHATGPT_OUT_OF_SCOPE_HOSTS, MAX_COMPARISON_NOTES } from "./limits.js";
import type {
  Applicability,
  PageComparison,
  PageConfidence,
  PageEvidenceEnvelope,
  PageExtraction,
  PageRisk,
  UntrustedRepairDslCandidate,
} from "./types.js";

function note(notes: string[], s: string): void {
  if (notes.length < MAX_COMPARISON_NOTES) notes.push(s);
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isChatGptOutOfScope(
  envelope: PageEvidenceEnvelope,
  extraction: PageExtraction,
): boolean {
  const host = (envelope.metadata.host ?? hostOf(envelope.url)).toLowerCase();
  if (CHATGPT_OUT_OF_SCOPE_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) {
    return true;
  }
  if (extraction.surface === "chatgpt_account") return true;
  // Generic ChatGPT session language without Codex surface signals.
  const text = `${envelope.visible_title}\n${envelope.visible_text}`.toLowerCase();
  const chatgpty =
    /\b(chatgpt|session expired|log\s*in again|account suspended|billing|subscription)\b/.test(
      text,
    );
  const codexy =
    /\bcodex\b/.test(text) ||
    extraction.surface === "browser_control" ||
    extraction.surface === "cli" ||
    extraction.surface === "desktop" ||
    extraction.stack_symbols.some((s) =>
      /browser-client|process-shim|chrome\.dll/i.test(s),
    );
  return chatgpty && !codexy;
}

/**
 * Compare untrusted page claims with local Incident Fingerprint.
 * Wrong platform/surface/mechanism cannot gain high confidence from lexical similarity.
 * ChatGPT/account/session pages are hard-gated away from Codex component defects.
 */
export function comparePageToLocal(
  envelope: PageEvidenceEnvelope,
  extraction: PageExtraction,
  local: IncidentFingerprint | null,
  dslCandidates: UntrustedRepairDslCandidate[],
  injectionQuarantined = false,
): PageComparison {
  const notes: string[] = [];
  const missing: string[] = [];
  const refuting: string[] = [];

  const page_platform = extraction.platform;
  const page_surface = extraction.surface;
  const local_platform = local?.platform.os ?? null;
  const local_surface = local?.surface ?? null;
  const local_fingerprint_digest = local?.local_facts_digest ?? null;

  // Hard gate: ChatGPT / account / session product pages.
  if (isChatGptOutOfScope(envelope, extraction)) {
    note(notes, "chatgpt_or_account_surface_out_of_scope");
    refuting.push("product_boundary:chatgpt_account_session");
    return {
      applicability: "chatgpt_out_of_scope",
      confidence: "none",
      missing_evidence: ["codex_component_signal"],
      refuting_evidence: refuting,
      risk: "low",
      safe_isolation_experiment: null,
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest,
      local_surface,
      local_platform,
      page_platform,
      page_surface,
      notes,
    };
  }

  if (!local) {
    missing.push("local_incident_fingerprint");
    return {
      applicability: "insufficient_evidence",
      confidence: "none",
      missing_evidence: missing,
      refuting_evidence: refuting,
      risk: "moderate",
      safe_isolation_experiment:
        "Provide an isolated target with incident.json matching Ticket 01.",
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest: null,
      local_surface: null,
      local_platform: null,
      page_platform,
      page_surface,
      notes: ["local_fingerprint_unavailable"],
    };
  }

  // Wrong platform hard gate.
  if (
    page_platform &&
    local_platform &&
    page_platform !== "unknown" &&
    local_platform !== "unknown" &&
    page_platform !== local_platform
  ) {
    refuting.push(
      `platform_mismatch:page=${page_platform}:local=${local_platform}`,
    );
    note(notes, "wrong_platform_hard_gate");
    return {
      applicability: "wrong_platform",
      confidence: "none",
      missing_evidence: missing,
      refuting_evidence: refuting,
      risk: "moderate",
      safe_isolation_experiment:
        "Do not apply page workaround; reproduce only on matching platform in isolation.",
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest,
      local_surface,
      local_platform,
      page_platform,
      page_surface,
      notes,
    };
  }

  // Wrong surface hard gate (when both known and incompatible).
  if (
    page_surface &&
    local_surface &&
    page_surface !== "unknown" &&
    local_surface !== "unknown" &&
    page_surface !== local_surface &&
    // browser_control vs desktop can be adjacent; only hard-refuse clear mismatches
    !(
      (page_surface === "browser_control" && local_surface === "desktop") ||
      (page_surface === "desktop" && local_surface === "browser_control")
    )
  ) {
    refuting.push(
      `surface_mismatch:page=${page_surface}:local=${local_surface}`,
    );
    note(notes, "wrong_surface_hard_gate");
    return {
      applicability: "wrong_surface",
      confidence: "none",
      missing_evidence: missing,
      refuting_evidence: refuting,
      risk: "moderate",
      safe_isolation_experiment:
        "Refuse surface-incompatible workaround; collect matching surface evidence first.",
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest,
      local_surface,
      local_platform,
      page_platform,
      page_surface,
      notes,
    };
  }

  // Mechanism signals: stack, AST, error class, failure phase.
  const localAst = new Set(local.ast_signature_ids ?? []);
  const localSymbols = new Set(
    (local.stack_frames ?? [])
      .flatMap((f) => [f.symbol, f.module, f.file])
      .filter((x): x is string => typeof x === "string" && x.length > 0),
  );
  const localErrorClass = local.error.class.toLowerCase();
  const localErrorMsg = local.error.normalized_message.toLowerCase();

  let structuralHits = 0;
  for (const s of extraction.stack_symbols) {
    const sl = s.toLowerCase();
    if (
      localAst.has(s) ||
      [...localAst].some((a) => sl.includes(a.toLowerCase())) ||
      [...localSymbols].some((ls) => sl.includes(ls.toLowerCase()))
    ) {
      structuralHits++;
    }
  }
  if (
    extraction.stack_symbols.some((s) =>
      /js\.global-process-shim-redefinition\.v1/i.test(s),
    ) &&
    localAst.has("js.global-process-shim-redefinition.v1")
  ) {
    structuralHits += 2;
  }

  let errorHit = false;
  for (const e of extraction.errors) {
    const el = e.toLowerCase();
    if (el.includes(localErrorClass) || localErrorMsg.includes(el.slice(0, 40))) {
      errorHit = true;
    }
    if (
      /protected global process binding rejected assignment/i.test(e) &&
      /protected global process/i.test(localErrorMsg)
    ) {
      errorHit = true;
      structuralHits++;
    }
  }

  const phaseHit =
    !!extraction.failure_phase &&
    extraction.failure_phase === local.failure_phase;

  // Unsupported / no-evidence assertion: conclusions without structural/error signal.
  const hasConclusion = extraction.conclusions.length > 0;
  const hasAnySignal =
    structuralHits > 0 || errorHit || extraction.stack_symbols.length > 0;

  if (!hasAnySignal && hasConclusion) {
    missing.push("structural_or_repro_signal");
    note(notes, "unsupported_assertion_without_evidence");
    return {
      applicability: "unsupported_assertion",
      confidence: "none",
      missing_evidence: missing,
      refuting_evidence: refuting,
      risk: "high",
      safe_isolation_experiment:
        "Ignore author conclusion; design a minimal isolated probe for claimed mechanism.",
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest,
      local_surface,
      local_platform,
      page_platform,
      page_surface,
      notes,
    };
  }

  if (!hasAnySignal) {
    missing.push("matching_error_or_stack_or_ast");
    if (!page_platform) missing.push("page_platform");
    if (!page_surface) missing.push("page_surface");
    note(notes, "insufficient_page_evidence");
    return {
      applicability: "insufficient_evidence",
      confidence: "none",
      missing_evidence: missing,
      refuting_evidence: refuting,
      risk: "moderate",
      safe_isolation_experiment:
        "Collect exact error class, stack symbols, and failure phase from the page or local repro.",
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest,
      local_surface,
      local_platform,
      page_platform,
      page_surface,
      notes,
    };
  }

  // Wrong mechanism: page has structural tokens that conflict with local.
  if (
    extraction.stack_symbols.length > 0 &&
    structuralHits === 0 &&
    !errorHit
  ) {
    refuting.push("stack_symbols_do_not_match_local");
    note(notes, "wrong_mechanism_lexical_only");
    return {
      applicability: "wrong_mechanism",
      confidence: "none",
      missing_evidence: missing,
      refuting_evidence: refuting,
      risk: "moderate",
      safe_isolation_experiment:
        "Do not transfer page workaround; re-measure local AST/hash before any repair preview.",
      eligible_for_repair_capsule_validation: false,
      local_fingerprint_digest,
      local_surface,
      local_platform,
      page_platform,
      page_surface,
      notes,
    };
  }

  // Applicable candidate path — confidence capped (never high from page alone).
  let confidence: PageConfidence = "low";
  if (structuralHits >= 2 && errorHit) confidence = "medium";
  else if (structuralHits >= 1 || (errorHit && phaseHit)) confidence = "low";
  else confidence = "low";

  const eligibleDsl = dslCandidates.filter((c) => c.eligible_for_validation);
  const eligible_for_repair_capsule_validation =
    (confidence === "low" || confidence === "medium") &&
    eligibleDsl.length > 0 &&
    structuralHits > 0;

  let risk: PageRisk = "moderate";
  if (eligibleDsl.some((c) => c.operation_kind === "exact_block_removal")) {
    risk = "moderate";
  }
  if (injectionQuarantined) {
    risk = "high";
  }

  note(notes, "page_is_untrusted_evidence_only");
  if (eligible_for_repair_capsule_validation) {
    note(
      notes,
      "dsl_candidate_may_enter_later_repair_capsule_validation_only",
    );
  }

  const applicability: Applicability = "applicable_candidate";

  return {
    applicability,
    confidence,
    missing_evidence: missing,
    refuting_evidence: refuting,
    risk,
    safe_isolation_experiment: eligible_for_repair_capsule_validation
      ? "Copy isolated fixture; run Ticket 01 diagnose; Ticket 02 repair-preview only after scope-bound checks — never execute page shell."
      : "Reproduce page-claimed mechanism in an isolated profile before any repair consideration.",
    eligible_for_repair_capsule_validation,
    local_fingerprint_digest,
    local_surface,
    local_platform,
    page_platform,
    page_surface,
    notes,
  };
}
