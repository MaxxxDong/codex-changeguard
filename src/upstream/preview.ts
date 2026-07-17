import { diagnose } from "../core/diagnose.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import { sha256Canonical, sha256Text } from "../evidence/canonical.js";
import { DoctorError, sanitizeDoctorJson } from "./doctor.js";
import { assessDuplicate } from "./duplicate.js";
import {
  buildUpstreamDisclosureManifest,
  formTransportPermitted,
  formTransportRequestPayload,
} from "./disclosure.js";
import {
  bundledOfficialFormSnapshot,
  validateOfficialFormSnapshot,
  viewFormSnapshot,
} from "./form-snapshot.js";
import { evaluateMaintainerValueGate } from "./maintainer-gate.js";
import {
  parseUpstreamRequest,
  UpstreamRequestError,
} from "./request.js";
import { applyFormMap, routeUpstream } from "./routing.js";
import type {
  CapsuleStatus,
  DisclosureDecision,
  DuplicateAssessment,
  DuplicateRecommendation,
  UpstreamFormTransport,
  UpstreamPreviewRequest,
  UpstreamPreviewResult,
  UpstreamRoute,
  UpstreamSubmissionCapsule,
} from "./types.js";

export interface UpstreamPreviewOptions {
  targetPath: string;
  /** Bounded request envelope (object or JSON string). */
  request: unknown;
  disclosure_decision?: DisclosureDecision;
  /**
   * Injectable official-only form transport (tests/orchestration only).
   * Production CLI/MCP pass null — no hidden network.
   */
  transport?: UpstreamFormTransport | null;
  /** Clock for snapshot freshness (tests may inject). */
  nowMs?: number;
}

function emptyResult(
  partial: Partial<UpstreamPreviewResult> &
    Pick<
      UpstreamPreviewResult,
      "ok" | "disclosure_decision" | "disclosure_manifest"
    >,
): UpstreamPreviewResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    capsule: partial.capsule ?? null,
    disclosure_decision: partial.disclosure_decision,
    disclosure_manifest: partial.disclosure_manifest,
    transport_calls: partial.transport_calls ?? 0,
    local_incident: partial.local_incident ?? null,
    // Truthful: production CLI/MCP inject null transport → always false.
    // Injected transport (tests/orchestration) that actually fires → true.
    network_used: partial.network_used ?? false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    external_write: false,
    submission_status: "none",
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
  };
}

function capsuleId(material: unknown): string {
  return `usc_${sha256Canonical(material).slice(0, 24)}`;
}

/**
 * Replace free-text fields that may carry injection with a deterministic
 * quarantine placeholder. Retains structure; no raw injection prose in export.
 */
function quarantineRequestFreeText(
  request: UpstreamPreviewRequest,
  placeholder: string,
): UpstreamPreviewRequest {
  return {
    ...request,
    actual_behavior: placeholder,
    technical_signals: request.technical_signals.map(() => placeholder),
    platform: {
      os: request.platform.os ? placeholder : null,
      arch: request.platform.arch ? placeholder : null,
      unknown_reason: request.platform.unknown_reason ? placeholder : null,
    },
    codex_version: request.codex_version ? placeholder : null,
    version_unknown_reason: request.version_unknown_reason ? placeholder : null,
    reproduction: {
      ...request.reproduction,
      steps: request.reproduction.steps.map(() => placeholder),
      intermittent_marker: request.reproduction.intermittent_marker
        ? placeholder
        : null,
    },
    observed_facts: request.observed_facts.map(() => placeholder),
    user_reports: request.user_reports.map(() => placeholder),
    hypotheses: request.hypotheses.map(() => placeholder),
    error_strings: [],
    command_strings: [],
    evidence_delta: {
      items: request.evidence_delta.items.map((it) => ({
        ...it,
        summary: placeholder,
      })),
    },
    duplicate_search: {
      ...request.duplicate_search,
      candidates: request.duplicate_search.candidates.map((c) => ({
        ...c,
        title: placeholder,
        // Keep structural ids/urls for routing inspectability but strip free title.
      })),
    },
    // Drop doctor payload from export path when injection detected.
    doctor_json: null,
  };
}

/**
 * Central export invariant for submission-consumable draft fields:
 * - only PREVIEW_READY may export public/discussion draft content
 * - ROUTED_PRIVATE exports private_report recommendation and private guidance only
 * - PREVIEW_BLOCKED / GATE_FAILED export recommendation=blocked and null drafts
 * - exact-duplicate zero-delta PREVIEW_READY keeps subscribe_or_upvote + null drafts
 */
function applyCapsuleExportInvariant(input: {
  status: CapsuleStatus;
  route: UpstreamRoute;
  assessed: DuplicateAssessment & { draft_title: string | null };
}): {
  duplicate: DuplicateAssessment;
  draft_title: string | null;
  draft_labels: string[];
} {
  const { status, route, assessed } = input;

  if (status === "PREVIEW_BLOCKED" || status === "GATE_FAILED") {
    return {
      duplicate: {
        state: assessed.state,
        matched_issue_id: assessed.matched_issue_id,
        matched_issue_url: assessed.matched_issue_url,
        evidence_delta_material: assessed.evidence_delta_material,
        evidence_delta_hash: assessed.evidence_delta_hash,
        recommendation: "blocked" satisfies DuplicateRecommendation,
        draft_body: null,
        draft_comment: null,
        cross_link_issue_ids: [],
      },
      draft_title: null,
      draft_labels: [],
    };
  }

  if (status === "ROUTED_PRIVATE") {
    return {
      duplicate: {
        state: assessed.state,
        matched_issue_id: assessed.matched_issue_id,
        matched_issue_url: assessed.matched_issue_url,
        evidence_delta_material: assessed.evidence_delta_material,
        evidence_delta_hash: assessed.evidence_delta_hash,
        recommendation: "private_report",
        draft_body: null,
        draft_comment: null,
        cross_link_issue_ids: [],
      },
      draft_title: null,
      draft_labels: [],
    };
  }

  // PREVIEW_READY only: public/discussion drafts and labels may export.
  // Exact-dup zero-delta subscribe/upvote: no drafts and no cross-link actions.
  if (assessed.recommendation === "subscribe_or_upvote") {
    return {
      duplicate: {
        state: assessed.state,
        matched_issue_id: assessed.matched_issue_id,
        matched_issue_url: assessed.matched_issue_url,
        evidence_delta_material: assessed.evidence_delta_material,
        evidence_delta_hash: assessed.evidence_delta_hash,
        recommendation: "subscribe_or_upvote",
        draft_body: null,
        draft_comment: null,
        cross_link_issue_ids: [],
      },
      draft_title: null,
      draft_labels: [],
    };
  }

  return {
    duplicate: {
      state: assessed.state,
      matched_issue_id: assessed.matched_issue_id,
      matched_issue_url: assessed.matched_issue_url,
      evidence_delta_material: assessed.evidence_delta_material,
      evidence_delta_hash: assessed.evidence_delta_hash,
      recommendation: assessed.recommendation,
      draft_body: assessed.draft_body,
      draft_comment: assessed.draft_comment,
      cross_link_issue_ids: assessed.cross_link_issue_ids,
    },
    draft_title: assessed.draft_title,
    draft_labels:
      route === "GITHUB_ISSUE" && assessed.state === "NEW_INCIDENT"
        ? ["bug", "changeguard-preview"]
        : [],
  };
}

/**
 * Shared Ticket 10 core: generate a privacy-reviewed Upstream Submission Capsule.
 *
 * PREVIEW ONLY — never performs external write, reaction, subscription, upload,
 * comment, issue creation, or token/auth operations.
 */
export function previewUpstream(
  options: UpstreamPreviewOptions,
): UpstreamPreviewResult {
  const disclosure_decision: DisclosureDecision =
    options.disclosure_decision ?? "not_requested";
  const disclosure_manifest = buildUpstreamDisclosureManifest();
  const nowMs = options.nowMs ?? Date.now();

  let parsed;
  try {
    parsed = parseUpstreamRequest(options.request);
  } catch (e) {
    const code = e instanceof UpstreamRequestError ? e.code : "REQUEST_ERROR";
    const message =
      e instanceof UpstreamRequestError ? e.message : "Invalid upstream request.";
    return emptyResult({
      ok: false,
      disclosure_decision,
      disclosure_manifest,
      transport_calls: 0,
      network_used: false,
      error_code: code,
      error_message: message,
    });
  }

  const {
    request: parsedRequest,
    injection_detected,
    injection_reason,
    injection_material,
  } = parsed;

  // Quarantine injection-bearing free text for capsule privacy record.
  const quarantine =
    injection_detected && injection_reason
      ? {
          quarantined: true as const,
          reason: injection_reason,
          original_sha256: sha256Text(
            injection_material ?? `injection:${injection_reason}`,
          ),
          placeholder: `<quarantined:body:${injection_reason}>`,
        }
      : null;

  // When injection is present, strip free text before any draft construction.
  const request = injection_detected && quarantine
    ? quarantineRequestFreeText(parsedRequest, quarantine.placeholder)
    : parsedRequest;

  // Load local incident (read-only) for cross-check; never required for routing.
  const diagnosis = diagnose(options.targetPath);
  const local_incident = diagnosis.incident_fingerprint;

  // Doctor sanitization (orchestrator-supplied only; never exec codex).
  // Skip doctor content when injection already quarantined the request.
  let doctor;
  try {
    doctor = sanitizeDoctorJson(
      injection_detected ? null : request.doctor_json,
    );
    if (injection_detected) {
      doctor = {
        ...doctor,
        refused_reasons: ["injection_quarantined"],
      };
    }
  } catch (e) {
    const code = e instanceof DoctorError ? e.code : "DOCTOR_ERROR";
    const message =
      e instanceof DoctorError ? e.message : "Doctor sanitization failed.";
    return emptyResult({
      ok: false,
      disclosure_decision,
      disclosure_manifest,
      transport_calls: 0,
      network_used: false,
      local_incident,
      error_code: code,
      error_message: message,
    });
  }

  // Route first; form map applied after snapshot so filenames follow current forms.
  let routeDecision = routeUpstream(request.case_kind);

  // Form snapshot: bundled immutable by default; optional approved transport refresh.
  let transport_calls = 0;
  let formSnapshot = bundledOfficialFormSnapshot();
  let snapshotSource: "bundled_immutable" | "transport_refresh" =
    "bundled_immutable";
  const transport = options.transport ?? null;
  if (formTransportPermitted(disclosure_decision, transport !== null)) {
    try {
      const req = formTransportRequestPayload(disclosure_manifest.manifest_id);
      const resp = transport!.fetchForms(req);
      transport_calls = 1;
      formSnapshot = validateOfficialFormSnapshot(resp.snapshot, nowMs);
      snapshotSource = "transport_refresh";
    } catch (e) {
      transport_calls = 1;
      // Fall back to bundled immutable snapshot; mark via view freshness.
      void e;
      formSnapshot = bundledOfficialFormSnapshot();
      snapshotSource = "bundled_immutable";
    }
  } else {
    transport_calls = 0;
  }

  // Dynamic form filename from the validated current snapshot role.
  routeDecision = applyFormMap(
    routeDecision,
    request.surface,
    formSnapshot.forms,
  );

  const form_snapshot = viewFormSnapshot(formSnapshot, nowMs, snapshotSource);
  // Truthful network/transport: production null transport → false/0; injected call → true/1.
  const network_used = transport_calls > 0;

  // Duplicate assessment for gate evaluation (full drafts kept until export filter).
  const assessed = assessDuplicate(request, routeDecision.route);
  const assessmentForGate: DuplicateAssessment = {
    state: assessed.state,
    matched_issue_id: assessed.matched_issue_id,
    matched_issue_url: assessed.matched_issue_url,
    evidence_delta_material: assessed.evidence_delta_material,
    evidence_delta_hash: assessed.evidence_delta_hash,
    recommendation: assessed.recommendation,
    // Gate material_value inspects draft presence; injection still nulls usable drafts.
    draft_body: injection_detected ? null : assessed.draft_body,
    draft_comment: injection_detected ? null : assessed.draft_comment,
    cross_link_issue_ids: injection_detected ? [] : assessed.cross_link_issue_ids,
  };

  // Request privacy booleans only (never OR-lift doctor redaction into them).
  // Doctor secrets/paths stay in doctor_inclusion. passed and the gate privacy
  // check share these exact four operands.
  const secrets_redacted = request.privacy_review.secrets_redacted;
  const paths_redacted = request.privacy_review.paths_redacted;
  const session_excluded = request.privacy_review.session_excluded;
  const privacy_review_passed =
    !injection_detected &&
    secrets_redacted &&
    paths_redacted &&
    session_excluded;

  const gate = evaluateMaintainerValueGate({
    request,
    route: routeDecision.route,
    duplicate: assessmentForGate,
    doctor,
    privacy_passed: privacy_review_passed,
  });

  // Injection → PREVIEW_BLOCKED. Gate failure precedes private routing:
  // only a gate-passed private (Bugcrowd) route is ROUTED_PRIVATE.
  let status: CapsuleStatus;
  if (injection_detected) {
    status = "PREVIEW_BLOCKED";
  } else if (!gate.passed) {
    status = "GATE_FAILED";
  } else if (routeDecision.route === "BUGCROWD") {
    status = "ROUTED_PRIVATE";
  } else {
    status = "PREVIEW_READY";
  }

  const exported = applyCapsuleExportInvariant({
    status,
    route: routeDecision.route,
    assessed,
  });
  const duplicate = exported.duplicate;

  // Guidance is status-scoped: private guidance only on ROUTED_PRIVATE;
  // support/discussion guidance only on PREVIEW_READY for those routes.
  const private_report_guidance =
    status === "ROUTED_PRIVATE"
      ? "Report privately via OpenAI Bugcrowd. Do not open a public GitHub Issue for validated security vulnerabilities."
      : null;
  const support_guidance =
    status === "PREVIEW_READY" && routeDecision.route === "OPENAI_SUPPORT"
      ? "Contact OpenAI Support for account, billing, or private cases. No public Issue draft is generated."
      : null;
  const discussion_guidance =
    status === "PREVIEW_READY" && routeDecision.route === "GITHUB_DISCUSSIONS"
      ? "Open a GitHub Discussion for product support questions (not a bug Issue form)."
      : null;

  // GATE_FAILED: strip submission-reconstructable free text; keep only
  // structured gate diagnostics and quarantine-safe metadata.
  const stripFreeText = status === "GATE_FAILED";
  const observed_facts = stripFreeText ? [] : request.observed_facts;
  const user_reports = stripFreeText ? [] : request.user_reports;
  const hypotheses = stripFreeText ? [] : request.hypotheses;
  const error_strings = stripFreeText ? [] : request.error_strings;
  const command_strings = stripFreeText ? [] : request.command_strings;

  // Canonical payload without id / content hash — content-addresses distinct
  // safe capsule/draft/facts/doctor/snapshot/gate material (no circular hash).
  const capsulePayload = {
    schema_version: 1 as const,
    mode: "preview_only" as const,
    locality: "local_only" as const,
    repair_authorized: false as const,
    external_write: false as const,
    requires_ticket11_confirmation: true as const,
    status,
    route: routeDecision.route,
    github_issue_form: routeDecision.github_issue_form,
    form_filename: routeDecision.form_filename,
    duplicate,
    maintainer_value_gate: gate,
    form_snapshot,
    doctor_inclusion: doctor,
    privacy_review: {
      passed: privacy_review_passed,
      secrets_redacted,
      paths_redacted,
      session_excluded,
      injection_quarantined: injection_detected,
      quarantine,
    },
    observed_facts,
    user_reports,
    hypotheses,
    error_strings,
    command_strings,
    route_rationale: routeDecision.rationale,
    draft_title: exported.draft_title,
    draft_labels: exported.draft_labels,
    private_report_guidance,
    support_guidance,
    discussion_guidance,
  };

  const capsule: UpstreamSubmissionCapsule = {
    ...capsulePayload,
    capsule_id: capsuleId(capsulePayload),
    capsule_content_sha256: "",
  };
  capsule.capsule_content_sha256 = sha256Canonical({
    ...capsule,
    capsule_content_sha256: null,
  });

  // PREVIEW_BLOCKED and GATE_FAILED are non-ready: ok=false so CLI/MCP error.
  // Only PREVIEW_READY and gate-passed ROUTED_PRIVATE are ok=true.
  const ok = status === "PREVIEW_READY" || status === "ROUTED_PRIVATE";

  return emptyResult({
    ok,
    capsule,
    disclosure_decision,
    disclosure_manifest,
    transport_calls,
    network_used,
    local_incident,
    error_code:
      status === "GATE_FAILED"
        ? "GATE_FAILED"
        : status === "PREVIEW_BLOCKED"
          ? "INJECTION_QUARANTINED"
          : null,
    error_message:
      status === "GATE_FAILED"
        ? `Maintainer-value gate failed: ${gate.failed_ids.join(", ")}`
        : status === "PREVIEW_BLOCKED"
          ? "Prompt-injection content quarantined; preview blocked for public draft."
          : null,
  });
}
