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
  UpstreamFormTransport,
  UpstreamPreviewRequest,
  UpstreamPreviewResult,
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

  // Duplicate assessment (exact enums + zero-delta reaction-only).
  const dupFull = assessDuplicate(request, routeDecision.route);
  const draft_title = dupFull.draft_title;
  // Injection always nulls usable drafts — including private routes.
  const blockDrafts =
    injection_detected || routeDecision.public_issue_draft_forbidden;
  const duplicate = {
    state: dupFull.state,
    matched_issue_id: dupFull.matched_issue_id,
    matched_issue_url: dupFull.matched_issue_url,
    evidence_delta_material: dupFull.evidence_delta_material,
    evidence_delta_hash: dupFull.evidence_delta_hash,
    recommendation: injection_detected
      ? dupFull.recommendation
      : routeDecision.public_issue_draft_forbidden
        ? dupFull.recommendation
        : dupFull.recommendation,
    draft_body: blockDrafts ? null : dupFull.draft_body,
    draft_comment: blockDrafts ? null : dupFull.draft_comment,
    cross_link_issue_ids: injection_detected ? [] : dupFull.cross_link_issue_ids,
  };

  const privacy_passed = !injection_detected;
  const gate = evaluateMaintainerValueGate({
    request,
    route: routeDecision.route,
    duplicate,
    doctor,
    privacy_passed,
  });

  // Privacy/injection takes precedence over private routing and gate outcomes.
  let status: CapsuleStatus;
  if (injection_detected) {
    status = "PREVIEW_BLOCKED";
  } else if (routeDecision.route === "BUGCROWD") {
    status = "ROUTED_PRIVATE";
  } else if (!gate.passed) {
    status = "GATE_FAILED";
  } else {
    status = "PREVIEW_READY";
  }

  const private_report_guidance =
    routeDecision.route === "BUGCROWD"
      ? "Report privately via OpenAI Bugcrowd. Do not open a public GitHub Issue for validated security vulnerabilities."
      : null;
  const support_guidance =
    routeDecision.route === "OPENAI_SUPPORT"
      ? "Contact OpenAI Support for account, billing, or private cases. No public Issue draft is generated."
      : null;
  const discussion_guidance =
    routeDecision.route === "GITHUB_DISCUSSIONS"
      ? "Open a GitHub Discussion for product support questions (not a bug Issue form)."
      : null;

  const capsuleMaterial = {
    mode: "preview_only" as const,
    locality: "local_only" as const,
    route: routeDecision.route,
    github_issue_form: routeDecision.github_issue_form,
    duplicate_state: duplicate.state,
    evidence_delta_hash: duplicate.evidence_delta_hash,
    form_snapshot_id: form_snapshot.snapshot_id,
    form_integrity: form_snapshot.integrity_sha256,
    gate_passed: gate.passed,
    status,
  };

  const exportTitle =
    injection_detected ||
    routeDecision.public_issue_draft_forbidden ||
    duplicate.recommendation === "subscribe_or_upvote"
      ? null
      : draft_title;

  const capsule: UpstreamSubmissionCapsule = {
    schema_version: 1,
    capsule_id: capsuleId(capsuleMaterial),
    mode: "preview_only",
    locality: "local_only",
    repair_authorized: false,
    external_write: false,
    requires_ticket11_confirmation: true,
    status,
    route: routeDecision.route,
    github_issue_form: routeDecision.github_issue_form,
    form_filename: routeDecision.form_filename,
    duplicate,
    maintainer_value_gate: gate,
    form_snapshot,
    doctor_inclusion: doctor,
    privacy_review: {
      passed: privacy_passed && request.privacy_review.secrets_redacted,
      secrets_redacted:
        request.privacy_review.secrets_redacted || doctor.secrets_redacted,
      paths_redacted:
        request.privacy_review.paths_redacted || doctor.paths_redacted,
      injection_quarantined: injection_detected,
      quarantine,
    },
    // Injection: only placeholders / empty safe fields — no raw free text.
    observed_facts: request.observed_facts,
    user_reports: request.user_reports,
    hypotheses: request.hypotheses,
    error_strings: request.error_strings,
    command_strings: request.command_strings,
    route_rationale: routeDecision.rationale,
    draft_title: exportTitle,
    draft_labels:
      !injection_detected &&
      routeDecision.route === "GITHUB_ISSUE" &&
      duplicate.state === "NEW_INCIDENT"
        ? ["bug", "changeguard-preview"]
        : [],
    private_report_guidance,
    support_guidance,
    discussion_guidance,
    capsule_content_sha256: "",
  };
  capsule.capsule_content_sha256 = sha256Canonical({
    ...capsule,
    capsule_content_sha256: null,
  });

  // PREVIEW_BLOCKED is not a success: ok=false so CLI exits non-zero.
  // ROUTED_PRIVATE / GATE_FAILED remain inspectable previews with ok=true.
  const ok =
    status === "PREVIEW_READY" ||
    status === "ROUTED_PRIVATE" ||
    status === "GATE_FAILED";

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
