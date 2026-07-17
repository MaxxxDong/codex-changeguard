import crypto from "node:crypto";
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
  FormSnapshotError,
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
    network_used: false,
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
      error_code: code,
      error_message: message,
    });
  }

  const { request, injection_detected, injection_reason } = parsed;

  // Quarantine injection-bearing free text for capsule privacy record.
  const quarantine =
    injection_detected && injection_reason
      ? {
          quarantined: true as const,
          reason: injection_reason,
          original_sha256: sha256Text(`injection:${injection_reason}`),
          placeholder: `<quarantined:body:${injection_reason}>`,
        }
      : null;

  // Load local incident (read-only) for cross-check; never required for routing.
  const diagnosis = diagnose(options.targetPath);
  const local_incident = diagnosis.incident_fingerprint;

  // Doctor sanitization (orchestrator-supplied only; never exec codex).
  let doctor;
  try {
    doctor = sanitizeDoctorJson(request.doctor_json);
  } catch (e) {
    const code = e instanceof DoctorError ? e.code : "DOCTOR_ERROR";
    const message =
      e instanceof DoctorError ? e.message : "Doctor sanitization failed.";
    return emptyResult({
      ok: false,
      disclosure_decision,
      disclosure_manifest,
      transport_calls: 0,
      local_incident,
      error_code: code,
      error_message: message,
    });
  }

  // Route + form map.
  let routeDecision = routeUpstream(request.case_kind);
  routeDecision = applyFormMap(routeDecision, request.surface);

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
      formSnapshot = validateOfficialFormSnapshot(resp.snapshot);
      snapshotSource = "transport_refresh";
    } catch (e) {
      transport_calls = 1;
      // Fall back to bundled immutable snapshot; mark via view freshness.
      if (e instanceof FormSnapshotError) {
        formSnapshot = bundledOfficialFormSnapshot();
        snapshotSource = "bundled_immutable";
      } else {
        formSnapshot = bundledOfficialFormSnapshot();
        snapshotSource = "bundled_immutable";
      }
    }
  } else {
    transport_calls = 0;
  }

  const form_snapshot = viewFormSnapshot(formSnapshot, nowMs, snapshotSource);

  // Duplicate assessment (exact enums + zero-delta reaction-only).
  const dupFull = assessDuplicate(request, routeDecision.route);
  const draft_title = dupFull.draft_title;
  const duplicate = {
    state: dupFull.state,
    matched_issue_id: dupFull.matched_issue_id,
    matched_issue_url: dupFull.matched_issue_url,
    evidence_delta_material: dupFull.evidence_delta_material,
    evidence_delta_hash: dupFull.evidence_delta_hash,
    recommendation: dupFull.recommendation,
    // Security path: never render public Issue draft body/comment.
    draft_body: routeDecision.public_issue_draft_forbidden
      ? null
      : dupFull.draft_body,
    draft_comment: routeDecision.public_issue_draft_forbidden
      ? null
      : dupFull.draft_comment,
    cross_link_issue_ids: dupFull.cross_link_issue_ids,
  };

  const privacy_passed = !injection_detected;
  const gate = evaluateMaintainerValueGate({
    request,
    route: routeDecision.route,
    duplicate,
    doctor,
    privacy_passed,
  });

  let status: CapsuleStatus;
  if (routeDecision.route === "BUGCROWD") {
    status = "ROUTED_PRIVATE";
  } else if (injection_detected) {
    // Injection quarantine blocks public draft regardless of other gate checks.
    status = "PREVIEW_BLOCKED";
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
    observed_facts: request.observed_facts,
    user_reports: request.user_reports,
    hypotheses: request.hypotheses,
    error_strings: request.error_strings,
    command_strings: request.command_strings,
    route_rationale: routeDecision.rationale,
    draft_title:
      routeDecision.public_issue_draft_forbidden ||
      duplicate.recommendation === "subscribe_or_upvote"
        ? null
        : draft_title,
    draft_labels:
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

  // ok when we produced a capsule (including private/gate-failed previews for inspectability)
  // Fail only on parse/doctor hard errors above.
  const ok =
    status === "PREVIEW_READY" ||
    status === "ROUTED_PRIVATE" ||
    status === "GATE_FAILED" ||
    status === "PREVIEW_BLOCKED";

  return emptyResult({
    ok,
    capsule,
    disclosure_decision,
    disclosure_manifest,
    transport_calls,
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

/** Stable nonce helper for tests (not used for external auth). */
export function randomPreviewNonce(): string {
  return crypto.randomBytes(8).toString("hex");
}
