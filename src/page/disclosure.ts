import crypto from "node:crypto";
import type {
  PageDisclosureDecision,
  PageDisclosureField,
  PageDisclosureManifest,
  PageEvidenceEnvelope,
} from "./types.js";

function field(
  field_name: string,
  trust_class: PageDisclosureField["trust_class"],
  source_class: PageDisclosureField["source_class"],
  transformation: string,
  destination: string,
  purpose: string,
  optional: boolean,
): PageDisclosureField {
  return {
    field_name,
    trust_class,
    source_class,
    transformation,
    destination,
    purpose,
    optional,
  };
}

/**
 * Build a page-fetch disclosure manifest.
 * Public retrieval (if ever used) requires explicit displayed disclosure first.
 * Logged-page mode never discloses cookies/storage/tokens/request bodies.
 */
export function buildPageDisclosureManifest(
  envelope: PageEvidenceEnvelope | null,
): PageDisclosureManifest {
  const manifest_id = crypto
    .createHash("sha256")
    .update(
      `page-disclosure:${envelope?.url ?? "none"}:${envelope?.page_mode ?? "none"}`,
    )
    .digest("hex")
    .slice(0, 32);

  const fields: PageDisclosureField[] = [
    field(
      "page_url",
      "redacted_structured",
      "user_provided",
      "absolute_url_no_userinfo",
      "page_transport_or_local_only",
      "identify_public_problem_page",
      false,
    ),
    field(
      "page_mode",
      "redacted_structured",
      "user_provided",
      "enum",
      "local_only",
      "distinguish_public_vs_logged_visible",
      false,
    ),
    field(
      "visible_title",
      "redacted_structured",
      "user_provided",
      "nfkc_bound_redact",
      "local_analysis",
      "title_for_extraction",
      true,
    ),
    field(
      "visible_text",
      "redacted_structured",
      "user_provided",
      "nfkc_bound_quarantine_redact",
      "local_analysis",
      "sanitized_visible_document_content",
      false,
    ),
    // Device-only exclusions — never sent / never collected from browser.
    field(
      "cookies",
      "device_only",
      "local_observed",
      "never_collected",
      "never_sent",
      "logged_page_privacy_boundary",
      false,
    ),
    field(
      "browser_storage",
      "device_only",
      "local_observed",
      "never_collected",
      "never_sent",
      "logged_page_privacy_boundary",
      false,
    ),
    field(
      "tokens_and_auth_headers",
      "device_only",
      "local_observed",
      "never_collected",
      "never_sent",
      "logged_page_privacy_boundary",
      false,
    ),
    field(
      "complete_browser_requests",
      "device_only",
      "local_observed",
      "never_collected",
      "never_sent",
      "logged_page_privacy_boundary",
      false,
    ),
    field(
      "request_bodies",
      "device_only",
      "local_observed",
      "never_collected",
      "never_sent",
      "logged_page_privacy_boundary",
      false,
    ),
  ];

  return {
    schema_version: 1,
    manifest_id,
    fields,
    purpose:
      "Optional public page visible-content refresh after explicit disclosure; logged pages use orchestrator-supplied visible content only",
    destinations: ["local_page_analysis", "optional_injected_page_transport"],
  };
}

export function pageDisclosureSendableFieldNames(
  manifest: PageDisclosureManifest,
): string[] {
  return manifest.fields
    .filter((f) => f.trust_class !== "device_only" && f.destination !== "never_sent")
    .map((f) => f.field_name)
    .filter((n) => n === "page_url" || n === "page_mode");
}

/**
 * Public retrieval requires disclosure approved AND an injected transport.
 * Production seams never inject transport → transport_calls stay 0.
 */
export function pageTransportPermitted(
  decision: PageDisclosureDecision,
  hasTransport: boolean,
): boolean {
  return decision === "approved" && hasTransport;
}
