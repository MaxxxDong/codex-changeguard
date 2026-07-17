import crypto from "node:crypto";
import { OFFICIAL_HOSTS, OFFICIAL_REPOSITORY } from "./limits.js";
import type {
  DisclosureDecision,
  UpstreamDisclosureManifest,
  UpstreamFormTransport,
} from "./types.js";

export function buildUpstreamDisclosureManifest(): UpstreamDisclosureManifest {
  const manifest_id = `up_${crypto
    .createHash("sha256")
    .update("upstream_form_refresh_v1")
    .digest("hex")
    .slice(0, 16)}`;
  return {
    schema_version: 1,
    manifest_id,
    purpose:
      "Optional refresh of official openai/codex Issue form definitions after user-approved disclosure. Preview-only; never submits Issues.",
    destinations: [
      "https://github.com/openai/codex",
      "https://api.github.com/repos/openai/codex",
      "https://raw.githubusercontent.com/openai/codex",
    ],
    fields: [
      {
        field_name: "disclosure_manifest_id",
        trust_class: "redacted_structured",
        source_class: "local_observed",
        transformation: "manifest_id_token",
        destination: "official_github_api",
        purpose: "Bind the form refresh to the reviewed disclosure manifest.",
        optional: false,
      },
      {
        field_name: "allowed_hosts",
        trust_class: "redacted_structured",
        source_class: "official_snapshot",
        transformation: "exact_official_host_allowlist",
        destination: "official_github_api",
        purpose: "Constrain fetch hosts to the official allowlist.",
        optional: false,
      },
      {
        field_name: "allowed_repositories",
        trust_class: "redacted_structured",
        source_class: "official_snapshot",
        transformation: "exact_official_repo_allowlist",
        destination: "official_github_api",
        purpose: "Constrain repository to openai/codex only.",
        optional: false,
      },
      {
        field_name: "resource",
        trust_class: "redacted_structured",
        source_class: "official_snapshot",
        transformation: "const_issue_forms",
        destination: "official_github_api",
        purpose: "Request only Issue form YAML definitions.",
        optional: false,
      },
      {
        field_name: "tokens",
        trust_class: "device_only",
        source_class: "local_observed",
        transformation: "never_exported",
        destination: "none",
        purpose: "Auth tokens are never requested, stored, or exported.",
        optional: true,
      },
      {
        field_name: "session_rollout",
        trust_class: "device_only",
        source_class: "local_observed",
        transformation: "never_exported",
        destination: "none",
        purpose: "Full session rollouts are never exported.",
        optional: true,
      },
    ],
  };
}

/**
 * Official form transport is permitted only when disclosure is approved AND
 * an official-only transport is injected. Production CLI/MCP inject null.
 */
export function formTransportPermitted(
  decision: DisclosureDecision,
  transportPresent: boolean,
): boolean {
  return decision === "approved" && transportPresent;
}

export function formTransportRequestPayload(manifest_id: string): {
  disclosure_manifest_id: string;
  allowed_hosts: string[];
  allowed_repositories: string[];
  resource: "issue_forms";
} {
  return {
    disclosure_manifest_id: manifest_id,
    allowed_hosts: [...OFFICIAL_HOSTS],
    allowed_repositories: [OFFICIAL_REPOSITORY],
    resource: "issue_forms",
  };
}

export type { UpstreamFormTransport };
