import crypto from "node:crypto";
import { officialAllowlists } from "./allowlist.js";
import { sha256Canonical } from "./canonical.js";
import {
  MAX_DISCLOSURE_CONFIG_KEYS,
  MAX_DISCLOSURE_FEATURE_IDS,
  MAX_DISCLOSURE_TOKEN,
} from "./limits.js";
import type {
  DisclosureField,
  DisclosureManifest,
  LocalDisclosureContext,
  OfficialTransportRequest,
} from "./types.js";

/** Fixed allowlist metadata always present on outbound requests. */
const ALLOWLIST_FIELD_SPECS: readonly DisclosureField[] = Object.freeze([
  {
    field_name: "disclosure_manifest_id",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "manifest_id_token",
    destination: "official_github_api",
    purpose: "Bind the outbound request to the user-reviewed disclosure manifest.",
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
    purpose: "Constrain fetch repositories to openai/codex only.",
    optional: false,
  },
  {
    field_name: "resource_kinds",
    trust_class: "redacted_structured",
    source_class: "official_snapshot",
    transformation: "exact_evidence_kind_allowlist",
    destination: "official_github_api",
    purpose: "Constrain resource kinds to the official evidence kind set.",
    optional: false,
  },
]);

const LOCAL_FIELD_SPECS: Record<
  string,
  Omit<DisclosureField, "field_name"> & { field_name: string }
> = {
  codex_version: {
    field_name: "codex_version",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "exact_version_string_bounded",
    destination: "official_github_api",
    purpose: "Select official release/tag/diff range relevant to the installed version.",
    optional: false,
  },
  surface: {
    field_name: "surface",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "enum_surface_label_bounded",
    destination: "official_github_api",
    purpose: "Filter official changes that intersect the active Codex surface.",
    optional: false,
  },
  platform_os: {
    field_name: "platform_os",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "enum_os_label_bounded",
    destination: "official_github_api",
    purpose: "Filter platform-scoped official release notes and Issues.",
    optional: false,
  },
  platform_arch: {
    field_name: "platform_arch",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "enum_arch_label_bounded",
    destination: "official_github_api",
    purpose: "Filter architecture-specific official artifacts when present.",
    optional: true,
  },
  config_keys: {
    field_name: "config_keys",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "key_names_only_no_values_bounded",
    destination: "official_github_api",
    purpose: "Intersect official schema/config diffs with local key presence.",
    optional: true,
  },
  feature_ids: {
    field_name: "feature_ids",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "identifier_list_bounded",
    destination: "official_github_api",
    purpose: "Intersect official Plugin/Skill/MCP/Hook changes with enabled features.",
    optional: true,
  },
  error_class: {
    field_name: "error_class",
    trust_class: "redacted_structured",
    source_class: "local_observed",
    transformation: "error_class_token_bounded",
    destination: "official_github_api",
    purpose: "Retrieve official Issues whose structural class may match.",
    optional: true,
  },
};

/** Explicit device-only exclusions — documented, never present on the request. */
const DEVICE_ONLY_FIELDS: readonly DisclosureField[] = Object.freeze([
  {
    field_name: "absolute_paths",
    trust_class: "device_only",
    source_class: "local_observed",
    transformation: "never_sent",
    destination: "none",
    purpose: "Document that absolute paths never leave the device.",
    optional: true,
  },
  {
    field_name: "tokens_and_secrets",
    trust_class: "device_only",
    source_class: "local_observed",
    transformation: "never_sent",
    destination: "none",
    purpose: "Document that credentials and environment values never leave the device.",
    optional: true,
  },
  {
    field_name: "raw_logs_and_sessions",
    trust_class: "device_only",
    source_class: "local_observed",
    transformation: "never_sent",
    destination: "none",
    purpose: "Document that raw logs and full session rollouts never leave the device.",
    optional: true,
  },
  {
    field_name: "source_and_project_contents",
    trust_class: "device_only",
    source_class: "local_observed",
    transformation: "never_sent",
    destination: "none",
    purpose: "Document that raw project source never leaves the device.",
    optional: true,
  },
]);

/**
 * Centralized sendable-token invariant for every scalar/list disclosure field.
 *
 * Accepts only bounded identifier/token shapes used by the product today:
 * versions, platform/arch labels, surface labels, dotted config keys,
 * feature ids (including `plugin:…`), and error-class identifiers.
 *
 * Rejects free text that could smuggle cookies, OTPs, session/log bodies,
 * project source, env/path dumps, full-width/NFKC secrets, or control/whitespace.
 */
const SENDABLE_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:+-]*$/;

/** Secret-shaped substrings that must never ride a sendable identifier. */
const SENDABLE_SECRET_SHAPE_RE =
  /(?:password|secret|token|api[_-]?key|bearer|cookie|authorization|session[_-]?rollout|one[_-]?time[_-]?code|\botp\b|set-cookie|process\.env)/i;

/** High-confidence credential prefixes (never legitimate version/surface labels). */
const SENDABLE_CREDENTIAL_PREFIX_RE =
  /^(?:sk|pk|rk|ak|xox[baprs])[-_]/i;

/**
 * Return true when `value` is a genuinely bounded sendable disclosure token.
 * Exported for product-level negative controls (Ticket 16).
 */
export function isSendableDisclosureToken(value: string): boolean {
  if (typeof value !== "string") return false;
  // Reject leading/trailing whitespace by requiring exact match after trim.
  const t = value.trim();
  if (t.length === 0 || t.length > MAX_DISCLOSURE_TOKEN) return false;
  if (t !== value) return false; // embedded or surrounding whitespace
  // NFKC must not reveal a different secret form; non-ASCII is never an id.
  if (/[^\x20-\x7E]/.test(t)) return false;
  const nfkc = t.normalize("NFKC");
  if (nfkc !== t) return false;
  if (!SENDABLE_TOKEN_RE.test(t)) return false;
  // Path / URL / assignment / header free-text shapes.
  if (/[/\\]/.test(t)) return false;
  if (/=|;|,|\s|"|'|`|\{|\}|\[|\]/.test(t)) return false;
  if (SENDABLE_SECRET_SHAPE_RE.test(t)) return false;
  if (SENDABLE_CREDENTIAL_PREFIX_RE.test(t)) return false;
  return true;
}

function boundToken(value: string, field: string): string {
  if (!isSendableDisclosureToken(value)) {
    throw new Error(`Disclosure field ${field} rejected non-sendable token.`);
  }
  return value.trim();
}

function boundStringList(
  values: readonly string[] | null | undefined,
  max: number,
  field: string,
): string[] | undefined {
  if (!values || values.length === 0) return undefined;
  const out: string[] = [];
  for (const v of values) {
    if (typeof v !== "string") continue;
    try {
      const b = boundToken(v, field);
      if (!out.includes(b)) out.push(b);
    } catch {
      // Skip non-sendable tokens rather than failing the whole refresh.
      continue;
    }
    if (out.length >= max) break;
  }
  return out.length > 0 ? out : undefined;
}

/**
 * Sanitize local context into the exact sendable field set that will appear
 * on the outbound transport request (excluding fixed allowlist metadata).
 */
export function sanitizeSendableLocalFields(
  context: LocalDisclosureContext = {},
): Partial<
  Pick<
    OfficialTransportRequest,
    | "codex_version"
    | "surface"
    | "platform_os"
    | "platform_arch"
    | "config_keys"
    | "feature_ids"
    | "error_class"
  >
> {
  const out: Partial<OfficialTransportRequest> = {};
  if (context.codex_version) {
    try {
      out.codex_version = boundToken(context.codex_version, "codex_version");
    } catch {
      /* omit */
    }
  }
  if (context.surface) {
    try {
      out.surface = boundToken(context.surface, "surface");
    } catch {
      /* omit */
    }
  }
  if (context.platform_os) {
    try {
      out.platform_os = boundToken(context.platform_os, "platform_os");
    } catch {
      /* omit */
    }
  }
  if (context.platform_arch) {
    try {
      out.platform_arch = boundToken(context.platform_arch, "platform_arch");
    } catch {
      /* omit */
    }
  }
  const keys = boundStringList(
    context.config_keys,
    MAX_DISCLOSURE_CONFIG_KEYS,
    "config_keys",
  );
  if (keys) out.config_keys = keys;
  const features = boundStringList(
    context.feature_ids,
    MAX_DISCLOSURE_FEATURE_IDS,
    "feature_ids",
  );
  if (features) out.feature_ids = features;
  if (context.error_class) {
    try {
      out.error_class = boundToken(context.error_class, "error_class");
    } catch {
      /* omit */
    }
  }
  return out;
}

/**
 * Build a disclosure manifest that exactly describes the sanitized outbound
 * request field set (populated sendable + fixed allowlists) plus explicit
 * device-only exclusions. Refusal still produces a manifest without transport.
 */
export function buildDisclosureManifest(
  context: LocalDisclosureContext = {},
): DisclosureManifest {
  const sendable = sanitizeSendableLocalFields(context);
  const fields: DisclosureField[] = [
    ...ALLOWLIST_FIELD_SPECS.map((f) => ({ ...f })),
  ];
  for (const key of Object.keys(LOCAL_FIELD_SPECS)) {
    if (Object.prototype.hasOwnProperty.call(sendable, key)) {
      fields.push({ ...LOCAL_FIELD_SPECS[key]! });
    }
  }
  for (const f of DEVICE_ONLY_FIELDS) {
    fields.push({ ...f });
  }
  const base = {
    schema_version: 1 as const,
    fields,
    purpose:
      "Refresh official Codex evidence (docs, releases, tags, diffs, Issues, PRs, commits) for local intersection only.",
    destinations: ["official_github_api", "none"],
  };
  // Stable material for audit; random suffix keeps ids unique per build.
  const material = sha256Canonical({
    fields: fields.map((f) => f.field_name),
    sendable_keys: Object.keys(sendable).sort(),
  }).slice(0, 16);
  const manifest_id = `disclose_${material}_${crypto.randomBytes(4).toString("hex")}`;
  return {
    ...base,
    manifest_id,
  };
}

/**
 * Build the exact sanitized outbound transport request from the reviewed
 * manifest and local context. Request keys match non-device_only manifest fields.
 */
export function buildTransportRequest(
  manifest: DisclosureManifest,
  context: LocalDisclosureContext = {},
): OfficialTransportRequest {
  const allow = officialAllowlists();
  const sendable = sanitizeSendableLocalFields(context);
  const request: OfficialTransportRequest = {
    disclosure_manifest_id: manifest.manifest_id,
    allowed_hosts: allow.hosts,
    allowed_repositories: allow.repositories,
    resource_kinds: allow.kinds,
    ...sendable,
  };
  // Assert exact field-set match: every non-device_only manifest field is a request key.
  const manifestSendable = new Set(
    manifest.fields
      .filter((f) => f.trust_class !== "device_only")
      .map((f) => f.field_name),
  );
  const requestKeys = new Set(Object.keys(request));
  for (const name of manifestSendable) {
    if (!requestKeys.has(name)) {
      throw new Error(
        `Disclosure manifest field ${name} missing from transport request.`,
      );
    }
  }
  for (const key of requestKeys) {
    if (!manifestSendable.has(key)) {
      throw new Error(
        `Transport request key ${key} not listed in disclosure manifest.`,
      );
    }
  }
  // Device-only fields must never appear on the request object.
  for (const f of manifest.fields) {
    if (f.trust_class === "device_only" && requestKeys.has(f.field_name)) {
      throw new Error(`Device-only field ${f.field_name} leaked into request.`);
    }
  }
  return request;
}

/** Stable field-name list for tests and audits. */
export function disclosureFieldNames(manifest: DisclosureManifest): string[] {
  return manifest.fields.map((f) => f.field_name);
}

/** Non-device_only field names (exact outbound request key set). */
export function disclosureSendableFieldNames(
  manifest: DisclosureManifest,
): string[] {
  return manifest.fields
    .filter((f) => f.trust_class !== "device_only")
    .map((f) => f.field_name);
}
