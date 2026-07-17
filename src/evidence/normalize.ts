import { assertEvidenceKind, assertOfficialUrl, AllowlistError } from "./allowlist.js";
import { computeItemContentSha256 } from "./item-hash.js";
import {
  MAX_EVIDENCE_ITEMS,
  MAX_STRUCTURED_KEYS,
  MAX_STRUCTURED_TOKEN,
  MAX_SUMMARY_TOKENS,
} from "./limits.js";
import { mergeQuarantine, quarantineProse } from "./quarantine.js";
import type {
  EvidenceState,
  MaintainerStatus,
  OfficialEvidenceItem,
  OfficialStructuredPayload,
  RawOfficialTransportItem,
  VersionRange,
} from "./types.js";

export class EvidenceNormalizeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "EvidenceNormalizeError";
    this.code = code;
  }
}

function asStringArray(
  raw: unknown,
  maxItems: number,
  field: string,
): string[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    throw new EvidenceNormalizeError(
      "STRUCTURED_TYPE",
      `Invalid structured field ${field}.`,
    );
  }
  if (raw.length > maxItems) {
    throw new EvidenceNormalizeError(
      "STRUCTURED_LIMIT",
      `Structured field ${field} exceeds item limit.`,
    );
  }
  const out: string[] = [];
  for (const v of raw) {
    if (typeof v !== "string" || v.length === 0 || v.length > MAX_STRUCTURED_TOKEN) {
      throw new EvidenceNormalizeError(
        "STRUCTURED_TOKEN",
        `Invalid token in ${field}.`,
      );
    }
    // Never accept command-like tokens into structured arrays.
    if (/[;|&`$<>]/.test(v)) {
      throw new EvidenceNormalizeError(
        "STRUCTURED_TOKEN",
        `Structured token rejected in ${field}.`,
      );
    }
    out.push(v);
  }
  return out;
}

export function normalizeStructured(
  raw: Partial<OfficialStructuredPayload> | undefined,
): OfficialStructuredPayload {
  const r = raw ?? {};
  return {
    config_keys: asStringArray(r.config_keys, MAX_STRUCTURED_KEYS, "config_keys"),
    component_ids: asStringArray(
      r.component_ids,
      MAX_STRUCTURED_KEYS,
      "component_ids",
    ),
    surfaces: asStringArray(r.surfaces, MAX_STRUCTURED_KEYS, "surfaces"),
    artifact_aliases: asStringArray(
      r.artifact_aliases,
      MAX_STRUCTURED_KEYS,
      "artifact_aliases",
    ),
    platforms: asStringArray(r.platforms, MAX_STRUCTURED_KEYS, "platforms"),
    summary_tokens: asStringArray(
      r.summary_tokens,
      MAX_SUMMARY_TOKENS,
      "summary_tokens",
    ),
    has_registered_mapper:
      typeof r.has_registered_mapper === "boolean"
        ? r.has_registered_mapper
        : Boolean(
            (r.config_keys && r.config_keys.length) ||
              (r.component_ids && r.component_ids.length) ||
              (r.surfaces && r.surfaces.length) ||
              (r.artifact_aliases && r.artifact_aliases.length),
          ),
  };
}

function normalizeVersionRange(raw: VersionRange | undefined): VersionRange {
  if (!raw || typeof raw !== "object") {
    return { from: null, to: null };
  }
  const from =
    raw.from === null || raw.from === undefined
      ? null
      : typeof raw.from === "string" && raw.from.length <= 64
        ? raw.from
        : null;
  const to =
    raw.to === null || raw.to === undefined
      ? null
      : typeof raw.to === "string" && raw.to.length <= 64
        ? raw.to
        : null;
  return { from, to };
}

function normalizeMaintainerStatus(
  raw: MaintainerStatus | undefined,
  kind: string,
): MaintainerStatus {
  const allowed = new Set([
    "official",
    "maintainer",
    "user_reported",
    "community",
    "unknown",
  ]);
  if (raw && allowed.has(raw)) return raw;
  // Issues/PRs default to user_reported; releases/tags/docs/commits default official.
  if (kind === "issue" || kind === "pr") return "user_reported";
  if (
    kind === "release" ||
    kind === "tag" ||
    kind === "doc" ||
    kind === "commit" ||
    kind === "diff"
  ) {
    return "official";
  }
  return "unknown";
}

export function normalizeRawItem(
  raw: RawOfficialTransportItem,
  ctx: {
    snapshot_id: string;
    fetched_at: string;
    evidence_state: EvidenceState;
    index: number;
  },
): OfficialEvidenceItem {
  let kind;
  let canonical_url: string;
  let origin: string;
  try {
    kind = assertEvidenceKind(raw.kind);
    ({ canonical_url, origin } = assertOfficialUrl(raw.canonical_url));
  } catch (e) {
    if (e instanceof AllowlistError) {
      throw new EvidenceNormalizeError(e.code, e.message);
    }
    throw e;
  }
  // Never trust serialized origin; reject mismatches against derived origin.
  if (typeof raw.origin === "string" && raw.origin.replace(/\/$/, "") !== origin) {
    throw new EvidenceNormalizeError(
      "ORIGIN_MISMATCH",
      "Serialized origin does not match derived canonical origin.",
    );
  }

  const titleQ = quarantineProse(raw.title ?? "", "title");
  const bodyQ = quarantineProse(raw.body ?? "", "body");
  const contentQ = quarantineProse(raw.content ?? "", "content");
  const quarantine = mergeQuarantine(
    titleQ.quarantine,
    bodyQ.quarantine,
    contentQ.quarantine,
  );
  const structured = normalizeStructured(raw.structured);
  const version_range = normalizeVersionRange(raw.version_range);
  const maintainer_status = normalizeMaintainerStatus(raw.maintainer_status, kind);
  const title = titleQ.safe_text || `${kind}:${canonical_url}`;

  const content_sha256 = computeItemContentSha256({
    kind,
    canonical_url,
    origin,
    title,
    structured,
    version_range,
    maintainer_status,
    evidence_state: ctx.evidence_state,
    quarantine,
  });
  const evidence_id = `ev_${kind}_${content_sha256.slice(0, 12)}_${ctx.index}`;

  return {
    schema_version: 1,
    evidence_id,
    kind,
    canonical_url,
    origin,
    fetched_at: ctx.fetched_at,
    version_range,
    evidence_state: ctx.evidence_state,
    content_sha256,
    snapshot_id: ctx.snapshot_id,
    title,
    structured,
    maintainer_status,
    quarantine,
  };
}

export function normalizeRawItems(
  items: RawOfficialTransportItem[],
  ctx: {
    snapshot_id: string;
    fetched_at: string;
    evidence_state: EvidenceState;
  },
): OfficialEvidenceItem[] {
  if (items.length > MAX_EVIDENCE_ITEMS) {
    throw new EvidenceNormalizeError(
      "ITEM_LIMIT",
      "Evidence item count exceeds bound.",
    );
  }
  return items.map((item, index) =>
    normalizeRawItem(item, { ...ctx, index }),
  );
}
