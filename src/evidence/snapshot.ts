import fs from "node:fs";
import path from "node:path";
import { findRepoRoot } from "../paths.js";
import {
  assertEvidenceKind,
  assertOfficialUrl,
  assertOriginAllowlist,
  AllowlistError,
} from "./allowlist.js";
import { canonicalStringify } from "./canonical.js";
import {
  computeItemContentSha256,
  computeSnapshotContentSha256,
} from "./item-hash.js";
import { MAX_EVIDENCE_ITEMS, MAX_SNAPSHOT_BYTES, OFFICIAL_ORIGINS } from "./limits.js";
import { normalizeStructured } from "./normalize.js";
import type {
  EvidenceState,
  MaintainerStatus,
  OfficialEvidenceItem,
  OfficialEvidenceSnapshot,
  OfficialStructuredPayload,
  QuarantineRecord,
  VersionRange,
} from "./types.js";

export class SnapshotError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "SnapshotError";
    this.code = code;
  }
}

function isIsoDate(s: string): boolean {
  return (
    typeof s === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(s) &&
    !Number.isNaN(Date.parse(s))
  );
}

function parseVersionRange(raw: unknown): VersionRange {
  if (!raw || typeof raw !== "object") return { from: null, to: null };
  const o = raw as Record<string, unknown>;
  return {
    from: typeof o.from === "string" ? o.from : null,
    to: typeof o.to === "string" ? o.to : null,
  };
}

function parseQuarantine(raw: unknown): QuarantineRecord | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (o.quarantined !== true) return null;
  if (typeof o.reason !== "string" || typeof o.original_sha256 !== "string") {
    throw new SnapshotError("QUARANTINE_SHAPE", "Invalid quarantine record.");
  }
  if (!/^[a-f0-9]{64}$/.test(o.original_sha256)) {
    throw new SnapshotError("QUARANTINE_HASH", "Invalid quarantine hash.");
  }
  return {
    quarantined: true,
    reason: o.reason,
    original_sha256: o.original_sha256,
    placeholder:
      typeof o.placeholder === "string"
        ? o.placeholder
        : `<quarantined:unknown:${o.reason}>`,
  };
}

function parseItem(raw: unknown, snapshot_id: string): OfficialEvidenceItem {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SnapshotError("ITEM_SHAPE", "Invalid evidence item.");
  }
  const o = raw as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new SnapshotError("ITEM_SCHEMA", "Unsupported evidence item schema.");
  }
  let kind;
  let canonical_url: string;
  let derived_origin: string;
  try {
    kind = assertEvidenceKind(String(o.kind ?? ""));
    ({ canonical_url, origin: derived_origin } = assertOfficialUrl(
      String(o.canonical_url ?? ""),
    ));
  } catch (e) {
    if (e instanceof AllowlistError) {
      throw new SnapshotError(e.code, e.message);
    }
    throw e;
  }
  // Never trust serialized origin — derive from URL; reject mismatches.
  if (typeof o.origin === "string") {
    const declared = o.origin.replace(/\/$/, "");
    if (declared !== derived_origin) {
      throw new SnapshotError(
        "ORIGIN_MISMATCH",
        "Item origin does not match derived canonical origin.",
      );
    }
  }
  if (typeof o.evidence_id !== "string" || o.evidence_id.length === 0) {
    throw new SnapshotError("ITEM_ID", "Missing evidence_id.");
  }
  if (typeof o.fetched_at !== "string" || !isIsoDate(o.fetched_at)) {
    throw new SnapshotError("ITEM_FETCHED_AT", "Invalid item fetched_at.");
  }
  if (
    typeof o.content_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(o.content_sha256)
  ) {
    throw new SnapshotError("ITEM_HASH", "Invalid or missing content_sha256.");
  }
  const states = new Set(["fresh", "stale", "snapshot", "unavailable"]);
  if (typeof o.evidence_state !== "string" || !states.has(o.evidence_state)) {
    throw new SnapshotError("ITEM_STATE", "Invalid evidence_state.");
  }
  const maintainerStatuses = new Set([
    "official",
    "maintainer",
    "user_reported",
    "community",
    "unknown",
  ]);
  const maintainer_status = (
    typeof o.maintainer_status === "string" &&
    maintainerStatuses.has(o.maintainer_status)
      ? o.maintainer_status
      : "unknown"
  ) as MaintainerStatus;

  const structured = normalizeStructured(
    o.structured as Partial<OfficialStructuredPayload> | undefined,
  );
  const title = typeof o.title === "string" ? o.title : `${kind}`;
  const item_snapshot_id =
    typeof o.snapshot_id === "string" && o.snapshot_id.length > 0
      ? o.snapshot_id
      : snapshot_id;
  const version_range = parseVersionRange(o.version_range);
  const quarantine = parseQuarantine(o.quarantine);
  const evidence_state = o.evidence_state as EvidenceState;
  const origin = derived_origin;

  const expectedHash = computeItemContentSha256({
    kind,
    canonical_url,
    origin,
    title,
    structured,
    version_range,
    maintainer_status,
    evidence_state,
    quarantine,
  });
  if (o.content_sha256 !== expectedHash) {
    throw new SnapshotError(
      "ITEM_HASH_MISMATCH",
      "Item content_sha256 does not match canonical persisted material.",
    );
  }

  return {
    schema_version: 1,
    evidence_id: o.evidence_id,
    kind,
    canonical_url,
    origin,
    fetched_at: o.fetched_at,
    version_range,
    evidence_state,
    content_sha256: o.content_sha256,
    snapshot_id: item_snapshot_id,
    title,
    structured,
    maintainer_status,
    quarantine,
  };
}

/**
 * Parse and validate a snapshot object. Fail closed on missing, malformed,
 * or mismatched content_sha256 (snapshot and items). Never silently recompute.
 */
export function parseSnapshotJson(text: string): OfficialEvidenceSnapshot {
  if (Buffer.byteLength(text, "utf8") > MAX_SNAPSHOT_BYTES) {
    throw new SnapshotError("SIZE_LIMIT", "Snapshot exceeds size limit.");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new SnapshotError("MALFORMED_JSON", "Malformed snapshot JSON.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SnapshotError("SHAPE", "Invalid snapshot root.");
  }
  const o = raw as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new SnapshotError("SCHEMA", "Unsupported snapshot schema.");
  }
  if (typeof o.snapshot_id !== "string" || o.snapshot_id.length === 0) {
    throw new SnapshotError("SNAPSHOT_ID", "Missing snapshot_id.");
  }
  if (typeof o.fetched_at !== "string" || !isIsoDate(o.fetched_at)) {
    throw new SnapshotError("FETCHED_AT", "Invalid snapshot fetched_at.");
  }
  if (
    typeof o.content_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(o.content_sha256)
  ) {
    throw new SnapshotError(
      "SNAPSHOT_HASH",
      "Missing or malformed snapshot content_sha256.",
    );
  }
  if (!Array.isArray(o.items)) {
    throw new SnapshotError("ITEMS", "Snapshot items must be an array.");
  }
  if (o.items.length > MAX_EVIDENCE_ITEMS) {
    throw new SnapshotError("ITEM_LIMIT", "Snapshot item count exceeds bound.");
  }

  let origin_allowlist: string[];
  try {
    origin_allowlist = assertOriginAllowlist(o.origin_allowlist);
  } catch (e) {
    if (e instanceof AllowlistError) {
      throw new SnapshotError(e.code, e.message);
    }
    throw e;
  }

  const items = o.items.map((it) => parseItem(it, o.snapshot_id as string));
  const expected = computeSnapshotContentSha256({
    schema_version: 1,
    snapshot_id: o.snapshot_id as string,
    fetched_at: o.fetched_at as string,
    origin_allowlist,
    items,
  });
  if (o.content_sha256 !== expected) {
    throw new SnapshotError(
      "SNAPSHOT_HASH_MISMATCH",
      "Snapshot content_sha256 does not match canonical persisted material.",
    );
  }

  const snapshot: OfficialEvidenceSnapshot = {
    schema_version: 1,
    snapshot_id: o.snapshot_id as string,
    fetched_at: o.fetched_at as string,
    origin_allowlist,
    items,
    content_sha256: o.content_sha256,
    immutable: true,
  };
  return deepFreeze(snapshot);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    Object.freeze(value);
    for (const v of Object.values(value as object)) {
      if (v && typeof v === "object" && !Object.isFrozen(v)) {
        deepFreeze(v);
      }
    }
  }
  return value;
}

export function buildSnapshotFromItems(
  items: OfficialEvidenceItem[],
  opts: { snapshot_id: string; fetched_at: string },
): OfficialEvidenceSnapshot {
  const origin_allowlist = [...OFFICIAL_ORIGINS];
  // Re-verify each item hash against canonical material (fail closed).
  for (const it of items) {
    const expected = computeItemContentSha256(it);
    if (it.content_sha256 !== expected) {
      throw new SnapshotError(
        "ITEM_HASH_MISMATCH",
        "Item content_sha256 does not match canonical material during build.",
      );
    }
  }
  const content_sha256 = computeSnapshotContentSha256({
    schema_version: 1,
    snapshot_id: opts.snapshot_id,
    fetched_at: opts.fetched_at,
    origin_allowlist,
    items,
  });
  return deepFreeze({
    schema_version: 1 as const,
    snapshot_id: opts.snapshot_id,
    fetched_at: opts.fetched_at,
    origin_allowlist,
    items,
    content_sha256,
    immutable: true as const,
  });
}

export function defaultBundledSnapshotPath(fromUrl: string = import.meta.url): string {
  const root = findRepoRoot(fromUrl);
  return path.join(root, "fixtures", "official-evidence", "snapshot.json");
}

export function loadBundledSnapshot(
  snapshotPath?: string,
): OfficialEvidenceSnapshot {
  const p = snapshotPath ?? defaultBundledSnapshotPath();
  let buf: Buffer;
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) {
      throw new SnapshotError("NOT_FILE", "Snapshot path is not a file.");
    }
    if (st.size > MAX_SNAPSHOT_BYTES) {
      throw new SnapshotError("SIZE_LIMIT", "Snapshot exceeds size limit.");
    }
    buf = fs.readFileSync(p);
  } catch (e) {
    if (e instanceof SnapshotError) throw e;
    throw new SnapshotError("READ_FAILED", "Snapshot read failed.");
  }
  return parseSnapshotJson(buf.toString("utf8"));
}

/** Relabel evidence_state on a copy of a snapshot (returns new immutable snapshot). */
export function relabelSnapshotState(
  snapshot: OfficialEvidenceSnapshot,
  evidence_state: EvidenceState,
  snapshot_id?: string,
): OfficialEvidenceSnapshot {
  const id = snapshot_id ?? snapshot.snapshot_id;
  const items = snapshot.items.map((it) => {
    const next = {
      ...it,
      evidence_state,
      snapshot_id: id,
    };
    return {
      ...next,
      content_sha256: computeItemContentSha256(next),
    };
  });
  return buildSnapshotFromItems(items, {
    snapshot_id: id,
    fetched_at: snapshot.fetched_at,
  });
}

export function snapshotFingerprint(snapshot: OfficialEvidenceSnapshot): string {
  return snapshot.content_sha256;
}

export function snapshotCanonicalBytes(snapshot: OfficialEvidenceSnapshot): string {
  return canonicalStringify(snapshot);
}
