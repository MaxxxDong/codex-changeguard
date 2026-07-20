/**
 * Version-fingerprint persistent state: versioned JSON, atomic write,
 * strict schema/size/no-symlink handling. No daemon, telemetry, or network.
 *
 * Schema v2 adds path-free artifact baselines. Load remains backward-readable
 * from v1 (empty baselines; never invents historical artifact rows). Writes
 * always persist schema_version 2.
 */
import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";
import {
  artifactBaselineDigest,
  overallArtifactDigest,
} from "./artifacts.js";
import {
  MAX_ARTIFACT_ENTRIES_PER_INSTANCE,
  MAX_ARTIFACT_KEY_LEN,
  MAX_INSTANCES,
  MAX_STATE_BYTES,
  MAX_STRING,
  STATE_FILE_NAME,
  STATE_SCHEMA_VERSION,
  STATE_SCHEMA_VERSION_V1,
} from "./limits.js";
import type {
  ArtifactKind,
  ArtifactReadStatus,
  InstallSource,
  InstanceArtifactBaseline,
  InstanceIdentity,
  InstanceSurface,
  LocalArtifactEntry,
  PlatformId,
  VersionFingerprintState,
  VersionProvenance,
} from "./types.js";

export class StateError extends Error {
  readonly code: string;
  constructor(code: string, message = "State error.") {
    super(message);
    this.name = "StateError";
    this.code = code;
  }
}

function openReadFlags(): number {
  const base = fsConstants.O_RDONLY;
  const nofollow =
    "O_NOFOLLOW" in fsConstants
      ? (fsConstants as NodeJS.Dict<number>).O_NOFOLLOW
      : undefined;
  if (typeof nofollow === "number") return base | nofollow;
  return base;
}

export function stateFilePath(stateDir: string): string {
  return path.join(stateDir, STATE_FILE_NAME);
}

function assertNoSymlinkPath(abs: string): fs.Stats {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(abs);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === "ENOENT") {
      throw new StateError("NOT_FOUND", "State not found.");
    }
    throw new StateError("STATE_IO", "State path refused.");
  }
  if (st.isSymbolicLink()) {
    throw new StateError("SYMLINK_REFUSED", "Symlink state refused.");
  }
  return st;
}

function readBoundedFile(abs: string, maxBytes: number): string {
  const st = assertNoSymlinkPath(abs);
  if (!st.isFile()) throw new StateError("INVALID_STATE", "State refused.");
  if (st.size > maxBytes) throw new StateError("SIZE_LIMIT", "State too large.");
  let fd: number;
  try {
    fd = fs.openSync(abs, openReadFlags());
  } catch {
    throw new StateError("STATE_IO", "State read failed.");
  }
  try {
    const fst = fs.fstatSync(fd);
    if (!fst.isFile() || fst.size > maxBytes) {
      throw new StateError("SIZE_LIMIT", "State refused.");
    }
    const buf = Buffer.alloc(fst.size);
    let offset = 0;
    while (offset < fst.size) {
      const n = fs.readSync(fd, buf, offset, fst.size - offset, offset);
      if (n === 0) break;
      offset += n;
    }
    return buf.subarray(0, offset).toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

const SOURCES = new Set([
  "desktop_bundled",
  "path",
  "package_manager",
  "windows_msix",
  "wsl",
  "unknown",
]);
const SURFACES = new Set(["desktop", "cli", "unknown"]);
const PLATFORMS = new Set(["macos", "windows", "linux", "wsl", "unknown"]);
const PROVENANCES = new Set([
  "package_json",
  "plist_metadata",
  "msix_manifest",
  "version_file",
  "fixture_declared",
  "unavailable",
]);
const ARTIFACT_KINDS = new Set([
  "executable",
  "plist",
  "asar",
  "code_resources",
  "manifest",
  "metadata",
  "other",
]);
const ARTIFACT_STATUSES = new Set([
  "read_ok",
  "missing",
  "symlink_refused",
  "out_of_root",
  "oversize",
  "not_file",
  "io_error",
  "time_budget_exceeded",
]);

function parseIdentity(raw: unknown): InstanceIdentity {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new StateError("SCHEMA", "Invalid instance in state.");
  }
  const o = raw as Record<string, unknown>;
  const str = (k: string): string => {
    const v = o[k];
    if (typeof v !== "string" || v.length === 0 || v.length > MAX_STRING) {
      throw new StateError("SCHEMA", `Invalid ${k}.`);
    }
    return v;
  };
  const nullStr = (k: string): string | null => {
    const v = o[k];
    if (v === null) return null;
    if (typeof v !== "string" || v.length > MAX_STRING) {
      throw new StateError("SCHEMA", `Invalid ${k}.`);
    }
    return v;
  };
  const install_source = str("install_source");
  const surface = str("surface");
  const platform = str("platform");
  const version_provenance = str("version_provenance");
  if (!SOURCES.has(install_source)) throw new StateError("SCHEMA", "Bad source.");
  if (!SURFACES.has(surface)) throw new StateError("SCHEMA", "Bad surface.");
  if (!PLATFORMS.has(platform)) throw new StateError("SCHEMA", "Bad platform.");
  if (!PROVENANCES.has(version_provenance)) {
    throw new StateError("SCHEMA", "Bad provenance.");
  }
  let path_precedence: number | null = null;
  if (o.path_precedence !== null && o.path_precedence !== undefined) {
    if (
      typeof o.path_precedence !== "number" ||
      !Number.isInteger(o.path_precedence) ||
      o.path_precedence < 0
    ) {
      throw new StateError("SCHEMA", "Bad path_precedence.");
    }
    path_precedence = o.path_precedence;
  }
  // Reject unknown keys on instance objects.
  const allowed = new Set([
    "instance_id",
    "path_hash",
    "path_alias",
    "surface",
    "install_source",
    "platform",
    "arch",
    "profile_root_alias",
    "config_root_alias",
    "version",
    "build",
    "version_provenance",
    "path_precedence",
    "runtime_domain",
  ]);
  for (const k of Object.keys(o)) {
    if (!allowed.has(k)) throw new StateError("SCHEMA", "Extra state field.");
  }
  let runtime_domain: string | null | undefined = undefined;
  if (o.runtime_domain !== undefined) {
    if (o.runtime_domain === null) {
      runtime_domain = null;
    } else if (
      typeof o.runtime_domain === "string" &&
      o.runtime_domain.length > 0 &&
      o.runtime_domain.length <= MAX_STRING
    ) {
      runtime_domain = o.runtime_domain;
    } else {
      throw new StateError("SCHEMA", "Invalid runtime_domain.");
    }
  }
  return {
    instance_id: str("instance_id"),
    path_hash: str("path_hash"),
    path_alias: str("path_alias"),
    surface: surface as InstanceSurface,
    install_source: install_source as InstallSource,
    platform: platform as PlatformId,
    arch: str("arch"),
    profile_root_alias: nullStr("profile_root_alias"),
    config_root_alias: nullStr("config_root_alias"),
    version: nullStr("version"),
    build: nullStr("build"),
    version_provenance: version_provenance as VersionProvenance,
    path_precedence,
    ...(runtime_domain !== undefined ? { runtime_domain } : {}),
  };
}

function parseArtifactEntry(raw: unknown): LocalArtifactEntry {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new StateError("SCHEMA", "Invalid artifact entry.");
  }
  const o = raw as Record<string, unknown>;
  const allowed = new Set([
    "key",
    "alias",
    "kind",
    "sha256",
    "size",
    "status",
  ]);
  for (const k of Object.keys(o)) {
    if (!allowed.has(k)) throw new StateError("SCHEMA", "Extra artifact field.");
  }
  if (
    typeof o.key !== "string" ||
    o.key.length === 0 ||
    o.key.length > MAX_ARTIFACT_KEY_LEN
  ) {
    throw new StateError("SCHEMA", "Invalid artifact key.");
  }
  if (
    typeof o.alias !== "string" ||
    o.alias.length === 0 ||
    o.alias.length > MAX_STRING
  ) {
    throw new StateError("SCHEMA", "Invalid artifact alias.");
  }
  if (typeof o.kind !== "string" || !ARTIFACT_KINDS.has(o.kind)) {
    throw new StateError("SCHEMA", "Invalid artifact kind.");
  }
  if (typeof o.status !== "string" || !ARTIFACT_STATUSES.has(o.status)) {
    throw new StateError("SCHEMA", "Invalid artifact status.");
  }
  let sha256: string | null = null;
  if (o.sha256 === null) {
    sha256 = null;
  } else if (typeof o.sha256 === "string" && /^[a-f0-9]{64}$/.test(o.sha256)) {
    sha256 = o.sha256;
  } else {
    throw new StateError("SCHEMA", "Invalid artifact sha256.");
  }
  let size: number | null = null;
  if (o.size === null) {
    size = null;
  } else if (
    typeof o.size === "number" &&
    Number.isInteger(o.size) &&
    o.size >= 0
  ) {
    size = o.size;
  } else {
    throw new StateError("SCHEMA", "Invalid artifact size.");
  }
  if (o.status === "read_ok") {
    if (sha256 === null || size === null) {
      throw new StateError("SCHEMA", "read_ok requires sha256 and size.");
    }
  } else if (sha256 !== null || size !== null) {
    // Gaps must not carry digests/sizes (no truncated hash material).
    throw new StateError("SCHEMA", "Gap entries must not carry digests.");
  }
  return {
    key: o.key,
    alias: o.alias,
    kind: o.kind as ArtifactKind,
    sha256,
    size,
    status: o.status as ArtifactReadStatus,
  };
}

function parseArtifactBaseline(raw: unknown): InstanceArtifactBaseline {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new StateError("SCHEMA", "Invalid artifact baseline.");
  }
  const o = raw as Record<string, unknown>;
  const allowed = new Set([
    "instance_id",
    "path_hash",
    "path_alias",
    "entries",
    "baseline_digest",
  ]);
  for (const k of Object.keys(o)) {
    if (!allowed.has(k)) {
      throw new StateError("SCHEMA", "Extra baseline field.");
    }
  }
  if (
    typeof o.instance_id !== "string" ||
    o.instance_id.length === 0 ||
    o.instance_id.length > MAX_STRING
  ) {
    throw new StateError("SCHEMA", "Invalid baseline instance_id.");
  }
  if (typeof o.path_hash !== "string" || !/^[a-f0-9]{64}$/.test(o.path_hash)) {
    throw new StateError("SCHEMA", "Invalid baseline path_hash.");
  }
  if (
    typeof o.path_alias !== "string" ||
    o.path_alias.length === 0 ||
    o.path_alias.length > MAX_STRING
  ) {
    throw new StateError("SCHEMA", "Invalid baseline path_alias.");
  }
  if (
    typeof o.baseline_digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(o.baseline_digest)
  ) {
    throw new StateError("SCHEMA", "Invalid baseline_digest.");
  }
  if (
    !Array.isArray(o.entries) ||
    o.entries.length > MAX_ARTIFACT_ENTRIES_PER_INSTANCE
  ) {
    throw new StateError("SCHEMA", "Invalid baseline entries.");
  }
  const entries = o.entries.map(parseArtifactEntry);
  // Fail closed: stored baseline_digest must match entries (no silent normalize).
  const recomputed = artifactBaselineDigest(entries);
  if (o.baseline_digest !== recomputed) {
    throw new StateError("SCHEMA", "baseline_digest does not match entries.");
  }
  return {
    instance_id: o.instance_id,
    path_hash: o.path_hash,
    path_alias: o.path_alias,
    entries,
    baseline_digest: recomputed,
  };
}

/**
 * Enforce exact one-to-one baseline ↔ instance binding and overall digest integrity.
 * Fail closed on duplicates, missing/extra baselines, or binding mismatches.
 * Digest material is owned by artifacts.ts (single source of truth).
 */
function validateV2ArtifactBindings(
  instances: InstanceIdentity[],
  baselines: InstanceArtifactBaseline[],
  overall_artifact_digest: string | null,
): string | null {
  if (baselines.length !== instances.length) {
    throw new StateError(
      "SCHEMA",
      "artifact_baselines must map 1:1 to instances.",
    );
  }
  const seenIds = new Set<string>();
  const byId = new Map(instances.map((i) => [i.instance_id, i]));
  if (byId.size !== instances.length) {
    throw new StateError("SCHEMA", "Duplicate instance_id in state.");
  }
  for (const b of baselines) {
    if (seenIds.has(b.instance_id)) {
      throw new StateError("SCHEMA", "Duplicate artifact baseline instance_id.");
    }
    seenIds.add(b.instance_id);
    const inst = byId.get(b.instance_id);
    if (!inst) {
      throw new StateError("SCHEMA", "Orphan artifact baseline instance_id.");
    }
    if (b.path_hash !== inst.path_hash || b.path_alias !== inst.path_alias) {
      throw new StateError(
        "SCHEMA",
        "Artifact baseline binding mismatch.",
      );
    }
  }
  if (baselines.length === 0) {
    // Empty v2 baselines: overall may be null (pre-measure) or the empty digest.
    if (overall_artifact_digest === null) return null;
    const empty = overallArtifactDigest([]);
    if (overall_artifact_digest !== empty) {
      throw new StateError(
        "SCHEMA",
        "overall_artifact_digest does not match baselines.",
      );
    }
    return overall_artifact_digest;
  }
  // Nonempty baselines require an exact overall digest string (never null).
  if (
    typeof overall_artifact_digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(overall_artifact_digest)
  ) {
    throw new StateError("SCHEMA", "Invalid overall_artifact_digest.");
  }
  const recomputed = overallArtifactDigest(baselines);
  if (overall_artifact_digest !== recomputed) {
    throw new StateError(
      "SCHEMA",
      "overall_artifact_digest does not match baselines.",
    );
  }
  return overall_artifact_digest;
}

export function parseStateJson(text: string): VersionFingerprintState {
  if (Buffer.byteLength(text, "utf8") > MAX_STATE_BYTES) {
    throw new StateError("SIZE_LIMIT", "State too large.");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new StateError("SCHEMA", "State JSON invalid.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new StateError("SCHEMA", "State JSON invalid.");
  }
  const o = raw as Record<string, unknown>;
  const topAllowed = new Set([
    "schema_version",
    "updated_at",
    "overall_fingerprint",
    "instances",
    "artifact_baselines",
    "overall_artifact_digest",
  ]);
  for (const k of Object.keys(o)) {
    if (!topAllowed.has(k)) throw new StateError("SCHEMA", "Extra state field.");
  }
  if (
    o.schema_version !== STATE_SCHEMA_VERSION_V1 &&
    o.schema_version !== STATE_SCHEMA_VERSION
  ) {
    throw new StateError("SCHEMA", "Unsupported state schema.");
  }
  if (typeof o.updated_at !== "string" || o.updated_at.length > 64) {
    throw new StateError("SCHEMA", "Invalid updated_at.");
  }
  if (
    typeof o.overall_fingerprint !== "string" ||
    !/^[a-f0-9]{64}$/.test(o.overall_fingerprint)
  ) {
    throw new StateError("SCHEMA", "Invalid overall_fingerprint.");
  }
  if (!Array.isArray(o.instances) || o.instances.length > MAX_INSTANCES) {
    throw new StateError("SCHEMA", "Invalid instances.");
  }

  // v1: never invent historical artifact entries.
  if (o.schema_version === STATE_SCHEMA_VERSION_V1) {
    if (o.artifact_baselines !== undefined || o.overall_artifact_digest !== undefined) {
      throw new StateError("SCHEMA", "v1 state must not carry artifact fields.");
    }
    return {
      schema_version: 1,
      updated_at: o.updated_at,
      overall_fingerprint: o.overall_fingerprint,
      instances: o.instances.map(parseIdentity),
      artifact_baselines: [],
      overall_artifact_digest: null,
    };
  }

  // v2
  if (!Array.isArray(o.artifact_baselines) || o.artifact_baselines.length > MAX_INSTANCES) {
    throw new StateError("SCHEMA", "Invalid artifact_baselines.");
  }
  let overall_artifact_digest: string | null = null;
  if (o.overall_artifact_digest === null) {
    overall_artifact_digest = null;
  } else if (
    typeof o.overall_artifact_digest === "string" &&
    /^[a-f0-9]{64}$/.test(o.overall_artifact_digest)
  ) {
    overall_artifact_digest = o.overall_artifact_digest;
  } else if (o.overall_artifact_digest === undefined) {
    // Field is required on the JSON schema for v2; refuse silent omission.
    throw new StateError("SCHEMA", "Invalid overall_artifact_digest.");
  } else {
    throw new StateError("SCHEMA", "Invalid overall_artifact_digest.");
  }
  const instances = o.instances.map(parseIdentity);
  const artifact_baselines = o.artifact_baselines.map(parseArtifactBaseline);
  const validatedOverall = validateV2ArtifactBindings(
    instances,
    artifact_baselines,
    overall_artifact_digest,
  );
  return {
    schema_version: 2,
    updated_at: o.updated_at,
    overall_fingerprint: o.overall_fingerprint,
    instances,
    artifact_baselines,
    overall_artifact_digest: validatedOverall,
  };
}

/** Load prior state or return null when missing (first baseline). */
export function loadState(stateDir: string): VersionFingerprintState | null {
  const file = stateFilePath(stateDir);
  try {
    assertNoSymlinkPath(stateDir);
  } catch (e) {
    if (e instanceof StateError && e.code === "NOT_FOUND") return null;
    throw e;
  }
  const dirStat = fs.lstatSync(stateDir);
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new StateError("INVALID_STATE", "State dir refused.");
  }
  if (!fs.existsSync(file)) return null;
  const text = readBoundedFile(file, MAX_STATE_BYTES);
  return parseStateJson(text);
}

/**
 * Atomic safe write: temp sibling + rename. Refuses symlink state paths.
 * Always persists schema_version 2 (v1 is read-only migration input).
 */
export function saveState(
  stateDir: string,
  state: VersionFingerprintState,
): void {
  if (state.schema_version !== STATE_SCHEMA_VERSION) {
    throw new StateError("SCHEMA", "Unsupported state schema.");
  }
  const text = JSON.stringify(state, null, 2) + "\n";
  if (Buffer.byteLength(text, "utf8") > MAX_STATE_BYTES) {
    throw new StateError("SIZE_LIMIT", "State too large.");
  }
  // Ensure directory exists (not a symlink).
  if (fs.existsSync(stateDir)) {
    const st = fs.lstatSync(stateDir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new StateError("INVALID_STATE", "State dir refused.");
    }
  } else {
    fs.mkdirSync(stateDir, { recursive: true });
    const st = fs.lstatSync(stateDir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new StateError("INVALID_STATE", "State dir refused.");
    }
  }

  const dest = stateFilePath(stateDir);
  if (fs.existsSync(dest)) {
    const existing = fs.lstatSync(dest);
    if (existing.isSymbolicLink()) {
      throw new StateError("SYMLINK_REFUSED", "Symlink state refused.");
    }
  }
  const tmp = path.join(
    stateDir,
    `.${STATE_FILE_NAME}.tmp.${process.pid}.${Date.now()}`,
  );
  try {
    fs.writeFileSync(tmp, text, { encoding: "utf8", flag: "wx" });
    // Refuse replacing through a symlink dest (already checked); atomic replace.
    fs.renameSync(tmp, dest);
  } catch (e) {
    try {
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    } catch {
      /* ignore cleanup */
    }
    if (e instanceof StateError) throw e;
    throw new StateError("STATE_IO", "State write failed.");
  }
  // Post-condition: dest must not be a symlink.
  const finalStat = fs.lstatSync(dest);
  if (finalStat.isSymbolicLink()) {
    throw new StateError("SYMLINK_REFUSED", "Symlink state refused.");
  }
}

/**
 * True when prior state has no usable artifact baseline history.
 * v1 migration and first-ever scan both yield this.
 */
export function priorArtifactBaselinesOrNull(
  previous: VersionFingerprintState | null,
): InstanceArtifactBaseline[] | null {
  if (previous === null) return null;
  if (previous.schema_version === 1) return null;
  return previous.artifact_baselines;
}
