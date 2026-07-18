/**
 * Version-fingerprint persistent state: versioned JSON, atomic write,
 * strict schema/size/no-symlink handling. No daemon, telemetry, or network.
 */
import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";
import {
  MAX_INSTANCES,
  MAX_STATE_BYTES,
  MAX_STRING,
  STATE_FILE_NAME,
  STATE_SCHEMA_VERSION,
} from "./limits.js";
import type {
  InstallSource,
  InstanceIdentity,
  InstanceSurface,
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
  ]);
  for (const k of Object.keys(o)) {
    if (!topAllowed.has(k)) throw new StateError("SCHEMA", "Extra state field.");
  }
  if (o.schema_version !== STATE_SCHEMA_VERSION) {
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
  return {
    schema_version: 1,
    updated_at: o.updated_at,
    overall_fingerprint: o.overall_fingerprint,
    instances: o.instances.map(parseIdentity),
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
 * State is ChangeGuard-owned metadata only (not a diagnosis target).
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
