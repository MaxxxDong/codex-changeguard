/**
 * Narrow atomic write + backup helpers for registered recovery only.
 * Mutation is allowed only under an already-validated isolated target root.
 * No shell, network, recursive delete, or out-of-root paths.
 */
import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";
import { PathSafetyError } from "../path-safety.js";
import { sha256Buffer } from "../measure.js";
import { digestObject, receiptId } from "./canonical.js";

export interface FileIdentity {
  abs: string;
  size: number;
  ino: number;
  dev: number;
  mode: number;
  mtimeMs: number;
  sha256: string;
  bytes: Buffer;
}

/**
 * Open a regular non-symlink file under targetReal for reading with TOCTOU checks.
 * Re-validates each path segment (no intermediate or leaf symlinks).
 */
export function openTargetFile(
  targetReal: string,
  relativeName: string,
  maxBytes: number,
): FileIdentity {
  const abs = resolveUnderRoot(targetReal, relativeName);
  assertNoSymlinkSegments(targetReal, abs);
  let pre: fs.Stats;
  try {
    pre = fs.lstatSync(abs);
  } catch {
    throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
  }
  if (pre.isSymbolicLink()) {
    throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
  }
  if (!pre.isFile()) {
    throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
  }
  if (pre.size > maxBytes) {
    throw new PathSafetyError("SIZE_LIMIT", "File exceeds size limit.");
  }

  const flags = openReadNoFollowFlags();
  let fd: number;
  try {
    fd = fs.openSync(abs, flags);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && (err.code === "ELOOP" || err.code === "EMLINK")) {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
    throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) {
      throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
    }
    if (st.dev !== pre.dev || st.ino !== pre.ino || st.size !== pre.size) {
      throw new PathSafetyError("TOCTOU", "Path refused.");
    }
    if (st.size > maxBytes) {
      throw new PathSafetyError("SIZE_LIMIT", "File exceeds size limit.");
    }
    const buf = Buffer.alloc(st.size);
    let offset = 0;
    while (offset < st.size) {
      const n = fs.readSync(fd, buf, offset, st.size - offset, offset);
      if (n === 0) break;
      offset += n;
    }
    const bytes = buf.subarray(0, offset);
    return {
      abs,
      size: st.size,
      ino: st.ino,
      dev: st.dev,
      mode: st.mode,
      mtimeMs: st.mtimeMs,
      sha256: sha256Buffer(bytes),
      bytes,
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Write verified backup of original bytes under targetReal/backupRel.
 * Creates parent dirs only within the isolated target.
 */
export function createVerifiedBackup(
  targetReal: string,
  backupRel: string,
  original: FileIdentity,
): { backupAbs: string; verified: boolean; receipt_id: string; original_sha256: string } {
  const backupAbs = resolveUnderRoot(targetReal, backupRel);
  ensureParentDir(targetReal, backupAbs);
  // Refuse if backup path already exists as a symlink.
  try {
    const existing = fs.lstatSync(backupAbs);
    if (existing.isSymbolicLink()) {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
  } catch (e) {
    if (!(e instanceof PathSafetyError) && (e as NodeJS.ErrnoException).code !== "ENOENT") {
      throw new PathSafetyError("BACKUP_ERROR", "Backup path refused.");
    }
    if (e instanceof PathSafetyError) throw e;
  }

  writeAtomicFile(backupAbs, original.bytes, original.mode);
  const verify = fs.readFileSync(backupAbs);
  const verifyHash = sha256Buffer(verify);
  if (verifyHash !== original.sha256) {
    throw new PathSafetyError("BACKUP_MISMATCH", "Backup verification failed.");
  }
  const metaRel = `${backupRel}.meta.json`;
  const metaAbs = resolveUnderRoot(targetReal, metaRel);
  const meta = {
    schema_version: 1,
    original_sha256: original.sha256,
    size: original.size,
    mode: original.mode,
    created_receipt: receiptId("backup"),
  };
  writeAtomicFile(metaAbs, Buffer.from(`${JSON.stringify(meta, null, 2)}\n`, "utf8"), 0o644);
  return {
    backupAbs,
    verified: true,
    receipt_id: meta.created_receipt,
    original_sha256: original.sha256,
  };
}

/**
 * Atomically replace a regular file under the isolated target with new bytes.
 * Steps: re-check open identity → sibling temp → fsync → rename → verify hash.
 */
export function atomicReplaceFile(
  targetReal: string,
  relativeName: string,
  expected: Pick<FileIdentity, "sha256" | "ino" | "dev" | "size" | "mode">,
  newBytes: Buffer,
  maxBytes: number,
): { resulting_sha256: string; abs: string } {
  if (newBytes.length > maxBytes) {
    throw new PathSafetyError("SIZE_LIMIT", "Replacement exceeds size limit.");
  }
  const abs = resolveUnderRoot(targetReal, relativeName);
  assertNoSymlinkSegments(targetReal, abs);

  // Re-check current target identity (TOCTOU).
  let pre: fs.Stats;
  try {
    pre = fs.lstatSync(abs);
  } catch {
    throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
  }
  if (pre.isSymbolicLink()) {
    throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
  }
  if (!pre.isFile()) {
    throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
  }
  if (pre.dev !== expected.dev || pre.ino !== expected.ino || pre.size !== expected.size) {
    throw new PathSafetyError("TOCTOU", "Path refused.");
  }

  // Sibling temp in the same directory for atomic rename.
  const dir = path.dirname(abs);
  const base = path.basename(abs);
  const tempName = `.${base}.cg-tmp-${process.pid}-${Date.now()}`;
  const tempAbs = path.join(dir, tempName);
  // Ensure temp stays under root.
  const tempRelCheck = path.relative(targetReal, tempAbs);
  if (tempRelCheck.startsWith("..") || path.isAbsolute(tempRelCheck)) {
    throw new PathSafetyError("PATH_ESCAPE", "Temp path refused.");
  }

  try {
    writeAtomicFile(tempAbs, newBytes, expected.mode);
    // Atomic replace (same filesystem rename).
    fs.renameSync(tempAbs, abs);
  } catch (e) {
    try {
      if (fs.existsSync(tempAbs)) fs.unlinkSync(tempAbs);
    } catch {
      /* best-effort temp cleanup */
    }
    if (e instanceof PathSafetyError) throw e;
    throw new PathSafetyError("ATOMIC_REPLACE", "Atomic replace failed.");
  }

  // Verify resulting hash from re-opened path (no follow).
  const after = openTargetFile(targetReal, relativeName, maxBytes);
  const want = sha256Buffer(newBytes);
  if (after.sha256 !== want) {
    throw new PathSafetyError("POST_HASH_MISMATCH", "Result hash mismatch.");
  }
  return { resulting_sha256: after.sha256, abs };
}

/**
 * Restore exact original bytes from a verified backup.
 */
export function restoreFromBackup(
  targetReal: string,
  relativeName: string,
  backupRel: string,
  expectedOriginalSha: string,
  maxBytes: number,
): { resulting_sha256: string } {
  const backup = openTargetFile(targetReal, backupRel, maxBytes);
  if (backup.sha256 !== expectedOriginalSha) {
    throw new PathSafetyError("BACKUP_MISMATCH", "Backup hash mismatch.");
  }
  // Current target may already be mutated — read identity for mode only if present.
  let mode = 0o644;
  const abs = resolveUnderRoot(targetReal, relativeName);
  try {
    const st = fs.lstatSync(abs);
    if (!st.isSymbolicLink() && st.isFile()) {
      mode = st.mode;
    }
  } catch {
    /* create-on-restore not supported for Ticket 02 — target must exist */
    throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
  }
  // Use current ino/dev/size for TOCTOU on the live target.
  const live = openTargetFile(targetReal, relativeName, maxBytes);
  const result = atomicReplaceFile(
    targetReal,
    relativeName,
    {
      sha256: live.sha256,
      ino: live.ino,
      dev: live.dev,
      size: live.size,
      mode: live.mode || mode,
    },
    backup.bytes,
    maxBytes,
  );
  if (result.resulting_sha256 !== expectedOriginalSha) {
    throw new PathSafetyError("ROLLBACK_MISMATCH", "Rollback hash mismatch.");
  }
  return { resulting_sha256: result.resulting_sha256 };
}

export function writeSessionState(
  targetReal: string,
  sessionRel: string,
  state: Record<string, unknown>,
): void {
  const abs = resolveUnderRoot(targetReal, sessionRel);
  ensureParentDir(targetReal, abs);
  const payload = Buffer.from(`${JSON.stringify(state, null, 2)}\n`, "utf8");
  writeAtomicFile(abs, payload, 0o644);
}

export function readSessionState(
  targetReal: string,
  sessionRel: string,
  maxBytes: number,
): Record<string, unknown> | null {
  try {
    const f = openTargetFile(targetReal, sessionRel, maxBytes);
    return JSON.parse(f.bytes.toString("utf8")) as Record<string, unknown>;
  } catch (e) {
    if (e instanceof PathSafetyError && e.code === "CANDIDATE_NOT_FOUND") {
      return null;
    }
    throw e;
  }
}

export function scopeDigestForTarget(targetReal: string): string {
  // Digest of canonical root identity without embedding the path string in outputs
  // that leave the device. Binding uses this digest only.
  let st: fs.Stats;
  try {
    st = fs.lstatSync(targetReal);
  } catch {
    throw new PathSafetyError("TARGET_NOT_FOUND", "Target not found.");
  }
  return digestObject({
    kind: "isolated_target_scope_v1",
    dev: st.dev,
    ino: st.ino,
    // Include realpath length + hash only (not the path itself in capsule fields
    // that are user-visible beyond scope_digest).
    path_sha256: sha256Buffer(Buffer.from(targetReal, "utf8")),
  });
}

// ---- path helpers (recovery-local; mirror diagnosis no-follow policy) ----

function resolveUnderRoot(targetReal: string, relativeName: string): string {
  if (
    typeof relativeName !== "string" ||
    relativeName.length === 0 ||
    path.isAbsolute(relativeName) ||
    relativeName.includes("\0")
  ) {
    throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
  }
  const normalized = path.normalize(relativeName);
  if (
    normalized.startsWith("..") ||
    normalized.includes(`${path.sep}..${path.sep}`) ||
    normalized.endsWith(`${path.sep}..`) ||
    normalized === ".."
  ) {
    throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
  }
  const abs = path.join(targetReal, normalized);
  const rel = path.relative(targetReal, abs);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
  }
  return abs;
}

function assertNoSymlinkSegments(targetReal: string, absFile: string): void {
  const rel = path.relative(targetReal, absFile);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
  }
  const parts = rel.split(path.sep).filter((p) => p.length > 0 && p !== ".");
  let cursor = targetReal;
  for (const part of parts) {
    cursor = path.join(cursor, part);
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(cursor);
    } catch {
      throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
    }
    if (lst.isSymbolicLink()) {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
  }
}

function ensureParentDir(targetReal: string, absFile: string): void {
  const dir = path.dirname(absFile);
  const rel = path.relative(targetReal, dir);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
  }
  if (dir === targetReal) return;
  // Create only intermediate dirs under target; refuse if any segment is a symlink.
  const parts = rel.split(path.sep).filter((p) => p.length > 0 && p !== ".");
  let cursor = targetReal;
  for (const part of parts) {
    cursor = path.join(cursor, part);
    try {
      const st = fs.lstatSync(cursor);
      if (st.isSymbolicLink()) {
        throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
      }
      if (!st.isDirectory()) {
        throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
      }
    } catch (e) {
      if (e instanceof PathSafetyError) throw e;
      const err = e as NodeJS.ErrnoException;
      if (err.code === "ENOENT") {
        fs.mkdirSync(cursor, { mode: 0o755 });
      } else {
        throw new PathSafetyError("BACKUP_ERROR", "Directory refused.");
      }
    }
  }
}

function openReadNoFollowFlags(): number {
  const base = fsConstants.O_RDONLY;
  const nofollow =
    "O_NOFOLLOW" in fsConstants
      ? (fsConstants as NodeJS.Dict<number>).O_NOFOLLOW
      : undefined;
  if (typeof nofollow === "number") {
    return base | nofollow;
  }
  return base;
}

/**
 * Write bytes to a new or existing regular file via temp+rename when possible.
 * fsync where supported.
 */
function writeAtomicFile(abs: string, bytes: Buffer, mode: number): void {
  const dir = path.dirname(abs);
  const base = path.basename(abs);
  const tempAbs = path.join(dir, `.${base}.cg-write-${process.pid}-${Date.now()}`);
  let fd: number | null = null;
  try {
    // Exclusive create of temp to avoid clobber races.
    const flags =
      fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_TRUNC |
      fsConstants.O_EXCL;
    fd = fs.openSync(tempAbs, flags, mode & 0o777);
    let offset = 0;
    while (offset < bytes.length) {
      const n = fs.writeSync(fd, bytes, offset, bytes.length - offset);
      offset += n;
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      /* fsync optional on some platforms/filesystems */
    }
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(tempAbs, abs);
    // Best-effort fsync of parent directory for durability on POSIX.
    try {
      const dfd = fs.openSync(dir, fsConstants.O_RDONLY);
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch {
      /* directory fsync may be unsupported */
    }
  } catch (e) {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
    try {
      if (fs.existsSync(tempAbs)) fs.unlinkSync(tempAbs);
    } catch {
      /* ignore */
    }
    if (e instanceof PathSafetyError) throw e;
    throw new PathSafetyError("WRITE_FAILED", "Write failed.");
  }
}
