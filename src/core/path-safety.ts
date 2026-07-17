import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";

export class PathSafetyError extends Error {
  readonly code: string;
  constructor(code: string, message = "Path refused.") {
    super(message);
    this.name = "PathSafetyError";
    this.code = code;
  }
}

/**
 * Resolve target directory.
 * Ticket 01 fail-closed policy: refuse a target that is itself a symlink.
 * Leaf must be a real directory (lstat, no follow).
 */
export function resolveTargetDirectory(target: string): {
  targetAbs: string;
  targetReal: string;
} {
  if (typeof target !== "string" || target.length === 0 || target.length > 4096) {
    throw new PathSafetyError("INVALID_TARGET", "Invalid target.");
  }
  const targetAbs = path.resolve(target);
  let st: fs.Stats;
  try {
    st = fs.lstatSync(targetAbs);
  } catch {
    throw new PathSafetyError("TARGET_NOT_FOUND", "Target not found.");
  }
  // Refuse symlink targets entirely (simplest fail-closed no-follow policy).
  if (st.isSymbolicLink()) {
    throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink target refused.");
  }
  if (!st.isDirectory()) {
    throw new PathSafetyError("INVALID_TARGET", "Target is not a directory.");
  }
  // Directory is not a symlink; realpath for canonical root comparison only.
  let targetReal: string;
  try {
    targetReal = fs.realpathSync.native(targetAbs);
  } catch {
    throw new PathSafetyError("TARGET_NOT_FOUND", "Target not found.");
  }
  return { targetAbs, targetReal };
}

/**
 * Walk each path segment under targetReal with lstat.
 * Refuse any symlink in intermediate segments or the leaf — even if the
 * symlink currently resolves inside the target. Fail closed, no follow.
 */
function assertNoSymlinkSegments(
  targetReal: string,
  relativeName: string,
): { abs: string; size: number; ino: number; dev: number; mode: number; mtimeMs: number } {
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
  const parts = normalized.split(path.sep).filter((p) => p.length > 0 && p !== ".");
  if (parts.length === 0) {
    throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
  }

  let cursor = targetReal;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    if (part === ".." || part.includes("\0")) {
      throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
    }
    cursor = path.join(cursor, part);
    const rel = path.relative(targetReal, cursor);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
    }

    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(cursor);
    } catch {
      throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
    }

    // Any symlink in any segment is refused (no-follow).
    if (lst.isSymbolicLink()) {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }

    const isLeaf = i === parts.length - 1;
    if (isLeaf) {
      if (!lst.isFile()) {
        throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
      }
      return {
        abs: cursor,
        size: lst.size,
        ino: lst.ino,
        dev: lst.dev,
        mode: lst.mode,
        mtimeMs: lst.mtimeMs,
      };
    }
    if (!lst.isDirectory()) {
      throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
    }
  }
  throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
}

/**
 * Join a relative candidate under targetReal.
 * Refuses absolute candidates, `..` escape, and any symlink segment/leaf.
 * Does not read file contents — only lstat metadata (no follow).
 */
export function resolveNamedCandidate(
  targetReal: string,
  relativeName: string,
): {
  abs: string;
  real: string;
  isSymlink: boolean;
  size: number;
  preOpen: { ino: number; dev: number; mode: number; mtimeMs: number; size: number };
} {
  const meta = assertNoSymlinkSegments(targetReal, relativeName);
  return {
    abs: meta.abs,
    real: meta.abs,
    isSymlink: false,
    size: meta.size,
    preOpen: {
      ino: meta.ino,
      dev: meta.dev,
      mode: meta.mode,
      mtimeMs: meta.mtimeMs,
      size: meta.size,
    },
  };
}

/**
 * Open flags: prefer O_NOFOLLOW (+ O_RDONLY) when available to reduce
 * lstat-to-open leaf swapping. Fall back to plain O_RDONLY on platforms
 * without O_NOFOLLOW.
 */
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
 * Bounded read of a candidate already validated by resolveNamedCandidate.
 * Opens with O_NOFOLLOW when available, fstats the fd, requires a regular
 * file, enforces the byte limit from the fd, and compares stable pre-open
 * metadata where meaningful. Never reads outside content before refusal.
 */
export function readBoundedFile(
  realPath: string,
  maxBytes: number,
  preOpen?: { ino: number; dev: number; mode: number; mtimeMs: number; size: number },
): Buffer {
  const flags = openReadNoFollowFlags();
  let fd: number;
  try {
    fd = fs.openSync(realPath, flags);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && (err.code === "ELOOP" || err.code === "EMLINK")) {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
    throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
  }
  try {
    const st = fs.fstatSync(fd);
    // Require a regular file from the opened fd (not a symlink, not a dir).
    if (!st.isFile()) {
      throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
    }
    if (st.size > maxBytes) {
      throw new PathSafetyError("SIZE_LIMIT", "File exceeds size limit.");
    }
    // Compare stable pre-open metadata where meaningful (TOCTOU hardening).
    if (preOpen) {
      if (st.dev !== preOpen.dev || st.ino !== preOpen.ino) {
        throw new PathSafetyError("TOCTOU", "Path refused.");
      }
      if (st.size !== preOpen.size) {
        throw new PathSafetyError("TOCTOU", "Path refused.");
      }
    }
    const buf = Buffer.alloc(st.size);
    let offset = 0;
    while (offset < st.size) {
      const n = fs.readSync(fd, buf, offset, st.size - offset, offset);
      if (n === 0) break;
      offset += n;
    }
    return buf.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
}
