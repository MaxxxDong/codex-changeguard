/**
 * Bounded path checks for Ticket 03 instance / metadata reads.
 * Aligns with Ticket 01 fail-closed no-follow policy: refuse any symlink
 * segment, refuse escape outside an explicit allowed root, open with
 * O_NOFOLLOW when available, fstat, require regular file, enforce size.
 */
import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";

export class BoundedPathError extends Error {
  readonly code: string;
  constructor(code: string, message = "Path refused.") {
    super(message);
    this.name = "BoundedPathError";
    this.code = code;
  }
}

function openReadNoFollowFlags(): number {
  const base = fsConstants.O_RDONLY;
  const nofollow =
    "O_NOFOLLOW" in fsConstants
      ? (fsConstants as NodeJS.Dict<number>).O_NOFOLLOW
      : undefined;
  if (typeof nofollow === "number") return base | nofollow;
  return base;
}

/** True when absPath is strictly inside or equal to rootAbs (after resolve). */
export function isInsideRoot(rootAbs: string, absPath: string): boolean {
  const root = path.resolve(rootAbs);
  const target = path.resolve(absPath);
  const rel = path.relative(root, target);
  if (rel === "") return true;
  if (rel.startsWith("..") || path.isAbsolute(rel)) return false;
  return true;
}

/**
 * Normalize a relative path under a root: refuse absolute, empty, null bytes,
 * and any `..` segment.
 */
export function normalizeRelativeUnderRoot(relativeName: string): string {
  if (
    typeof relativeName !== "string" ||
    relativeName.length === 0 ||
    path.isAbsolute(relativeName) ||
    relativeName.includes("\0")
  ) {
    throw new BoundedPathError("INVALID_CANDIDATE", "Path refused.");
  }
  const normalized = path.normalize(relativeName);
  if (
    normalized === ".." ||
    normalized.startsWith(`..${path.sep}`) ||
    normalized.includes(`${path.sep}..${path.sep}`) ||
    normalized.endsWith(`${path.sep}..`)
  ) {
    throw new BoundedPathError("PATH_ESCAPE", "Path refused.");
  }
  // Also refuse Windows-style parent segments when running on POSIX (fixtures use /).
  const parts = normalized.split(/[/\\]/).filter((p) => p.length > 0 && p !== ".");
  if (parts.some((p) => p === "..")) {
    throw new BoundedPathError("PATH_ESCAPE", "Path refused.");
  }
  if (parts.length === 0) {
    throw new BoundedPathError("INVALID_CANDIDATE", "Path refused.");
  }
  return parts.join(path.sep);
}

/**
 * Assert root is a real (non-symlink) directory.
 */
export function assertRealDirectory(rootAbs: string): string {
  const abs = path.resolve(rootAbs);
  let st: fs.Stats;
  try {
    st = fs.lstatSync(abs);
  } catch {
    throw new BoundedPathError("ROOT_NOT_FOUND", "Root not found.");
  }
  if (st.isSymbolicLink()) {
    throw new BoundedPathError("SYMLINK_ESCAPE", "Symlink root refused.");
  }
  if (!st.isDirectory()) {
    throw new BoundedPathError("INVALID_ROOT", "Root is not a directory.");
  }
  return abs;
}

/**
 * Walk each path segment under rootAbs with lstat (no follow).
 * Refuses any symlink intermediate or leaf; leaf must be a regular file.
 * Returns absolute path + pre-open identity metadata.
 */
export function resolveRegularFileUnderRoot(
  rootAbs: string,
  relativeName: string,
): {
  abs: string;
  size: number;
  ino: number;
  dev: number;
} {
  const root = assertRealDirectory(rootAbs);
  const normalized = normalizeRelativeUnderRoot(relativeName);
  const parts = normalized.split(path.sep).filter((p) => p.length > 0);

  let cursor = root;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    cursor = path.join(cursor, part);
    if (!isInsideRoot(root, cursor)) {
      throw new BoundedPathError("PATH_ESCAPE", "Path refused.");
    }
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(cursor);
    } catch {
      throw new BoundedPathError("NOT_FOUND", "Path not found.");
    }
    if (lst.isSymbolicLink()) {
      throw new BoundedPathError("SYMLINK_ESCAPE", "Symlink path refused.");
    }
    const isLeaf = i === parts.length - 1;
    if (isLeaf) {
      if (!lst.isFile()) {
        throw new BoundedPathError("INVALID_CANDIDATE", "Not a regular file.");
      }
      return { abs: cursor, size: lst.size, ino: lst.ino, dev: lst.dev };
    }
    if (!lst.isDirectory()) {
      throw new BoundedPathError("INVALID_CANDIDATE", "Path refused.");
    }
  }
  throw new BoundedPathError("NOT_FOUND", "Path not found.");
}

/**
 * Bounded read of a regular file already resolved under a root.
 * open + fstat + identity/size check; never follows symlinks.
 */
export function readBoundedRegularFile(
  meta: { abs: string; size: number; ino: number; dev: number },
  maxBytes: number,
): string {
  if (meta.size > maxBytes) {
    throw new BoundedPathError("SIZE_LIMIT", "File exceeds size limit.");
  }
  let fd: number;
  try {
    fd = fs.openSync(meta.abs, openReadNoFollowFlags());
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && (err.code === "ELOOP" || err.code === "EMLINK")) {
      throw new BoundedPathError("SYMLINK_ESCAPE", "Symlink path refused.");
    }
    throw new BoundedPathError("NOT_FOUND", "Path not found.");
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) {
      throw new BoundedPathError("INVALID_CANDIDATE", "Not a regular file.");
    }
    if (st.dev !== meta.dev || st.ino !== meta.ino || st.size !== meta.size) {
      throw new BoundedPathError("TOCTOU", "Path refused.");
    }
    if (st.size > maxBytes) {
      throw new BoundedPathError("SIZE_LIMIT", "File exceeds size limit.");
    }
    const buf = Buffer.alloc(st.size);
    let offset = 0;
    while (offset < st.size) {
      const n = fs.readSync(fd, buf, offset, st.size - offset, offset);
      if (n === 0) break;
      offset += n;
    }
    return buf.subarray(0, offset).toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Resolve an absolute path against an explicit allowlist of roots and read
 * it only when every intermediate segment under the matching root is real
 * (no symlinks). Returns null on any refusal (fail-closed, non-throwing).
 */
export function readFileUnderAllowedRoots(
  absOrLogical: string,
  allowedRoots: string[],
  maxBytes: number,
): string | null {
  if (typeof absOrLogical !== "string" || absOrLogical.length === 0) return null;
  if (!Array.isArray(allowedRoots) || allowedRoots.length === 0) return null;
  const target = path.resolve(absOrLogical);
  for (const rootRaw of allowedRoots) {
    if (typeof rootRaw !== "string" || rootRaw.length === 0) continue;
    let root: string;
    try {
      root = assertRealDirectory(rootRaw);
    } catch {
      continue;
    }
    if (!isInsideRoot(root, target)) continue;
    const rel = path.relative(root, target);
    if (rel === "") continue; // directory itself is not a file
    try {
      const meta = resolveRegularFileUnderRoot(root, rel);
      return readBoundedRegularFile(meta, maxBytes);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Join relative name under root and read with full no-follow segment checks.
 * Returns null on refusal.
 */
export function readRelativeUnderRoot(
  rootAbs: string,
  relativeName: string,
  maxBytes: number,
): string | null {
  try {
    const meta = resolveRegularFileUnderRoot(rootAbs, relativeName);
    return readBoundedRegularFile(meta, maxBytes);
  } catch {
    return null;
  }
}

/**
 * Select the first allowed root that contains absPath (resolved).
 */
export function findContainingRoot(
  absPath: string,
  allowedRoots: string[],
): string | null {
  const target = path.resolve(absPath);
  for (const rootRaw of allowedRoots) {
    if (typeof rootRaw !== "string" || rootRaw.length === 0) continue;
    try {
      const root = assertRealDirectory(rootRaw);
      if (isInsideRoot(root, target)) return root;
    } catch {
      continue;
    }
  }
  return null;
}
