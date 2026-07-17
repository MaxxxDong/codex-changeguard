import fs from "node:fs";
import path from "node:path";

export class PathSafetyError extends Error {
  readonly code: string;
  constructor(code: string, message = "Path refused.") {
    super(message);
    this.name = "PathSafetyError";
    this.code = code;
  }
}

function realpathOrThrow(p: string, code: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    throw new PathSafetyError(code, "Path refused.");
  }
}

/**
 * Resolve target directory. Refuses if not a directory or if a symlink chain
 * escapes an existing root after realpath. Uses lstat first for the leaf.
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
  if (st.isSymbolicLink()) {
    // Resolve once; realpath must remain a directory and we never read outside.
    let real: string;
    try {
      real = fs.realpathSync.native(targetAbs);
    } catch {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink target refused.");
    }
    let rst: fs.Stats;
    try {
      rst = fs.statSync(real);
    } catch {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink target refused.");
    }
    if (!rst.isDirectory()) {
      throw new PathSafetyError("INVALID_TARGET", "Target is not a directory.");
    }
    return { targetAbs, targetReal: real };
  }
  if (!st.isDirectory()) {
    throw new PathSafetyError("INVALID_TARGET", "Target is not a directory.");
  }
  const targetReal = realpathOrThrow(targetAbs, "TARGET_NOT_FOUND");
  return { targetAbs, targetReal };
}

/**
 * Join a relative candidate under targetReal. Refuses absolute candidates,
 * `..` escape, and any symlink whose realpath is outside targetReal.
 * Does not read file contents — only lstat / realpath metadata.
 */
export function resolveNamedCandidate(
  targetReal: string,
  relativeName: string,
): { abs: string; real: string; isSymlink: boolean; size: number } {
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
    normalized.endsWith(`${path.sep}..`)
  ) {
    throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
  }
  const abs = path.join(targetReal, normalized);
  const rel = path.relative(targetReal, abs);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new PathSafetyError("PATH_ESCAPE", "Candidate refused.");
  }

  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(abs);
  } catch {
    throw new PathSafetyError("CANDIDATE_NOT_FOUND", "Candidate not found.");
  }

  if (lst.isSymbolicLink()) {
    let real: string;
    try {
      real = fs.realpathSync.native(abs);
    } catch {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
    const realRel = path.relative(targetReal, real);
    if (realRel.startsWith("..") || path.isAbsolute(realRel)) {
      // Refuse without reading outside content.
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
    let rst: fs.Stats;
    try {
      rst = fs.statSync(real);
    } catch {
      throw new PathSafetyError("SYMLINK_ESCAPE", "Symlink candidate refused.");
    }
    if (!rst.isFile()) {
      throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
    }
    return { abs, real, isSymlink: true, size: rst.size };
  }

  if (!lst.isFile()) {
    throw new PathSafetyError("INVALID_CANDIDATE", "Candidate refused.");
  }
  return { abs, real: abs, isSymlink: false, size: lst.size };
}

/** Bounded read of a candidate already validated by resolveNamedCandidate. */
export function readBoundedFile(realPath: string, maxBytes: number): Buffer {
  const fd = fs.openSync(realPath, "r");
  try {
    const st = fs.fstatSync(fd);
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
    return buf.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
}
