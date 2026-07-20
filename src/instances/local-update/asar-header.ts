/**
 * Dependency-free, header-only Electron ASAR reader (Pickle layout).
 *
 * Official semantics match Electron `asar` `readArchiveHeaderSync`:
 * - read 8 bytes outer size Pickle
 * - first UInt32 = outer Pickle payload size (normally 4)
 * - second UInt32 = complete inner header-Pickle size
 * - read that many bytes for the inner Pickle
 * - first UInt32 = inner payload size; next Int32 = UTF-8 JSON byte length
 * - JSON starts after those 8 bytes (4-byte padded inside the Pickle)
 *
 * Does NOT implement the incorrect shortcut “JSON begins at archive byte 8”.
 * Never reads file bodies or extracts archives.
 */
import fs from "node:fs";
import { constants as fsConstants } from "node:fs";
import {
  MAX_ASAR_HEADER_JSON_BYTES,
  MAX_ASAR_HEADER_PICKLE_BYTES,
  MAX_ASAR_NODES,
  MAX_ASAR_PATH_LEN,
  MAX_ASAR_PATH_SEGMENT,
  MAX_ASAR_TREE_DEPTH,
} from "./limits.js";

export type AsarHeaderParseStatus =
  | "ok"
  | "truncated"
  | "malformed"
  | "oversize"
  | "io_error"
  | "not_file"
  | "symlink_refused";

/**
 * Validated optional integrity metadata from ASAR header file leaves.
 * Only algorithm SHA256 with exactly 64 hex digits is accepted; hash is
 * lowercased. Never derived from file bodies.
 */
export interface AsarValidatedIntegrity {
  algorithm: "SHA256";
  /** Lowercase 64-hex digest — internal only; never export in public JSON. */
  hash: string;
}

export interface AsarFileEntry {
  /** Normalized relative path using `/`. */
  path: string;
  size: number | null;
  /**
   * Validated header integrity when present and trusted; null when missing
   * or malformed (untrusted). Callers must not expose hash values publicly.
   */
  integrity: AsarValidatedIntegrity | null;
  /** True when entry looks like a content-addressed / chunk path. */
  is_chunk_like: boolean;
  is_node_module: boolean;
  basename: string;
}

const SHA256_HEX_RE = /^[0-9a-fA-F]{64}$/;

/**
 * Parse optional Electron ASAR header integrity block for a file leaf.
 * Accepts only algorithm exactly "SHA256" and hash exactly 64 hex chars.
 * Returns null for missing/malformed/untrusted metadata (never throws).
 */
export function parseValidatedIntegrity(
  node: Record<string, unknown>,
): AsarValidatedIntegrity | null {
  const raw = node.integrity;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const integ = raw as Record<string, unknown>;
  if (integ.algorithm !== "SHA256") return null;
  if (typeof integ.hash !== "string") return null;
  if (!SHA256_HEX_RE.test(integ.hash)) return null;
  return {
    algorithm: "SHA256",
    hash: integ.hash.toLowerCase(),
  };
}

export interface AsarHeaderParseResult {
  status: AsarHeaderParseStatus;
  reason: string | null;
  header_size: number | null;
  file_count: number;
  entries: AsarFileEntry[];
  nodes_visited: number;
  nodes_capped: boolean;
  depth_capped: boolean;
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

function align4(n: number): number {
  return (n + 3) & ~3;
}

function isChunkLikePath(p: string): boolean {
  // Content-addressed / generated chunks: collapse into aggregate buckets.
  if (/\.vite\//.test(p) && /chunk|assets?\//i.test(p)) return true;
  if (/\/[0-9a-f]{8,}\./i.test(p)) return true;
  if (/chunk-[A-Za-z0-9_-]+\.js$/i.test(p)) return true;
  if (/assets\/index-[A-Za-z0-9_-]+\./i.test(p)) return true;
  return false;
}

function basenameOf(p: string): string {
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : p;
}

/**
 * Walk Electron ASAR header JSON files tree.
 * Shape: { files: { name: { files?: …, size?: number, offset?: string, … } } }
 */
function walkFilesTree(
  node: unknown,
  prefix: string,
  depth: number,
  out: AsarFileEntry[],
  state: { nodes: number; capped: boolean; depth_capped: boolean },
): void {
  if (state.capped) return;
  if (depth > MAX_ASAR_TREE_DEPTH) {
    state.depth_capped = true;
    return;
  }
  if (!node || typeof node !== "object" || Array.isArray(node)) return;
  const files = (node as Record<string, unknown>).files;
  if (!files || typeof files !== "object" || Array.isArray(files)) return;

  for (const [name, child] of Object.entries(files as Record<string, unknown>)) {
    if (state.nodes >= MAX_ASAR_NODES) {
      state.capped = true;
      return;
    }
    state.nodes += 1;
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      name.length > MAX_ASAR_PATH_SEGMENT ||
      name.includes("\0") ||
      name.includes("..") ||
      name.includes("/") ||
      name.includes("\\")
    ) {
      continue;
    }
    const path =
      prefix.length === 0 ? name : `${prefix}/${name}`;
    if (path.length > MAX_ASAR_PATH_LEN) continue;
    if (!child || typeof child !== "object" || Array.isArray(child)) continue;
    const c = child as Record<string, unknown>;
    if (c.files && typeof c.files === "object") {
      walkFilesTree(c, path, depth + 1, out, state);
      continue;
    }
    // File leaf: may have size (number) and/or optional integrity; never bodies.
    let size: number | null = null;
    if (typeof c.size === "number" && Number.isFinite(c.size) && c.size >= 0) {
      size = Math.floor(c.size);
    }
    const base = basenameOf(path);
    out.push({
      path,
      size,
      integrity: parseValidatedIntegrity(c),
      is_chunk_like: isChunkLikePath(path),
      is_node_module: base.endsWith(".node"),
      basename: base,
    });
  }
}

/**
 * Parse ASAR header from an already-open fd at offset 0.
 * Reads only the bounded header region — never file bodies.
 */
export function parseAsarHeaderFromFd(
  fd: number,
  fileSize: number,
): AsarHeaderParseResult {
  const empty = (
    status: AsarHeaderParseStatus,
    reason: string,
  ): AsarHeaderParseResult => ({
    status,
    reason,
    header_size: null,
    file_count: 0,
    entries: [],
    nodes_visited: 0,
    nodes_capped: false,
    depth_capped: false,
  });

  if (fileSize < 16) {
    return empty("truncated", "archive_too_small");
  }

  const outer = Buffer.alloc(8);
  let n = fs.readSync(fd, outer, 0, 8, 0);
  if (n !== 8) return empty("truncated", "outer_pickle_short_read");

  // Outer size Pickle: payload_size (u32) then payload (u32 = size of inner pickle).
  const outerPayloadSize = outer.readUInt32LE(0);
  if (outerPayloadSize !== 4) {
    // Electron always writes payload size 4 for the size field.
    // Reject other values as malformed (do not treat bytes 4–7 as JSON start).
    return empty("malformed", "outer_payload_size_not_4");
  }
  const headerPickleSize = outer.readUInt32LE(4);
  if (headerPickleSize <= 8) {
    return empty("malformed", "header_pickle_too_small");
  }
  if (headerPickleSize > MAX_ASAR_HEADER_PICKLE_BYTES) {
    return empty("oversize", "header_pickle_oversize");
  }
  if (8 + headerPickleSize > fileSize) {
    return empty("truncated", "header_pickle_exceeds_file");
  }

  const headerPickle = Buffer.alloc(headerPickleSize);
  n = fs.readSync(fd, headerPickle, 0, headerPickleSize, 8);
  if (n !== headerPickleSize) {
    return empty("truncated", "header_pickle_short_read");
  }

  const innerPayloadSize = headerPickle.readUInt32LE(0);
  if (innerPayloadSize + 4 > headerPickleSize) {
    return empty("malformed", "inner_payload_exceeds_pickle");
  }
  // After payload size u32: string length Int32 + UTF-8 bytes (4-byte padded).
  if (headerPickleSize < 8) {
    return empty("malformed", "inner_pickle_too_small");
  }
  const jsonByteLength = headerPickle.readInt32LE(4);
  if (jsonByteLength < 2 || jsonByteLength > MAX_ASAR_HEADER_JSON_BYTES) {
    return empty(
      jsonByteLength > MAX_ASAR_HEADER_JSON_BYTES ? "oversize" : "malformed",
      "json_length_invalid",
    );
  }
  const jsonStart = 8;
  const jsonEnd = jsonStart + jsonByteLength;
  const paddedEnd = align4(jsonEnd);
  if (paddedEnd > headerPickleSize || jsonEnd > headerPickleSize) {
    return empty("malformed", "json_exceeds_header_pickle");
  }
  // inner payload should cover string length + padded string.
  if (innerPayloadSize < 4 + align4(jsonByteLength)) {
    return empty("malformed", "inner_payload_size_mismatch");
  }

  let jsonText: string;
  try {
    jsonText = headerPickle.subarray(jsonStart, jsonEnd).toString("utf8");
  } catch {
    return empty("malformed", "json_utf8_decode");
  }

  let root: unknown;
  try {
    root = JSON.parse(jsonText);
  } catch {
    return empty("malformed", "json_parse");
  }
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    return empty("malformed", "json_root_not_object");
  }

  const entries: AsarFileEntry[] = [];
  const state = { nodes: 0, capped: false, depth_capped: false };
  walkFilesTree(root, "", 0, entries, state);

  return {
    status: "ok",
    reason: null,
    header_size: 8 + headerPickleSize,
    file_count: entries.length,
    entries,
    nodes_visited: state.nodes,
    nodes_capped: state.capped,
    depth_capped: state.depth_capped,
  };
}

/**
 * Open a regular file (no symlink) and parse ASAR header only.
 * `absPath` is for local measurement; callers must not export it.
 */
export function parseAsarHeaderFile(absPath: string): AsarHeaderParseResult {
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(absPath);
  } catch {
    return {
      status: "io_error",
      reason: "lstat_failed",
      header_size: null,
      file_count: 0,
      entries: [],
      nodes_visited: 0,
      nodes_capped: false,
      depth_capped: false,
    };
  }
  if (lst.isSymbolicLink()) {
    return {
      status: "symlink_refused",
      reason: "symlink",
      header_size: null,
      file_count: 0,
      entries: [],
      nodes_visited: 0,
      nodes_capped: false,
      depth_capped: false,
    };
  }
  if (!lst.isFile()) {
    return {
      status: "not_file",
      reason: "not_file",
      header_size: null,
      file_count: 0,
      entries: [],
      nodes_visited: 0,
      nodes_capped: false,
      depth_capped: false,
    };
  }
  let fd: number;
  try {
    fd = fs.openSync(absPath, openReadNoFollowFlags());
  } catch {
    return {
      status: "io_error",
      reason: "open_failed",
      header_size: null,
      file_count: 0,
      entries: [],
      nodes_visited: 0,
      nodes_capped: false,
      depth_capped: false,
    };
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) {
      return {
        status: "not_file",
        reason: "fstat_not_file",
        header_size: null,
        file_count: 0,
        entries: [],
        nodes_visited: 0,
        nodes_capped: false,
        depth_capped: false,
      };
    }
    return parseAsarHeaderFromFd(fd, st.size);
  } catch {
    return {
      status: "io_error",
      reason: "fstat_or_read_failed",
      header_size: null,
      file_count: 0,
      entries: [],
      nodes_visited: 0,
      nodes_capped: false,
      depth_capped: false,
    };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
  }
}

/**
 * Build a minimal valid ASAR archive buffer with only a header (no file bodies).
 * Used by tests. Follows official Pickle layout.
 */
export function buildSyntheticAsarBuffer(
  filesTree: Record<string, unknown>,
): Buffer {
  const json = JSON.stringify({ files: filesTree });
  const jsonBuf = Buffer.from(json, "utf8");
  const jsonLen = jsonBuf.length;
  const jsonPadded = align4(jsonLen);
  // Inner pickle: u32 payload_size + i32 string_len + string + pad
  const innerPayloadSize = 4 + jsonPadded;
  const headerPickleSize = 4 + innerPayloadSize;
  const headerPickle = Buffer.alloc(headerPickleSize);
  headerPickle.writeUInt32LE(innerPayloadSize, 0);
  headerPickle.writeInt32LE(jsonLen, 4);
  jsonBuf.copy(headerPickle, 8);
  // outer size pickle: u32 payload_size=4 + u32 header_pickle_size
  const outer = Buffer.alloc(8);
  outer.writeUInt32LE(4, 0);
  outer.writeUInt32LE(headerPickleSize, 4);
  return Buffer.concat([outer, headerPickle]);
}
