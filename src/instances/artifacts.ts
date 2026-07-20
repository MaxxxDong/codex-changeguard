/**
 * Local installed-artifact measurement: exact named candidates only.
 * Read-only streaming SHA-256; never executes binaries; never copies files;
 * never persists absolute paths or file bodies.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";
import { pathHashOf, sha256Hex } from "./identity.js";
import {
  ARTIFACT_HASH_CHUNK_BYTES,
  MAX_ARTIFACT_ENTRIES_PER_INSTANCE,
  MAX_ARTIFACT_FILE_BYTES,
  MAX_ARTIFACT_KEY_LEN,
  MAX_ARTIFACT_SCAN_BYTES,
} from "./limits.js";
import {
  assertRealDirectory,
  BoundedPathError,
  isInsideRoot,
  resolveRegularFileUnderRoot,
} from "./path-bounded.js";
import type {
  ArtifactKind,
  ArtifactReadStatus,
  DiscoveredCandidate,
  InstanceArtifactBaseline,
  InstanceIdentity,
  LocalArtifactEntry,
  PlatformId,
} from "./types.js";

export interface MeasureArtifactsOptions {
  /** Fixture inventory root (trusted for relative metadata). */
  inventoryRoot?: string;
  maxFileBytes?: number;
  maxScanBytes?: number;
  maxEntriesPerInstance?: number;
  /**
   * Wall-clock budget in ms for named-artifact measurement (monotonic).
   * When exhausted, remaining exact named targets become explicit
   * `time_budget_exceeded` gaps — never silent "unchanged".
   * Undefined / non-positive: no wall-clock cap (byte caps still apply).
   */
  timeBudgetMs?: number;
  /** Injectable monotonic clock for tests (default: performance.now). */
  nowMs?: () => number;
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

function clampKey(raw: string): string {
  const s = raw
    .normalize("NFKC")
    .replace(/[^A-Za-z0-9._+-]/g, "_")
    .slice(0, MAX_ARTIFACT_KEY_LEN);
  return s.length > 0 ? s : "artifact";
}

function kindForKey(key: string): ArtifactKind {
  switch (key) {
    case "executable":
      return "executable";
    case "info_plist":
      return "plist";
    case "app_asar":
      return "asar";
    case "resources_codex":
      return "executable";
    case "code_resources":
      return "code_resources";
    case "msix_manifest":
      return "manifest";
    case "package_json":
    case "version_json":
      return "metadata";
    default:
      if (key.startsWith("metadata_")) return "metadata";
      return "other";
  }
}

function keyForBasename(base: string): string {
  const b = base.toLowerCase();
  if (b === "info.plist") return "info_plist";
  if (b === "app.asar") return "app_asar";
  if (b === "coderesources") return "code_resources";
  if (b === "appxmanifest.xml") return "msix_manifest";
  if (b === "package.json") return "package_json";
  if (b === "version.json") return "version_json";
  if (b === "codex" || b === "codex.exe") return "resources_codex";
  return clampKey(`metadata_${base}`);
}

function findAppBundleRoot(binaryAbs: string): string | null {
  let cur = path.resolve(binaryAbs);
  for (let i = 0; i < 10; i++) {
    const base = path.basename(cur);
    if (base.toLowerCase().endsWith(".app")) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

interface NamedTarget {
  key: string;
  abs: string;
  /** Allowed roots that may contain this file (must pass isInsideRoot). */
  roots: string[];
}

function pushNamed(
  out: NamedTarget[],
  seenKeys: Set<string>,
  seenAbs: Set<string>,
  key: string,
  abs: string,
  roots: string[],
): void {
  const k = clampKey(key);
  if (seenKeys.has(k)) return;
  const resolved = path.resolve(abs);
  if (seenAbs.has(resolved)) return;
  seenKeys.add(k);
  seenAbs.add(resolved);
  out.push({ key: k, abs: resolved, roots });
}

/**
 * Build exact named artifact targets for one discovered candidate.
 * No recursive install-tree or home traversal.
 */
export function namedArtifactTargetsForCandidate(
  candidate: DiscoveredCandidate,
  inventoryRoot?: string,
): NamedTarget[] {
  const out: NamedTarget[] = [];
  const seenKeys = new Set<string>();
  const seenAbs = new Set<string>();
  const trusted: string[] = [];
  if (Array.isArray(candidate.trusted_metadata_roots)) {
    for (const r of candidate.trusted_metadata_roots) {
      if (typeof r !== "string" || r.length === 0) continue;
      try {
        trusted.push(assertRealDirectory(r));
      } catch {
        /* skip invalid roots */
      }
    }
  }
  if (typeof inventoryRoot === "string" && inventoryRoot.length > 0) {
    try {
      trusted.push(assertRealDirectory(inventoryRoot));
    } catch {
      /* fixture root may be unavailable in pure unit tests */
    }
  }

  // Always: exact candidate executable/file.
  const candRoots =
    trusted.length > 0
      ? trusted
      : (() => {
          try {
            return [assertRealDirectory(path.dirname(candidate.path))];
          } catch {
            return [];
          }
        })();
  pushNamed(out, seenKeys, seenAbs, "executable", candidate.path, candRoots);

  // Existing registered absolute metadata entries.
  if (Array.isArray(candidate.version_metadata_abs)) {
    for (const abs of candidate.version_metadata_abs) {
      if (typeof abs !== "string" || abs.length === 0) continue;
      const key = keyForBasename(path.basename(abs));
      pushNamed(out, seenKeys, seenAbs, key, abs, trusted.length ? trusted : candRoots);
    }
  }

  // Fixture relative metadata.
  if (
    typeof candidate.version_metadata_rel === "string" &&
    candidate.version_metadata_rel.length > 0 &&
    typeof inventoryRoot === "string" &&
    inventoryRoot.length > 0
  ) {
    const abs = path.resolve(inventoryRoot, candidate.version_metadata_rel);
    const key = keyForBasename(path.basename(candidate.version_metadata_rel));
    pushNamed(out, seenKeys, seenAbs, key, abs, trusted.length ? trusted : [inventoryRoot]);
  }

  const platform: PlatformId = candidate.platform;
  const appRoot = findAppBundleRoot(candidate.path);

  // macOS desktop .app: exact named bundle components under registered real app root.
  if (
    platform === "macos" &&
    candidate.install_source === "desktop_bundled" &&
    appRoot
  ) {
    let realApp: string | null = null;
    try {
      realApp = assertRealDirectory(appRoot);
    } catch {
      realApp = null;
    }
    if (realApp) {
      const appRoots = [realApp];
      pushNamed(
        out,
        seenKeys,
        seenAbs,
        "info_plist",
        path.join(realApp, "Contents", "Info.plist"),
        appRoots,
      );
      pushNamed(
        out,
        seenKeys,
        seenAbs,
        "app_asar",
        path.join(realApp, "Contents", "Resources", "app.asar"),
        appRoots,
      );
      pushNamed(
        out,
        seenKeys,
        seenAbs,
        "resources_codex",
        path.join(realApp, "Contents", "Resources", "codex"),
        appRoots,
      );
      pushNamed(
        out,
        seenKeys,
        seenAbs,
        "code_resources",
        path.join(realApp, "Contents", "_CodeSignature", "CodeResources"),
        appRoots,
      );
    }
  }

  // Windows desktop/MSIX: optional exact resources/app.asar under trusted root.
  if (platform === "windows" && trusted.length > 0) {
    for (const root of trusted) {
      const asar = path.join(root, "resources", "app.asar");
      pushNamed(out, seenKeys, seenAbs, "app_asar", asar, [root]);
      // Only the first trusted-root asar candidate key is used (dedupe by key).
      break;
    }
  }

  return out.slice(0, MAX_ARTIFACT_ENTRIES_PER_INSTANCE);
}

interface MeasureBudget {
  /** Aggregate remaining hashable bytes. */
  remaining: number;
  /** Deadline from monotonic clock; null = no wall-clock cap. */
  deadlineMs: number | null;
  nowMs: () => number;
}

function timeBudgetExhausted(budget: MeasureBudget): boolean {
  if (budget.deadlineMs === null) return false;
  return budget.nowMs() >= budget.deadlineMs;
}

function gapEntry(
  key: string,
  alias: string,
  status: ArtifactReadStatus,
): LocalArtifactEntry {
  return {
    key,
    alias,
    kind: kindForKey(key),
    sha256: null,
    size: null,
    status,
  };
}

/**
 * Stream SHA-256 of a regular file under allowed roots. Symlinks, out-of-root,
 * oversize, and non-files become explicit gaps (never truncated digests).
 */
export function measureNamedFile(
  key: string,
  alias: string,
  abs: string,
  roots: string[],
  budget: MeasureBudget,
  maxFileBytes: number,
): LocalArtifactEntry {
  if (timeBudgetExhausted(budget)) {
    return gapEntry(key, alias, "time_budget_exceeded");
  }
  if (!Array.isArray(roots) || roots.length === 0) {
    return gapEntry(key, alias, "out_of_root");
  }
  const target = path.resolve(abs);
  let matchedRoot: string | null = null;
  for (const r of roots) {
    try {
      const root = assertRealDirectory(r);
      if (isInsideRoot(root, target)) {
        matchedRoot = root;
        break;
      }
    } catch {
      continue;
    }
  }
  if (!matchedRoot) {
    return gapEntry(key, alias, "out_of_root");
  }

  // Leaf may be missing → explicit gap (named candidate expected).
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(target);
  } catch {
    return gapEntry(key, alias, "missing");
  }
  if (lst.isSymbolicLink()) {
    return gapEntry(key, alias, "symlink_refused");
  }
  if (!lst.isFile()) {
    return gapEntry(key, alias, "not_file");
  }
  if (lst.size > maxFileBytes) {
    return gapEntry(key, alias, "oversize");
  }
  if (lst.size > budget.remaining) {
    return gapEntry(key, alias, "oversize");
  }

  // Resolve via segment walk under root (refuses intermediate symlinks).
  const rel = path.relative(matchedRoot, target);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    return gapEntry(key, alias, "out_of_root");
  }
  let meta: { abs: string; size: number; ino: number; dev: number };
  try {
    meta = resolveRegularFileUnderRoot(matchedRoot, rel);
  } catch (e) {
    if (e instanceof BoundedPathError) {
      if (e.code === "SYMLINK_ESCAPE") return gapEntry(key, alias, "symlink_refused");
      if (e.code === "NOT_FOUND") return gapEntry(key, alias, "missing");
      if (e.code === "PATH_ESCAPE") return gapEntry(key, alias, "out_of_root");
      if (e.code === "SIZE_LIMIT") return gapEntry(key, alias, "oversize");
      return gapEntry(key, alias, "io_error");
    }
    return gapEntry(key, alias, "io_error");
  }
  if (meta.size > maxFileBytes || meta.size > budget.remaining) {
    return gapEntry(key, alias, "oversize");
  }

  let fd: number;
  try {
    fd = fs.openSync(meta.abs, openReadNoFollowFlags());
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && (err.code === "ELOOP" || err.code === "EMLINK")) {
      return gapEntry(key, alias, "symlink_refused");
    }
    return gapEntry(key, alias, "io_error");
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return gapEntry(key, alias, "not_file");
    if (st.dev !== meta.dev || st.ino !== meta.ino || st.size !== meta.size) {
      return gapEntry(key, alias, "io_error");
    }
    if (st.size > maxFileBytes || st.size > budget.remaining) {
      return gapEntry(key, alias, "oversize");
    }
    const hash = crypto.createHash("sha256");
    const chunk = Buffer.alloc(
      Math.min(ARTIFACT_HASH_CHUNK_BYTES, Math.max(st.size, 1)),
    );
    let offset = 0;
    while (offset < st.size) {
      // Real wall-clock budget: check inside the streaming loop so a single
      // large file cannot run past the deadline after scheduling.
      if (timeBudgetExhausted(budget)) {
        // Discard partial hash material; never emit a truncated digest/size.
        return gapEntry(key, alias, "time_budget_exceeded");
      }
      const toRead = Math.min(chunk.length, st.size - offset);
      const n = fs.readSync(fd, chunk, 0, toRead, offset);
      if (n <= 0) break;
      hash.update(chunk.subarray(0, n));
      offset += n;
    }
    if (timeBudgetExhausted(budget)) {
      return gapEntry(key, alias, "time_budget_exceeded");
    }
    if (offset !== st.size) {
      return gapEntry(key, alias, "io_error");
    }
    budget.remaining -= st.size;
    return {
      key,
      alias,
      kind: kindForKey(key),
      sha256: hash.digest("hex"),
      size: st.size,
      status: "read_ok",
    };
  } catch {
    return gapEntry(key, alias, "io_error");
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
  }
}

/** Stable digest of a baseline's path-free entries (sorted by key). */
export function artifactBaselineDigest(entries: LocalArtifactEntry[]): string {
  const rows = [...entries]
    .map(
      (e) =>
        `${e.key}|${e.kind}|${e.status}|${e.sha256 ?? ""}|${e.size === null ? "" : String(e.size)}`,
    )
    .sort();
  return sha256Hex(`artifact_baseline:v1:${rows.join("\n")}`);
}

export function overallArtifactDigest(
  baselines: InstanceArtifactBaseline[],
): string {
  // Always recompute per-baseline digests from entries so public overall
  // cannot disagree with entry material after validation.
  const rows = [...baselines]
    .map((b) => `${b.instance_id}|${artifactBaselineDigest(b.entries)}`)
    .sort();
  return sha256Hex(`overall_artifacts:v1:${rows.join("\n")}`);
}

function sortEntries(entries: LocalArtifactEntry[]): LocalArtifactEntry[] {
  return [...entries].sort((a, b) => a.key.localeCompare(b.key));
}

/**
 * Measure exact named artifacts for each identity, matched by path_hash.
 * Returns one baseline per identity (empty entries only when no candidate match).
 */
export function measureInstanceArtifactBaselines(
  identities: InstanceIdentity[],
  candidates: DiscoveredCandidate[],
  opts: MeasureArtifactsOptions = {},
): InstanceArtifactBaseline[] {
  const maxFile = opts.maxFileBytes ?? MAX_ARTIFACT_FILE_BYTES;
  const maxScan = opts.maxScanBytes ?? MAX_ARTIFACT_SCAN_BYTES;
  const maxEntries =
    opts.maxEntriesPerInstance ?? MAX_ARTIFACT_ENTRIES_PER_INSTANCE;
  const nowMs =
    typeof opts.nowMs === "function"
      ? opts.nowMs
      : () =>
          typeof performance !== "undefined" &&
          typeof performance.now === "function"
            ? performance.now()
            : Date.now();
  const timeBudgetMs =
    typeof opts.timeBudgetMs === "number" &&
    Number.isFinite(opts.timeBudgetMs) &&
    opts.timeBudgetMs > 0
      ? opts.timeBudgetMs
      : null;
  const startMs = nowMs();
  const budget: MeasureBudget = {
    remaining: maxScan,
    deadlineMs: timeBudgetMs === null ? null : startMs + timeBudgetMs,
    nowMs,
  };

  const candByHash = new Map<string, DiscoveredCandidate>();
  for (const c of candidates) {
    const h = pathHashOf(c.path);
    // Prefer first registration (desktop over path) — candidates already deduped.
    if (!candByHash.has(h)) candByHash.set(h, c);
  }

  const baselines: InstanceArtifactBaseline[] = [];
  for (const id of identities) {
    const cand = candByHash.get(id.path_hash);
    if (!cand) {
      baselines.push({
        instance_id: id.instance_id,
        path_hash: id.path_hash,
        path_alias: id.path_alias,
        entries: [],
        baseline_digest: artifactBaselineDigest([]),
      });
      continue;
    }
    const targets = namedArtifactTargetsForCandidate(
      cand,
      opts.inventoryRoot,
    ).slice(0, maxEntries);
    const entries: LocalArtifactEntry[] = [];
    let budgetHit = false;
    for (const t of targets) {
      const alias = clampKey(`${id.path_alias}:${t.key}`);
      if (budgetHit || timeBudgetExhausted(budget)) {
        budgetHit = true;
        // Stop scheduling further named reads; emit explicit path-free gap.
        entries.push(gapEntry(t.key, alias, "time_budget_exceeded"));
        continue;
      }
      const measured = measureNamedFile(
        t.key,
        alias,
        t.abs,
        t.roots,
        budget,
        maxFile,
      );
      if (measured.status === "time_budget_exceeded") {
        budgetHit = true;
      }
      entries.push(measured);
    }
    const sorted = sortEntries(entries);
    baselines.push({
      instance_id: id.instance_id,
      path_hash: id.path_hash,
      path_alias: id.path_alias,
      entries: sorted,
      baseline_digest: artifactBaselineDigest(sorted),
    });
  }
  return baselines.sort((a, b) => a.instance_id.localeCompare(b.instance_id));
}
