/**
 * Read version/build evidence from metadata/manifest files only.
 * Never execute a discovered binary merely to learn its version.
 *
 * All metadata candidates are clamped to explicit allowed roots.
 * Implicit parent traversal (`../Info.plist`, npm parent paths) is removed.
 * Parent metadata is only reachable when the system adapter registers a
 * trusted install root that already contains that file.
 */
import path from "node:path";
import { MAX_VERSION_META_BYTES } from "./limits.js";
import {
  findContainingRoot,
  isInsideRoot,
  readFileUnderAllowedRoots,
  readRelativeUnderRoot,
} from "./path-bounded.js";
import type { DiscoveredCandidate, VersionProvenance } from "./types.js";

export interface VersionEvidence {
  version: string | null;
  build: string | null;
  provenance: VersionProvenance;
}

function parseJsonVersion(text: string): {
  version: string | null;
  build: string | null;
} {
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    const version =
      typeof obj.version === "string" && obj.version.length <= 128
        ? obj.version
        : null;
    const buildRaw = obj.build ?? obj.build_sha ?? obj.buildSha;
    const build =
      typeof buildRaw === "string" && buildRaw.length <= 128 ? buildRaw : null;
    return { version, build };
  } catch {
    return { version: null, build: null };
  }
}

/** Extract CFBundleShortVersionString / CFBundleVersion from a minimal plist text. */
function parsePlistVersion(text: string): {
  version: string | null;
  build: string | null;
} {
  const short =
    text.match(
      /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/,
    )?.[1] ?? null;
  const build =
    text.match(/<key>CFBundleVersion<\/key>\s*<string>([^<]+)<\/string>/)?.[1] ??
    null;
  return {
    version: short && short.length <= 128 ? short : null,
    build: build && build.length <= 128 ? build : null,
  };
}

/** Identity / Version from a minimal AppxManifest. */
function parseMsixVersion(text: string): {
  version: string | null;
  build: string | null;
} {
  const m =
    text.match(/\bVersion="([^"]+)"/) ??
    text.match(/<Identity[^>]*\sVersion="([^"]+)"/);
  const version = m?.[1] && m[1].length <= 128 ? m[1] : null;
  return { version, build: null };
}

function parseByProvenance(
  text: string,
  provenance: VersionProvenance,
): { version: string | null; build: string | null } {
  if (provenance === "plist_metadata") return parsePlistVersion(text);
  if (provenance === "msix_manifest") return parseMsixVersion(text);
  return parseJsonVersion(text);
}

function provenanceForBasename(base: string): VersionProvenance {
  const b = base.toLowerCase();
  if (b === "package.json") return "package_json";
  if (b === "info.plist" || b.endsWith(".plist")) return "plist_metadata";
  if (b === "appxmanifest.xml") return "msix_manifest";
  return "version_file";
}

function tryMetaText(
  text: string | null,
  provenance: VersionProvenance,
): VersionEvidence | null {
  if (text === null) return null;
  const p = parseByProvenance(text, provenance);
  if (p.version) return { ...p, provenance };
  return null;
}

/**
 * Collect explicit allowed roots for this candidate.
 * Fixture mode: inventoryRoot only.
 * System mode: candidate.trusted_metadata_roots (+ inventoryRoot if provided).
 * Never invent parent-of-candidate roots.
 */
export function allowedRootsForCandidate(
  candidate: DiscoveredCandidate,
  inventoryRoot?: string,
): string[] {
  const roots: string[] = [];
  if (inventoryRoot) roots.push(path.resolve(inventoryRoot));
  if (Array.isArray(candidate.trusted_metadata_roots)) {
    for (const r of candidate.trusted_metadata_roots) {
      if (typeof r === "string" && r.length > 0) roots.push(path.resolve(r));
    }
  }
  // Deduplicate while preserving order.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of roots) {
    if (seen.has(r)) continue;
    seen.add(r);
    out.push(r);
  }
  return out;
}

/**
 * Resolve version evidence for a candidate without executing it.
 * Prefer declared fixture evidence, then metadata under explicit allowed roots.
 */
export function readVersionEvidence(
  candidate: DiscoveredCandidate,
  inventoryRoot?: string,
): VersionEvidence {
  if (
    candidate.declared_version !== undefined &&
    candidate.declared_version !== null
  ) {
    return {
      version: candidate.declared_version,
      build: candidate.declared_build ?? null,
      provenance: candidate.declared_provenance ?? "fixture_declared",
    };
  }

  const roots = allowedRootsForCandidate(candidate, inventoryRoot);
  if (roots.length === 0) {
    return { version: null, build: null, provenance: "unavailable" };
  }

  // Explicit relative metadata declared by inventory / adapter (must stay in root).
  if (candidate.version_metadata_rel) {
    const rel = candidate.version_metadata_rel;
    // Prefer inventoryRoot when present; otherwise each trusted root.
    const tryRoots = inventoryRoot
      ? [path.resolve(inventoryRoot)]
      : roots;
    for (const root of tryRoots) {
      const base = path.basename(rel);
      const prov = provenanceForBasename(base);
      const text = readRelativeUnderRoot(root, rel, MAX_VERSION_META_BYTES);
      const hit = tryMetaText(text, prov);
      if (hit) return hit;
    }
  }

  // Adapter-declared absolute metadata files (must still fall inside trusted roots).
  if (Array.isArray(candidate.version_metadata_abs)) {
    for (const abs of candidate.version_metadata_abs) {
      if (typeof abs !== "string" || abs.length === 0) continue;
      const prov = provenanceForBasename(path.basename(abs));
      const text = readFileUnderAllowedRoots(abs, roots, MAX_VERSION_META_BYTES);
      const hit = tryMetaText(text, prov);
      if (hit) return hit;
    }
  }

  // Adjacent metadata only when the candidate directory itself is inside a trusted root.
  // No implicit parent traversal.
  const near = path.dirname(path.resolve(candidate.path));
  const nearRoot = findContainingRoot(near, roots);
  if (nearRoot && isInsideRoot(nearRoot, near)) {
    const probes: Array<{ file: string; provenance: VersionProvenance }> = [
      { file: "version.json", provenance: "version_file" },
      { file: "VERSION.json", provenance: "version_file" },
      { file: "package.json", provenance: "package_json" },
      { file: "Info.plist", provenance: "plist_metadata" },
      { file: "AppxManifest.xml", provenance: "msix_manifest" },
    ];
    for (const p of probes) {
      const abs = path.join(near, p.file);
      const text = readFileUnderAllowedRoots(abs, roots, MAX_VERSION_META_BYTES);
      const hit = tryMetaText(text, p.provenance);
      if (hit) return hit;
    }
  }

  return { version: null, build: null, provenance: "unavailable" };
}
