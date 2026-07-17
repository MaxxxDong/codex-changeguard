/**
 * Enumerate Codex install candidates as separate identities.
 * Uses inventory fixtures / injectable roots — never scans arbitrary user homes
 * unless an explicit production adapter is supplied with concrete roots.
 */
import fs from "node:fs";
import path from "node:path";
import { constants as fsConstants } from "node:fs";
import {
  INVENTORY_FILE_NAME,
  MAX_INVENTORY_BYTES,
  MAX_INSTANCES,
} from "./limits.js";
import {
  assertRealDirectory,
  normalizeRelativeUnderRoot,
  resolveRegularFileUnderRoot,
} from "./path-bounded.js";
import type {
  DiscoveredCandidate,
  InstallSource,
  InstanceSurface,
  ObservedContext,
  PlatformId,
} from "./types.js";

export class InventoryError extends Error {
  readonly code: string;
  constructor(code: string, message = "Invalid inventory.") {
    super(message);
    this.name = "InventoryError";
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

function readBoundedNoSymlink(abs: string, maxBytes: number): string {
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(abs);
  } catch {
    throw new InventoryError("INVENTORY_NOT_FOUND", "Inventory not found.");
  }
  if (lst.isSymbolicLink()) {
    throw new InventoryError("SYMLINK_REFUSED", "Symlink inventory refused.");
  }
  if (!lst.isFile() || lst.size > maxBytes) {
    throw new InventoryError("INVENTORY_LIMIT", "Inventory refused.");
  }
  let fd: number;
  try {
    fd = fs.openSync(abs, openReadFlags());
  } catch {
    throw new InventoryError("INVENTORY_NOT_FOUND", "Inventory not found.");
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) {
      throw new InventoryError("INVENTORY_LIMIT", "Inventory refused.");
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

const SOURCES = new Set<InstallSource>([
  "desktop_bundled",
  "path",
  "package_manager",
  "windows_msix",
  "wsl",
  "unknown",
]);

const SURFACES = new Set<InstanceSurface>(["desktop", "cli", "unknown"]);
const PLATFORMS = new Set<PlatformId>([
  "macos",
  "windows",
  "linux",
  "wsl",
  "unknown",
]);

function asString(v: unknown, field: string): string {
  if (typeof v !== "string" || v.length === 0 || v.length > 1024) {
    throw new InventoryError("MALFORMED_INVENTORY", `Invalid ${field}.`);
  }
  return v;
}

function asNullableString(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v !== "string" || v.length > 1024) {
    throw new InventoryError("MALFORMED_INVENTORY", "Invalid string field.");
  }
  return v;
}

export interface ParsedInventory {
  platform: PlatformId;
  arch: string;
  candidates: DiscoveredCandidate[];
  observed: ObservedContext;
}

/**
 * Load an isolated inventory fixture describing multi-instance roots.
 * Paths in the inventory are relative to the inventory root and resolved only
 * for local hashing/metadata reads — never emitted in public results.
 */
export function loadInventory(inventoryRoot: string): ParsedInventory {
  if (typeof inventoryRoot !== "string" || inventoryRoot.length === 0) {
    throw new InventoryError("INVALID_ROOT", "Invalid inventory root.");
  }
  let rootAbs: string;
  try {
    rootAbs = assertRealDirectory(inventoryRoot);
  } catch (e) {
    const code =
      e && typeof e === "object" && "code" in e
        ? String((e as { code: string }).code)
        : "INVALID_ROOT";
    if (code === "ROOT_NOT_FOUND") {
      throw new InventoryError("INVENTORY_NOT_FOUND", "Inventory root not found.");
    }
    if (code === "SYMLINK_ESCAPE") {
      throw new InventoryError("INVALID_ROOT", "Inventory root refused.");
    }
    throw new InventoryError("INVALID_ROOT", "Inventory root refused.");
  }

  // Inventory file: no-follow segment walk under root (Ticket 01 equivalent).
  let text: string;
  try {
    const meta = resolveRegularFileUnderRoot(rootAbs, INVENTORY_FILE_NAME);
    if (meta.size > MAX_INVENTORY_BYTES) {
      throw new InventoryError("INVENTORY_LIMIT", "Inventory refused.");
    }
    text = readBoundedNoSymlink(meta.abs, MAX_INVENTORY_BYTES);
  } catch (e) {
    if (e instanceof InventoryError) throw e;
    throw new InventoryError("INVENTORY_NOT_FOUND", "Inventory not found.");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new InventoryError("MALFORMED_INVENTORY", "Inventory JSON invalid.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new InventoryError("MALFORMED_INVENTORY", "Inventory JSON invalid.");
  }
  const obj = raw as Record<string, unknown>;
  if (obj.schema_version !== 1) {
    throw new InventoryError("SCHEMA", "Unsupported inventory schema.");
  }

  const platform = asString(obj.platform ?? "unknown", "platform") as PlatformId;
  if (!PLATFORMS.has(platform)) {
    throw new InventoryError("MALFORMED_INVENTORY", "Invalid platform.");
  }
  const arch = asString(obj.arch ?? "unknown", "arch");

  if (!Array.isArray(obj.candidates)) {
    throw new InventoryError("MALFORMED_INVENTORY", "candidates required.");
  }
  if (obj.candidates.length > MAX_INSTANCES) {
    throw new InventoryError("INSTANCE_LIMIT", "Too many candidates.");
  }

  const candidates: DiscoveredCandidate[] = [];
  for (const item of obj.candidates) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new InventoryError("MALFORMED_INVENTORY", "Invalid candidate.");
    }
    const c = item as Record<string, unknown>;
    const install_source = asString(
      c.install_source,
      "install_source",
    ) as InstallSource;
    if (!SOURCES.has(install_source)) {
      throw new InventoryError("MALFORMED_INVENTORY", "Invalid install_source.");
    }
    const surface = asString(c.surface ?? "unknown", "surface") as InstanceSurface;
    if (!SURFACES.has(surface)) {
      throw new InventoryError("MALFORMED_INVENTORY", "Invalid surface.");
    }
    const rel = asString(c.relative_path, "relative_path");
    let safeRel: string;
    try {
      safeRel = normalizeRelativeUnderRoot(rel);
    } catch {
      throw new InventoryError("PATH_ESCAPE", "Candidate path refused.");
    }
    const abs = path.resolve(rootAbs, safeRel);
    const relCheck = path.relative(rootAbs, abs);
    if (relCheck.startsWith("..") || path.isAbsolute(relCheck)) {
      throw new InventoryError("PATH_ESCAPE", "Candidate path refused.");
    }
    // Candidate leaf may be missing in some fixtures; when present, refuse
    // intermediate symlink segments (no out-of-root reads via redirected trees).
    try {
      resolveRegularFileUnderRoot(rootAbs, safeRel);
    } catch (e) {
      const code =
        e && typeof e === "object" && "code" in e
          ? String((e as { code: string }).code)
          : "";
      if (code === "SYMLINK_ESCAPE" || code === "PATH_ESCAPE") {
        throw new InventoryError(
          code === "SYMLINK_ESCAPE" ? "SYMLINK_REFUSED" : "PATH_ESCAPE",
          "Candidate path refused.",
        );
      }
      // NOT_FOUND / non-file: still allow identity (placeholder may be absent);
      // version evidence will report unavailable rather than following links.
    }

    // version_metadata_rel must stay under inventory root — no `..` segments.
    let version_metadata_rel = asNullableString(c.version_metadata_rel);
    if (version_metadata_rel) {
      try {
        version_metadata_rel = normalizeRelativeUnderRoot(version_metadata_rel);
      } catch {
        throw new InventoryError("PATH_ESCAPE", "Metadata path refused.");
      }
    }

    let path_precedence: number | null = null;
    if (c.path_precedence !== undefined && c.path_precedence !== null) {
      if (
        typeof c.path_precedence !== "number" ||
        !Number.isInteger(c.path_precedence) ||
        c.path_precedence < 0
      ) {
        throw new InventoryError("MALFORMED_INVENTORY", "Invalid path_precedence.");
      }
      path_precedence = c.path_precedence;
    } else if (install_source === "path") {
      path_precedence = candidates.filter((x) => x.install_source === "path")
        .length;
    }

    candidates.push({
      install_source,
      surface,
      path: abs,
      platform:
        install_source === "wsl"
          ? "wsl"
          : ((c.platform as PlatformId | undefined) ?? platform),
      arch: typeof c.arch === "string" ? c.arch : arch,
      profile_root_alias: asNullableString(c.profile_root_alias),
      config_root_alias: asNullableString(c.config_root_alias),
      path_precedence,
      declared_version:
        c.version === undefined ? undefined : asNullableString(c.version),
      declared_build:
        c.build === undefined ? undefined : asNullableString(c.build),
      declared_provenance:
        typeof c.version_provenance === "string"
          ? (c.version_provenance as DiscoveredCandidate["declared_provenance"])
          : undefined,
      version_metadata_rel,
      // Fixture mode: inventory root is the sole trusted metadata root.
      trusted_metadata_roots: [rootAbs],
    });
  }

  // Ensure PATH / package_manager / desktop / msix / wsl stay distinct — never collapse.
  const observedRaw =
    obj.observed_context && typeof obj.observed_context === "object"
      ? (obj.observed_context as Record<string, unknown>)
      : {};
  const observed: ObservedContext = {
    process_path: resolveOptionalRel(rootAbs, observedRaw.process_path_rel),
    log_path: resolveOptionalRel(rootAbs, observedRaw.log_path_rel),
    launch_path: resolveOptionalRel(rootAbs, observedRaw.launch_path_rel),
    process_path_hash:
      typeof observedRaw.process_path_hash === "string"
        ? observedRaw.process_path_hash
        : null,
    log_path_hash:
      typeof observedRaw.log_path_hash === "string"
        ? observedRaw.log_path_hash
        : null,
    launch_path_hash:
      typeof observedRaw.launch_path_hash === "string"
        ? observedRaw.launch_path_hash
        : null,
    process_version:
      typeof observedRaw.process_version === "string"
        ? observedRaw.process_version
        : null,
  };

  return { platform, arch, candidates, observed };
}

function resolveOptionalRel(
  rootAbs: string,
  rel: unknown,
): string | null {
  if (rel === null || rel === undefined) return null;
  if (typeof rel !== "string" || rel.length === 0) return null;
  let safeRel: string;
  try {
    safeRel = normalizeRelativeUnderRoot(rel);
  } catch {
    throw new InventoryError("PATH_ESCAPE", "Observed path refused.");
  }
  const abs = path.resolve(rootAbs, safeRel);
  const check = path.relative(rootAbs, abs);
  if (check.startsWith("..") || path.isAbsolute(check)) {
    throw new InventoryError("PATH_ESCAPE", "Observed path refused.");
  }
  return abs;
}
