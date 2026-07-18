/**
 * Namespaced macOS platform adapter (Ticket 13).
 *
 * Discovers only bounded registered candidates:
 * - install sources (Desktop / PATH / package_manager roots)
 * - profile / config / log / cache aliases
 * - registered operations
 *
 * Forbidden: broad home crawl, raw path export, executing discovered binaries
 * for version, sudo, system certificate/proxy/security-control changes,
 * signed app or OpenAI binary mutation, active ~/.codex mutation.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { enumerateSystemCandidates } from "../../instances/system-adapter.js";
import type {
  DiscoveredCandidate,
  PlatformId,
  SystemEnumerateCaps,
} from "../../instances/types.js";
import type {
  PlatformCapabilities,
  PlatformPathAlias,
  PlatformSafetyConstraints,
  RegisteredOperation,
  CodexVersionProvenance,
} from "../types.js";

const SAFETY: PlatformSafetyConstraints = {
  broad_home_crawl: false,
  raw_path_export: false,
  execute_discovered_binaries: false,
  sudo_required: false,
  system_certificate_change: false,
  system_proxy_change: false,
  security_control_change: false,
  signed_app_mutation: false,
  openai_binary_mutation: false,
  active_profile_mutation: false,
};

const MACOS_OPERATIONS: RegisteredOperation[] = [
  "diagnose_read_only",
  "scan_instances",
  "config_repair",
  "plugin_cache_repair",
  "verify",
  "rollback",
  "lifecycle_known_good",
  "lifecycle_canary",
  "upstream_preview",
  "impact_local",
  "package_smoke",
];

/** Registered public path aliases only — never absolute paths. */
const MACOS_PATH_ALIASES: PlatformPathAlias[] = [
  { alias: "DESKTOP_APP_BUNDLE", role: "install", registered: true },
  { alias: "DESKTOP_USER_APP_BUNDLE", role: "install", registered: true },
  { alias: "PATH_CODEX", role: "install", registered: true },
  { alias: "PKG_CODEX", role: "install", registered: true },
  { alias: "DESKTOP_PROFILE", role: "profile", registered: true },
  { alias: "CODEX_HOME_DEFAULT", role: "profile", registered: true },
  { alias: "CODEX_CONFIG_PRIMARY", role: "config", registered: true },
  { alias: "CODEX_LOG_ROOT", role: "log", registered: true },
  { alias: "PLUGIN_CACHE_ROOT", role: "cache", registered: true },
  { alias: "CRASH_REPORTS_METADATA", role: "crash_metadata", registered: true },
];

/** Exact system metadata path — no directory crawl. */
const SYSTEM_VERSION_PLIST =
  "/System/Library/CoreServices/SystemVersion.plist";

export interface MacosAdapterCaps {
  /** Injectable system enumeration (tests). */
  systemCaps?: SystemEnumerateCaps;
  /** Override platform detection (tests). */
  platform?: PlatformId;
  arch?: string;
  /** Optional home for registered Desktop user-app path only (never crawled). */
  homeDir?: string | null;
  /** Clock for tests. */
  now?: () => Date;
  /**
   * When true (default on real host), probe registered Desktop/PATH candidates
   * via the system adapter. Fixtures inject systemCaps instead.
   */
  probeHost?: boolean;
}

function sha256Text(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function detectPlatform(caps: MacosAdapterCaps): PlatformId {
  if (caps.platform) return caps.platform;
  if (caps.systemCaps?.platform) return caps.systemCaps.platform;
  switch (process.platform) {
    case "darwin":
      return "macos";
    case "win32":
      return "windows";
    case "linux":
      return "linux";
    default:
      return "unknown";
  }
}

function detectArch(caps: MacosAdapterCaps): string {
  if (caps.arch && caps.arch.length > 0) return caps.arch;
  if (caps.systemCaps?.arch && caps.systemCaps.arch.length > 0) {
    return caps.systemCaps.arch;
  }
  return process.arch || "unknown";
}

/**
 * Coarse ProductVersion from the registered SystemVersion.plist only.
 * Falls back to darwin kernel major (os.release) when plist is unavailable.
 * Never includes username, hostname, or home path.
 */
export function readCoarseOsVersion(
  pathKind?: (abs: string) => "file" | "dir" | "symlink" | "missing" | "other",
  readFile?: (abs: string) => string,
): string {
  const kind =
    pathKind ??
    ((abs: string) => {
      try {
        const st = fs.lstatSync(abs);
        if (st.isSymbolicLink()) return "symlink";
        if (st.isFile()) return "file";
        if (st.isDirectory()) return "dir";
        return "other";
      } catch {
        return "missing";
      }
    });
  const read =
    readFile ??
    ((abs: string) => fs.readFileSync(abs, { encoding: "utf8" }));

  if (kind(SYSTEM_VERSION_PLIST) === "file") {
    try {
      const raw = read(SYSTEM_VERSION_PLIST);
      // Minimal plist string parse for ProductVersion (no XML library).
      const m = raw.match(
        /<key>\s*ProductVersion\s*<\/key>\s*<string>\s*([^<]+)\s*<\/string>/i,
      );
      if (m && m[1]) {
        const ver = m[1].trim();
        const major = ver.split(".")[0] ?? "unknown";
        if (/^\d+$/.test(major)) return `macos-${major}.x`;
      }
    } catch {
      /* fall through */
    }
  }
  // Darwin kernel release e.g. 25.5.0 → macos-darwin-25.x
  const rel = os.release() || "unknown";
  const maj = rel.split(".")[0] ?? "unknown";
  if (/^\d+$/.test(maj)) return `macos-darwin-${maj}.x`;
  return "macos-unknown";
}

/**
 * Build macOS platform capabilities. Mutation is enabled only on darwin
 * when the adapter is the macOS namespace; other platforms get read_only.
 */
export function buildMacosCapabilities(
  caps: MacosAdapterCaps = {},
): PlatformCapabilities {
  const platform = detectPlatform(caps);
  const arch = detectArch(caps);
  const isMac = platform === "macos";
  const coarse = isMac
    ? readCoarseOsVersion(caps.systemCaps?.pathKind)
    : null;

  return {
    schema_version: 1,
    platform,
    arch,
    coarse_os_version: coarse,
    install_sources: isMac
      ? ["desktop_bundled", "path", "package_manager"]
      : [],
    path_aliases: isMac ? MACOS_PATH_ALIASES.map((a) => ({ ...a })) : [],
    operations: isMac ? [...MACOS_OPERATIONS] : ["diagnose_read_only"],
    constraints: { ...SAFETY },
    mutation_enabled: isMac,
    // Pre-receipt marketing claim: macOS aims for Full after real harness.
    declared_support_level: isMac ? "preview" : "unsupported",
  };
}

/**
 * Enumerate registered macOS install candidates only.
 * Delegates to the production system adapter with macOS-bounded defaults.
 * Never executes binaries; never crawls $HOME beyond exact registered paths.
 */
export function enumerateMacosCandidates(
  caps: MacosAdapterCaps = {},
): DiscoveredCandidate[] {
  const platform = detectPlatform(caps);
  if (platform !== "macos") return [];

  const systemCaps: SystemEnumerateCaps = {
    platform: "macos",
    arch: detectArch(caps),
    ...caps.systemCaps,
  };
  if (caps.homeDir !== undefined && caps.homeDir !== null) {
    systemCaps.homeDir = caps.homeDir;
  }
  // Explicit empty package roots unless tests register them — no invented crawl.
  if (systemCaps.packageRoots === undefined) {
    systemCaps.packageRoots = [];
  }
  // Windows/WSL paths never apply.
  systemCaps.msixPaths = [];
  systemCaps.wslPaths = [];

  if (caps.probeHost === false && !caps.systemCaps) {
    return [];
  }

  return enumerateSystemCandidates(systemCaps).filter(
    (c) =>
      c.platform === "macos" &&
      (c.install_source === "desktop_bundled" ||
        c.install_source === "path" ||
        c.install_source === "package_manager"),
  );
}

/**
 * Safe Codex version provenance from registered metadata only.
 * Does not execute any discovered binary.
 */
export function readMacosCodexVersionProvenance(
  candidates: DiscoveredCandidate[],
): CodexVersionProvenance {
  for (const c of candidates) {
    for (const meta of c.version_metadata_abs ?? []) {
      try {
        const st = fs.lstatSync(meta);
        if (!st.isFile() || st.isSymbolicLink()) continue;
        const raw = fs.readFileSync(meta, { encoding: "utf8" });
        if (meta.endsWith("Info.plist") || meta.endsWith(".plist")) {
          const m =
            raw.match(
              /<key>\s*CFBundleShortVersionString\s*<\/key>\s*<string>\s*([^<]+)\s*<\/string>/i,
            ) ??
            raw.match(
              /<key>\s*CFBundleVersion\s*<\/key>\s*<string>\s*([^<]+)\s*<\/string>/i,
            );
          if (m && m[1]) {
            return {
              available: true,
              version: m[1].trim().slice(0, 64),
              provenance: "plist_metadata",
            };
          }
        }
        if (meta.endsWith("package.json") || meta.endsWith("version.json")) {
          try {
            const j = JSON.parse(raw) as { version?: unknown };
            if (typeof j.version === "string" && j.version.length > 0) {
              return {
                available: true,
                version: j.version.slice(0, 64),
                provenance: meta.endsWith("package.json")
                  ? "package_json"
                  : "version_file",
              };
            }
          } catch {
            /* continue */
          }
        }
      } catch {
        /* continue */
      }
    }
    if (c.declared_version) {
      return {
        available: true,
        version: c.declared_version,
        provenance: c.declared_provenance ?? "fixture_declared",
      };
    }
  }
  return { available: false, version: null, provenance: "unavailable" };
}

/** Protected system / package roots — any hit is refused (after realpath). */
export const PROTECTED_ROOTS = [
  "/Applications",
  "/System",
  "/Library",
  "/usr",
  "/bin",
  "/sbin",
  "/private/var/db",
  "/var/db",
  "/root",
  "/etc",
  "/private/etc",
  "/dev",
  "/private/var/root",
] as const;

export interface DisposableTargetOptions {
  /**
   * Extra allowed roots for disposable writes (e.g. repo `.grok-output/verification`).
   * Each is realpath'd when present.
   */
  allowedRoots?: string[];
  /**
   * When true (default), existing paths must resolve under a trusted temp or
   * allowed root. Deny-only checks always apply.
   */
  requireTrustedRoot?: boolean;
}

function tryRealpath(abs: string): string | null {
  try {
    return fs.realpathSync.native(abs);
  } catch {
    return null;
  }
}

function pathIsUnder(root: string, candidate: string): boolean {
  const r = path.resolve(root);
  const c = path.resolve(candidate);
  if (c === r) return true;
  const prefix = r.endsWith(path.sep) ? r : r + path.sep;
  return c.startsWith(prefix);
}

function isProtectedPath(abs: string): boolean {
  for (const root of PROTECTED_ROOTS) {
    if (pathIsUnder(root, abs)) return true;
  }
  return false;
}

/**
 * Trusted disposable roots: realpath(os.tmpdir()), TMPDIR, and optional extras.
 * Public outputs never embed these paths.
 */
export function listTrustedDisposableRoots(
  extraAllowed: string[] = [],
): string[] {
  const roots: string[] = [];
  const add = (p: string | null | undefined) => {
    if (!p || typeof p !== "string" || p.length === 0) return;
    const resolved = path.resolve(p);
    const real = tryRealpath(resolved) ?? resolved;
    if (!roots.includes(real)) roots.push(real);
  };
  add(os.tmpdir());
  add(process.env.TMPDIR);
  add(process.env.TMP);
  add(process.env.TEMP);
  // Common macOS temp firmlink targets (only as allow roots, never as write-into-protected).
  add("/tmp");
  add("/private/tmp");
  add("/var/folders");
  add("/private/var/folders");
  for (const e of extraAllowed) add(e);
  return roots;
}

/**
 * Read-only, path-free witness of active ~/.codex existence + coarse metadata.
 * Never reads secret file contents; only directory metadata and top-level names.
 *
 * When ~/.codex is a symlink, isolation cannot be proved safely without
 * following the link (path leakage / out-of-bounds risk). The safest policy is
 * isolation_unprovable: digest is a stable unprovable marker and
 * `isolation_provable` is false so harness must not seal Full.
 */
export function captureActiveCodexHomeWitness(
  homeDir?: string | null,
): { digest: string; present: boolean; isolation_provable: boolean } {
  const home =
    homeDir ?? process.env.HOME ?? process.env.USERPROFILE ?? null;
  if (!home || home.length === 0) {
    return {
      digest: sha256Text("active_codex:v1:no_home"),
      present: false,
      isolation_provable: true,
    };
  }
  const active = path.resolve(path.join(home, ".codex"));
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(active);
  } catch {
    return {
      digest: sha256Text("active_codex:v1:absent"),
      present: false,
      isolation_provable: true,
    };
  }
  if (lst.isSymbolicLink()) {
    // Do not hash only symlink leaf metadata (uninformative) and do not follow
    // the link for a deep witness (privacy / boundary). Fail closed for Full.
    return {
      digest: sha256Text("active_codex:v1:isolation_unprovable:symlink"),
      present: true,
      isolation_provable: false,
    };
  }
  const parts = [
    "active_codex:v1",
    lst.isDirectory() ? "dir" : lst.isFile() ? "file" : "other",
    `ino=${lst.ino}`,
    `dev=${lst.dev}`,
    `mode=${lst.mode}`,
    `uid=${lst.uid}`,
    `gid=${lst.gid}`,
    `mtime=${Math.trunc(lst.mtimeMs)}`,
    `ctime=${Math.trunc(lst.ctimeMs)}`,
    `nlink=${lst.nlink}`,
    `size=${lst.size}`,
  ];
  if (lst.isDirectory()) {
    try {
      const names = fs.readdirSync(active).sort();
      // Bound listing — names only, no file contents (privacy).
      const bounded = names.slice(0, 64).join(",");
      parts.push(`entries=${names.length}`, `names=${bounded}`);
    } catch {
      parts.push("entries=unreadable");
    }
  }
  return {
    digest: sha256Text(parts.join("|")),
    present: true,
    isolation_provable: true,
  };
}

/**
 * Prove a candidate absolute path is not the active user Codex home,
 * not a protected system location, and not a symlink/firmlink alias escape.
 * Used by harness isolation only; public outputs never include the raw path.
 */
export function assertDisposableTarget(
  targetAbs: string,
  homeDir?: string | null,
  options: DisposableTargetOptions = {},
): { ok: true; real: string } | { ok: false; code: string } {
  if (
    typeof targetAbs !== "string" ||
    targetAbs.length === 0 ||
    targetAbs.length > 4096 ||
    targetAbs.includes("\0")
  ) {
    return { ok: false, code: "INVALID_TARGET" };
  }

  const resolved = path.resolve(targetAbs);
  const home =
    homeDir ??
    process.env.HOME ??
    process.env.USERPROFILE ??
    null;

  /**
   * Collect every deny root for the active Codex profile:
   * - logical HOME/.codex
   * - realpath(HOME)/.codex
   * - realpath(HOME/.codex) itself (symlink/firmlink target)
   * Fail-closed: refuse the logical path, its real target, and any child.
   */
  const collectActiveCodexDenyRoots = (): string[] => {
    if (!home || home.length === 0) return [];
    const roots = new Set<string>();
    const homeResolved = path.resolve(home);
    const activeLogical = path.resolve(path.join(home, ".codex"));
    roots.add(activeLogical);

    // realpath of active ~/.codex itself (not only HOME).
    const activeReal = tryRealpath(activeLogical);
    if (activeReal) roots.add(activeReal);

    const homeReal = tryRealpath(homeResolved);
    if (homeReal) {
      const viaHome = path.resolve(path.join(homeReal, ".codex"));
      roots.add(viaHome);
      const viaHomeReal = tryRealpath(viaHome);
      if (viaHomeReal) roots.add(viaHomeReal);
    }
    return [...roots];
  };

  const activeDenyRoots = collectActiveCodexDenyRoots();

  const denyPath = (abs: string): string | null => {
    for (const root of activeDenyRoots) {
      if (pathIsUnder(root, abs)) {
        return "ACTIVE_CODEX_PROFILE_REFUSED";
      }
    }
    if (home && home.length > 0) {
      const homeResolved = path.resolve(home);
      if (abs === homeResolved) {
        return "HOME_ROOT_REFUSED";
      }
      const homeReal = tryRealpath(homeResolved);
      if (homeReal && abs === homeReal) {
        return "HOME_ROOT_REFUSED";
      }
    }
    if (isProtectedPath(abs)) {
      return "PROTECTED_ROOT_REFUSED";
    }
    return null;
  };

  const deniedResolved = denyPath(resolved);
  if (deniedResolved) {
    return { ok: false, code: deniedResolved };
  }

  // lstat the leaf when it exists — refuse symlink leaves.
  let lst: fs.Stats | null = null;
  try {
    lst = fs.lstatSync(resolved);
  } catch {
    lst = null;
  }

  if (lst?.isSymbolicLink()) {
    return { ok: false, code: "SYMLINK_REFUSED" };
  }

  // Walk parent segments: refuse if any existing segment is a symlink that
  // redirects outside trusted roots (firmlink/symlink alias escape).
  // Fail-closed: existing paths must realpath; unresolvable aliases are refused.
  const real = tryRealpath(resolved);
  if (lst && !real) {
    return { ok: false, code: "REALPATH_UNPROVABLE" };
  }
  if (real) {
    const deniedReal = denyPath(real);
    if (deniedReal) {
      return { ok: false, code: deniedReal };
    }
  }

  // When the path exists, require ownership by current uid when getuid is available.
  if (lst && typeof process.getuid === "function") {
    const uid = process.getuid();
    if (lst.uid !== uid) {
      return { ok: false, code: "OWNER_UID_REFUSED" };
    }
  }

  // Existing paths (or their realpath) must sit under a trusted disposable root.
  const requireTrusted = options.requireTrustedRoot !== false;
  if (requireTrusted) {
    const trusted = listTrustedDisposableRoots(options.allowedRoots ?? []);
    const candidate = real ?? resolved;
    // For not-yet-created paths, check the nearest existing ancestor.
    let check = candidate;
    if (!lst) {
      let cursor = path.resolve(resolved);
      while (cursor !== path.dirname(cursor)) {
        try {
          fs.lstatSync(cursor);
          check = tryRealpath(cursor) ?? cursor;
          break;
        } catch {
          cursor = path.dirname(cursor);
        }
      }
    }
    const underTrusted = trusted.some((t) => pathIsUnder(t, check));
    if (!underTrusted) {
      return { ok: false, code: "UNTRUSTED_ROOT_REFUSED" };
    }
  }

  return { ok: true, real: real ?? resolved };
}

/**
 * Assert harness output directory passes the isolation gate.
 * Allowed only under trusted temp roots or explicitly listed allowedRoots
 * (typically audited repo `.grok-output/verification`).
 */
export function assertHarnessOutputDir(
  outDir: string,
  homeDir?: string | null,
  options: DisposableTargetOptions = {},
): { ok: true; real: string } | { ok: false; code: string } {
  return assertDisposableTarget(outDir, homeDir, {
    requireTrustedRoot: true,
    allowedRoots: options.allowedRoots,
    ...options,
  });
}

/** Stable isolation digest (hashes only; no paths). */
export function isolationDigestOf(parts: {
  scenario_count: number;
  platform: string;
  arch: string;
  no_sudo: true;
  disposable_only: true;
  /** Path-free active ~/.codex witness digest bound into isolation. */
  active_home_witness_digest: string;
}): string {
  return sha256Text(
    [
      "isolation:v1",
      parts.platform,
      parts.arch,
      String(parts.scenario_count),
      "no_sudo",
      "disposable_only",
      parts.active_home_witness_digest,
    ].join("|"),
  );
}

/** Public alias map for registered macOS roles (path-free). */
export function macosRegisteredAliases(): PlatformPathAlias[] {
  return MACOS_PATH_ALIASES.map((a) => ({ ...a }));
}

/** Whether an operation is registered on the macOS adapter. */
export function isMacosOperationRegistered(op: string): boolean {
  return (MACOS_OPERATIONS as string[]).includes(op);
}
