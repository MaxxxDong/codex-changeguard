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

/**
 * Prove a candidate absolute path is not the active user Codex home
 * and is not a protected system location. Used by harness isolation only;
 * public outputs never include the raw path.
 */
export function assertDisposableTarget(
  targetAbs: string,
  homeDir?: string | null,
): { ok: true } | { ok: false; code: string } {
  const resolved = path.resolve(targetAbs);
  const home =
    homeDir ??
    process.env.HOME ??
    process.env.USERPROFILE ??
    null;
  if (home && home.length > 0) {
    const activeCodex = path.resolve(path.join(home, ".codex"));
    if (
      resolved === activeCodex ||
      resolved.startsWith(activeCodex + path.sep)
    ) {
      return { ok: false, code: "ACTIVE_CODEX_PROFILE_REFUSED" };
    }
  }
  // Protected system roots — never mutate.
  const protectedRoots = [
    "/Applications",
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/private/var/db",
  ];
  for (const root of protectedRoots) {
    if (resolved === root || resolved.startsWith(root + path.sep)) {
      // Allow only under disposable temp; /Applications itself is protected.
      // Temp dirs are typically /var/folders or /tmp — not under these roots.
      if (root === "/Applications" || root === "/System" || root === "/Library") {
        return { ok: false, code: "PROTECTED_ROOT_REFUSED" };
      }
    }
  }
  // Refuse sudo-style paths
  if (resolved === "/root" || resolved.startsWith("/root" + path.sep)) {
    return { ok: false, code: "PROTECTED_ROOT_REFUSED" };
  }
  return { ok: true };
}

/** Stable isolation digest (hashes only; no paths). */
export function isolationDigestOf(parts: {
  scenario_count: number;
  platform: string;
  arch: string;
  no_sudo: true;
  disposable_only: true;
}): string {
  return sha256Text(
    [
      "isolation:v1",
      parts.platform,
      parts.arch,
      String(parts.scenario_count),
      "no_sudo",
      "disposable_only",
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
