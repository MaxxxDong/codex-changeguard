/**
 * Namespaced Windows 11 system adapter (Ticket 14).
 * Injected env/fs capabilities distinguish MSIX, Desktop app, Desktop-bundled
 * CLI, PATH CLI, WSL, and multiple user profiles without collapsing identities.
 * Never executes candidates; never writes system packages.
 */
import fs from "node:fs";
import path from "node:path";
import { MAX_INSTANCES } from "../limits.js";
import { assertRealDirectory, isInsideRoot } from "../path-bounded.js";
import type { DiscoveredCandidate, PlatformId } from "../types.js";
import type {
  WindowsDiscoveryResult,
  WindowsEnumerateCaps,
  WindowsInstallKind,
  WindowsProfileSpec,
} from "./types.js";

const DEFAULT_MAX_PATH_ENTRIES = 64;
const CODEX_NAMES = new Set(["codex", "codex.exe", "Codex.exe", "Codex"]);

function realDefaultPathKind(
  absPath: string,
): "file" | "dir" | "symlink" | "missing" | "other" {
  try {
    const st = fs.lstatSync(absPath);
    if (st.isSymbolicLink()) return "symlink";
    if (st.isFile()) return "file";
    if (st.isDirectory()) return "dir";
    return "other";
  } catch {
    return "missing";
  }
}

function homeOf(caps: WindowsEnumerateCaps): string | null {
  if (caps.homeDir) return caps.homeDir;
  const env = caps.env ?? {};
  const h = env.HOME || env.USERPROFILE || null;
  return h && h.length > 0 ? h : null;
}

function pathEntriesOf(caps: WindowsEnumerateCaps): string[] {
  if (caps.pathEntries) return caps.pathEntries;
  const env = caps.env ?? {};
  const raw = env.PATH || env.Path || "";
  const delim = caps.pathDelimiter ?? ";";
  return raw
    .split(delim)
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
}

function isCodexBasename(name: string): boolean {
  return (
    CODEX_NAMES.has(name) ||
    name.toLowerCase() === "codex" ||
    name.toLowerCase() === "codex.exe"
  );
}

function pushCandidate(
  out: DiscoveredCandidate[],
  c: DiscoveredCandidate,
  max: number,
  seen: Set<string>,
): void {
  if (out.length >= max) return;
  const key = `${c.install_source}|${c.surface}|${path.resolve(c.path)}|${c.profile_root_alias ?? ""}`;
  if (seen.has(key)) return;
  seen.add(key);
  out.push(c);
}

function trustDir(
  dir: string,
  pathKind: (p: string) => string,
): string[] {
  if (pathKind(dir) !== "dir") return [];
  try {
    return [assertRealDirectory(dir)];
  } catch {
    return [];
  }
}

function defaultDesktopAppPaths(caps: WindowsEnumerateCaps): string[] {
  if (caps.desktopPaths) return caps.desktopPaths;
  const env = caps.env ?? {};
  const local = env.LOCALAPPDATA;
  if (!local) return [];
  return [
    path.join(local, "Programs", "Codex", "Codex.exe"),
    path.join(local, "Codex", "Codex.exe"),
  ];
}

/** Documented Desktop-bundled CLI relative layouts under the Desktop app root. */
function defaultDesktopCliPaths(caps: WindowsEnumerateCaps): string[] {
  if (caps.desktopCliPaths) return caps.desktopCliPaths;
  const env = caps.env ?? {};
  const local = env.LOCALAPPDATA;
  if (!local) return [];
  // Registered exact candidates only — no directory crawl.
  return [
    path.join(local, "Programs", "Codex", "resources", "codex", "codex.exe"),
    path.join(local, "Programs", "Codex", "resources", "cli", "codex.exe"),
    path.join(local, "Codex", "resources", "codex", "codex.exe"),
  ];
}

function defaultMsixPaths(caps: WindowsEnumerateCaps): string[] {
  if (caps.msixPaths) return caps.msixPaths;
  const env = caps.env ?? {};
  const local = env.LOCALAPPDATA;
  if (!local) return [];
  return [
    path.join(local, "Microsoft", "WindowsApps", "codex.exe"),
    path.join(local, "Microsoft", "WindowsApps", "Codex.exe"),
  ];
}

function defaultWslPaths(caps: WindowsEnumerateCaps): string[] {
  if (caps.wslPaths) return caps.wslPaths;
  // Host-registered WSL paths only when explicitly supplied or classic locations
  // under injected roots — production never invents \\wsl$\ crawls.
  return [];
}

function defaultProfiles(caps: WindowsEnumerateCaps): WindowsProfileSpec[] {
  if (caps.userProfiles) return caps.userProfiles;
  const home = homeOf(caps);
  if (!home) return [];
  return [
    {
      profile_root_alias: "WIN_USER_PROFILE",
      config_root_alias: "WIN_USER_CODEX_CONFIG",
      root_abs: path.join(home, ".codex"),
    },
  ];
}

function kindOf(c: DiscoveredCandidate): WindowsInstallKind {
  if (c.install_source === "windows_msix") return "msix_app";
  if (c.install_source === "desktop_bundled" && c.surface === "cli") {
    return "desktop_bundled_cli";
  }
  if (c.install_source === "desktop_bundled") return "desktop_app";
  if (c.install_source === "path") return "path_cli";
  if (c.install_source === "wsl") return "wsl_cli";
  if (c.install_source === "package_manager") return "package_manager_cli";
  return "path_cli";
}

/**
 * Enumerate Windows-oriented candidates from injected capabilities.
 * When platform is not windows/wsl, still honors explicit path lists for tests.
 */
export function enumerateWindowsCandidates(
  caps: WindowsEnumerateCaps = {},
): WindowsDiscoveryResult {
  const platform: PlatformId = caps.platform ?? "windows";
  const arch = caps.arch && caps.arch.length > 0 ? caps.arch : "x64";
  const pathKind = caps.pathKind ?? realDefaultPathKind;
  const max = Math.min(caps.maxCandidates ?? MAX_INSTANCES, MAX_INSTANCES);
  const maxPath = Math.min(
    caps.maxPathEntries ?? DEFAULT_MAX_PATH_ENTRIES,
    DEFAULT_MAX_PATH_ENTRIES,
  );
  const out: DiscoveredCandidate[] = [];
  const seen = new Set<string>();
  const profiles = defaultProfiles(caps);
  const primaryProfile = profiles[0] ?? null;

  // --- MSIX App Execution Alias (existence only; no package store crawl) ---
  for (const p of defaultMsixPaths(caps)) {
    if (out.length >= max) break;
    const kind = pathKind(p);
    if (kind === "missing" || kind === "dir" || kind === "other") continue;
    const dir = path.dirname(p);
    const trusted = trustDir(dir, pathKind);
    pushCandidate(
      out,
      {
        install_source: "windows_msix",
        surface: "desktop",
        path: path.resolve(p),
        platform: "windows",
        arch,
        profile_root_alias: "MSIX_PROFILE",
        config_root_alias: primaryProfile?.config_root_alias ?? null,
        path_precedence: null,
        trusted_metadata_roots: trusted,
        version_metadata_abs: trusted.length
          ? [path.join(dir, "AppxManifest.xml")]
          : [],
      },
      max,
      seen,
    );
  }

  // --- Desktop app ---
  for (const p of defaultDesktopAppPaths(caps)) {
    if (out.length >= max) break;
    const kind = pathKind(p);
    if (kind === "missing" || kind === "dir" || kind === "other") continue;
    const dir = path.dirname(p);
    const trusted = trustDir(dir, pathKind);
    pushCandidate(
      out,
      {
        install_source: "desktop_bundled",
        surface: "desktop",
        path: path.resolve(p),
        platform: "windows",
        arch,
        profile_root_alias:
          primaryProfile?.profile_root_alias ?? "DESKTOP_PROFILE",
        config_root_alias: primaryProfile?.config_root_alias ?? null,
        path_precedence: null,
        trusted_metadata_roots: trusted,
        version_metadata_abs: trusted.length
          ? [
              path.join(dir, "version.json"),
              path.join(dir, "AppxManifest.xml"),
            ]
          : [],
      },
      max,
      seen,
    );
  }

  // --- Desktop-bundled CLI (distinct surface=cli identity) ---
  for (const p of defaultDesktopCliPaths(caps)) {
    if (out.length >= max) break;
    const kind = pathKind(p);
    if (kind === "missing" || kind === "dir" || kind === "other") continue;
    const dir = path.dirname(p);
    const trusted = trustDir(dir, pathKind);
    pushCandidate(
      out,
      {
        install_source: "desktop_bundled",
        surface: "cli",
        path: path.resolve(p),
        platform: "windows",
        arch,
        profile_root_alias: "DESKTOP_CLI_PROFILE",
        config_root_alias: primaryProfile?.config_root_alias ?? null,
        path_precedence: null,
        trusted_metadata_roots: trusted,
        version_metadata_abs: trusted.length
          ? [
              path.join(dir, "version.json"),
              path.join(dir, "package.json"),
            ]
          : [],
      },
      max,
      seen,
    );
  }

  // --- PATH CLI ---
  let pathIndex = 0;
  for (const dir of pathEntriesOf(caps).slice(0, maxPath)) {
    if (out.length >= max) break;
    if (pathKind(dir) !== "dir") {
      pathIndex += 1;
      continue;
    }
    for (const name of ["codex", "codex.exe"]) {
      const full = path.join(dir, name);
      const kind = pathKind(full);
      if (kind === "missing" || kind === "dir" || kind === "other") continue;
      if (!isCodexBasename(path.basename(full))) continue;
      const trusted = trustDir(dir, pathKind);
      pushCandidate(
        out,
        {
          install_source: "path",
          surface: "cli",
          path: path.resolve(full),
          platform: "windows",
          arch,
          profile_root_alias: null,
          config_root_alias: primaryProfile?.config_root_alias ?? null,
          path_precedence: pathIndex,
          trusted_metadata_roots: trusted,
          version_metadata_abs: trusted.length
            ? [
                path.join(dir, "version.json"),
                path.join(dir, "package.json"),
              ]
            : [],
        },
        max,
        seen,
      );
    }
    pathIndex += 1;
  }

  // --- Package manager roots (explicit only) ---
  for (const root of caps.packageRoots ?? []) {
    if (out.length >= max) break;
    let trustedRoot: string;
    try {
      trustedRoot = assertRealDirectory(root);
    } catch {
      continue;
    }
    let binary: string | null = null;
    for (const cand of [
      path.join(trustedRoot, "bin", "codex"),
      path.join(trustedRoot, "bin", "codex.exe"),
      path.join(trustedRoot, "codex"),
      path.join(trustedRoot, "codex.exe"),
    ]) {
      const k = pathKind(cand);
      if (k === "file" || k === "symlink") {
        binary = cand;
        break;
      }
    }
    const identity =
      binary ??
      (pathKind(path.join(trustedRoot, "package.json")) === "file"
        ? path.join(trustedRoot, "package.json")
        : null);
    if (!identity) continue;
    pushCandidate(
      out,
      {
        install_source: "package_manager",
        surface: "cli",
        path: path.resolve(identity),
        platform: "windows",
        arch,
        profile_root_alias: null,
        config_root_alias: null,
        path_precedence: null,
        trusted_metadata_roots: [trustedRoot],
        version_metadata_abs: [
          path.join(trustedRoot, "package.json"),
          path.join(trustedRoot, "version.json"),
        ],
      },
      max,
      seen,
    );
  }

  // --- WSL identities (host coexistence): never collapse with native ---
  const includeWsl =
    caps.includeHostWsl !== false &&
    (platform === "windows" || platform === "wsl" || (caps.wslPaths?.length ?? 0) > 0);
  if (includeWsl) {
    const wslPaths =
      defaultWslPaths(caps).length > 0
        ? defaultWslPaths(caps)
        : (caps.wslPaths ?? []);
    // Secondary profile alias for WSL when multiple profiles registered.
    const wslProfile =
      profiles.find((p) => p.profile_root_alias.includes("WSL")) ??
      ({
        profile_root_alias: "WSL_PROFILE",
        config_root_alias: "WSL_CODEX_CONFIG",
      } satisfies WindowsProfileSpec);

    for (const p of wslPaths) {
      if (out.length >= max) break;
      const kind = pathKind(p);
      if (kind === "missing" || kind === "dir" || kind === "other") continue;
      const dir = path.dirname(p);
      const trusted = trustDir(dir, pathKind);
      pushCandidate(
        out,
        {
          install_source: "wsl",
          surface: "cli",
          path: path.resolve(p),
          platform: "wsl",
          arch,
          profile_root_alias: wslProfile.profile_root_alias,
          config_root_alias: wslProfile.config_root_alias,
          path_precedence: null,
          trusted_metadata_roots: trusted,
          version_metadata_abs: trusted.length
            ? [
                path.join(dir, "version.json"),
                path.join(dir, "package.json"),
              ]
            : [],
        },
        max,
        seen,
      );
    }
  }

  // --- Multi-profile: attach additional profile-only markers as path-free
  // aliases on already-discovered candidates is done via profile_root_alias
  // above. When multiple userProfiles are supplied, re-emit desktop/msix
  // rows with alternate aliases only when root_abs markers exist (tests).
  if (profiles.length > 1) {
    const baseNative = out.filter(
      (c) => c.install_source === "desktop_bundled" && c.surface === "desktop",
    );
    for (let i = 1; i < profiles.length; i++) {
      const prof = profiles[i]!;
      if (!prof.root_abs || pathKind(prof.root_abs) === "missing") continue;
      for (const b of baseNative) {
        if (out.length >= max) break;
        // Distinct identity: same binary path would collapse — use profile
        // sentinel path under the profile root for hashing only when the
        // profile marker file exists.
        const marker = path.join(prof.root_abs, "profile-marker");
        if (pathKind(marker) === "missing" && pathKind(prof.root_abs) === "dir") {
          // Profile root exists without marker: still emit alias-distinct row
          // only when a registered codex control file exists.
          const control = path.join(prof.root_abs, "config.toml");
          if (pathKind(control) === "missing") continue;
          pushCandidate(
            out,
            {
              ...b,
              path: path.resolve(control),
              profile_root_alias: prof.profile_root_alias,
              config_root_alias: prof.config_root_alias,
              surface: "cli",
              install_source: "path",
              path_precedence: null,
              trusted_metadata_roots: trustDir(prof.root_abs, pathKind),
              version_metadata_abs: [],
            },
            max,
            seen,
          );
        } else if (pathKind(marker) === "file" || pathKind(marker) === "symlink") {
          pushCandidate(
            out,
            {
              ...b,
              path: path.resolve(marker),
              profile_root_alias: prof.profile_root_alias,
              config_root_alias: prof.config_root_alias,
              surface: "cli",
              install_source: "path",
              path_precedence: null,
              trusted_metadata_roots: trustDir(prof.root_abs, pathKind),
              version_metadata_abs: [],
            },
            max,
            seen,
          );
        }
      }
    }
  }

  // Filter version_metadata_abs to trusted roots.
  for (const c of out) {
    const trusted = c.trusted_metadata_roots ?? [];
    if (c.version_metadata_abs) {
      c.version_metadata_abs = c.version_metadata_abs.filter((m) =>
        trusted.some((t) => isInsideRoot(t, m)),
      );
    }
  }

  const install_kinds = [...new Set(out.map(kindOf))];
  const profile_aliases = [
    ...new Set(
      out
        .map((c) => c.profile_root_alias)
        .filter((a): a is string => typeof a === "string" && a.length > 0),
    ),
  ];
  const hasNative = out.some(
    (c) => c.platform === "windows" && c.install_source !== "wsl",
  );
  const hasWsl = out.some((c) => c.install_source === "wsl" || c.platform === "wsl");

  return {
    platform: platform === "wsl" ? "wsl" : "windows",
    candidates: out,
    profile_aliases,
    install_kinds,
    win_wsl_coexistence: hasNative && hasWsl,
  };
}
