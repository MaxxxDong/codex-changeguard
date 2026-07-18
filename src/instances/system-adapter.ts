/**
 * Production registered system adapter for Codex instance enumeration.
 *
 * Safely enumerates bounded known candidates without executing them:
 * - Desktop-bundled locations (exact registered paths only)
 * - PATH entries named codex / codex.exe (hard-capped)
 * - Supported package-manager metadata adjacent to registered install roots
 * - Windows MSIX / App Execution Alias candidates (exact registered paths)
 * - WSL candidates (exact registered paths)
 *
 * Missing permissions or version metadata produce explicit unavailable
 * evidence — never candidate execution or broad home traversal.
 */
import fs from "node:fs";
import path from "node:path";
import {
  enumerateLinuxCliCandidates,
} from "../platform/linux-adapter.js";
import {
  enumerateWslCliCandidates,
} from "../platform/wsl-adapter.js";
import { MAX_INSTANCES } from "./limits.js";
import { assertRealDirectory, isInsideRoot } from "./path-bounded.js";
import type {
  DiscoveredCandidate,
  PlatformId,
  SystemEnumerateCaps,
} from "./types.js";

const DEFAULT_MAX_PATH_ENTRIES = 64;
const CODEX_NAMES = new Set(["codex", "codex.exe", "Codex.exe", "Codex"]);

function defaultPathKind(
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

function detectPlatform(caps: SystemEnumerateCaps): PlatformId {
  if (caps.platform) return caps.platform;
  const env = caps.env ?? process.env;
  if (env.WSL_DISTRO_NAME || env.WSL_INTEROP) return "wsl";
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

function detectArch(caps: SystemEnumerateCaps): string {
  if (caps.arch && caps.arch.length > 0) return caps.arch;
  return process.arch || "unknown";
}

function homeOf(caps: SystemEnumerateCaps): string | null {
  if (caps.homeDir) return caps.homeDir;
  const env = caps.env ?? process.env;
  const h = env.HOME || env.USERPROFILE || null;
  return h && h.length > 0 ? h : null;
}

/**
 * Known Desktop-bundled install locations (exact paths, no directory crawl).
 */
function defaultDesktopPaths(
  platform: PlatformId,
  caps: SystemEnumerateCaps,
): string[] {
  if (caps.desktopPaths) return caps.desktopPaths;
  const home = homeOf(caps);
  const out: string[] = [];
  if (platform === "macos") {
    out.push("/Applications/Codex.app/Contents/MacOS/Codex");
    if (home) {
      out.push(path.join(home, "Applications/Codex.app/Contents/MacOS/Codex"));
    }
  } else if (platform === "windows") {
    const env = caps.env ?? process.env;
    const local = env.LOCALAPPDATA;
    if (local) {
      out.push(
        path.join(local, "Programs", "Codex", "Codex.exe"),
        path.join(local, "Codex", "Codex.exe"),
      );
    }
  }
  return out;
}

function defaultMsixPaths(
  platform: PlatformId,
  caps: SystemEnumerateCaps,
): string[] {
  if (caps.msixPaths) return caps.msixPaths;
  if (platform !== "windows") return [];
  const env = caps.env ?? process.env;
  const local = env.LOCALAPPDATA;
  if (!local) return [];
  // App Execution Alias + common MSIX layout — exact registered candidates only.
  return [
    path.join(local, "Microsoft", "WindowsApps", "codex.exe"),
    path.join(local, "Microsoft", "WindowsApps", "Codex.exe"),
  ];
}

/** @deprecated Prefer platform adapters; retained for caps.wslPaths injection. */
function defaultWslPaths(
  platform: PlatformId,
  caps: SystemEnumerateCaps,
): string[] {
  if (caps.wslPaths) return caps.wslPaths;
  if (platform !== "wsl") return [];
  return ["/usr/local/bin/codex", "/usr/bin/codex"];
}

function defaultPackageRoots(caps: SystemEnumerateCaps): string[] {
  if (caps.packageRoots) return caps.packageRoots;
  // Production does not invent package roots; only explicit registration.
  // PATH-adjacent npm layout is handled when a package root is supplied.
  return [];
}

function pathEntriesOf(caps: SystemEnumerateCaps): string[] {
  if (caps.pathEntries) return caps.pathEntries;
  const env = caps.env ?? process.env;
  const raw = env.PATH || env.Path || "";
  const delim = caps.pathDelimiter ?? path.delimiter;
  return raw
    .split(delim)
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
}

function isCodexBasename(name: string): boolean {
  return CODEX_NAMES.has(name) || name.toLowerCase() === "codex" || name.toLowerCase() === "codex.exe";
}

/** Walk parents to find a `*.app` bundle root (Desktop macOS layout). */
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

/**
 * For a Desktop MacOS binary, trusted root is the .app bundle when present.
 * Metadata such as Contents/Info.plist is registered explicitly under that root.
 */
function desktopTrustedRootAndMeta(
  binaryAbs: string,
  platform: PlatformId,
): { roots: string[]; metaAbs: string[] } {
  const roots: string[] = [];
  const metaAbs: string[] = [];
  const appRoot = findAppBundleRoot(binaryAbs);
  if (appRoot) {
    roots.push(appRoot);
    metaAbs.push(path.join(appRoot, "Contents", "Info.plist"));
    return { roots, metaAbs };
  }
  // Fallback: directory of binary is the only trusted root (adjacent metadata only).
  roots.push(path.dirname(binaryAbs));
  if (platform === "windows") {
    metaAbs.push(path.join(path.dirname(binaryAbs), "AppxManifest.xml"));
  }
  return { roots, metaAbs };
}

function packageMetaForRoot(root: string): {
  roots: string[];
  metaAbs: string[];
  binary: string | null;
} {
  const roots = [root];
  const metaAbs = [
    path.join(root, "package.json"),
    path.join(root, "version.json"),
  ];
  // Common layouts under a registered package root.
  const binCandidates = [
    path.join(root, "bin", "codex"),
    path.join(root, "bin", "codex.exe"),
    path.join(root, "codex"),
    path.join(root, "codex.exe"),
  ];
  return { roots, metaAbs, binary: binCandidates[0] ?? null };
}

function pushCandidate(
  out: DiscoveredCandidate[],
  c: DiscoveredCandidate,
  max: number,
  seen: Set<string>,
): void {
  if (out.length >= max) return;
  const key = `${c.install_source}|${path.resolve(c.path)}`;
  if (seen.has(key)) return;
  seen.add(key);
  out.push(c);
}

/**
 * Enumerate registered system candidates. Never executes binaries.
 * Symlink leaves are accepted as path identities for hashing only; version
 * metadata still uses no-follow reads under trusted roots.
 */
export function enumerateSystemCandidates(
  caps: SystemEnumerateCaps = {},
): DiscoveredCandidate[] {
  const platform = detectPlatform(caps);
  const arch = detectArch(caps);
  const pathKind = caps.pathKind ?? defaultPathKind;
  const max = Math.min(caps.maxCandidates ?? MAX_INSTANCES, MAX_INSTANCES);
  const maxPath = Math.min(
    caps.maxPathEntries ?? DEFAULT_MAX_PATH_ENTRIES,
    DEFAULT_MAX_PATH_ENTRIES,
  );
  const out: DiscoveredCandidate[] = [];
  const seen = new Set<string>();

  // --- Desktop bundled ---
  for (const p of defaultDesktopPaths(platform, caps)) {
    if (out.length >= max) break;
    const kind = pathKind(p);
    // Accept real file; skip missing. Symlink binary leaves are still path identities
    // but we do not follow them for content — only record the path for hashing.
    if (kind === "missing" || kind === "other" || kind === "dir") continue;
    const { roots, metaAbs } = desktopTrustedRootAndMeta(p, platform);
    // Only keep trusted roots that are real directories (no symlink root).
    const trusted: string[] = [];
    for (const r of roots) {
      try {
        trusted.push(assertRealDirectory(r));
      } catch {
        // root unavailable — still emit candidate with empty trusted roots
        // so version becomes explicit "unavailable"
      }
    }
    pushCandidate(
      out,
      {
        install_source: "desktop_bundled",
        surface: "desktop",
        path: path.resolve(p),
        platform,
        arch,
        profile_root_alias: "DESKTOP_PROFILE",
        config_root_alias: null,
        path_precedence: null,
        trusted_metadata_roots: trusted,
        version_metadata_abs: metaAbs.filter((m) =>
          trusted.some((t) => isInsideRoot(t, m)),
        ),
        runtime_domain:
          platform === "windows"
            ? "windows_host"
            : platform === "macos"
              ? "macos_host"
              : null,
      },
      max,
      seen,
    );
  }

  // --- PATH entries ---
  let pathIndex = 0;
  const entries = pathEntriesOf(caps).slice(0, maxPath);
  for (const dir of entries) {
    if (out.length >= max) break;
    // Refuse PATH dir that is a symlink (no follow into redirected trees).
    const dirKind = pathKind(dir);
    if (dirKind !== "dir") {
      pathIndex += 1;
      continue;
    }
    for (const name of ["codex", "codex.exe"]) {
      const full = path.join(dir, name);
      const kind = pathKind(full);
      if (kind === "missing" || kind === "dir" || kind === "other") continue;
      if (!isCodexBasename(path.basename(full))) continue;
      // Trusted root is the PATH directory itself — adjacent metadata only.
      // No parent traversal for package.json.
      let trusted: string[] = [];
      try {
        trusted = [assertRealDirectory(dir)];
      } catch {
        trusted = [];
      }
      // Native Linux PATH CLI must never be labeled install_source=wsl.
      const pathInstallSource =
        platform === "wsl" ? "wsl" : ("path" as const);
      const pathDomain =
        platform === "linux"
          ? "native_linux"
          : platform === "wsl"
            ? "wsl_distro"
            : platform === "windows"
              ? "windows_host"
              : platform === "macos"
                ? "macos_host"
                : null;
      pushCandidate(
        out,
        {
          install_source: pathInstallSource,
          surface: "cli",
          path: path.resolve(full),
          platform,
          arch,
          profile_root_alias:
            platform === "linux"
              ? "LINUX_PROFILE"
              : platform === "wsl"
                ? "WSL_PROFILE"
                : null,
          config_root_alias:
            platform === "linux"
              ? "LINUX_CONFIG_PRIMARY"
              : platform === "wsl"
                ? "WSL_CONFIG_PRIMARY"
                : null,
          path_precedence: pathIndex,
          trusted_metadata_roots: trusted,
          version_metadata_abs: trusted.length
            ? [
                path.join(dir, "version.json"),
                path.join(dir, "package.json"),
              ]
            : [],
          runtime_domain: pathDomain,
        },
        max,
        seen,
      );
    }
    pathIndex += 1;
  }

  // --- Package manager roots (explicit registration only) ---
  for (const root of defaultPackageRoots(caps)) {
    if (out.length >= max) break;
    let trustedRoot: string;
    try {
      trustedRoot = assertRealDirectory(root);
    } catch {
      continue;
    }
    const { roots, metaAbs } = packageMetaForRoot(trustedRoot);
    // Prefer an existing binary under the root; otherwise register package.json path as identity.
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
    // Identity path: binary if present, else package.json (metadata identity only).
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
        platform,
        arch,
        profile_root_alias: null,
        config_root_alias: null,
        path_precedence: null,
        trusted_metadata_roots: roots,
        version_metadata_abs: metaAbs,
        runtime_domain:
          platform === "linux"
            ? "native_linux"
            : platform === "wsl"
              ? "wsl_distro"
              : platform === "windows"
                ? "windows_host"
                : platform === "macos"
                  ? "macos_host"
                  : null,
      },
      max,
      seen,
    );
  }

  // --- Windows MSIX / App Execution Alias ---
  for (const p of defaultMsixPaths(platform, caps)) {
    if (out.length >= max) break;
    const kind = pathKind(p);
    if (kind === "missing" || kind === "dir" || kind === "other") continue;
    const dir = path.dirname(p);
    let trusted: string[] = [];
    try {
      trusted = [assertRealDirectory(dir)];
    } catch {
      trusted = [];
    }
    pushCandidate(
      out,
      {
        install_source: "windows_msix",
        surface: "desktop",
        path: path.resolve(p),
        platform: "windows",
        arch,
        profile_root_alias: "MSIX_PROFILE",
        config_root_alias: null,
        path_precedence: null,
        trusted_metadata_roots: trusted,
        version_metadata_abs: trusted.length
          ? [path.join(dir, "AppxManifest.xml")]
          : [],
        runtime_domain: "windows_host",
      },
      max,
      seen,
    );
  }

  // --- Native Linux registered paths (install_source path — never wsl) ---
  if (platform === "linux") {
    for (const c of enumerateLinuxCliCandidates(caps, arch, pathKind)) {
      if (out.length >= max) break;
      const dir = path.dirname(c.path);
      let trusted: string[] = [];
      try {
        trusted = [assertRealDirectory(dir)];
      } catch {
        trusted = [];
      }
      pushCandidate(
        out,
        {
          ...c,
          path: path.resolve(c.path),
          install_source: "path",
          platform: "linux",
          trusted_metadata_roots: trusted,
          version_metadata_abs: trusted.length
            ? [path.join(dir, "version.json"), path.join(dir, "package.json")]
            : [],
          runtime_domain: "native_linux",
        },
        max,
        seen,
      );
    }
  }

  // --- WSL registered paths (explicit wsl only; may coexist with Windows) ---
  if (platform === "wsl" || (caps.wslPaths && caps.wslPaths.length > 0 && platform !== "linux")) {
    // When caps inject wslPaths on non-linux hosts (coexistence harness), emit WSL identities.
    const wslCaps =
      platform === "wsl"
        ? caps
        : { ...caps, wslPaths: caps.wslPaths ?? defaultWslPaths("wsl", caps) };
    for (const c of enumerateWslCliCandidates(
      wslCaps,
      arch,
      pathKind,
    )) {
      if (out.length >= max) break;
      const dir = path.dirname(c.path);
      let trusted: string[] = [];
      try {
        trusted = [assertRealDirectory(dir)];
      } catch {
        trusted = [];
      }
      pushCandidate(
        out,
        {
          ...c,
          path: path.resolve(c.path),
          install_source: "wsl",
          platform: "wsl",
          trusted_metadata_roots: trusted,
          version_metadata_abs: trusted.length
            ? [path.join(dir, "version.json"), path.join(dir, "package.json")]
            : [],
          runtime_domain: "wsl_distro",
        },
        max,
        seen,
      );
    }
  }

  return out;
}
