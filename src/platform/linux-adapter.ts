/**
 * Native Linux adapter — registered CLI/config/log/cache discovery only.
 * install_source for CLI must be path | package_manager (never wsl).
 */
import type { DiscoveredCandidate, SystemEnumerateCaps } from "../instances/types.js";
import { buildCapabilityReport } from "./capability.js";
import { discoverBoundedSurfaces, isHostMountPath } from "./discovery.js";
import type { PlatformCapabilityReport } from "./types.js";

export const LINUX_REGISTERED_CLI_PATHS = [
  "/usr/local/bin/codex",
  "/usr/bin/codex",
  "/opt/codex/bin/codex",
] as const;

export function linuxCliPaths(caps: SystemEnumerateCaps): string[] {
  if (caps.linuxPaths && caps.linuxPaths.length > 0) return caps.linuxPaths;
  // Prefer shared wslPaths injection only when platform is linux and linuxPaths unset —
  // production defaults use registered linux paths, never mislabel as wsl.
  return [...LINUX_REGISTERED_CLI_PATHS];
}

/**
 * Build linux CLI candidates. install_source is always path (never wsl).
 * Host mounts (/mnt/c) are refused as trusted roots.
 */
export function enumerateLinuxCliCandidates(
  caps: SystemEnumerateCaps,
  arch: string,
  pathKind: (p: string) => "file" | "dir" | "symlink" | "missing" | "other",
): DiscoveredCandidate[] {
  const out: DiscoveredCandidate[] = [];
  for (const p of linuxCliPaths(caps)) {
    if (isHostMountPath(p)) continue;
    const kind = pathKind(p);
    if (kind === "missing" || kind === "dir" || kind === "other") continue;
    // Symlink leaves accepted as path identity only (hash); no follow for content.
    if (kind !== "file" && kind !== "symlink") continue;
    const dir = p.includes("/") ? p.replace(/\/[^/]+$/, "") : ".";
    let trusted: string[] = [];
    try {
      // Only real directories; skip symlink roots.
      if (pathKind(dir) === "dir") {
        trusted = [dir];
      }
    } catch {
      trusted = [];
    }
    out.push({
      install_source: "path",
      surface: "cli",
      path: p,
      platform: "linux",
      arch,
      profile_root_alias: "LINUX_PROFILE",
      config_root_alias: "LINUX_CONFIG_PRIMARY",
      path_precedence: null,
      trusted_metadata_roots: trusted,
      version_metadata_abs: trusted.length
        ? [`${dir}/version.json`, `${dir}/package.json`]
        : [],
      runtime_domain: "native_linux",
    });
  }
  return out;
}

export function linuxCapabilityReport(input: {
  configRoots?: string[];
  logRoots?: string[];
  cacheRoots?: string[];
  pathKind?: SystemEnumerateCaps["pathKind"];
}): PlatformCapabilityReport {
  const discoveries = discoverBoundedSurfaces({
    configRoots: input.configRoots,
    logRoots: input.logRoots,
    cacheRoots: input.cacheRoots,
    pathKind: input.pathKind,
  });
  return buildCapabilityReport({
    adapter: "linux",
    runtime_domain: "native_linux",
    discoveries,
  });
}
