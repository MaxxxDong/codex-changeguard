/**
 * WSL adapter — distro-scoped CLI discovery; host Windows remains a separate identity.
 * Never auto-registers /mnt/c as a Linux trusted root.
 */
import type { DiscoveredCandidate, SystemEnumerateCaps } from "../instances/types.js";
import { buildCapabilityReport } from "./capability.js";
import { discoverBoundedSurfaces, isHostMountPath } from "./discovery.js";
import type { PlatformCapabilityReport } from "./types.js";

export const WSL_REGISTERED_CLI_PATHS = [
  "/usr/local/bin/codex",
  "/usr/bin/codex",
] as const;

export function wslCliPaths(caps: SystemEnumerateCaps): string[] {
  if (caps.wslPaths && caps.wslPaths.length > 0) return caps.wslPaths;
  return [...WSL_REGISTERED_CLI_PATHS];
}

export function enumerateWslCliCandidates(
  caps: SystemEnumerateCaps,
  arch: string,
  pathKind: (p: string) => "file" | "dir" | "symlink" | "missing" | "other",
): DiscoveredCandidate[] {
  const out: DiscoveredCandidate[] = [];
  const distro =
    (caps.env?.WSL_DISTRO_NAME && caps.env.WSL_DISTRO_NAME.length > 0
      ? caps.env.WSL_DISTRO_NAME
      : "default") ?? "default";
  for (const p of wslCliPaths(caps)) {
    if (isHostMountPath(p)) continue;
    const kind = pathKind(p);
    if (kind === "missing" || kind === "dir" || kind === "other") continue;
    if (kind !== "file" && kind !== "symlink") continue;
    const dir = p.includes("/") ? p.replace(/\/[^/]+$/, "") : ".";
    let trusted: string[] = [];
    if (pathKind(dir) === "dir" && !isHostMountPath(dir)) {
      trusted = [dir];
    }
    out.push({
      install_source: "wsl",
      surface: "cli",
      path: p,
      platform: "wsl",
      arch,
      profile_root_alias: "WSL_PROFILE",
      config_root_alias: "WSL_CONFIG_PRIMARY",
      path_precedence: null,
      trusted_metadata_roots: trusted,
      version_metadata_abs: trusted.length
        ? [`${dir}/version.json`, `${dir}/package.json`]
        : [],
      runtime_domain: "wsl_distro",
      // Distro name never exported raw on wire; domain + path_hash separate identities.
      wsl_distro_token: distro.slice(0, 64),
    });
  }
  return out;
}

export function wslCapabilityReport(input: {
  configRoots?: string[];
  logRoots?: string[];
  cacheRoots?: string[];
  pathKind?: SystemEnumerateCaps["pathKind"];
  distro_name?: string | null;
}): PlatformCapabilityReport {
  const discoveries = discoverBoundedSurfaces({
    configRoots: input.configRoots,
    logRoots: input.logRoots,
    cacheRoots: input.cacheRoots,
    pathKind: input.pathKind,
    refusePrefixes: ["/mnt/c", "/mnt/d"],
  });
  return buildCapabilityReport({
    adapter: "wsl",
    runtime_domain: "wsl_distro",
    discoveries,
    distro_name: input.distro_name ?? null,
  });
}

/** Host Windows candidates must use windows platform + windows_host domain — never merge into WSL rows. */
export function assertNoIdentityCollapse(
  instances: Array<{ platform: string; install_source: string; instance_id: string }>,
): { ok: boolean; reason: string | null } {
  const wsl = instances.filter((i) => i.platform === "wsl");
  const win = instances.filter((i) => i.platform === "windows");
  if (wsl.length === 0 || win.length === 0) {
    return { ok: true, reason: null };
  }
  for (const a of wsl) {
    for (const b of win) {
      if (a.instance_id === b.instance_id) {
        return { ok: false, reason: "WSL_WINDOWS_INSTANCE_COLLAPSE" };
      }
    }
  }
  return { ok: true, reason: null };
}
