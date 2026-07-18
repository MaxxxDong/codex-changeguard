import crypto from "node:crypto";
import path from "node:path";
import type {
  DiscoveredCandidate,
  InstanceIdentity,
  VersionProvenance,
} from "./types.js";

export function sha256Hex(data: string | Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/** Stable path hash: never expose the raw path externally. */
export function pathHashOf(absoluteOrLogicalPath: string): string {
  const normalized = absoluteOrLogicalPath.split(path.sep).join("/");
  return sha256Hex(`path:v1:${normalized}`);
}

export function instanceIdOf(parts: {
  path_hash: string;
  install_source: string;
  surface: string;
  /** Ticket 15: when set, use v2 material so domains cannot collapse. */
  runtime_domain?: string | null;
}): string {
  const domain =
    typeof parts.runtime_domain === "string" && parts.runtime_domain.length > 0
      ? parts.runtime_domain
      : null;
  if (domain) {
    return sha256Hex(
      `instance:v2:${domain}:${parts.install_source}:${parts.surface}:${parts.path_hash}`,
    );
  }
  return sha256Hex(
    `instance:v1:${parts.install_source}:${parts.surface}:${parts.path_hash}`,
  );
}

/** Compact fingerprint for one observed instance (repair binding). */
export function instanceFingerprintOf(id: InstanceIdentity): string {
  return sha256Hex(
    [
      id.instance_id,
      id.path_hash,
      id.install_source,
      id.surface,
      id.version ?? "",
      id.build ?? "",
      id.path_precedence === null ? "" : String(id.path_precedence),
    ].join("|"),
  );
}

export function overallFingerprintOf(instances: InstanceIdentity[]): string {
  const rows = [...instances]
    .map((i) =>
      [
        i.instance_id,
        i.path_hash,
        i.install_source,
        i.surface,
        i.version ?? "",
        i.build ?? "",
        i.path_precedence === null ? "" : String(i.path_precedence),
      ].join("|"),
    )
    .sort();
  return sha256Hex(`overall:v1:${rows.join("\n")}`);
}

const SOURCE_ALIAS_PREFIX: Record<string, string> = {
  desktop_bundled: "DESKTOP",
  path: "PATH",
  package_manager: "PKG",
  windows_msix: "MSIX",
  wsl: "WSL",
  unknown: "UNK",
};

/** Prefer domain-aware prefixes so Linux PATH and WSL do not share labels. */
function aliasPrefixFor(
  install_source: string,
  platform: string,
  runtime_domain?: string | null,
): string {
  if (runtime_domain === "native_linux" || platform === "linux") {
    if (install_source === "path") return "LINUX";
    if (install_source === "package_manager") return "LINUX_PKG";
  }
  if (runtime_domain === "wsl_distro" || platform === "wsl") {
    return "WSL";
  }
  if (runtime_domain === "windows_host" || platform === "windows") {
    if (install_source === "windows_msix") return "MSIX";
    if (install_source === "desktop_bundled") return "WIN_DESKTOP";
    if (install_source === "path") return "WIN_PATH";
  }
  return SOURCE_ALIAS_PREFIX[install_source] ?? "UNK";
}

export function assignPathAliases(
  identities: Array<Omit<InstanceIdentity, "path_alias"> & { path_alias?: string }>,
): InstanceIdentity[] {
  const counters = new Map<string, number>();
  return identities.map((raw) => {
    const prefix = aliasPrefixFor(
      raw.install_source,
      raw.platform,
      raw.runtime_domain,
    );
    const n = (counters.get(prefix) ?? 0) + 1;
    counters.set(prefix, n);
    const path_alias = `${prefix}_${n}`;
    return { ...raw, path_alias } as InstanceIdentity;
  });
}

export function toIdentity(
  c: DiscoveredCandidate,
  version: string | null,
  build: string | null,
  provenance: VersionProvenance,
): Omit<InstanceIdentity, "path_alias"> {
  const path_hash = pathHashOf(c.path);
  const runtime_domain = c.runtime_domain ?? null;
  return {
    instance_id: instanceIdOf({
      path_hash,
      install_source: c.install_source,
      surface: c.surface,
      runtime_domain,
    }),
    path_hash,
    surface: c.surface,
    install_source: c.install_source,
    platform: c.platform,
    arch: c.arch,
    profile_root_alias: c.profile_root_alias,
    config_root_alias: c.config_root_alias,
    version,
    build,
    version_provenance: provenance,
    path_precedence: c.path_precedence,
    runtime_domain,
  };
}
