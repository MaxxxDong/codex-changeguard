/**
 * Bounded read-only discovery of CLI/config/log/user-owned cache candidates.
 * Named paths only; no home crawl; no binary execution; no symlink follow.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DiscoveryKind, DiscoveryObservation } from "./types.js";

const MAX_DISCOVERY_BYTES = 64 * 1024;
const MAX_LOG_FILES = 8;

export interface DiscoveryCaps {
  /** Injectable path kind (tests). */
  pathKind?: (
    absPath: string,
  ) => "file" | "dir" | "symlink" | "missing" | "other";
  /** Absolute roots that are already user-owned and registered. */
  configRoots?: string[];
  logRoots?: string[];
  cacheRoots?: string[];
  /** Refuse any path under these prefixes (e.g. /mnt/c host mounts). */
  refusePrefixes?: string[];
}

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

function pathHash(abs: string): string {
  const normalized = abs.split(path.sep).join("/");
  return crypto.createHash("sha256").update(`path:v1:${normalized}`).digest("hex");
}

function isRefused(abs: string, refusePrefixes: string[]): boolean {
  const norm = abs.split(path.sep).join("/");
  for (const p of refusePrefixes) {
    const pref = p.split(path.sep).join("/");
    if (norm === pref || norm.startsWith(pref.endsWith("/") ? pref : pref + "/")) {
      return true;
    }
  }
  // Default host-mount refuse for WSL guest.
  if (norm === "/mnt/c" || norm.startsWith("/mnt/c/")) return true;
  if (norm === "/mnt/d" || norm.startsWith("/mnt/d/")) return true;
  return false;
}

function observeFile(
  kind: DiscoveryKind,
  abs: string,
  alias: string,
  pathKind: DiscoveryCaps["pathKind"],
  refusePrefixes: string[],
): DiscoveryObservation {
  if (isRefused(abs, refusePrefixes)) {
    return {
      kind,
      path_alias: alias,
      path_hash: pathHash(abs),
      present: false,
      readable: false,
      content_sha256: null,
      refused_reason: "HOST_MOUNT_OR_REFUSED_PREFIX",
    };
  }
  const pk = pathKind ?? defaultPathKind;
  const k = pk(abs);
  if (k === "missing") {
    return {
      kind,
      path_alias: alias,
      path_hash: pathHash(abs),
      present: false,
      readable: false,
      content_sha256: null,
      refused_reason: null,
    };
  }
  if (k === "symlink") {
    return {
      kind,
      path_alias: alias,
      path_hash: pathHash(abs),
      present: true,
      readable: false,
      content_sha256: null,
      refused_reason: "SYMLINK_REFUSED",
    };
  }
  if (k !== "file") {
    return {
      kind,
      path_alias: alias,
      path_hash: pathHash(abs),
      present: true,
      readable: false,
      content_sha256: null,
      refused_reason: "NOT_REGULAR_FILE",
    };
  }
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_DISCOVERY_BYTES) {
      return {
        kind,
        path_alias: alias,
        path_hash: pathHash(abs),
        present: true,
        readable: false,
        content_sha256: null,
        refused_reason: "LIMIT_OR_SYMLINK",
      };
    }
    const buf = fs.readFileSync(abs);
    const digest = crypto.createHash("sha256").update(buf).digest("hex");
    return {
      kind,
      path_alias: alias,
      path_hash: pathHash(abs),
      present: true,
      readable: true,
      content_sha256: digest,
      refused_reason: null,
    };
  } catch {
    return {
      kind,
      path_alias: alias,
      path_hash: pathHash(abs),
      present: true,
      readable: false,
      content_sha256: null,
      refused_reason: "READ_DENIED",
    };
  }
}

const CONFIG_RELS = [
  "config/config.toml",
  "config/config.override.toml",
  "config/managed.policy.json",
] as const;

const CONFIG_ALIASES = [
  "LINUX_CONFIG_PRIMARY",
  "LINUX_CONFIG_OVERRIDE",
  "LINUX_CONFIG_MANAGED",
] as const;

/**
 * Discover registered config/log/cache candidates under explicit roots only.
 */
export function discoverBoundedSurfaces(caps: DiscoveryCaps = {}): DiscoveryObservation[] {
  const pathKind = caps.pathKind ?? defaultPathKind;
  const refuse = caps.refusePrefixes ?? [];
  const out: DiscoveryObservation[] = [];

  for (const root of caps.configRoots ?? []) {
    if (isRefused(root, refuse) || pathKind(root) === "symlink") {
      out.push({
        kind: "config",
        path_alias: "LINUX_CONFIG_ROOT",
        path_hash: pathHash(root),
        present: true,
        readable: false,
        content_sha256: null,
        refused_reason:
          pathKind(root) === "symlink" ? "SYMLINK_REFUSED" : "HOST_MOUNT_OR_REFUSED_PREFIX",
      });
      continue;
    }
    for (let i = 0; i < CONFIG_RELS.length; i++) {
      const rel = CONFIG_RELS[i]!;
      const alias = CONFIG_ALIASES[i]!;
      const abs = path.join(root, rel);
      const kind: DiscoveryKind =
        rel.endsWith("managed.policy.json") ? "managed_policy" : "config";
      out.push(observeFile(kind, abs, alias, pathKind, refuse));
    }
  }

  for (const root of caps.logRoots ?? []) {
    if (isRefused(root, refuse) || pathKind(root) === "symlink") {
      out.push({
        kind: "log",
        path_alias: "LINUX_LOG_ROOT",
        path_hash: pathHash(root),
        present: true,
        readable: false,
        content_sha256: null,
        refused_reason:
          pathKind(root) === "symlink" ? "SYMLINK_REFUSED" : "HOST_MOUNT_OR_REFUSED_PREFIX",
      });
      continue;
    }
    const k = pathKind(root);
    if (k !== "dir") {
      out.push({
        kind: "log",
        path_alias: "LINUX_LOG_ROOT",
        path_hash: pathHash(root),
        present: k !== "missing",
        readable: false,
        content_sha256: null,
        refused_reason: k === "missing" ? null : "NOT_DIRECTORY",
      });
      continue;
    }
    try {
      const names = fs
        .readdirSync(root)
        .filter((n) => n.endsWith(".log") || n.endsWith(".txt"))
        .sort()
        .slice(0, MAX_LOG_FILES);
      if (names.length === 0) {
        out.push({
          kind: "log",
          path_alias: "LINUX_LOG_ROOT",
          path_hash: pathHash(root),
          present: true,
          readable: true,
          content_sha256: null,
          refused_reason: null,
        });
      }
      for (const name of names) {
        out.push(
          observeFile(
            "log",
            path.join(root, name),
            `LINUX_LOG_${name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 48)}`,
            pathKind,
            refuse,
          ),
        );
      }
    } catch {
      out.push({
        kind: "log",
        path_alias: "LINUX_LOG_ROOT",
        path_hash: pathHash(root),
        present: true,
        readable: false,
        content_sha256: null,
        refused_reason: "READ_DENIED",
      });
    }
  }

  for (const root of caps.cacheRoots ?? []) {
    // User-owned plugin-cache inventory only when registered.
    const inv = path.join(root, "plugin-cache", "inventory.json");
    out.push(observeFile("user_cache", inv, "LINUX_USER_CACHE_INVENTORY", pathKind, refuse));
  }

  return out;
}

/** True when a candidate absolute path is a WSL host mount that must not be a Linux trusted root. */
export function isHostMountPath(abs: string): boolean {
  return isRefused(abs, []);
}
