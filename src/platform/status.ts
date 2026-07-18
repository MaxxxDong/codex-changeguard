/**
 * Public platform-status / capabilities result for CLI and MCP.
 */
import fs from "node:fs";
import path from "node:path";
import { findRepoRoot } from "../paths.js";
import {
  buildMacosCapabilities,
  enumerateMacosCandidates,
  readMacosCodexVersionProvenance,
  type MacosAdapterCaps,
} from "./macos/index.js";
import { validatePlatformSupportReceipt } from "./receipt.js";
import type {
  PlatformCapabilities,
  PlatformId,
  ReceiptValidationResult,
} from "./types.js";

export interface PlatformStatusResult {
  schema_version: 1;
  ok: boolean;
  platform: PlatformId;
  arch: string;
  capabilities: PlatformCapabilities | null;
  codex_version_provenance: {
    available: boolean;
    version: string | null;
    provenance: string;
  } | null;
  changeguard_version: string;
  /** Verified support level from an optional receipt; null if none provided. */
  verified_support_level: string | null;
  receipt_validation: ReceiptValidationResult | null;
  network_used: false;
  target_mutated: false;
  repair_applied: false;
  error_code: string | null;
  error_message: string | null;
}

function packageVersion(): string {
  try {
    const root = findRepoRoot(import.meta.url);
    const pkg = JSON.parse(
      fs.readFileSync(path.join(root, "package.json"), "utf8"),
    ) as { version?: string };
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function detectPlatform(): PlatformId {
  switch (process.platform) {
    case "darwin":
      return "macos";
    case "win32":
      return "windows";
    case "linux":
      return process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP
        ? "wsl"
        : "linux";
    default:
      return "unknown";
  }
}

export interface PlatformStatusOptions {
  /** When set, validate this receipt object and surface verified level. */
  receipt?: unknown;
  adapterCaps?: MacosAdapterCaps;
  /** Probe host installs (default true on darwin). */
  probeHost?: boolean;
}

/**
 * Read-only platform status: capabilities + optional receipt validation.
 * Never mutates host state; never executes discovered binaries.
 */
export function platformStatus(
  options: PlatformStatusOptions = {},
): PlatformStatusResult {
  const platform = detectPlatform();
  const arch = process.arch || "unknown";
  const version = packageVersion();

  if (platform !== "macos") {
    return {
      schema_version: 1,
      ok: true,
      platform,
      arch,
      capabilities: null,
      codex_version_provenance: null,
      changeguard_version: version,
      verified_support_level: null,
      receipt_validation: options.receipt
        ? validatePlatformSupportReceipt(options.receipt)
        : null,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      error_code: null,
      error_message:
        "This host is not macOS; use the matching platform ticket adapter.",
    };
  }

  const caps = buildMacosCapabilities({
    platform: "macos",
    arch,
    probeHost: options.probeHost,
    ...options.adapterCaps,
  });
  const candidates = enumerateMacosCandidates({
    platform: "macos",
    arch,
    probeHost: options.probeHost !== false,
    ...options.adapterCaps,
  });
  const provenance = readMacosCodexVersionProvenance(candidates);
  const receipt_validation = options.receipt
    ? validatePlatformSupportReceipt(options.receipt)
    : null;

  return {
    schema_version: 1,
    ok: true,
    platform: "macos",
    arch,
    capabilities: caps,
    codex_version_provenance: provenance,
    changeguard_version: version,
    verified_support_level: receipt_validation?.ok
      ? receipt_validation.support_level
      : null,
    receipt_validation,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: null,
    error_message: null,
  };
}
