/**
 * Unified public platform-status for CLI and MCP (Tickets 13 + 14 + 15).
 *
 * Always surfaces:
 * - Host/macOS capability probe fields (Ticket 13)
 * - Ticket 15 capability matrix reports (Linux/WSL/enterprise defaults)
 * Never fabricates Full from synthetic evidence.
 */
import fs from "node:fs";
import path from "node:path";
import { findRepoRoot } from "../paths.js";
import {
  buildCapabilityReport,
  defaultCapabilityStatus,
} from "./capability.js";
import {
  buildMacosCapabilities,
  enumerateMacosCandidates,
  readMacosCodexVersionProvenance,
  type MacosAdapterCaps,
} from "./macos/index.js";
import { validatePlatformSupportReceipt } from "./receipt.js";
import type {
  AdapterId,
  PlatformCapabilities,
  PlatformCapabilityReport,
  PlatformCapabilityStatus,
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
  /** Ticket 15 capability matrix reports. */
  reports: PlatformCapabilityReport[];
  /** Primary / filtered adapter default status. */
  default_status: PlatformCapabilityStatus;
  /** Never true without a real-machine receipt path (framework honesty). */
  full_support_claimed: false;
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

function detectAdapterHint(platform?: string): AdapterId {
  switch (platform) {
    case "linux":
      return "linux";
    case "wsl":
      return "wsl";
    case "win32":
    case "windows":
      return "windows";
    case "darwin":
    case "macos":
      return "macos";
    case "enterprise_managed":
      return "enterprise_managed";
    case "unknown":
      return "unknown";
    default:
      return "unknown";
  }
}

const ALL_ADAPTERS: AdapterId[] = [
  "unknown",
  "linux",
  "wsl",
  "windows",
  "macos",
  "enterprise_managed",
];

export interface PlatformStatusOptions {
  /** When set, validate this receipt object and surface verified level (macOS). */
  receipt?: unknown;
  adapterCaps?: MacosAdapterCaps;
  /** Probe host installs (default true on darwin). */
  probeHost?: boolean;
  /**
   * Ticket 15: when set, capability matrix reports are filtered to this adapter.
   * Does not override trusted host detection for production write gates.
   */
  adapter?: AdapterId;
  /** Optional platform hint for default_status when adapter is omitted. */
  platform?: string;
}

/**
 * Read-only unified platform status: macOS capabilities + T15 capability matrix
 * + optional macOS receipt validation.
 * Never mutates host state; never executes discovered binaries; never claims Full
 * without a real-machine receipt path.
 */
export function platformStatus(
  options: PlatformStatusOptions = {},
): PlatformStatusResult {
  const platform = detectPlatform();
  const arch = process.arch || "unknown";
  const version = packageVersion();

  const adapters: AdapterId[] = options.adapter
    ? [options.adapter]
    : ALL_ADAPTERS;
  const reports = adapters.map((a) => buildCapabilityReport({ adapter: a }));
  const primary: AdapterId =
    options.adapter ??
    detectAdapterHint(options.platform) ??
    (platform === "unknown" ? "unknown" : (platform as AdapterId));
  const default_status = defaultCapabilityStatus(primary);

  const receipt_validation = options.receipt
    ? validatePlatformSupportReceipt(options.receipt)
    : null;

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
      receipt_validation,
      reports,
      default_status,
      full_support_claimed: false,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      error_code: null,
      error_message:
        platform === "linux" || platform === "wsl"
          ? "Linux/WSL host: capability matrix is Limited/Read-only; no real-machine Full receipt."
          : platform === "windows"
            ? "Windows host: support status is PREVIEW without a real-machine receipt + live witness."
            : "This host is not macOS; use the matching platform ticket adapter.",
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
    reports,
    default_status,
    full_support_claimed: false,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: null,
    error_message: null,
  };
}
