/**
 * Ticket 15 platform / capability / IT handoff public surface.
 */
export type {
  AdapterId,
  DiscoveryKind,
  DiscoveryObservation,
  ITHandoff,
  ITHandoffMinimalEvidence,
  NetworkCompareBranch,
  NetworkCompareObservation,
  NetworkCompareResult,
  OfficialReference,
  PlatformCapabilityReport,
  PlatformCapabilityStatus,
  PlatformGap,
  RuntimeDomain,
  SupportReceipt,
  WriteGateInput,
  WriteGateResult,
} from "./types.js";

export {
  buildCapabilityReport,
  defaultCapabilityStatus,
  evaluateWriteGate,
  resolveEffectiveStatus,
  runtimeDomainFor,
} from "./capability.js";

export {
  discoverBoundedSurfaces,
  isHostMountPath,
} from "./discovery.js";

export {
  enumerateLinuxCliCandidates,
  linuxCapabilityReport,
  linuxCliPaths,
  LINUX_REGISTERED_CLI_PATHS,
} from "./linux-adapter.js";

export {
  assertNoIdentityCollapse,
  enumerateWslCliCandidates,
  wslCapabilityReport,
  wslCliPaths,
  WSL_REGISTERED_CLI_PATHS,
} from "./wsl-adapter.js";

export {
  assertSafeHandoffText,
  buildITHandoff,
} from "./it-handoff.js";

export { compareNetworkPaths } from "./network-compare.js";

export {
  syntheticLimitedReceipt,
  validateSupportReceipt,
} from "./support-receipt.js";

import { buildCapabilityReport, defaultCapabilityStatus } from "./capability.js";
import type {
  AdapterId,
  PlatformCapabilityReport,
  PlatformCapabilityStatus,
} from "./types.js";

/**
 * Read-only platform-status matrix for CLI/MCP.
 * Never claims Full without a real-machine support receipt.
 */
export function platformStatus(input?: {
  adapter?: AdapterId;
  platform?: string;
}): {
  schema_version: 1;
  ok: true;
  reports: PlatformCapabilityReport[];
  default_status: PlatformCapabilityStatus;
  full_support_claimed: false;
  network_used: false;
  target_mutated: false;
  repair_applied: false;
} {
  const adapters: AdapterId[] = input?.adapter
    ? [input.adapter]
    : ["unknown", "linux", "wsl", "windows", "macos", "enterprise_managed"];
  const reports = adapters.map((a) => buildCapabilityReport({ adapter: a }));
  const primary = input?.adapter ?? detectAdapterHint(input?.platform);
  return {
    schema_version: 1,
    ok: true,
    reports,
    default_status: defaultCapabilityStatus(primary),
    full_support_claimed: false,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
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
    default:
      return "unknown";
  }
}
