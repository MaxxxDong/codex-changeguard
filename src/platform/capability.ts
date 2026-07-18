/**
 * Platform capability matrix and deterministic write-disable gate.
 * Status upgrades require support receipts — never developer prose.
 */
import type {
  AdapterId,
  PlatformCapabilityReport,
  PlatformCapabilityStatus,
  PlatformGap,
  RuntimeDomain,
  SupportReceipt,
  WriteGateInput,
  WriteGateResult,
} from "./types.js";
import { validateSupportReceipt } from "./support-receipt.js";

/** Ship defaults — fail closed; no FULL without real-machine receipt. */
const DEFAULT_STATUS: Record<AdapterId, PlatformCapabilityStatus> = {
  unknown: "READ_ONLY",
  macos: "PREVIEW",
  windows: "PREVIEW",
  linux: "LIMITED",
  wsl: "LIMITED",
  enterprise_managed: "LIMITED",
};

const DEFAULT_GAPS: Record<AdapterId, PlatformGap[]> = {
  unknown: [
    {
      id: "unknown_adapter",
      summary: "Platform adapter unknown; discovery only, mutation refused.",
      status: "READ_ONLY",
    },
  ],
  macos: [
    {
      id: "macos_full_receipt",
      summary: "macOS Full remains Ticket 13 real-machine receipt.",
      status: "PREVIEW",
    },
  ],
  windows: [
    {
      id: "windows_full_receipt",
      summary: "Windows Full remains Ticket 14 real-machine receipt.",
      status: "PREVIEW",
    },
  ],
  linux: [
    {
      id: "linux_real_machine",
      summary:
        "No real Linux host Scenario Harness receipt; status Limited only.",
      status: "LIMITED",
    },
    {
      id: "linux_distro_matrix",
      summary: "Distro matrix (Ubuntu/RHEL/Arch/…) not fully exercised.",
      status: "LIMITED",
    },
  ],
  wsl: [
    {
      id: "wsl_real_machine",
      summary:
        "No real WSL host Scenario Harness receipt; status Limited only.",
      status: "LIMITED",
    },
    {
      id: "wsl1_vs_wsl2",
      summary: "WSL1 vs WSL2 behavioral differences not fully receipted.",
      status: "LIMITED",
    },
  ],
  enterprise_managed: [
    {
      id: "mdm_variants",
      summary: "Enterprise MDM variants beyond fixture markers are Limited.",
      status: "LIMITED",
    },
  ],
};

export function defaultCapabilityStatus(
  adapter: AdapterId,
): PlatformCapabilityStatus {
  return DEFAULT_STATUS[adapter] ?? "READ_ONLY";
}

export function runtimeDomainFor(
  adapter: AdapterId,
  distroName?: string | null,
): RuntimeDomain {
  switch (adapter) {
    case "linux":
      return "native_linux";
    case "wsl":
      return distroName && distroName.length > 0 ? "wsl_distro" : "wsl_distro";
    case "windows":
      return "windows_host";
    case "macos":
      return "macos_host";
    default:
      return "unknown";
  }
}

/**
 * Deterministic write gate (Ticket 15).
 * Unverified adapters: may_mutate false even when a Capsule could be built.
 */
export function evaluateWriteGate(input: WriteGateInput): WriteGateResult {
  const status = input.capability_status;
  if (input.managed_policy || input.admin_permission_bound) {
    return {
      may_mutate: false,
      reason_code: "ADMIN_OR_MANAGED_BLOCK",
      capability_status: status,
    };
  }
  if (status === "READ_ONLY") {
    return {
      may_mutate: false,
      reason_code: "CAPABILITY_READ_ONLY",
      capability_status: status,
    };
  }
  if (status === "LIMITED") {
    const allowLimited =
      input.allow_limited_user_owned_recovery === true &&
      (input.isolation === "isolated_fixture" ||
        input.isolation === "user_owned_registered");
    if (!allowLimited) {
      return {
        may_mutate: false,
        reason_code: "CAPABILITY_LIMITED_WRITE_DISABLED",
        capability_status: status,
      };
    }
  }
  if (status === "PREVIEW" || status === "FULL" || status === "LIMITED") {
    if (
      input.isolation !== "isolated_fixture" &&
      input.isolation !== "user_owned_registered"
    ) {
      return {
        may_mutate: false,
        reason_code: "ISOLATION_REQUIRED",
        capability_status: status,
      };
    }
    if (status === "FULL") {
      // FULL still requires isolation; real-machine only upgrades status claim.
      return {
        may_mutate: true,
        reason_code: "ALLOWED",
        capability_status: status,
      };
    }
    return {
      may_mutate: true,
      reason_code: "ALLOWED",
      capability_status: status,
    };
  }
  return {
    may_mutate: false,
    reason_code: "CAPABILITY_UNKNOWN",
    capability_status: status,
  };
}

export function resolveEffectiveStatus(
  adapter: AdapterId,
  receipt: SupportReceipt | null,
): PlatformCapabilityStatus {
  const base = defaultCapabilityStatus(adapter);
  if (!receipt) return base;
  const v = validateSupportReceipt(receipt, adapter);
  if (!v.ok) return base;
  // Never promote above validated claim; never invent FULL without real_machine.
  const order: PlatformCapabilityStatus[] = [
    "READ_ONLY",
    "LIMITED",
    "PREVIEW",
    "FULL",
  ];
  const claimIdx = order.indexOf(receipt.claimed_status);
  const baseIdx = order.indexOf(base);
  if (claimIdx < 0) return base;
  // Allow upgrade only when receipt validates and claim is higher.
  if (claimIdx > baseIdx) {
    if (receipt.claimed_status === "FULL" && !receipt.real_machine) {
      return base === "READ_ONLY" ? "READ_ONLY" : "LIMITED";
    }
    return receipt.claimed_status;
  }
  return base;
}

export function buildCapabilityReport(input: {
  adapter: AdapterId;
  runtime_domain?: RuntimeDomain;
  discoveries?: PlatformCapabilityReport["discoveries"];
  support_receipt?: SupportReceipt | null;
  distro_name?: string | null;
}): PlatformCapabilityReport {
  const adapter = input.adapter;
  const status = resolveEffectiveStatus(
    adapter,
    input.support_receipt ?? null,
  );
  const writes =
    evaluateWriteGate({
      capability_status: status,
      isolation: "production_unknown",
      managed_policy: adapter === "enterprise_managed",
      admin_permission_bound: adapter === "enterprise_managed",
    }).may_mutate === true;
  return {
    schema_version: 1,
    adapter,
    platform: adapter,
    runtime_domain:
      input.runtime_domain ??
      runtimeDomainFor(adapter, input.distro_name ?? null),
    status,
    writes_enabled: writes,
    mutation_disabled_by_default: !writes,
    discoveries: input.discoveries ?? [],
    gaps: DEFAULT_GAPS[adapter] ?? DEFAULT_GAPS.unknown,
    support_receipt: input.support_receipt ?? null,
    network_used: false,
    target_mutated: false,
    full_support_claimed: false,
  };
}
