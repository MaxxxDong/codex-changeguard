/**
 * Evaluate platform support level from a validated receipt (Ticket 14).
 *
 * Rules:
 * - Default / no receipt → PREVIEW with explicit gaps
 * - synthetic / cross_platform_ci → can never be FULL
 * - non-Windows platform receipt → cannot authorize Windows FULL
 * - Structural completeness (real_machine + Windows 11 + all critical
 *   scenarios + attestation) is necessary but not sufficient for FULL
 * - FULL requires a matching process-local live harness witness sealed in
 *   the same process (WeakMap). External JSON / CLI / MCP / plain objects
 *   alone are capped at Preview (FULL_REQUIRES_LIVE_WITNESS).
 */
import {
  WINDOWS11_CRITICAL_SCENARIOS,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
} from "./critical-scenarios.js";
import {
  parsePlatformSupportReceipt,
  receiptDigest,
  ReceiptValidationError,
  windowsLiveWitnessMatchesReceipt,
  type WindowsLiveHarnessWitness,
} from "./receipt.js";
import type {
  PlatformSupportGap,
  PlatformSupportReceipt,
  PlatformSupportStatus,
  Windows11CriticalScenarioId,
} from "./types.js";

function isWindows11(receipt: PlatformSupportReceipt): boolean {
  if (receipt.platform !== "windows") return false;
  const family = receipt.os_family.toLowerCase();
  const version = (receipt.os_version ?? "").toLowerCase();
  // Accept explicit "Windows 11" family or version "11".
  if (family.includes("windows") && (family.includes("11") || version === "11")) {
    return true;
  }
  if (version.includes("windows 11")) return true;
  // Build-based hint: Windows 11 builds are 22000+.
  if (receipt.os_build) {
    const n = parseInt(receipt.os_build.replace(/[^\d]/g, ""), 10);
    if (Number.isFinite(n) && n >= 22000) return true;
  }
  return false;
}

function gap(
  code: string,
  message: string,
  scenario_id: Windows11CriticalScenarioId | null = null,
): PlatformSupportGap {
  return { code, message, scenario_id };
}

export interface EvaluatePlatformSupportOptions {
  now?: () => Date;
  expectedPlatform?: "windows";
  /**
   * Process-local witness from a controlled live Windows harness only.
   * Never accept a JSON field or plain object as a substitute.
   */
  liveWitness?: WindowsLiveHarnessWitness;
}

/**
 * Evaluate support status. Never fabricates FULL from synthetic evidence
 * or from external/self-reported real_machine JSON alone.
 */
export function evaluatePlatformSupport(
  receiptOrUnknown: PlatformSupportReceipt | unknown | null,
  options?: EvaluatePlatformSupportOptions,
): PlatformSupportStatus {
  const now = options?.now ?? (() => new Date());
  const evaluated_at = now().toISOString();
  const expected = options?.expectedPlatform ?? "windows";

  if (receiptOrUnknown === null || receiptOrUnknown === undefined) {
    return {
      schema_version: 1,
      platform: expected,
      level: "preview",
      full_authorized: false,
      gaps: [
        gap(
          "NO_RECEIPT",
          "No platform support receipt; status remains PREVIEW.",
        ),
        ...WINDOWS11_CRITICAL_SCENARIO_IDS.map((id) =>
          gap(
            "MISSING_SCENARIO",
            `Critical scenario ${id} not evidenced.`,
            id,
          ),
        ),
      ],
      receipt: null,
      receipt_digest: null,
      evaluated_at,
      summary:
        "Windows 11 support is PREVIEW: no real-machine Scenario Harness receipt.",
    };
  }

  let receipt: PlatformSupportReceipt;
  try {
    // Always re-parse to enforce bounds and extra-key fail-closed even for
    // typed objects or prior parse results.
    receipt = parsePlatformSupportReceipt(receiptOrUnknown);
  } catch (e) {
    const code =
      e instanceof ReceiptValidationError ? e.code : "INVALID_RECEIPT";
    const message =
      e instanceof ReceiptValidationError
        ? e.message
        : "Receipt validation failed.";
    return {
      schema_version: 1,
      platform: expected,
      level: "preview",
      full_authorized: false,
      gaps: [gap(code, message)],
      receipt: null,
      receipt_digest: null,
      evaluated_at,
      summary: `Windows 11 support is PREVIEW: receipt rejected (${code}).`,
    };
  }

  const digest = receiptDigest(receipt);
  const gaps: PlatformSupportGap[] = [];

  if (receipt.host_kind === "synthetic") {
    gaps.push(
      gap(
        "SYNTHETIC_HOST",
        "Synthetic receipts can only support PREVIEW, never FULL.",
      ),
    );
  }
  if (receipt.host_kind === "cross_platform_ci") {
    gaps.push(
      gap(
        "CROSS_PLATFORM_CI",
        "Cross-platform CI receipts can only support PREVIEW, never FULL.",
      ),
    );
  }
  if (receipt.platform !== "windows") {
    gaps.push(
      gap(
        "NON_WINDOWS_RECEIPT",
        `Receipt platform is ${receipt.platform}; cannot authorize Windows FULL.`,
      ),
    );
  }
  if (receipt.platform === "windows" && !isWindows11(receipt)) {
    gaps.push(
      gap(
        "NOT_WINDOWS_11",
        "Receipt is not recognized as Windows 11 (os_family/version/build).",
      ),
    );
  }
  if (receipt.host_kind === "real_machine") {
    const att = receipt.operator_attestation;
    if (!att) {
      gaps.push(
        gap(
          "MISSING_ATTESTATION",
          "Real-machine FULL requires operator_attestation.",
        ),
      );
    } else {
      if (!att.non_primary_profile) {
        gaps.push(
          gap(
            "PRIMARY_PROFILE_RISK",
            "Operator must attest non-primary Codex profile was used.",
          ),
        );
      }
      if (!att.real_hardware) {
        gaps.push(
          gap(
            "HARDWARE_ATTESTATION",
            "Operator must attest real hardware collection.",
          ),
        );
      }
    }
  }

  const byId = new Map(
    receipt.critical_scenarios.map((s) => [s.id, s] as const),
  );
  for (const def of WINDOWS11_CRITICAL_SCENARIOS) {
    const row = byId.get(def.id);
    if (!row) {
      gaps.push(
        gap(
          "MISSING_SCENARIO",
          `Critical scenario ${def.id} (${def.title}) missing from receipt.`,
          def.id,
        ),
      );
      continue;
    }
    if (!row.passed) {
      gaps.push(
        gap(
          "SCENARIO_FAILED",
          `Critical scenario ${def.id} did not pass.`,
          def.id,
        ),
      );
    }
    if (row.passed && !row.evidence_digest) {
      gaps.push(
        gap(
          "MISSING_EVIDENCE",
          `Critical scenario ${def.id} passed without evidence_digest.`,
          def.id,
        ),
      );
    }
  }

  // Structural completeness: real Windows 11 host + zero structural gaps.
  // Still not Full without a matching process-local live witness.
  const structurallyComplete =
    gaps.length === 0 &&
    receipt.host_kind === "real_machine" &&
    receipt.platform === "windows" &&
    isWindows11(receipt);

  let liveWitnessOk = false;
  if (structurallyComplete) {
    const witness = options?.liveWitness;
    if (witness && windowsLiveWitnessMatchesReceipt(receipt, witness)) {
      liveWitnessOk = true;
    } else if (witness !== undefined && witness !== null) {
      // Present but not a matching process-local witness (plain object, wrong binding).
      gaps.push(
        gap(
          "LIVE_WITNESS_MISMATCH",
          "Live harness witness is missing, forged, or does not match this receipt binding.",
        ),
      );
    } else {
      gaps.push(
        gap(
          "FULL_REQUIRES_LIVE_WITNESS",
          "FULL requires a process-local live Windows Scenario Harness witness; external JSON alone cannot authorize FULL.",
        ),
      );
    }
  }

  const full_authorized = structurallyComplete && liveWitnessOk && gaps.length === 0;

  // Limited: discovery-only narrative for non-Windows or explicit limited
  // (Ticket 15 owns Linux/WSL limited; Windows path uses preview until full).
  let level: PlatformSupportStatus["level"] = "preview";
  if (full_authorized) {
    level = "full";
  } else if (
    receipt.platform === "linux" ||
    receipt.platform === "wsl"
  ) {
    level = "limited";
  }

  const summary = full_authorized
    ? "Windows 11 support is FULL: live harness witness covers all critical scenarios."
    : `Windows 11 support is ${level.toUpperCase()}: ${gaps.length} gap(s); FULL not authorized.`;

  return {
    schema_version: 1,
    platform: receipt.platform === "unknown" ? expected : receipt.platform,
    level,
    full_authorized,
    gaps,
    receipt,
    receipt_digest: digest,
    evaluated_at,
    summary,
  };
}

/**
 * Convenience: evaluate Windows 11 status and always keep PREVIEW language
 * when full is not authorized (never silent upgrade).
 */
export function windows11SupportStatus(
  receipt: PlatformSupportReceipt | unknown | null,
  options?: Omit<EvaluatePlatformSupportOptions, "expectedPlatform">,
): PlatformSupportStatus {
  return evaluatePlatformSupport(receipt, {
    ...options,
    expectedPlatform: "windows",
  });
}
