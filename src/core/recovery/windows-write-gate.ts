/**
 * Windows write-scope gate for shared recovery (Ticket 14 P1).
 *
 * On a trusted Windows host, classify the repair target directory and any
 * concrete artifact write paths before preview/apply may proceed. Fail closed
 * for admin_required / forbidden_system / unknown with ADMIN_ACTION_REQUIRED +
 * IT handoff (no elevation or bypass guidance). Only user-owned cache/control
 * data paths may continue into the Ticket 02 engine.
 *
 * Platform resolution is trusted-host only: process.platform in production;
 * optional in-process injection for tests. Never accepted from CLI argv or
 * MCP tool JSON. Real win32 hosts cannot be downgraded.
 */
import path from "node:path";
import {
  classifyWriteTarget,
  writeScopeToErrorCode,
} from "../../instances/windows/policy.js";
import type { WindowsWriteClassification } from "../../instances/windows/types.js";
import type { AdminHandoff } from "./types.js";

export interface WindowsWriteGateContext {
  /**
   * Trusted host platform override for deterministic tests.
   * Production CLI/MCP omit this; defaults to process.platform.
   * Never sourced from user-supplied repair request JSON.
   */
  hostPlatform?: string;
  /** Explicit user-owned roots (tests / registered control roots). */
  userOwnedRoots?: string[];
  /** Managed / admin ownership probe flags when already known. */
  managed?: {
    policy_class: string;
    admin_owned: boolean;
    signed: boolean;
    permission_bound: boolean;
  };
  /**
   * Additional absolute paths that would be written (artifact targets).
   * Each is classified independently after the target directory.
   */
  writePaths?: Array<{ absPath: string; alias: string }>;
}

export interface WindowsWriteGateBlocked {
  blocked: true;
  error_code: "ADMIN_ACTION_REQUIRED";
  error_message: string;
  classification: WindowsWriteClassification;
  admin_handoff: AdminHandoff;
}

export interface WindowsWriteGateAllowed {
  blocked: false;
  classification: WindowsWriteClassification | null;
}

export type WindowsWriteGateResult =
  | WindowsWriteGateBlocked
  | WindowsWriteGateAllowed;

function normalizePlatform(raw: string): string {
  const n = raw.toLowerCase();
  if (n === "windows" || n === "win32") return "win32";
  if (n === "darwin" || n === "macos") return "darwin";
  if (n === "linux") return "linux";
  return n;
}

/**
 * Resolve trusted host platform.
 * Precedence: real win32 (non-downgradable) → in-process injection →
 * dual-key test harness env → process.platform.
 */
export function resolveTrustedHostPlatform(
  injected?: string | null,
): string {
  // Real Windows hosts are always Windows — never allow test/env downgrade.
  if (process.platform === "win32") {
    return "win32";
  }
  if (typeof injected === "string" && injected.length > 0) {
    return normalizePlatform(injected);
  }
  // Test harness only: both keys required. Not CLI/MCP product flags.
  if (
    process.env.CHANGEGUARD_ALLOW_HOST_PLATFORM_INJECTION === "1" &&
    typeof process.env.CHANGEGUARD_TRUSTED_HOST_PLATFORM === "string" &&
    process.env.CHANGEGUARD_TRUSTED_HOST_PLATFORM.length > 0
  ) {
    return normalizePlatform(process.env.CHANGEGUARD_TRUSTED_HOST_PLATFORM);
  }
  return normalizePlatform(process.platform);
}

export function isWindowsTrustedHost(injected?: string | null): boolean {
  return resolveTrustedHostPlatform(injected) === "win32";
}

function handoffFromClassification(
  c: WindowsWriteClassification,
): AdminHandoff {
  return {
    policy_class: c.policy_class,
    target_path_alias: c.target_path_alias,
    config_key: null,
    requested_action: c.requested_action,
    evidence_digests: [],
    admin_owned: c.admin_owned,
    signed: c.signed,
    permission_bound: c.permission_bound,
  };
}

function assertNoElevationLanguage(text: string): string {
  const lower = text.toLowerCase();
  // Strip any accidental elevation verbs if a future classifier drifts.
  if (
    lower.includes("chmod") ||
    lower.includes("runas") ||
    lower.includes("uac") ||
    lower.includes("elevate") ||
    lower.includes("sudo")
  ) {
    return "Contact IT/admin through the approved enterprise change process. Local privilege elevation is not offered.";
  }
  return text;
}

/**
 * Evaluate Windows write scope for a target directory and optional write paths.
 * Non-Windows hosts return allowed immediately (existing fixtures stay compatible).
 */
export function evaluateWindowsWriteGate(
  targetReal: string,
  ctx: WindowsWriteGateContext = {},
): WindowsWriteGateResult {
  if (!isWindowsTrustedHost(ctx.hostPlatform ?? null)) {
    return { blocked: false, classification: null };
  }

  const candidates: Array<{ absPath: string; alias: string }> = [
    { absPath: path.resolve(targetReal), alias: "REPAIR_TARGET" },
    ...(ctx.writePaths ?? []).map((w) => ({
      absPath: path.resolve(w.absPath),
      alias: w.alias,
    })),
  ];

  let lastUserOwned: WindowsWriteClassification | null = null;

  for (const cand of candidates) {
    const classification = classifyWriteTarget({
      absPath: cand.absPath,
      target_path_alias: cand.alias,
      userOwnedRoots: ctx.userOwnedRoots,
      managed: ctx.managed,
    });

    if (classification.scope === "user_owned") {
      lastUserOwned = classification;
      continue;
    }

    // Fail closed: admin_required / forbidden_system / unknown → ADMIN_ACTION_REQUIRED.
    const code = writeScopeToErrorCode(classification.scope);
    const action = assertNoElevationLanguage(classification.requested_action);
    const fixed: WindowsWriteClassification = {
      ...classification,
      requested_action: action,
    };
    return {
      blocked: true,
      error_code: "ADMIN_ACTION_REQUIRED",
      error_message:
        code === "ADMIN_ACTION_REQUIRED"
          ? "Windows write scope refused; administrator/IT action required. No local elevation or bypass is offered."
          : "Windows write scope refused for unclear or non-user-owned target.",
      classification: fixed,
      admin_handoff: handoffFromClassification(fixed),
    };
  }

  return { blocked: false, classification: lastUserOwned };
}
