/**
 * Platform support status + Scenario Harness receipt contracts (Ticket 14).
 *
 * FULL is never claimed from synthetic or cross-platform CI evidence, nor
 * from external/self-reported real_machine JSON alone. Full requires a
 * process-local live harness witness bound to a complete Windows 11 receipt.
 */

/** Published support level for a platform. */
export type PlatformSupportLevel =
  | "preview"
  | "full"
  | "limited"
  | "unsupported";

/** How the receipt was collected. Synthetic can never upgrade to full. */
export type PlatformReceiptHostKind =
  | "real_machine"
  | "synthetic"
  | "cross_platform_ci";

export type PlatformReceiptPlatform =
  | "windows"
  | "macos"
  | "linux"
  | "wsl"
  | "unknown";

/** Critical Windows 11 Scenario Harness IDs (W11-S01 … W11-S11). */
export type Windows11CriticalScenarioId =
  | "W11-S01"
  | "W11-S02"
  | "W11-S03"
  | "W11-S04"
  | "W11-S05"
  | "W11-S06"
  | "W11-S07"
  | "W11-S08"
  | "W11-S09"
  | "W11-S10"
  | "W11-S11";

export interface CriticalScenarioResult {
  id: Windows11CriticalScenarioId;
  /** Human-readable scenario title (no secrets / paths). */
  title: string;
  passed: boolean;
  /**
   * Digest of scenario evidence only — never absolute paths, tokens, or dump bodies.
   * Null when the scenario was not executed.
   */
  evidence_digest: string | null;
  /** Optional bounded note (redacted; no absolute paths). */
  note: string | null;
}

export interface PlatformOperatorAttestation {
  /** Operator asserts tests did not use the primary active Codex profile. */
  non_primary_profile: boolean;
  /** Operator asserts collection ran on real hardware (not a VM claim alone). */
  real_hardware: boolean;
}

/**
 * Auditable platform support receipt.
 * Public fields only — never absolute user paths or secrets.
 */
export interface PlatformSupportReceipt {
  schema_version: 1;
  platform: PlatformReceiptPlatform;
  /** e.g. "Windows 11", "macOS 15" — free text, bounded. */
  os_family: string;
  /** e.g. "11" or marketing version string. */
  os_version: string | null;
  /** OS build string when known (e.g. Windows build 22631). */
  os_build: string | null;
  arch: string;
  host_kind: PlatformReceiptHostKind;
  /** Codex product versions observed during the run (aliases only). */
  codex_versions: string[];
  /** Overall fingerprint of observed instances (path-free). */
  instances_fingerprint: string | null;
  /** Git SHA of the ChangeGuard tree under test, when known. */
  git_sha: string | null;
  /** ISO-8601 UTC collection time. */
  collected_at: string;
  critical_scenarios: CriticalScenarioResult[];
  operator_attestation: PlatformOperatorAttestation | null;
}

export interface PlatformSupportGap {
  code: string;
  message: string;
  scenario_id: Windows11CriticalScenarioId | null;
}

export interface PlatformSupportStatus {
  schema_version: 1;
  platform: PlatformReceiptPlatform;
  level: PlatformSupportLevel;
  /** True only when level === "full" under validator rules. */
  full_authorized: boolean;
  gaps: PlatformSupportGap[];
  receipt: PlatformSupportReceipt | null;
  /** Digest of the receipt payload used for evaluation (null when no receipt). */
  receipt_digest: string | null;
  evaluated_at: string;
  /** Explicit product language for consumers. */
  summary: string;
}
