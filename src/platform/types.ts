/**
 * Platform support contracts (Ticket 13+).
 * Public outputs never include raw user paths, usernames, or temp roots.
 */

import type { InstallSource, PlatformId, VersionProvenance } from "../instances/types.js";

export type { PlatformId, InstallSource, VersionProvenance };

/** Support level declared only from real-machine Scenario Harness receipts. */
export type PlatformSupportLevel =
  | "full"
  | "preview"
  | "limited"
  | "read_only"
  | "unsupported";

/** Registered path-role aliases (never absolute paths). */
export type PathRole =
  | "install"
  | "profile"
  | "config"
  | "log"
  | "cache"
  | "crash_metadata";

/** Bounded operations the platform adapter may advertise. */
export type RegisteredOperation =
  | "diagnose_read_only"
  | "scan_instances"
  | "config_repair"
  | "plugin_cache_repair"
  | "verify"
  | "rollback"
  | "lifecycle_known_good"
  | "lifecycle_canary"
  | "upstream_preview"
  | "impact_local"
  | "package_smoke";

export interface PlatformPathAlias {
  alias: string;
  role: PathRole;
  /** Always true — only registered candidates exist. */
  registered: true;
}

/** Hard safety constraints for every supported platform adapter. */
export interface PlatformSafetyConstraints {
  broad_home_crawl: false;
  raw_path_export: false;
  execute_discovered_binaries: false;
  sudo_required: false;
  system_certificate_change: false;
  system_proxy_change: false;
  security_control_change: false;
  signed_app_mutation: false;
  openai_binary_mutation: false;
  active_profile_mutation: false;
}

export interface PlatformCapabilities {
  schema_version: 1;
  platform: PlatformId;
  arch: string;
  /** Coarse OS label (e.g. macos-26.x); never username or home path. */
  coarse_os_version: string | null;
  install_sources: InstallSource[];
  path_aliases: PlatformPathAlias[];
  operations: RegisteredOperation[];
  constraints: PlatformSafetyConstraints;
  /** False when only read-only generic diagnosis is safe. */
  mutation_enabled: boolean;
  /**
   * Marketing/pre-receipt claim only. Verified level lives on the receipt.
   * Never upgrade this field based on fixture-only tests.
   */
  declared_support_level: PlatformSupportLevel;
}

export interface CodexVersionProvenance {
  available: boolean;
  version: string | null;
  provenance: VersionProvenance | "unavailable";
}

export type ScenarioStatus = "pass" | "fail" | "skipped";

export interface ScenarioOutcome {
  scenario_id: string;
  /** SHA-256 of the scenario definition / fixture identity (no paths). */
  scenario_hash: string;
  status: ScenarioStatus;
  outcome_summary: string;
  duration_ms: number;
  required: boolean;
}

export interface IsolationProof {
  active_codex_home_untouched: true;
  disposable_targets_only: true;
  no_sudo: true;
  no_protected_write: true;
  no_active_profile_mutation: true;
  /** Digest over isolation assertion material (hashes only). */
  isolation_digest: string;
}

export interface ReceiptAssertions {
  no_sudo: true;
  no_active_profile: true;
  no_protected_write: true;
  no_username: true;
  no_raw_temp_path: true;
}

/**
 * Real-machine Scenario Harness receipt.
 * Full support requires every required scenario to pass and validation to succeed.
 */
export interface PlatformSupportReceipt {
  schema_version: 1;
  receipt_id: string;
  platform: PlatformId;
  arch: string;
  coarse_os_version: string;
  changeguard_version: string;
  /** Tested tree commit when safely available (git SHA); never a local path. */
  changeguard_commit: string | null;
  codex_version_provenance: CodexVersionProvenance;
  capabilities: PlatformCapabilities;
  scenarios: ScenarioOutcome[];
  isolation: IsolationProof;
  started_at: string;
  ended_at: string;
  duration_ms: number;
  support_level: PlatformSupportLevel;
  uncovered_gaps: string[];
  assertions: ReceiptAssertions;
  network_used: false;
}

export interface ReceiptValidationResult {
  schema_version: 1;
  ok: boolean;
  support_level: PlatformSupportLevel;
  errors: string[];
  gaps: string[];
  receipt_id: string | null;
  network_used: false;
}

/** Required real-machine scenario ids for macOS Full. */
export const MACOS_REQUIRED_SCENARIO_IDS = [
  "core_read_only_detection",
  "multi_instance_scan",
  "config_repair_success",
  "forced_verify_fail_auto_rollback",
  "explicit_rollback",
  "plugin_cache_repair_rollback",
  "known_good_canary",
  "privacy_refusal_local_diagnosis",
  "upstream_preview_zero_network",
  "package_smoke",
] as const;

export type MacosRequiredScenarioId =
  (typeof MACOS_REQUIRED_SCENARIO_IDS)[number];
