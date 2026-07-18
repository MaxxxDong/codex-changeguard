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
  /**
   * Isolation claim bits. Failures may set false (schema allows boolean).
   * Full support requires every bit to be true.
   */
  active_codex_home_untouched: boolean;
  disposable_targets_only: boolean;
  no_sudo: boolean;
  no_protected_write: boolean;
  no_active_profile_mutation: boolean;
  /** Digest over isolation assertion material (hashes only). */
  isolation_digest: string;
  /**
   * Path-free witness digest of active ~/.codex (existence + coarse metadata).
   * Bound into isolation_digest; never contains raw paths or secret contents.
   */
  active_home_witness_digest: string;
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

// ---------------------------------------------------------------------------
// Ticket 15 — Linux / WSL / enterprise capability contracts
// Distinct from macOS/Windows harness receipts above (no second truth source).
// ---------------------------------------------------------------------------

/** Uppercase capability matrix status (Ticket 15). Distinct from PlatformSupportLevel. */
export type PlatformCapabilityStatus =
  | "READ_ONLY"
  | "LIMITED"
  | "PREVIEW"
  | "FULL";

export type AdapterId =
  | "unknown"
  | "macos"
  | "windows"
  | "linux"
  | "wsl"
  | "enterprise_managed";

/** Cross-OS identity domain — prevents WSL/host collapse. */
export type RuntimeDomain =
  | "native_linux"
  | "wsl_distro"
  | "windows_host"
  | "macos_host"
  | "unknown";

export type DiscoveryKind =
  | "cli_instance"
  | "config"
  | "log"
  | "user_cache"
  | "managed_policy";

export interface DiscoveryObservation {
  kind: DiscoveryKind;
  /** Alias only — never absolute path. */
  path_alias: string;
  path_hash: string;
  present: boolean;
  readable: boolean;
  /** Content digest when a regular file was read under bounds; null otherwise. */
  content_sha256: string | null;
  refused_reason: string | null;
}

export interface PlatformGap {
  id: string;
  summary: string;
  status: PlatformCapabilityStatus;
}

export interface OfficialReference {
  title: string;
  /** Allowlisted official URL only (help.openai.com / docs / status). */
  url_allowlisted: string;
}

/**
 * Ticket 15 lightweight support-status claim evidence.
 * Distinct from PlatformSupportReceipt (macOS harness) and WindowsPlatformSupportReceipt.
 * Synthetic fixtures alone cannot claim FULL.
 */
export interface SupportReceipt {
  schema_version: 1;
  /** Hashed scenario IDs that justify a capability claim. */
  scenario_ids: string[];
  claimed_status: PlatformCapabilityStatus;
  adapter: AdapterId;
  /** Real-machine receipts are required for FULL; synthetic fixtures alone cannot. */
  real_machine: boolean;
  notes: string[];
}

export interface PlatformCapabilityReport {
  schema_version: 1;
  adapter: AdapterId;
  platform: AdapterId;
  runtime_domain: RuntimeDomain;
  status: PlatformCapabilityStatus;
  /** Mutation disabled unless status is PREVIEW/FULL and gates pass. */
  writes_enabled: boolean;
  mutation_disabled_by_default: boolean;
  discoveries: DiscoveryObservation[];
  gaps: PlatformGap[];
  support_receipt: SupportReceipt | null;
  network_used: false;
  target_mutated: false;
  /** Truthful: no real Linux/WSL host FULL receipt in this repository. */
  full_support_claimed: false;
}

export type NetworkCompareBranch =
  | "service_incident"
  | "network_security_path"
  | "auth_method_sso_mismatch"
  | "local_session_state"
  | "unresolved_support";

/** Orchestrator-supplied observation only — never opens sockets. */
export interface NetworkCompareObservation {
  status_page_class: "operational" | "incident" | "unknown";
  path_a_success: boolean | null;
  path_b_success: boolean | null;
  /** Hashed network-path id only — never public IP. */
  network_path_id_hash: string | null;
  sso_method_class: string | null;
  surface_a: string | null;
  surface_b: string | null;
  proxy_or_filter_active: boolean | null;
  ssl_inspection_suspected: boolean | null;
}

export interface NetworkCompareResult {
  schema_version: 1;
  branch: NetworkCompareBranch;
  maximum_claim: string;
  safe_action: string;
  evidence_notes: string[];
  network_used: false;
  settings_mutated: false;
  official_reference: OfficialReference | null;
}

export interface ITHandoffMinimalEvidence {
  digests: string[];
  observed_flags: string[];
  adapter_status: PlatformCapabilityStatus;
  instance_id: string | null;
}

/**
 * Full IT Handoff for ADMIN_ACTION_REQUIRED.
 * Additive over Ticket 07 AdminHandoff field names for wire compatibility.
 */
export interface ITHandoff {
  schema_version: 1;
  status: "ADMIN_ACTION_REQUIRED";
  policy_class: string;
  target_path_alias: string;
  config_key: string | null;
  /** Ticket 07 compatibility aliases. */
  requested_action: string;
  evidence_digests: string[];
  admin_owned: boolean;
  signed: boolean;
  permission_bound: boolean;
  /** Ticket 15 IT fields. */
  minimal_evidence: ITHandoffMinimalEvidence;
  proposed_action: string;
  risk: "low" | "moderate" | "high";
  rollback: string;
  official_reference: OfficialReference | null;
  network_compare: NetworkCompareResult | null;
  secrets_present: false;
  absolute_paths_present: false;
}

export interface WriteGateInput {
  capability_status: PlatformCapabilityStatus;
  /** Isolated fixture / allowlisted user-owned recovery only. */
  isolation: "isolated_fixture" | "user_owned_registered" | "production_unknown";
  managed_policy: boolean;
  admin_permission_bound: boolean;
  /**
   * LIMITED may expose only validated user-owned registered recovery when
   * explicitly allowed; READ_ONLY never mutates.
   */
  allow_limited_user_owned_recovery?: boolean;
}

export interface WriteGateResult {
  may_mutate: boolean;
  reason_code: string;
  capability_status: PlatformCapabilityStatus;
}
